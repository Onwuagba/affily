import logging
from base64 import urlsafe_b64encode

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt import serializers as jwt_serializers

from authy.backends.custom_auth_backend import CustomBackend
from authy.models import CustomToken, UserAccount
from authy.signals import user_created
from authy.utilities.constants import admin_support_sender, email_sender
from authy.utilities.tasks import send_notif_email
from django.db.models import Q

logger = logging.getLogger("app")


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = UserAccount
        exclude = [
            "regToken",
        ]
        read_only_fields = [
            "groups",
            "user_permissions",
            "is_superuser",
            "is_staff",
            "is_deleted",
            "is_active",
            "last_login",
            "date_joined",
        ]

    def validate(self, data):
        if not data.get("password") or not data.get("confirm_password"):
            raise serializers.ValidationError(
                "Please enter a password and confirm it"
            )
        if data.get("password") != data.get("confirm_password"):
            raise serializers.ValidationError("Your passwords do not match")

        return data

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        validated_data.pop("confirm_password", None)

        user = self.Meta.model(**validated_data)

        user.set_password(password)
        user.save()

        user_created.send(
            sender=self.Meta.model,
            instance=user,
            created=True,
            request=self.context.get("request"),
        )

        return user


class ConfirmEmailSerializer(serializers.Serializer):
    def update(self, instance, validated_data):
        with transaction.atomic():
            try:
                token = CustomToken.generate_key()
                CustomToken.objects.filter(
                    user=instance.user, key=instance.key
                ).update(
                    key=token,
                    expiry_date=F("created"),
                    verified_on=timezone.localtime(),
                )
                UserAccount.objects.filter(uid=instance.user.uid).update(
                    is_active=True, regToken=instance.key
                )

                self.welcome_mail(instance)
            except Exception as e:
                transaction.set_rollback(True)
                logger.error(f"Error confirming email for {instance.user}: {e}")
                raise serializers.ValidationError(
                    "Error occurred confirming your email. Please try again later."
                ) from e
        return instance

    def welcome_mail(self, instance):
        request = self.context.get("request")
        email_content = {
            "subject": "Welcome to Affily! 🎉",
            "sender": email_sender,
            "recipient": instance.user.email,
            "template": "welcome-publisher.html",
        }
        url = f"{request.scheme}://{request.get_host()}/login"
        context = {
            "username": instance.user.username,
            "email": instance.user.email,
            "url": url,
        }
        logger.info(f"context for publisher welcome email to be sent: {context}")

        # call celery
        send_notif_email.delay(email_content, context)
        return True


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)

    def validate(self, data):
        UserAccountModel = get_user_model()
        try:
            user = UserAccountModel.objects.get(
                Q(username=data.get("username")) | Q(email=data.get("email")),
                is_deleted=False,
            )
        except (ValidationError, UserAccountModel.DoesNotExist) as e:
            logger.error(f"Exception in forgot password: {e}")
            raise serializers.ValidationError(
                "No account found with this email or username"
            ) from e

        return user

    def create_token_send_email(self, request, *args):
        user = self.validated_data
        token = default_token_generator.make_token(user)
        uid = urlsafe_b64encode(bytes(str(user.uid), "utf-8")).decode("utf-8")

        email_content = {
            "subject": "Reset password verification",
            "sender": email_sender,
            "recipient": user.email,
            "template": "forgot_password.html",
        }
        reset_url = request.build_absolute_uri(f"new_password/{uid}/{token}")
        print(reset_url)
        context = {"username": user.username, "url": reset_url}
        logger.info(f"context for forgot email to be sent: {user.username}")

        # call celery
        send_notif_email.delay(email_content, context)
        return True


class ChangePasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        if not data.get("new_password") or not data.get("confirm_password"):
            raise serializers.ValidationError(
                "Please enter a password and confirm it"
            )
        if data.get("new_password") != data.get("confirm_password"):
            raise serializers.ValidationError("Your passwords do not match")

        return data

    def update(self, instance, validated_data):
        if not instance.check_password(validated_data["new_password"]):
            instance.set_password(validated_data["new_password"])
            instance.save()

            self.send_mail(instance)
            return instance
        else:
            raise serializers.ValidationError(
                "Your password is similar to one previously used. Change it!"
            )

    def send_mail(self, instance):
        email_content = {
            "subject": "Password changed on Affily",
            "sender": email_sender,
            "recipient": instance.email,
            "template": "password_changed.html",
        }
        context = {
            "username": instance.username,
            "email": instance.email,
            "admin_email": admin_support_sender,
        }
        logger.info(f"context for password changed email to be sent: {context}")

        # call celery
        send_notif_email.delay(email_content, context)


class RegenerateEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)

    def validate(self, data):
        UserAccountModel = get_user_model()
        try:
            user = UserAccountModel.objects.get(
                Q(username=data.get("username")) | Q(email=data.get("email")),
                is_deleted=False,
            )
        except (ValidationError, UserAccountModel.DoesNotExist) as e:
            raise serializers.ValidationError(
                "No account found with this email or username"
            ) from e

        if user and user.is_active is True and not user.is_deleted:
            raise serializers.ValidationError("Account validated already")

        user_created.send(
            sender=UserAccountModel,
            instance=user,
            created=True,
            request=self.context.get("request"),
        )

        return user


class CustomTokenSerializer(jwt_serializers.TokenObtainPairSerializer):
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)
    password = serializers.CharField(required=True)

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["username"] = user.username
        return token

    @property
    def fields(self):
        fields = super().fields
        fields["username"].required = False
        return fields

    def validate(self, attrs):
        """
        Validate the input attributes.

        Args:
            attrs (dict): A dictionary containing the input attributes.
                - 'username' (str): The username.
                - 'email' (str): The email.
                - 'password' (str): The password.

        Raises:
            serializers.ValidationError: If 'username' or 'email' is not provided.
            serializers.ValidationError: If 'password' is not provided.
            AuthenticationFailed: If no account is found with the given credentials.
            ValidationError: If authentication fails.

        Returns:
            dict: The validated attributes.
        """
        username = attrs.get("username")
        email = attrs.get("email")
        password = attrs.get("password")
        req = self.context["request"]

        if not (username or email):
            raise serializers.ValidationError("Username/Email is required")
        if not password:
            raise serializers.ValidationError("Password is required")

        authenticate_kwargs = {
            self.username_field: username or email,
            "password": password,
        }

        try:
            authenticate_kwargs["request"] = req
            user = CustomBackend.authenticate(self, **authenticate_kwargs)
            if not user or user.is_deleted:
                raise AuthenticationFailed("No account found with this credential")

            if not user.is_active:
                data = {"email": email} if email else {"username": username}
                RegenerateEmailVerificationSerializer(
                    context={"request": req}
                ).validate(data)
                raise AuthenticationFailed(
                    "Account not verified yet. Check email to complete verification"
                )

        except Exception as e:
            logger.error(
                f"Authentication failed for **{username or email}** with error: {e}"
            )
            raise ValidationError(e) from e

        token = self.get_token(user)
        return {
            "access": str(token.access_token),
            "refresh": str(token),
        }


class ResetPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    confirm_password = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = UserAccount
        fields = ("old_password", "password", "confirm_password")

    def validate(self, data):
        error = {}
        user = self.instance

        if not data.get("password") or not data.get("confirm_password"):
            error["password"] = "Please enter a password and confirm it."
        if data.get("password") != data.get("confirm_password"):
            error["password"] = "Your passwords do not match"
        if not user.check_password(data.get("old_password")):
            error["password"] = "Your old password is not valid"
        if data.get("password") == data.get("old_password"):
            error["password"] = "New password cannot be same as old password"

        if error:
            raise serializers.ValidationError(error)

        data.pop("old_password")
        data.pop("confirm_password")
        return data

    def update(self, instance, validated_data):
        instance.set_password(validated_data["password"])
        instance.save()

        email_content = {
            "subject": "Your password was recently changed",
            "sender": email_sender,
            "recipient": instance.email,
            "template": "password_changed.html",
        }
        context = {"username": instance.first_name}
        logger.info(f"context for reset password email to be sent: {context}")

        send_notif_email.delay(email_content, context)

        return instance


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
