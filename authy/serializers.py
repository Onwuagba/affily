import logging
from base64 import urlsafe_b64encode

from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt import serializers as jwt_serializers
# from rest_framework_simplejwt.tokens import RefreshToken

from authy.backends.custom_auth_backend import CustomBackend
from authy.helpers.helper import (
    GoogleSignIn,
    TwitterSignIn,
    allowed_providers,
    facebook_social_check,
)
from authy.models import CustomToken, UserAccount
from authy.signals import user_created
from authy.utilities.constants import admin_support_sender, email_sender
from authy.utilities.tasks import send_notif_email
from common.exceptions import AccountLocked, AlreadyExists
from two_fa.views import (
    custom_verify,
    custom_verify_backup_code,
    get_user_totp_device,
)

logger = logging.getLogger("app")
UserModel = get_user_model()


token_validator = RegexValidator(
    regex=r"^[a-zA-Z0-9-]+$",
    message=(
        "Invalid token format. Only alphanumeric characters and hyphens are allowed."
    ),
)


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
                # token = CustomToken.generate_key()
                CustomToken.objects.filter(
                    user=instance.user, key=instance.key
                ).update(
                    # key=token, # can't update PK
                    expiry_date=instance.created,
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
        reset_url = request.build_absolute_uri(f"update/{uid}/{token}/")
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
            user = CustomBackend().authenticate(req, **authenticate_kwargs)
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

            # check axes for locked out user
            check_lockout, check_lockout_msg = user.check_lockout()
            if check_lockout:
                raise AccountLocked(check_lockout_msg)
            elif check_lockout_msg:
                # workaround for axes_reset_on_success
                # Wasn't working from settings.py
                # check_lockout_msg is now an obj
                check_lockout_msg.failures_since_start = 0
                check_lockout_msg.save()

            if device := get_user_totp_device(user):
                # generate token and return it.
                return self.confirm_2fa_required(user, device)

        except Exception as e:
            logger.error(
                f"Authentication failed for **{username or email}** with error: {e}"
            )

            if isinstance(e, AccountLocked):
                raise
            raise ValidationError(e) from e

        return self.return_token(user)

    def confirm_2fa_required(self, user, device):
        if device and device.confirmed:
            return {
                "token": default_token_generator.make_token(user),
                "2fa_required": True,
            }
        return self.return_token(user)

    def return_token(self, user):
        token = self.get_token(user)
        update_last_login(None, user)  # fix: simplejwt last_login attr not working
        return {
            "access": str(token.access_token),
            "refresh": str(token),
            "2fa_required": False,
        }


class LoginWith2faTokenSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    token = serializers.CharField(validators=[token_validator])
    otp = serializers.CharField(max_length=8)

    def validate(self, attrs):
        username = attrs.get("username")
        email = attrs.get("email")
        token = attrs.get("token")
        otp = attrs.get("otp")

        if not username and not email:
            raise ValidationError("Username or email must be provided.")

        user = UserModel.objects.filter(
            Q(username=username) | Q(email=username), is_deleted=False
        ).first()

        if not user:
            raise ValidationError("Invalid username or email.")

        if not user.is_active:
            data = {"email": email} if email else {"username": username}
            RegenerateEmailVerificationSerializer(
                context={"request": self.context["request"]}
            ).validate(data)
            raise AuthenticationFailed(
                "Account not verified yet. Check email to complete verification"
            )

        if not default_token_generator.check_token(user, token):
            raise ValidationError("Invalid token.")

        stat, msg = self.verify_user_otp(user, otp)
        if stat:
            auth_token = jwt_serializers.TokenObtainPairSerializer.get_token(user)
            update_last_login(None, user)  # simplejwt last_login not working
            return {
                "access": str(auth_token.access_token),
                "refresh": str(auth_token),
            }
        raise ValidationError(msg)

    def validate_otp(self, value):
        # default otp field validation
        if len(value) in {6, 8}:
            return value
        else:
            raise ValidationError("Invalid OTP format.")

    def verify_user_otp(self, user, otp):
        stat, otp_message = custom_verify(user, otp, self.context["request"])
        return (True, "") if stat else (False, otp_message)


class LoginWithLost2faDeviceTokenSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    token = serializers.CharField(validators=[token_validator])
    otp = serializers.CharField(max_length=10)

    def validate(self, attrs):
        username = attrs.get("username")
        email = attrs.get("email")
        token = attrs.get("token")
        otp = attrs.get("otp")

        if not username and not email:
            raise ValidationError("Username or email must be provided.")

        user = UserModel.objects.filter(
            Q(username=username) | Q(email=username), is_deleted=False
        ).first()

        if not user:
            raise ValidationError("Invalid username or email.")

        if not user.is_active:
            data = {"email": email} if email else {"username": username}
            RegenerateEmailVerificationSerializer(
                context={"request": self.context["request"]}
            ).validate(data)
            raise AuthenticationFailed(
                "Account not verified yet. Check email to complete verification"
            )

        if not default_token_generator.check_token(user, token):
            raise ValidationError("Invalid token.")

        stat, msg = self.verify_user_otp(user, otp)
        if stat:
            auth_token = jwt_serializers.TokenObtainPairSerializer.get_token(user)
            update_last_login(None, user)  # simplejwt last_login not working
            return {
                "access": str(auth_token.access_token),
                "refresh": str(auth_token),
            }
        raise ValidationError(msg)

    def verify_user_otp(self, user, otp):
        stat, otp_message = custom_verify_backup_code(
            user, otp, self.context["request"]
        )
        return (True, "") if stat else (False, otp_message)


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
            error["password"] = "Old password not valid"
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


class SocialSignUpSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    access_token_secret = serializers.CharField(required=False)
    oauth_callback_confirmed = serializers.BooleanField(required=False)

    def get_provider_class(self, provider, data):
        provider_dict = {
            "google": (GoogleSignIn, "save_user_info"),
            "facebook": (TwitterSignIn, "twitter_social_check"),
            # "twitter": '',
        }

        if res := provider_dict.get(provider.lower()):
            class_name, method = res
            instance = class_name()
            if hasattr(instance, method):
                return getattr(instance, method)(data)

        raise serializers.ValidationError(f"Error connecting to {provider}")

    # def validate(self, data):
    #     provider = self.context.get("provider")
    #     if not provider or not data["access_token"]:
    #         raise serializers.ValidationError(
    #             "Provider and access_token are required."
    #         )

    #     return data

    def validate(self, data):
        provider = self.context.get("provider")
        if provider and not allowed_providers(provider):
            raise serializers.ValidationError(f"Invalid provider {provider}")
        return data

    def create(self, validated_data):
        try:
            return self.get_provider_class(
                self.context.get("provider"), validated_data
            )
        except AlreadyExists as ex:
            raise ex
        except Exception as e:
            raise serializers.ValidationError(str(e)) from e

        # if not social_account:
        #     raise serializers.ValidationError(
        #         "Invalid or expired access token. Please try again later"
        #     )

        # if (
        #     social_account.get("email_verified") == True
        #     and UserModel.objects.filter(email=social_account.get("email")).exists()
        # ):
        #     raise AlreadyExists("Email account already exists")

        # return UserModel.objects.create(
        #     username=(
        #         f"{social_account.get('given_name')[:4]}_{str(uuid.uuid4())[:8]}"
        #     ),
        #     email=social_account.get("email"),
        #     first_name=social_account.get("given_name"),
        #     last_name=social_account.get("family_name"),
        #     is_active=True,
        # )
