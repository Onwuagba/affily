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

from authy.models import CustomToken, UserAccount
from authy.signals import user_created
from authy.utilities.constants import admin_support_sender, email_sender
from authy.utilities.tasks import send_notif_email

logger = logging.getLogger("app")


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = UserAccount
        exclude = ["regToken"]

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
            except Exception as e:
                transaction.set_rollback(True)
                raise serializers.ValidationError(
                    "Error occurred confirming your email. Please try again later."
                ) from e
            self.welcome_mail(instance)
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
        UserDb = get_user_model()
        try:
            user = UserDb.objects.get(email=data.get("email"))
        except (ValidationError, UserDb.DoesNotExist):
            try:
                user = UserDb.objects.get(username=data.get("username"))
            except UserDb.DoesNotExist as e:
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
        logger.info(f"context for forgot email to be sent: {context}")

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
            user = UserAccountModel.objects.get(email=data.get("email"))
        except (ValidationError, UserAccountModel.DoesNotExist):
            try:
                user = UserAccountModel.objects.get(username=data.get("username"))
            except UserAccountModel.DoesNotExist as e:
                raise serializers.ValidationError(
                    "No account found with this email or username"
                ) from e

        if user and user.is_active == True:
            raise serializers.ValidationError("Account validated already")

        user_created.send(
            sender=UserAccountModel,
            instance=user,
            created=True,
            request=self.context.get("request"),
        )

        return user
