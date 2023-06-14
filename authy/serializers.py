from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from django.db.models import F
from rest_framework import serializers
from django.db import transaction

from authy.models import CustomToken, UserAccount
from authy.utilities.constants import email_sender
from authy.signals import user_created
from authy.utilities.tasks import send_welcome_mail
import logging

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
        model = get_user_model()
        fields = "__all__"

    def validate(self, data):
        error = {}
        if not data.get("password") or not data.get("confirm_password"):
            error["password"] = "Please enter a password and confirm it"
        if data.get("password") != data.get("confirm_password"):
            error["password"] = "Your passwords do not match"

        if error:
            raise serializers.ValidationError(error)
        return data

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        validated_data.pop("confirm_password", None)

        user = self.Meta.model(**validated_data)

        user.set_password(password)
        user.save()

        user_created.send(
            sender=UserAccount,
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
                    is_active=True
                )
            except Exception:
                transaction.set_rollback(True)
                raise serializers.ValidationError(
                    "Error occurred confirming your email. Please try again later."
                )
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
        send_welcome_mail.delay(email_content, context)
        return True
