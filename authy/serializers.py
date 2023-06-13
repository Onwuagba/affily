import contextlib
from authy.signals import user_created
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model
from django.db.models import F
from django.utils import timezone

from authy.models import CustomToken, UserAccount


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
        try:
            token = CustomToken.generate_key(self)
            CustomToken.objects.filter(user=instance.user, key=instance.key).update(
                key=token,
                expiry_date=F("created"),
                verified_on=timezone.now()
            )
            UserAccount.objects.filter(uid=instance.user.uid).update(is_active=True)
        except Exception as ex:
            serializers.ValidationError(
                "Error occurred confirming your email. Please try again later.")
        return instance
