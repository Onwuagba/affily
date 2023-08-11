from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from rest_framework.exceptions import ValidationError


class CustomTOTPDeviceModel(models.Model):
    # not using the normal FK method cos I want model to be related to either TOTPDevice or StaticDeviceModel
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    user_device = GenericForeignKey("content_type", "object_id")

    endpoint = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        help_text="Endpoint that called the 2fa method",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        from django.apps import apps

        # Check if the related object is an instance of TOTPDevice or StaticDeviceModel
        valid_models = (
            apps.get_model("otp", "TOTPDevice"),
            apps.get_model("otp_static", "StaticDeviceModel"),
        )
        if self.user_device.__class__ not in valid_models:
            raise ValidationError(
                "user_device must be a TOTPDevice or StaticDeviceModel instance"
            )
