from django.db import models
from django_otp.plugins.otp_totp.models import TOTPDevice


class CustomTOTPDeviceModel(models.Model):
    user_device = models.ForeignKey(
        TOTPDevice, related_name="user_device", on_delete=models.CASCADE
    )
    endpoint = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        help_text="Endpoint that called the 2fa method",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
