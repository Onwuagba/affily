from django.db import models
from django_otp.plugins.otp_totp.models import TOTPDevice


class CustomTOTPDeviceModel(models.Model):
    user_device = models.OneToOneField(
        TOTPDevice, related_name="user_device", on_delete=models.CASCADE
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
