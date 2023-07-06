from django.contrib import admin
from two_fa.models import CustomTOTPDeviceModel


@admin.register(CustomTOTPDeviceModel)
class CustomTOTPDeviceAdmin(admin.ModelAdmin):
    list_display = (
        "user_device",
        "created_at",
        "updated_at",
    )
