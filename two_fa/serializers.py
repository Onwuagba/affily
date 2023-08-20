from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework import serializers
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from two_fa.models import CustomTOTPDeviceModel


class UserOTPDeviceSerializer(serializers.ModelSerializer):
    date_added = serializers.SerializerMethodField('get_date_added')

    class Meta:
        model = TOTPDevice
        fields = ('name','confirmed','date_added')

    def get_date_added(self, obj):
        content_type = ContentType.objects.get_for_model(obj)
        custom_device = CustomTOTPDeviceModel.objects.get(
            content_type=content_type,
            object_id=obj.id,
            endpoint__endswith='activate/'
        )
        
        created_at_utc = custom_device.created_at
        created_at_local = timezone.localtime(created_at_utc)

        return created_at_local.strftime("%Y-%m-%d %H:%M:%S")