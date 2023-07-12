from django_otp import user_has_device
from rest_framework.permissions import IsAuthenticated


class OtpRequired(IsAuthenticated):

    message = "Verified OTP device is required for this service"

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        
        return user_has_device(request.user, confirmed=True)
