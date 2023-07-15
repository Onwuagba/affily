from django_otp import user_has_device
from rest_framework.exceptions import PermissionDenied

from authy.permissions import IsAuthenticated


class OtpRequired(IsAuthenticated):
    message = "Verified OTP device required for this service"

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            raise PermissionDenied(
                {
                    "message": "Authentication credentials were not provided",
                    "status": "failed",
                }
            )

        if not user_has_device(request.user, confirmed=True):
            raise PermissionDenied({"message": self.message, "status": "failed"})

        return True
