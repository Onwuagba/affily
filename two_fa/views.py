from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice

from authy.api_response import CustomAPIResponse
from two_fa.models import CustomTOTPDeviceModel
from django.contrib.auth.tokens import default_token_generator
from base64 import urlsafe_b64encode, urlsafe_b64decode
from authy.utilities.constants import email_sender
from notification.utilities.tasks import send_notification_email
import logging
from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied

logger = logging.getLogger("app")


def get_user_totp_device(user, confirmed=None):
    if devices := devices_for_user(user, confirmed=confirmed):
        for device in devices:
            if isinstance(device, TOTPDevice):
                return device


class TOTPCreateView(APIView):
    """
    Endpoint to activate 2fa and add TOTP device
    """

    http_method_names = ["post"]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user = request.user

        if not user or user.is_deleted or not user.is_active:
            return CustomAPIResponse(
                "No account found for this user",
                status.HTTP_400_BAD_REQUEST,
                "failed",
            ).send()

        device = get_user_totp_device(user) or user.totpdevice_set.create(
            confirmed=False,
            name=request.data.get("name") or None,
        )
        CustomTOTPDeviceModel.objects.get_or_create(
            user_device=device,
        )
        message = device.config_url
        status_code = status.HTTP_201_CREATED
        response = CustomAPIResponse(message, status_code, "success")
        return response.send()


class TOTPDeleteView(APIView):
    """
    Endpoint to deactivate 2fa and delete TOTP device
    """

    http_method_names = ["delete"]
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        message = "2FA not activated for this user"
        status_code = status.HTTP_400_BAD_REQUEST
        code_status = "failed"

        if get_user_totp_device(user):
            self.create_token_send_email(request)
            message = (
                "2FA deactivation initiated. Check your email to complete process"
            )
            status_code = status.HTTP_200_OK
            code_status = "success"
        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()

    def create_token_send_email(self, request, *args):
        user = request.user
        token = default_token_generator.make_token(user)
        uid = urlsafe_b64encode(bytes(str(user.uid), "utf-8")).decode("utf-8")

        email_content = {
            "subject": "2FA deactivation on your Affily account",
            "sender": email_sender,
            "recipient": user.email,
            "template": "2fa_deactivated.html",
        }
        reset_url = request.build_absolute_uri(f"complete_deactivate/{uid}/{token}")
        context = {"username": user.username, "url": reset_url}
        logger.info(f"context for 2fa deactivation email to be sent: {context}")

        # call celery
        send_notification_email.delay(email_content, context)
        return True
    

class TOTPCompleteDeleteView(APIView):
    """
    Endpoint to complete deactivation of 2fa
    """

    http_method_names = ["get"]
    permission_classes = [IsAuthenticated]

    def get_object(self, user, uid, token):
        model = get_user_model()

        if not all([uid, token]):
            raise ValidationError(
                "Link is invalid or expired."
            )

        uid = urlsafe_b64decode(uid).decode("utf-8")
        try:
            user_obj = model.objects.get(uid=uid)
        except model.DoesNotExist as e:
            raise ValidationError(
                "No user found with given ID. "
            ) from e
        
        if user != user_obj:
            raise PermissionDenied(
                "Access denied for user"
            )

        if not default_token_generator.check_token(user_obj, token):
            raise ValidationError(
                "Deactivation link has expired."
            )

        return user

    def get(self, request, **kwargs):
        uid = kwargs.get("uid", "")
        token = kwargs.get("token", "")
        user = request.user
        status_code = status.HTTP_400_BAD_REQUEST
        code_status = "failed"

        try:
            if user := self.get_object(user, uid, token):
                if device := get_user_totp_device(user):
                    device.delete()
                    message = "2FA deactivated successfully"
                    status_code = status.HTTP_200_OK
                    code_status = "success"
                else:
                    message = "2FA not activated for this user"
            else:
                message = "Link is invalid or expired."
        except Exception as e:
            message = e.args[0]
            status_code = status.HTTP_403_FORBIDDEN
        
        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()
    

class TOTPVerifyView(APIView):
    """
    Endpoint to verify/enable a TOTP device
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, token, format=None):
        message = "Invalid token"
        status_code = status.HTTP_400_BAD_REQUEST
        code_status = "failed"

        user = request.user
        device = get_user_totp_device(user)

        if not isinstance(token, int) or len(str(token)) != 6:
            message = "Token is not valid"
            response = CustomAPIResponse(message, status_code, code_status)
            return response.send()

        if not device:
            message = "No device found for this user"

        if device and device.verify_token(token):
            if not device.confirmed:
                device.confirmed = True
                device.save()

                CustomTOTPDeviceModel.objects.update_or_create(
                    user_device=device,
                )

                message = "Device verified successfully"
                status_code = status.HTTP_200_OK
                code_status = "success"
            else:
                message = "Device already verified"

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()
