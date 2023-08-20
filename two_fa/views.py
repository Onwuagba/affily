from datetime import datetime
import logging
import os
from base64 import urlsafe_b64decode, urlsafe_b64encode

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django_otp import devices_for_user
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice
from dotenv import load_dotenv
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView

from authy.api_response import CustomAPIResponse
from authy.utilities.constants import email_sender
from common.permissions import IsAuthenticated
from notification.utilities.tasks import send_notification_email
from two_fa.models import CustomTOTPDeviceModel
from two_fa.permissions import OtpRequired
from two_fa.serializers import UserOTPDeviceSerializer
from two_fa.utils import hash_string

load_dotenv()

logger = logging.getLogger("app")

OTP_ENCRYPT_KEY = os.getenv("OTP_ENCRYPT_KEY").encode("utf-8")


###### NOTES ########
# User can activate token
# User can verify token
# User can deactive token
# User can create recovery backup codes if they lose their device

def get_or_create_custom_device(user_device, endpoint):
    content_type = ContentType.objects.get_for_model(user_device)
    custom_device, created = CustomTOTPDeviceModel.objects.get_or_create(
        content_type=content_type,
        object_id=user_device.id,
        endpoint=endpoint,
    )
    if not created:
        custom_device.updated_at = datetime.now()
        custom_device.save()

def get_user_static_device(user, confirmed=None):
    # for holding backup codes
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        if isinstance(device, StaticDevice):
            return device


def get_user_totp_device(user, confirmed=None):
    if devices := devices_for_user(user, confirmed=confirmed):
        for device in devices:
            if isinstance(device, TOTPDevice):
                return device


def custom_verify(user, otp, request=None):
    """
    Custom verification function to verify the One-Time Password (OTP) for a user.

    Args:
        user (User): The user object for whom the OTP is being verified.
        otp (str): The OTP entered by the user.
        request (HttpRequest, optional): The HTTP request object (default: None).

    Returns:
        tuple: A tuple containing two values:
            - res (bool): The result of the OTP verification. True if the OTP is valid, False otherwise.
            - message (str or object): The verification result message. It can be one of the following:
                - If the OTP is valid and a device is found for the user, the device object is returned.
                - If the OTP is not valid, the message is set to "otp is not valid".
                - If no device is found for the user, the message is set to "No device found for this user".

    """
    if not otp or len(otp) not in (6, 8):
        return False, "otp is not valid"

    device = get_user_totp_device(user)

    if not device:
        return False, "No device found for this user"

    if device.verify_token(otp):
        get_or_create_custom_device(
            user_device=device, endpoint=request.path if request else None
        )
        return True, device

    # instead of calling 2 endpoints (otplogin & lostdevicelogin)
    # combine both and check whichever one the user provides
    # check attached image from gitlab 2fa (otp_sample.png)
    res, msg = custom_verify_backup_code(user, otp, request)
    if res:
        get_or_create_custom_device(
            user_device=msg, endpoint=request.path if request else None
        )
        return True, msg

    return False, "Invalid otp"


def custom_verify_backup_code(user, code, request=None):
    # code: recovery code
    res = False
    message = "Invalid code"
    device = get_user_static_device(user, confirmed=True)

    if not code or len(code) != 8:
        return res, "Recovery code is not valid"

    if not device:
        message = "No device found for this user"

    # compare the hashed value of the code with the hashed value stored in db
    decrypted_code = hash_string(code)
    if device and device.verify_token(decrypted_code):
        get_or_create_custom_device(
            user_device=device, endpoint=request.path if request else None
        )
        res = True
        message = device

    return res, message


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
        get_or_create_custom_device(
            user_device=device, endpoint=request.path
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
    permission_classes = [OtpRequired]

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
            raise ValidationError("Link is invalid or expired.")

        uid = urlsafe_b64decode(uid).decode("utf-8")
        try:
            user_obj = model.objects.get(uid=uid)
        except model.DoesNotExist as e:
            raise ValidationError("No user found with given ID. ") from e

        if user != user_obj:
            raise PermissionDenied("Access denied for user")

        if not default_token_generator.check_token(user_obj, token):
            raise ValidationError("Deactivation link has expired.")

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
    http_method_names = ["post"]

    def post(self, request):
        message = "Invalid otp"
        status_code = status.HTTP_400_BAD_REQUEST
        code_status = "failed"
        token = request.data.get("otp")
        user = request.user

        stat, otp_message = custom_verify(user, token, request)
        message = otp_message

        if stat:
            # otp_message represents device since custom_verify returns the device obj if check otp is valid
            if not otp_message.confirmed:
                otp_message.confirmed = True
                otp_message.save()

                message = "Device verified successfully"
                status_code = status.HTTP_200_OK
                code_status = "success"
            else:
                message = "Device already verified"

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class BackupCodesCreateView(APIView):
    permission_classes = [OtpRequired]
    number_of_static_tokens = int(os.getenv("NUMBER_OF_RECOVERY_KEY"))

    def post(self, request):
        status_code = status.HTTP_400_BAD_REQUEST
        code_status = "failed"

        try:
            device = get_user_static_device(
                request.user
            ) or StaticDevice.objects.create(user=request.user, name="Static")

            device.token_set.all().delete()
            tokens = []
            for _ in range(self.number_of_static_tokens):
                token = StaticToken.random_token()
                device.token_set.create(token=hash_string(token))
                tokens.append(token)

            message = tokens
            status_code = status.HTTP_201_CREATED
            code_status = "success"

        except IntegrityError:
            message = "Error creating static device. Please try again"

        except ValidationError as e:
            logger.error(
                "ValidationError in creating recovery codes: ", str(e.args[0])
            )
            message = str(e.args[0])

        except Exception as e:
            logger.error("Exception in creating recovery codes: ", str(e.args[0]))
            message = "An error occurred"

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class AccessOTPServiceWithLostDevice(APIView):
    """
    Endpoint for access any service if user loses their OTP device
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, otp):
        """
        POST method for the API.

        Args:
            request (Request): The request object.
            otp (str): The one-time password.

        Returns:
            CustomAPIResponse: The response object.
        """
        user = request.user

        if not user or user.is_deleted or not user.is_active:
            return CustomAPIResponse(
                "No account found for this user",
                status.HTTP_400_BAD_REQUEST,
                "failed",
            ).send()

        stat, otp_message = custom_verify_backup_code(user, otp, request)
        message = otp_message

        if stat:
            if not otp_message.confirmed:
                otp_message.confirmed = True
                otp_message.save()

                message = "Device verified successfully"
                status_code = status.HTTP_200_OK
                code_status = "success"
            else:
                message = "Device already verified"

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()
    
class UserOTPDevice(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserOTPDeviceSerializer
    http_method_names = ["get"]

    def get_queryset(self, user):
        return TOTPDevice.objects.filter(user=user) or None

    def get(self, request):
        """
        Retrieve all user otp devices
        """
        try:
            if queryset := self.get_queryset(request.user):
                serializer = self.serializer_class(queryset, many=True)
                message = serializer.data
                status_code = status.HTTP_200_OK
                stat = "success"
            else:
                message = "No device found for this user"
                status_code = status.HTTP_400_BAD_REQUEST
                stat = "failed"
        except Exception as ex:
            message = str(ex)
            status_code = status.HTTP_400_BAD_REQUEST
            stat = "failed"
        
        response = CustomAPIResponse(message, status_code, stat)
        return response.send()
