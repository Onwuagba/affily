import logging
from base64 import urlsafe_b64decode

from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from authy.api_response import CustomAPIResponse
from authy.models import CustomToken, UserAccount
from authy.serializers import ConfirmEmailSerializer, RegistrationSerializer

logger = logging.getLogger("app")


class Home(APIView):
    # permission_classes = (IsAuthenticated,)

    def get(self, request, *args):
        user_name = request.user
        message = f"Welcome {user_name}"
        status_code = status.HTTP_400_BAD_REQUEST
        code_status = "failed"

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


# Create your views here.
class RegisterAPIView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        try:
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                message = (
                    "Registration successful."
                    "Please confirm your email to complete set up"
                )
                status_code = status.HTTP_201_CREATED
                code_status = "success"
            else:
                message = serializer.errors
                status_code = status.HTTP_400_BAD_REQUEST
                code_status = "failed"
        except Exception as e:
            message = e.args[0]
            status_code = status.HTTP_400_BAD_REQUEST
            code_status = "failed"

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class ConfirmEmailView(UpdateAPIView):
    """
    User confirms their emails after registration.
    """

    permission_classes = (AllowAny,)
    serializer_class = ConfirmEmailSerializer
    http_method_names = ["get"]

    def get_object(self, uid, token):
        try:
            token_obj = self.get_user(uid, token)
        except Exception as e:
            raise ValidationError(e) from e

        return token_obj

    def get_user(self, uid, token):
        if not all([uid, token]):
            raise ValidationError("Invalid confirmation link.")

        uid = urlsafe_b64decode(uid).decode("utf-8")
        user = UserAccount.objects.filter(uid=uid).first()
        token_obj = CustomToken.objects.filter(key=token).first()

        if not user or not token_obj or token_obj.user != user:
            raise ValidationError(
                "Invalid verification link. Unable to retrieve user information"
            )

        if (
            token_obj.expiry_date is not None
            and token_obj.expiry_date < timezone.now()
        ):
            raise ValidationError("Confirmation link has expired")

        return token_obj

    def get(self, request, **kwargs):
        uid = kwargs.get("uid", None)
        token = kwargs.get("token", None)

        try:
            obj = self.get_object(uid, token)
            serializer = self.serializer_class(obj, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                message = "Account activation is complete. Please proceed to login"
                code_status = "success"
                status_code = status.HTTP_200_OK
            else:
                message = serializer.errors
                code_status = "failed"
                status_code = status.HTTP_400_BAD_REQUEST
        except Exception as e:
            message = e.args[0]
            code_status = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()
