import logging
from base64 import urlsafe_b64decode

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.db.models import Q
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt import views as jwt_views
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from authy.api_response import CustomAPIResponse
from authy.generics import check_email_username
from authy.models import CustomToken, UserAccount
from authy.serializers import (
    ChangePasswordSerializer,
    ConfirmEmailSerializer,
    CustomTokenSerializer,
    ForgotPasswordSerializer,
    RegenerateEmailVerificationSerializer,
    RegistrationSerializer,
)
from authy.utilities.constants import admin_support_sender, email_sender
from authy.utilities.tasks import send_notif_email

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


class RegisterAPIView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer
    http_method_names = ["post"]

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
    http_method_names = ["patch"]

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
            and token_obj.expiry_date < timezone.localtime()
        ):
            raise ValidationError("Confirmation link has expired")

        return token_obj

    def patch(self, request, **kwargs):
        uid = kwargs.get("uid", None)
        token = kwargs.get("token", None)

        try:
            obj = self.get_object(uid, token)
            serializer = self.serializer_class(
                obj, data=request.data, context={"request": request}
            )
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


class ForgotPasswordView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = ForgotPasswordSerializer

    def get(self, request, **kwargs):
        """
        Params:
        - Email/Username

        Returns:
        - A JSON response containing a message and status.
        """
        reset_data = request.data

        try:
            # check if email or username is in request
            check_email_username(reset_data)

            change_serializer = self.serializer_class(data=reset_data)
            if change_serializer.is_valid(raise_exception=True):
                change_serializer.create_token_send_email(request)
                email = reset_data.get("email")
                username = reset_data.get("username")
                message = (
                    "Password reset link has been sent to "
                    + f"{email or str(username).capitalize()}."
                    + " Check your email to complete the process."
                )
                code_status = "success"
                status_code = status.HTTP_200_OK
            else:
                message = change_serializer.errors
                code_status = "failed"
                status_code = status.HTTP_400_BAD_REQUEST
        except Exception as e:
            message = e.args[0]
            code_status = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()

    def check_email_username(self, reset_data):
        """
        Checks whether the reset_data dictionary contains either an
        email or username key, and raises a ValidationError if neither is present.

        :param reset_data: A dictionary containing reset information.
        :type reset_data: dict

        :raises: ValidationError if the reset_data dictionary
        does not contain either an email or username key.
        """
        if not {"username", "email"}.intersection(map(str.lower, reset_data.keys())):
            print(reset_data)
            raise ValidationError("Email or Username is required")


class ChangePasswordView(UpdateAPIView):
    """chnage password after clicking forgot password"""

    permission_classes = (AllowAny,)
    serializer_class = ChangePasswordSerializer
    http_method_names = ["patch"]

    def get_object(self, uid, token):
        model = get_user_model()

        if not all([uid, token]):
            raise ValidationError(
                "Link is invalid or expired."
                " Please begin the forgot password process again"
            )

        uid = urlsafe_b64decode(uid).decode("utf-8")
        try:
            user = model.objects.get(uid=uid)
        except model.DoesNotExist as e:
            raise ValidationError(
                "No user found with user ID. "
                "Please begin the forgot password process again"
            ) from e

        if not default_token_generator.check_token(user, token):
            raise ValidationError(
                "Reset password link has expired."
                + " Please click the forgot password button to get a new link"
            )

        return user

    def patch(self, request, **kwargs):
        uid = kwargs.get("uid", "")
        token = kwargs.get("token", "")

        try:
            user = self.get_object(uid, token)
            data = request.data
            serializer = self.serializer_class(user, data=data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                message = "Completed. Please proceed to login"
                code_status = "success"
                status_code = status.HTTP_200_OK
            else:
                for error in serializer.errors:
                    message = error
                code_status = "failed"
                status_code = status.HTTP_400_BAD_REQUEST
        except Exception as e:
            message = e.args[0]
            code_status = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class RegenerateEmailVerificationView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegenerateEmailVerificationSerializer
    http_method_names = ["post"]

    def post(self, request, **kwargs):
        """
        Params:
        - Email/Username

        Returns:
        - A JSON response containing a message and status.
        """

        try:
            # check if email or username is in request
            check_email_username(request.data)

            change_serializer = self.serializer_class(
                data=request.data, context={"request": request}
            )
            if change_serializer.is_valid(raise_exception=True):
                message = "Verification email sent."
                code_status = "success"
                status_code = status.HTTP_200_OK
            else:
                message = change_serializer.errors
                code_status = "failed"
                status_code = status.HTTP_400_BAD_REQUEST
        except Exception as e:
            message = e.args[0]
            code_status = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class DeleteAccountView(APIView):
    permission_classes = (IsAuthenticated,)
    http_method_names = ["delete"]

    def get_object(self, request, username=None, email=None):
        model = get_user_model()

        query = Q(username=username) | Q(email=email)
        if user := model.objects.filter(query).first():
            if request.user != user:
                raise PermissionDenied("Access Denied.")
            return user
        else:
            raise ValidationError("Email or Username not found.")

    def delete(self, request, **kwargs):
        """
        Deactivate account
        """
        email = request.data.get("email")
        username = request.data.get("username")

        try:
            check_email_username(request.data)

            obj = self.get_object(request, username, email)
            obj.is_deleted = True
            obj.is_active = False
            obj.save()
            message = "Account deleted successfully"
            code_status = "success"
            status_code = status.HTTP_200_OK

            self.send_mail(obj)
        except (PermissionDenied, Exception) as e:
            message = e.args[0]
            code_status = "failed"
            status_code = (
                status.HTTP_403_FORBIDDEN
                if isinstance(e, PermissionDenied)
                else status.HTTP_400_BAD_REQUEST
            )
        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()

    def send_mail(self, instance):
        email_content = {
            "subject": "Your Affily account has been deleted ✖",
            "sender": email_sender,
            "recipient": instance.email,
            "template": "delete-account.html",
        }
        context = {
            "username": instance.username,
            "email": instance.email,
            "admin_email": admin_support_sender,
        }
        logger.info(
            f"context for email called from delete account endpoint: {context}"
        )

        # call celery
        send_notif_email.delay(email_content, context)


# customise JWT login payload to accept username or email
class CustomTokenView(jwt_views.TokenObtainPairView):
    serializer_class = CustomTokenSerializer
    token_obtain_pair = jwt_views.TokenObtainPairView.as_view()

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data,
                context={
                    "request": self.request,
                },
            )
            serializer.is_valid(raise_exception=True)
            return Response(serializer._validated_data, status=status.HTTP_200_OK)

        except TokenError as ex:
            raise InvalidToken(ex.args[0]) from ex
        except (ValidationError, Exception) as exc:
            message = exc.args[0]
            code_status = "failed"
            status_code = (
                status.HTTP_401_UNAUTHORIZED
                if isinstance(exc, ValidationError)
                else status.HTTP_400_BAD_REQUEST
            )

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()
