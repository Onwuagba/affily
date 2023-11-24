import base64
import json
import logging
import uuid
from base64 import urlsafe_b64decode

import requests
from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client, OAuth2Error
from allauth.socialaccount.providers.twitter.views import TwitterOAuthAdapter
from dj_rest_auth.registration.views import SocialLoginView
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone
from django.views.generic import RedirectView
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt import views as jwt_views
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from authy.api_response import CustomAPIResponse
from authy.generics import check_email_username
from authy.models import CustomToken
from authy.serializers import (
    ChangePasswordSerializer,
    ConfirmEmailSerializer,
    CustomTokenSerializer,
    ForgotPasswordSerializer,
    LoginWith2faTokenSerializer,
    LoginWithLost2faDeviceTokenSerializer,
    LogoutSerializer,
    RegenerateEmailVerificationSerializer,
    RegistrationSerializer,
    ResetPasswordSerializer,
    SocialSignUpSerializer,
)
from authy.utilities.constants import admin_support_sender, email_sender
from authy.utilities.tasks import send_notif_email
from common.exceptions import AccountLocked, AlreadyExists
from common.permissions import IsAuthenticated
from two_fa.permissions import OtpRequired

logger = logging.getLogger("app")
UserModel = get_user_model()


class Home(APIView):
    permission_classes = (OtpRequired,)

    def get(self, request, *args):
        user_name = request.user
        message = f"Welcome {user_name.first_name}"
        status_code = status.HTTP_200_OK
        code_status = "success"

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
        user = UserModel.objects.filter(uid=uid).first()
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
    http_method_names = ["post"]

    def post(self, request, **kwargs):
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
            raise ValidationError("Reset password link has expired.")

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
                message = serializer.errors
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
    http_method_names = ["post"]

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
        except (ValidationError, AccountLocked, Exception) as exc:
            message = exc.args[0]
            code_status = "failed"
            status_code = (
                status.HTTP_401_UNAUTHORIZED
                if isinstance(exc, ValidationError)
                else status.HTTP_423_LOCKED
                if isinstance(exc, AccountLocked)
                else status.HTTP_400_BAD_REQUEST
            )

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class LoginWith2fa(APIView):
    """
    User hits login ednpoint first to obtain token before calling this endpoint
    """

    serializer_class = LoginWith2faTokenSerializer
    http_method_names = ["post"]

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
            logger.error(f"Exception in 2fa login: {exc}")
            message = exc.args[0]
            code_status = "failed"
            status_code = (
                status.HTTP_401_UNAUTHORIZED
                if isinstance(exc, ValidationError)
                else status.HTTP_400_BAD_REQUEST
            )

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class LoginWithLostDevice(APIView):
    # deprecating this as it is now taken care of in loginWith2fa
    """
    Endpoint for backup access if user loses their OTP device.

    Process
    - User logs in
    - Notices he can't proceed cos device is lost
    - Clicks 'lost device'
    - FrontEnd calls this endpoint
    """

    serializer_class = LoginWithLost2faDeviceTokenSerializer
    http_method_names = ["post"]

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


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LogoutSerializer
    http_method_names = ["post"]

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            logout(request)
            message = "Logout successful"
            code_status = "success"
            status_code = status.HTTP_205_RESET_CONTENT

        except Exception as e:
            message = e.args[0]
            code_status = "failed"
            status_code = status.HTTP_400_BAD_REQUEST

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class ResetPasswordView(UpdateAPIView):
    """
    Allow authenticated user to change password

    Accepts - password, confirm_password, old_password
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = ResetPasswordSerializer
    http_method_names = ["patch"]

    def get_object(self):
        return self.request.user

    def patch(self, request, **kwargs):
        user = self.get_object()
        change_data = request.data
        # change_data['user'] = request.user
        change_serializer = self.serializer_class(user, data=change_data)
        try:
            if change_serializer.is_valid(raise_exception=True):
                change_serializer.save()
                message = "Password reset completed."
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


## Process for social signin ##
# User clicks on the desired social login button and is redirected to provider page
# User authenticates with provider and authorises access
# if authentication is successful, user is redirected to a website page (defined by me)
# On this page, I extract access token, connect to provider and get user details
# I then use this detail to get info about the user and create_or_sretrive in my DB


# class GoogleLogin(SocialLoginView):
#     adapter_class = GoogleOAuth2Adapter
#     client_class = OAuth2Client


# class TestLogin(APIView):
#     def get_user_info(self, access_token):
#         url = "https://www.googleapis.com/oauth2/v3/userinfo"
#         headers = {"Authorization": f"Bearer {access_token}"}

#         response = requests.get(url, headers=headers, verify=False)

#         return response.json() if response.status_code == 200 else None

#     def get(self, **kwargs):
#         # access_token = kwargs.get('access_token')
#         self.get_user_info(
#             "ya29.a0AbVbY6N2w6q8bT54x0LfTBODlv0YmNtz4BQvnH1PaTh2663gXKUJYvvx78xzPh4I1PgargcQdpiny21xufHQP7qF44W0XSeojmZPOUE3cCNDjGBz5qxEvJczK2Mh-iapebBLk4WQWxB6Vi2ed9S_7f7JNbKQaCgYKAYcSARMSFQFWKvPl4fGv62QoIbRvkEDBpWoZ8Q0163"
#         )


# class UserRedirectView(LoginRequiredMixin, RedirectView):
#     """
#     This view is needed by the dj-rest-auth-library in order to work the google login. It's a bug.
#     """

#     permanent = False

#     def get_redirect_url(self):
#         return "redirect-url"


class SocialSignUpView(CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = SocialSignUpSerializer
    http_method_names = ["post"]

    def post(self, request, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"provider": kwargs.get("provider")}
            )
            if serializer.is_valid(raise_exception=True):
                user = serializer.save()
                # for Twitter, we return the authorisation URL
                # Then complete user creation
                if isinstance(user, UserModel):
                    refresh = RefreshToken.for_user(user)
                    return Response(
                        {
                            "refresh": str(refresh),
                            "access": str(refresh.access_token),
                        },
                        status=status.HTTP_201_CREATED,
                    )
                else:
                    message = user
                    code_status = "success"
                    status_code = status.HTTP_200_OK
            else:
                message = serializer.errors
                code_status = "failed"
                status_code = status.HTTP_400_BAD_REQUEST

        except (ValidationError, Exception) as exc:
            message = exc.args[0]
            code_status = "failed"
            status_code = (
                status.HTTP_409_CONFLICT
                if isinstance(exc, AlreadyExists)
                else status.HTTP_400_BAD_REQUEST
            )

        response = CustomAPIResponse(message, status_code, code_status)
        return response.send()


class SocialLogin1View(APIView):
    permission_classes = [AllowAny]
    http_method_names = ["get"]

    def get_adapter(self, service):
        adapter = {
            "facebook": FacebookOAuth2Adapter,
            "google": GoogleOAuth2Adapter,
            "twitter": TwitterOAuthAdapter,
        }
        return adapter.get(service)

    def allowed_providers(self, provider):
        providers = {"facebook", "twitter", "google"}
        return provider in providers

    def get(self, request, **kwargs):
        provider = kwargs.get("provider")
        access_token = request.data.get("access_token")

        if not provider or not access_token:
            response = CustomAPIResponse(
                "Provider and access_token are required.",
                status.HTTP_400_BAD_REQUEST,
                "failed",
            )
            return response.send()

        if not self.allowed_providers(provider):
            response = CustomAPIResponse(
                "Provider not profiled yet.", status.HTTP_400_BAD_REQUEST, "failed"
            )
            return response.send()

        adapter = self.get_adapter(provider)

        if not adapter:
            response = CustomAPIResponse(
                "No adapter for selected service.",
                status.HTTP_400_BAD_REQUEST,
                "failed",
            )
            return response.send()

        adapter_class = adapter(request)

        try:
            app = SocialApp.objects.get(provider=provider)
            token = adapter_class.parse_token(request.data)
            # login_token = adapter_class.unstash_token(token)
            # client = adapter_class.get_client_class()(request)
            # token = client.exchange_token(login_token)
        except (ValueError, OAuth2Error):
            response = CustomAPIResponse(
                "Invalid access_token or provider.",
                status.HTTP_400_BAD_REQUEST,
                "failed",
            )
            return response.send()

        segments = token.token.split(".")

        # if (len(segments) != 3):
        #     raise ValidationError('Wrong number of segments in token')

        b64string = segments[1]
        b64string = b64string.encode("ascii")

        # Remove padding characters from the base64 string
        while len(b64string) % 4 != 0:
            b64string += b"="

        padded = base64.urlsafe_b64decode(b64string)
        decoded = base64.b64decode(padded)
        json.loads(decoded)

        try:
            token.account and (
                social_account := SocialAccount.objects.filter(
                    provider=provider, uid=token.account.uid
                ).first()
            )

            # Retrieve the user associated with the social account
            user_instance = social_account.user
        except Exception:
            # User does not exist, create a new user
            user_instance = UserModel.objects.create_user(
                email=token["email"],
                password=get_user_model().objects.make_random_password(),
            )
            user_instance.is_active = True
            user_instance.save()
        # except Exception as e:
        #     raise ValidationError("BLOOOD") from e

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user_instance)
        tokens = {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

        return Response(tokens, status=200)
