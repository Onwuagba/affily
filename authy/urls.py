from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from authy.views import (
    ChangePasswordView,
    ConfirmEmailView,
    CustomTokenView,
    DeleteAccountView,
    ForgotPasswordView,
    Home,
    LoginWith2fa,
    LoginWithLostDevice,
    LogoutView,
    RegenerateEmailVerificationView,
    RegisterAPIView,
    ResetPasswordView,
    SocialLogin1View,
    SocialSignUpView,
)

app_name = "auth"

urlpatterns = [
    # auth
    path("", Home.as_view()),
    path("signup/", RegisterAPIView.as_view(), name="signup"),
    path(
        "confirm_email/<str:uid>/<str:token>",
        ConfirmEmailView.as_view(),
        name="confirm_email",
    ),
    path("forgot_password/", ForgotPasswordView.as_view()),
    path("regenerate_email/", RegenerateEmailVerificationView.as_view()),
    path(
        "new_password/<str:uid>/<str:token>",
        ChangePasswordView.as_view(),
        name="change_password",
    ),
    path("delete_account", DeleteAccountView.as_view(), name="delete_account"),
    path("login/", CustomTokenView.as_view(), name="token_obtain_pair"),
    path("totp/login/", LoginWith2fa.as_view(), name="login_2fa"),
    path(
        "totp/login/lost_device/",
        LoginWithLostDevice.as_view(),
        name="login_lost_2fa",
    ),
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("validate_token/", TokenVerifyView.as_view(), name="validate"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("reset_password/", ResetPasswordView.as_view(), name="reset_password"),
    # social
    path(
        "social/signup/<str:provider>/",
        SocialSignUpView.as_view(),
        name="social_signup",
    ),
    path(
        "social/login/<str:provider>/",
        SocialLogin1View.as_view(),
        name="social_login",
    ),
    # path("socialsignup/", signup, name="socialaccount_signup"),
    # path("google/", GoogleLogin.as_view(), name="google_login"),
    # path("twitter/", TestLogin().get_user_info('ya29.a0AbVbY6N2w6q8bT54x0LfTBODlv0YmNtz4BQvnH1PaTh2663gXKUJYvvx78xzPh4I1PgargcQdpiny21xufHQP7qF44W0XSeojmZPOUE3cCNDjGBz5qxEvJczK2Mh-iapebBLk4WQWxB6Vi2ed9S_7f7JNbKQaCgYKAYcSARMSFQFWKvPl4fGv62QoIbRvkEDBpWoZ8Q0163'), name="boy"),
    # path("~redirect/", view=UserRedirectView.as_view(), name="redirect"),
]

from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
