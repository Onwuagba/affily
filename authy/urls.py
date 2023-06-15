from django.urls import path

from authy.views import (
    ChangePasswordView,
    ConfirmEmailView,
    ForgotPasswordView,
    Home,
    RegenerateEmailVerificationView,
    RegisterAPIView,
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
    path("forgot_password", ForgotPasswordView.as_view()),
    path("regenerate_email", RegenerateEmailVerificationView.as_view()),
    path(
        "new_password/<str:uid>/<str:token>",
        ChangePasswordView.as_view(),
        name="change_password",
    ),
    # path("validate_token/", TokenVerifyView.as_view(), name="validate"),
    # path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # path("refresh/", RefreshPage.as_view()),
]
