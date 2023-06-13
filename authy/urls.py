from django.urls import path

from authy.views import ConfirmEmailView, Home, RegisterAPIView

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
    # path("validate_token/", TokenVerifyView.as_view(), name="validate"),
    # path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # path("refresh/", RefreshPage.as_view()),
]
