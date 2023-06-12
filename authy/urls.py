from django.urls import path
from authy.views import RegisterAPIView, Home

app_name = "auth"

urlpatterns = [
    # auth
    path("signup/", RegisterAPIView.as_view(), name="signup"),
    path("", Home.as_view()),
    # path("validate_token/", TokenVerifyView.as_view(), name="validate"),
    # path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # path("refresh/", RefreshPage.as_view()),
]
