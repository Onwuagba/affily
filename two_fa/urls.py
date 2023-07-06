from django.urls import re_path, path
from two_fa.views import TOTPCompleteDeleteView, TOTPCreateView, TOTPDeleteView, TOTPVerifyView

app_name = "two_fa"

urlpatterns = [
    path("activate/", TOTPCreateView.as_view(), name="totp-activate"),
    path("verify/<int:token>/", TOTPVerifyView.as_view(), name="totp-login"),
    path("deactivate/", TOTPDeleteView.as_view(), name="totp-deactivate"),
    path(
        "complete_deactivate/<str:uid>/<str:token>",
        TOTPCompleteDeleteView.as_view(),
        name="totp-deactivate-complete",
    ),
]
