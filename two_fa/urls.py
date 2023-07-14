from django.urls import path

from two_fa.views import (
    BackupCodesCreateView,
    TOTPCompleteDeleteView,
    TOTPCreateView,
    TOTPDeleteView,
    TOTPVerifyView,
)

app_name = "two_fa"

urlpatterns = [
    path("activate/", TOTPCreateView.as_view(), name="totp-activate"),
    path("verify/", TOTPVerifyView.as_view(), name="totp-verify"),
    path("deactivate/", TOTPDeleteView.as_view(), name="totp-deactivate"),
    path(
        "complete_deactivate/<str:uid>/<str:token>",
        TOTPCompleteDeleteView.as_view(),
        name="totp-deactivate-complete",
    ),
    path(
        "create_backup/", BackupCodesCreateView.as_view(), name="totp-create-backup"
    ),
]
