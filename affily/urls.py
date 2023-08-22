"""affily URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
import os

from django.contrib import admin
from django.urls import include, path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from django_otp.admin import OTPAdminSite

admin.site.__class__ = OTPAdminSite

schema_view = get_schema_view(
    openapi.Info(
        title="Affily API",
        default_version="v1",
        description=(
            "Affiliate Marketing API: "
            "Automate and manage affiliate programs,"
            "track conversions, and provide real-time data"
            "exchange for merchants, publishers, and affiliates."
        ),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

base_api_url = os.getenv("BASE_API_URL")

urlpatterns = [
    path("pamin/", admin.site.urls),
    path(f"{base_api_url}/auth/", include("authy.urls")),
    path(f"{base_api_url}/totp/", include("two_fa.urls")),
    path(
        f"{base_api_url}/doc/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
]
