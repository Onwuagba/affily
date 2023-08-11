"""
Django settings for affily project.

Generated by 'django-admin startproject' using Django 3.0.3.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import datetime
import logging
import os

from dotenv import load_dotenv
from celery.schedules import crontab

from affily import utils

load_dotenv()

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("AF_SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = os.getenv("AF_ALLOWED_HOSTS").split(",")


# Application definition

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.admin",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    # 3rd party
    "drf_yasg",
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    "axes",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.twitter",
    "allauth.socialaccount.providers.facebook",
    "allauth.socialaccount.providers.google",
    "rest_framework.authtoken",
    "dj_rest_auth",
    # rest api
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    # logs
    "drf_api_logger",
    # internal apps
    "authy",
    "notification",
    "two_fa",
    "common",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "drf_api_logger.middleware.api_logger_middleware.APILoggerMiddleware",
    "authy.middleware.admin_middleware.AutoLogoutMiddleware",
    # AxesMiddleware should be the last middleware in the MIDDLEWARE list.
    "axes.middleware.AxesMiddleware",
]

ROOT_URLCONF = "affily.urls"
APPEND_SLASH = True

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "affily.wsgi.application"


# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

DATABASES = {
    # "default": {
    #     "ENGINE": "django.db.backends.sqlite3",
    #     "NAME": f"{BASE_DIR}/db.sqlite3",
    # }
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": utils.decrypt_data(os.getenv("DB_NAME")),
        "USER": utils.decrypt_data(os.getenv("DB_USER")),
        "PASSWORD": utils.decrypt_data(os.getenv("DB_PASS")),
        "HOST": os.getenv("DB_HOST"),
        "PORT": os.getenv("DB_PORT", "5432"),
    }
    # "default": {
    #     "ENGINE": "django.db.backends.postgresql",
    #     "NAME": "affil",
    #     "USER": "postgres",
    #     "PASSWORD": "password",
    #     "HOST": "localhost",
    #     "PORT": "5432",
    # }
}

# DJANGO-ALL-AUTH FOR SOCIAL AUTH
SITE_ID = 1
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "none"

SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "APP": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "secret": os.getenv("GOOGLE_SECRET"),
            "key": "",  # leave empty
        },
        "SCOPE": [
            "profile",
            "email",
        ],
        "AUTH_PARAMS": {
            "access_type": "offline",
        },
        "VERIFIED_EMAIL": True,
    },
}

# DRF API LOGGER
DRF_API_LOGGER_DATABASE = True
DRF_LOGGER_QUEUE_MAX_SIZE = 50
DRF_LOGGER_INTERVAL = 200
DRF_API_LOGGER_EXCLUDE_KEYS = [
    "password",
    "confirm_password",
    "token",
    "access",
    "refresh",
]
DRF_API_LOGGER_SLOW_API_ABOVE = 200  # to identify slow API calls
DRF_API_LOGGER_TIMEDELTA = 60  # representing UTC + 60 mins

# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "authy.validators.CustomPasswordValidator"},
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        )
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 8,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# CELERY
CELERY_BROKER_URL = (
    "redis://" + os.getenv("REDIS_HOST") + ":" + os.getenv("REDIS_PORT")
)
CELERY_RESULT_BACKEND = (
    "redis://" + os.getenv("REDIS_HOST") + ":" + os.getenv("REDIS_PORT")
)
CELERY_TIMEZONE = "Africa/Lagos"
# CELERY_BEAT_SCHEDULE = {
#  'send-notification-every-10min': {
#        'task': 'common.utilities.tasks.resend_welcome_email',
#        'schedule': crontab(minute=0), # execute every hour
#     },
#  'flush-expired-tokens': {
#        'task': 'common.utilities.tasks.flush_expired_tokens',
#        'schedule': crontab(hour=1, minute=0), # 1 AM daily
#     }
# }

# Email configuration
EMAIL_BACKEND = os.getenv("EMAIL_BACKEND")
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = os.getenv("EMAIL_PORT")
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = utils.decrypt_data(os.getenv("EMAIL_HOST_PASSWORD"))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS")

AUTH_USER_MODEL = "authy.UserAccount"

# time (in seconds) before password_reset token expires
PASSWORD_RESET_TIMEOUT = 900

AUTHENTICATION_BACKENDS = [
    # AxesStandaloneBackend should be the first backend in the AUTHENTICATION_BACKENDS list.
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
    "authy.backends.custom_auth_backend.CustomBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

# JWT
SIMPLE_JWT = {
    "USER_ID_FIELD": "uid",
    "AUTH_HEADER_TYPES": ("Bearer",),
    "ACCESS_TOKEN_LIFETIME": datetime.timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": datetime.timedelta(days=1),
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "UPDATE_LAST_LOGIN": True,
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

# Rest Framework settings
REST_FRAMEWORK = {
    "NON_FIELD_ERRORS_KEY": "error",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 15,
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.AllowAny",),
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.coreapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {"anon": "150/day", "user": "400/day"},
}

# OTP config
OTP_ADMIN_HIDE_SENSITIVE_DATA = False  # change to True
OTP_TOTP_ISSUER = "Affily"

# Axes Configuration
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]
AXES_FAILURE_LIMIT = 3
AXES_RESET_ON_SUCCESS = True
AXES_VERBOSE = False
AXES_ENABLED = True
AXES_IPWARE_META_PRECEDENCE_ORDER = (
    "HTTP_X_REAL_IP",
    "REMOTE_ADDR",
)
AXES_LOCKOUT_PARAMETERS = ["username"]
AXES_COOLOFF_TIME = 3600
AXES_USERNAME_FORM_FIELD = "username"
AXES_EMAIL_FORM_FIELD = "email"


# logging configuration

# check if logs folder exists, else create one
LOG_DIR = os.path.join(BASE_DIR, "logs")
if not os.path.exists(LOG_DIR):
    os.mkdir(LOG_DIR)


class NonEmptyLogFilter(logging.Filter):
    def filter(self, record):
        """
        Logging filter to prevent the generation of empty log files for
        TimedRotatingFileHandler handlers

        Args:
            record: The record to be filtered.

        Returns:
            bool: True if the record's message is not empty after
            stripping whitespace, False otherwise.
        """
        return bool(record.getMessage().strip())


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "non_empty_logs": {
            "()": NonEmptyLogFilter,
        }
    },
    "formatters": {
        "verbose": {
            "format": (
                "[%(asctime)s] %(levelname)s [%(name)s-%(lineno)s] %(module)s "
                "%(process)d %(thread)d %(message)s"
            ),
            "datefmt": "%d/%b/%Y %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "logs/debug.log",
            "formatter": "verbose",
            "level": "DEBUG",
        },
        "error_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": f"logs/app-{datetime.datetime.now():%Y-%m-%d}-error.log",
            "when": "midnight",
            "backupCount": 10,
            "formatter": "verbose",
            "level": "ERROR",
            "filters": ["non_empty_logs"],
        },
        "info_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": f"logs/app-{datetime.datetime.now():%Y-%m-%d}-info.log",
            "when": "midnight",
            "backupCount": 10,
            "formatter": "verbose",
            "level": "INFO",
            "filters": ["non_empty_logs"],
        },
    },
    "loggers": {
        "app": {
            "handlers": ["console", "error_file", "info_file"],
            "level": "INFO",
        },
        "app_debug": {
            "handlers": ["console", "file"],
            "level": "DEBUG",
        },
    },
}
# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Africa/Lagos"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = "/static/"
