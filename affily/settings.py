"""
Django settings for affily project.

Generated by 'django-admin startproject' using Django 3.0.3.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import datetime
import os

from dotenv import load_dotenv

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

ALLOWED_HOSTS = [os.getenv("AF_ALLOWED_HOSTS")]


# Application definition

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.admin",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    'drf_api_logger',
    "authy",
    "drf_yasg",
    "notification",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    'drf_api_logger.middleware.api_logger_middleware.APILoggerMiddleware',
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
}

# API LOGGER
DRF_API_LOGGER_DATABASE = True
DRF_LOGGER_QUEUE_MAX_SIZE = 100
DRF_LOGGER_INTERVAL = 600
DRF_API_LOGGER_EXCLUDE_KEYS = ['password', 'token', 'access', 'refresh']
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
    "django.contrib.auth.backends.ModelBackend",
    "authy.backends.custom_auth_backend.CustomBackend",
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
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
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


# logging configuration

# check if logs folder exists, else create one
LOG_DIR = os.path.join(BASE_DIR, "logs")
if not os.path.exists(LOG_DIR):
    os.mkdir(LOG_DIR)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": (
                "[%(asctime)s]- %(levelname)s - [%(name)s:%(lineno)s] - %(message)s"
            ),
            "datefmt": "%d/%b/%Y %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
            "level": "DEBUG",
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
        },
        "info_file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": f"logs/app-{datetime.datetime.now():%Y-%m-%d}-info.log",
            "when": "midnight",
            "backupCount": 10,
            "formatter": "verbose",
            "level": "INFO",
        },
    },
    "loggers": {
        "app": {
            "handlers": ["console", "error_file", "info_file", "file"],
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
