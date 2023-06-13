import contextlib

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q

UserModel = get_user_model()


class CustomBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        user = None

        with contextlib.suppress(UserModel.DoesNotExist):
            user = UserModel.objects.get(Q(username=username) | Q(email=username))
        return user if user and user.check_password(password) else None
