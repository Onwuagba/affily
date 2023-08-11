import contextlib
import datetime
from datetime import timedelta

from axes.models import AccessAttempt
from axes.signals import user_login_failed
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from django.utils import timezone

UserModel = get_user_model()


class CustomBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticates a user with either username or email.

        Parameters:
            username (str): The username/email of the user.
            password (str): The password of the user.

        Returns:
            object: The authenticated user OR None.
        """
        user = None

        with contextlib.suppress(UserModel.DoesNotExist):
            user = UserModel.objects.get(
                Q(username=username) | Q(email=username), is_deleted=False
            )
        if user and user.check_password(password):
            return user

        # Send failure signal to AxesBackend
        self.check_axes_backend(username)
        user_login_failed.send(
            sender=UserModel,
            request=request,
            credentials={"username": username},
        )
        return None

    def check_axes_backend(self, username):
        """
        Delete user attempt from Axes db if attempt was made more than 1 hour ago.
        This is basically to ensure that user is only blocked if several attempts are made within one hour.

        Parameters:
            username (str): The username for which to check the access attempt.

        Returns:
            None
        """

        if user := AccessAttempt.objects.filter(username__iexact=username).first():
            time_diff = timezone.localtime() - user.attempt_time
            if time_diff > timedelta(hours=1):
                user.delete()
