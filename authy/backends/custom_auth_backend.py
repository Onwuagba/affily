import contextlib
import datetime
from datetime import timedelta

from axes.models import AccessAttempt
from axes.signals import user_login_failed
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from django.utils import timezone
from common.exceptions import AccountLocked

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
            self.check_locked_user(user)
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

    def check_locked_user(self, user):
        """
        Check if the user is locked and raise an AccountLocked exception if necessary.

        Parameters:
            user (User): The user to check for lockout.

        Raises:
            AccountLocked: If the user is locked.

        Returns:
            None
        
        """
        check_lockout, check_lockout_msg = user.check_lockout()
        if check_lockout:
            raise AccountLocked(check_lockout_msg)
        elif check_lockout_msg:
            # workaround for axes_reset_on_success
            # Wasn't working from settings.py
            # check_lockout_msg is now an obj
            check_lockout_msg.failures_since_start = 0
            check_lockout_msg.save()
