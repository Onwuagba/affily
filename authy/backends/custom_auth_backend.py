import contextlib

from axes.signals import user_login_failed
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q

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
        else:
            # Send failure signal to AxesBackend
            user_login_failed.send(
                sender=UserModel,
                request=request,
                credentials={"username": username},
            )
        return None
