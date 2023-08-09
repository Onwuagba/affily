import contextlib
import datetime
import uuid

from axes.models import AccessAttempt
from django.contrib.auth.models import (
    AbstractUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.db import IntegrityError, models, transaction
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.authtoken.models import Token

from affily.settings import AXES_COOLOFF_TIME, AXES_FAILURE_LIMIT
from authy.validators import validate_phone_number
from authy.utilities.constants import CHANNELS


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(
        _("Deactivate Account"),
        default=False,
        help_text=_("Designates whether this entry has been deleted."),
    )

    class Meta:
        abstract = True
        ordering = ["-created_at", "-updated_at"]


class CustomAdminManager(BaseUserManager):
    """relevant for admin to still see soft-deleted users
    that is hidden via the UserManager class below."""

    pass


class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email and not username:
            raise ValueError("Email and username is required")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if password is None:
            raise TypeError("Superusers must have a password.")

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, username, password, **extra_fields)

    def get_queryset(self) -> QuerySet:
        # hide deleted users from queries. Incase I forget to do manually
        return super().get_queryset().filter(is_deleted=False)


class UserAccount(AbstractUser, PermissionsMixin, BaseModel):
    uid = models.UUIDField(
        default=uuid.uuid4, editable=False, unique=True, primary_key=True
    )
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        _("username"),
        max_length=50,
        null=False,
        blank=False,
        unique=True,
        validators=[username_validator],
        error_messages={
            "unique": _("A user with that username already exists."),
        },
    )
    first_name = models.CharField(max_length=50, null=False, blank=False)
    last_name = models.CharField(max_length=50, null=False, blank=False)
    email = models.EmailField(db_index=True, max_length=255, unique=True)
    # password = models.CharField(max_length=32, null=False, blank=False)
    phone_number = models.CharField(
        max_length=20,
        validators=[validate_phone_number],
        unique=True,
        blank=True,
        null=True,
    )
    is_active = models.BooleanField(
        _("Activate Account"),
        default=False,
        help_text=_(
            "Designates whether the user has completed validation and is active."
        ),
    )
    channel = models.CharField(
        _("Channel"),
        choices=CHANNELS,
        default="email",
        help_text=_("Select channel from which the user was created."),
    )
    regToken = models.CharField(
        _("Token"),
        max_length=40,
        null=True,
        blank=True,
        help_text=_("Token user used to validate account."),
    )

    REQUIRED_FIELDS = ["email", "first_name", "last_name"]

    objects = UserManager()
    admin_objects = CustomAdminManager()  # manager for admin

    def __str__(self):
        return self.email

    def check_lockout(self):
        """
        Check if the user is locked out based on their access attempts.

        Args:
            user_obj: The user object.

        Returns:
            A tuple containing a boolean indicating if the user is locked out and
            an `AccessAttempt` object if found, otherwise `None`.
        """
        access_attempt = (
            AccessAttempt.objects.filter(username=self.username)
            .order_by("-attempt_time")
            .first()
        )

        if (
            access_attempt
            and access_attempt.failures_since_start >= AXES_FAILURE_LIMIT
        ):
            lockout_start_time = access_attempt.attempt_time
            cooloff_period = datetime.timedelta(seconds=AXES_COOLOFF_TIME)

            lockout_end_time = lockout_start_time + cooloff_period
            remaining_time = max(
                lockout_end_time - timezone.now(), datetime.timedelta()
            )

            if remaining_time.total_seconds() > 0:
                return (
                    True,
                    (
                        "Account locked."
                        f"Try again after {int(remaining_time.total_seconds())} seconds"
                    ),
                )

        return (
            False,
            access_attempt,
        )  # access_attempt can be None if no obj is found


class CustomToken(Token):
    id = models.UUIDField(
        _("ID"), default=uuid.uuid4, editable=False, unique=True, primary_key=True
    )
    expiry_date = models.DateTimeField(null=False, blank=False)
    verified_on = models.DateTimeField(null=True, blank=True)

    def create_expiry_date(self, created):
        return created + datetime.timedelta(days=3) if created else None

    def save(self, *args, **kwargs):
        if self._state.adding:
            while True:
                with contextlib.suppress(IntegrityError):
                    with transaction.atomic():
                        if not self.created:
                            self.created = timezone.localtime()
                        if not self.key:
                            self.key = self.generate_key()
                        self.expiry_date = self.create_expiry_date(self.created)
                        super(Token, self).save(*args, **kwargs)
                        break  # Exit the loop if the expiry is set successfully
        else:
            super(Token, self).save(*args, **kwargs)
