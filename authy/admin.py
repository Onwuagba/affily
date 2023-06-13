from typing import Any
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from authy.models import CustomToken, UserAccount
from django import forms
from django.utils.translation import gettext_lazy as _
from authy.signals import user_created


@admin.register(UserAccount)
class CustomAdmin(UserAdmin):
    # define the fields to show in the list display for staff users
    staff_fields = (
        "username",
        "email",
        "first_name",
        "last_name",
        "is_active",
        "created_at",
    )

    list_filter = ("is_staff", "is_superuser", "is_active", "groups", "is_deleted")

    add_fieldsets = (
        (
            _("Personal info"),
            {
                "fields": (
                    "username",
                    "first_name",
                    "last_name",
                    "phone_number",
                    "email",
                    "password1",
                    "password2",
                ),
            },
        ),
        (
            _("Superadmin checks"),
            {
                "fields": (
                    "is_deleted",
                    "is_active",
                    "is_superuser",
                    "is_staff",
                ),
            },
        ),
    )

    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (
            _("Personal info"),
            {"fields": ("first_name", "last_name", "phone_number", "email")},
        ),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_deleted",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )

    readonly_fields = ["date_joined", "last_login"]

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        is_superuser = request.user.is_superuser
        disabled_fields = set()

        # prevent non-superadmin from editing these fields
        if not is_superuser:
            disabled_fields |= {
                "is_staff",
                "is_active",
                "is_deleted",
                "is_superuser",
                "groups",
                "user_permissions",
            }

        for f in disabled_fields:
            if f in form.base_fields:
                form.base_fields[f].widget = forms.HiddenInput()

        return form

    def get_list_filter(self, request):
        if not request.user.is_superuser:
            # if the user is not a superuser, remove the "is_superuser" and "is_staff" filters
            return ("is_active", "groups", "is_deleted")
        return super().get_list_filter(request)

    def get_list_display(self, request):
        if request.user.is_superuser:
            return self.staff_fields + (
                "is_staff",
                "is_superuser",
            )

        elif request.user.is_staff:
            return self.staff_fields

        else:
            return super().get_list_display(request)

    def get_fieldsets(self, request, obj=None):
        if not request.user.is_superuser:
            # if the user is not a superuser, remove the "Permissions" and "Important dates" sections
            return (
                (None, {"fields": ("username", "password")}),
                (
                    _("Personal info"),
                    {"fields": ("first_name", "last_name", "phone_number", "email")},
                ),
            )
        return super().get_fieldsets(request, obj)
    

    def save_model(self, request: Any, obj: Any, form: Any, change: Any) -> None:
        # fire signal when user is created from Django Admin
        super().save_model(request, obj, form, change)

        # Emit the user_created signal
        user_created.send(sender=self.__class__, instance=obj, created=True, request=request)



class CustomTokenAdmin(admin.ModelAdmin):
    list_display = ("key", "user", "created", "expiry_date", "verified_on")


admin.site.register(CustomToken, CustomTokenAdmin)
