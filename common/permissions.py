from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission


class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    """

    message = "Authentication credentials were not provided"

    def has_permission(self, request, view):
        if bool(request.user and request.user.is_authenticated):
            res, msg = request.user.check_lockout()
            if res:
                raise PermissionDenied(
                    {
                        "message": msg,
                        "status": "failed",
                    }
                )
            return True
        return False
