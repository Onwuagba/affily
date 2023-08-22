from django.http import HttpResponseForbidden

from affily.settings import ALLOWED_ADMIN_IPS


class RestrictAdminMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the request is to the admin site and if the request IP is allowed
        if (
            (request.path.startswith("/pamin/")
            or request.path.startswith("/admin/"))
            and self.get_client_ip(request) not in ALLOWED_ADMIN_IPS
        ):
            return HttpResponseForbidden(
                "You are not authorized to access the admin interface."
            )

        return self.get_response(request)
    
    def get_client_ip(self, request):
        return (
            x_forwarded_for.split(',')[0].strip()
            if (x_forwarded_for := request.META.get('HTTP_X_FORWARDED_FOR'))
            else request.META.get('REMOTE_ADDR')
        )
