from django.apps import AppConfig


class AuthConfig(AppConfig):
    name = "authy"

    def ready(self):
        import authy.signals  # noqa
