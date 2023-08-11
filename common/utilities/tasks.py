import logging

from affily.celery import app
from django.utils import timezone
from rest_framework.authtoken.models import Token

logger = logging.getLogger("app")


@app.task()
def flush_expired_tokens():
    now = timezone.now()
    try:
        Token.objects.filter(expiration_date__lt=now).delete()
    except Exception as e:
        logger.exception(e)