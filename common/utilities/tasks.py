import datetime
import logging
import os

import celery
from django.conf import settings
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from affily.celery import app

logger = logging.getLogger("app")


class BaseTaskWithRetry(celery.Task):
    autoretry_for = (Exception, KeyError)
    retry_kwargs = {"max_retries": 3}
    retry_backoff = True


@app.task()
def flush_expired_tokens(self):
    OutstandingToken.objects.filter(expires_at__lt=timezone.now()).delete()


# @celery.shared_task(bind=True, base=BaseTaskWithRetry)
# def flush_expired_tokens(self):
#     OutstandingToken.objects.filter(expires_at__lt=timezone.now()).delete()


@celery.shared_task(bind=True, base=BaseTaskWithRetry)
def delete_empty_log_files(self):
    """
    Deletes empty log files that are older than two days.

    This function iterates over all files in the 'logs' folder and checks if they are
    empty and are older than two days. If a file meets both criteria, it is deleted.

    Parameters:
    - None

    Returns:
    - None
    """
    logs_folder = os.path.join(settings.BASE_DIR, "logs")
    today = datetime.datetime.now()
    two_days_ago = today - datetime.timedelta(days=2)

    try:
        for filename in os.listdir(logs_folder):
            if filename.endswith(".log"):
                file_path = os.path.join(logs_folder, filename)
                if os.path.isfile(file_path) and os.path.getsize(file_path) == 0:
                    creation_time = datetime.datetime.fromtimestamp(
                        os.path.getctime(file_path)
                    )
                    if creation_time < two_days_ago:
                        os.remove(file_path)
                        logger.info(f"Deleted empty log file: {file_path}")

    except Exception as e:
        logger.exception(e)
