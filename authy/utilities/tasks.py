import logging

from affily.celery import app
from authy.utilities.mail.send_mail import send_mail_now

logger = logging.getLogger("app")


@app.task()
def send_welcome_mail(email_content, context):
    logger.info(
        f"Successfully entered celery to send mail to recipient:\
              {email_content.get('recipient')}"
    )
    return send_mail_now(email_content, context)


# @shared_task()
# def resend_welcome_email():
#     queryset = ClaimEmailMessage.objects.filter(
#         status='pending',
#         retries__lt=5)
#     logger.info('Number of mails to retry: %s', {len(queryset)})

#     for row in queryset:
#         email_content = {
#             'subject': row.subject,
#             'sender': row.sender,
#             'recipient': row.recipient,
#             'template': row.template,
#         }
#         context = row.message
#         logger.info(f"Retrying email for: {row.recipient} at {datetime.now()}")
#         if send_mail_now(email_content, context):
#             row.delete()
