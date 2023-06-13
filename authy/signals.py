from django.db.models.signals import post_save
from django.dispatch import receiver
from authy.models import CustomToken
from authy.utilities.constants import email_sender
import logging
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from authy.utilities.tasks import send_welcome_mail
from django.dispatch import Signal

logger = logging.getLogger("app")

user_created = Signal()


@receiver(user_created)
def send_email_on_user_creation(sender, instance, created, request, **kwargs):
    if created:
        email_content = {
            "subject": "Confirm your email account on Affily",
            "sender": email_sender,
            "recipient": instance.email,
            "template": "verify-account.html",
        }
        try:
            token, _ = CustomToken.objects.update_or_create(user=instance)
            uid = urlsafe_base64_encode(force_bytes(instance.pk))
            domain = get_current_site(request).domain
            confirm_url = reverse(
                "auth:confirm_email", kwargs={"uid": uid, "token": token}
            )
            confirm_url = f"{request.scheme}://{domain}{confirm_url}"

            context = {"username": instance.username, "url": confirm_url}
            print(context)
            send_welcome_mail.delay(email_content, context)
        except Exception as e:
            logger.error(
                f"Error sending welcome email to {instance.username}", exc_info=True
            )
            raise ValueError(
                "An error occurred while sending the welcome email"
            ) from e


# @receiver(user_created)
# def send_email_on_user_creation(sender, instance, created, request, **kwargs):
#     if created:
#         email_content = {
#             "subject": "Confirm your email account on Affily",
#             "sender": email_sender,
#             "recipient": instance.email,
#             "template": "verify-account.html",
#         }
#         try:
#             token = default_token_generator.make_token(instance)
#             uid = urlsafe_base64_encode(force_bytes(instance.pk))
#             domain = get_current_site(request).domain
#             confirm_url = reverse(
#                 "confirm_email", kwargs={"uidb64": uid, "token": token}
#             )
#             confirm_url = f"{request.scheme}://{domain}{confirm_url}"

#             context = {"username": instance.username, "url": confirm_url}
#             send_welcome_mail.delay(email_content, context)
#         except Exception as e:
#             logger.error(
#                 f"Error sending welcome email to {instance.username}", exc_info=True
#             )
#             raise ValueError(
#                 "An error occurred while sending the welcome email"
#             ) from e

# @receiver(post_save, sender=UserAccount)
# def welcome_email(sender, instance, created, **kwargs):
#     if created:
#         subject = "Welcome to Affily: #1 Affiliate Marketing Network"
#         message = f"Hello {instance.username}, thank you for joining us!"
#         from_email = email_sender
#         to_email = [instance.email]
#         send_mail(subject, message, from_email, to_email)
