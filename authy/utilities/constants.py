import os
from dotenv import load_dotenv

load_dotenv()

email_sender = os.getenv("EMAIL_SENDER")
admin_support_sender = os.getenv("SUPPORT_EMAIL")
CHANNELS = (
    ("facebook", "facebook"),
    ("twitter", "twitter"),
    ("google", "google"),
    ("email", "email"),
)
