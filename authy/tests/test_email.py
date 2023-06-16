import unittest
from django.contrib.auth import get_user_model
from authy.utilities.mail.send_mail import send_mail_now

UserModel = get_user_model()


# EMAIL TESTS
class TestSendMailNow(unittest.TestCase):
    def test_send_mail_success(self):
        result = self._context()
        self.assertEqual(result, ("Mail sent successfully", True))

    def test_send_mail_failure(self):
        content = {
            "subject": "Test Email",
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
        }
        context = {"name": "John Doe"}
        result = send_mail_now(content, context)
        self.assertEqual(result, (False, False))

    def test_send_mail_return_type(self):
        result = self._context()
        self.assertIsInstance(result[0], str)
        self.assertIsInstance(result[1], bool)

    def _context(self):
        content = {
            "subject": "Test Email",
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "template": "veify-email.html",
        }
        context = {"name": "John Doe"}
        return send_mail_now(content, context)
