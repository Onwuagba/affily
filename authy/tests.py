import unittest

from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from authy.utilities.mail.send_mail import send_mail_now
from authy.validators import validate_phone_number

UserModel = get_user_model()


# AUTHENTICATION TESTS


class AuthenticateTestCase(TestCase):
    def test_authenticate_valid_credentials(self):
        # Test valid credentials
        request = None
        email = "test@test.com"
        username = "testuser"
        password = "testpass"
        user = UserModel.objects.create_user(
            email=email, username=username, password=password
        )
        authenticated_user = authenticate(
            request, username=username, password=password
        )
        self.assertEqual(user, authenticated_user)

    def test_authenticate_invalid_credentials(self):
        # Test invalid credentials
        request = None
        email = "test@test.com"
        username = "testuser"
        password = "testpass"
        UserModel.objects.create_user(
            email=email, username=username, password=password
        )
        authenticated_user = authenticate(
            request, username=username, password="wrongpass"
        )
        self.assertIsNone(authenticated_user)

    def test_authenticate_nonexistent_user(self):
        # Test nonexistent user
        request = None
        username = "nonexistentuser"
        password = "testpass"
        authenticated_user = authenticate(
            request, username=username, password=password
        )
        self.assertIsNone(authenticated_user)


# PHONE NUMBER TESTS


class TestValidatePhoneNumber(unittest.TestCase):
    def test_valid_phone_number(self):
        """
        Tests the function validate_phone_number with a valid phone number.

        :param self: A reference to the class instance.
        :return: None
        """
        # Test valid phone number
        value = "01234567890"
        self.assertIsNone(validate_phone_number(value))

    def test_invalid_phone_number(self):
        # Test invalid phone number with less than 11 digits
        value = "123456789"
        with self.assertRaises(ValidationError):
            validate_phone_number(value)

        # Test invalid phone number with more than 11 digits
        value = "123456789012"
        with self.assertRaises(ValidationError):
            validate_phone_number(value)

        # Test invalid phone number with non-numeric characters
        value = "12-34-56-78-90"
        with self.assertRaises(ValidationError):
            validate_phone_number(value)


# EMAIL TESTS


class TestSendMailNow(unittest.TestCase):
    def test_send_mail_success(self):
        result = self._extracted_from_test_send_mail_return_type_2()
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
        result = self._extracted_from_test_send_mail_return_type_2()
        self.assertIsInstance(result[0], str)
        self.assertIsInstance(result[1], bool)

    # TODO Rename this here and in `test_send_mail_success`
    # and `test_send_mail_return_type`
    def _extracted_from_test_send_mail_return_type_2(self):
        content = {
            "subject": "Test Email",
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "template": "test_template.html",
        }
        context = {"name": "John Doe"}
        return send_mail_now(content, context)
