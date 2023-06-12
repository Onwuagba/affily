from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.test import TestCase
import unittest
from django.core.exceptions import ValidationError
from authy.validators import validate_phone_number

UserModel = get_user_model()


class AuthenticateTestCase(TestCase):
    def test_authenticate_valid_credentials(self):
        # Test valid credentials
        request = None
        email = "test@test.com"
        username = "testuser"
        password = "testpass"
        user = UserModel.objects.create_user(email=email,username=username, password=password)
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
        UserModel.objects.create_user(email=email,username=username, password=password)
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


class TestValidatePhoneNumber(unittest.TestCase):

    def test_valid_phone_number(self):
        """
        Tests the function validate_phone_number with a valid phone number.

        :param self: A reference to the class instance.
        :return: None
        """
        # Test valid phone number
        value = '01234567890'
        self.assertIsNone(validate_phone_number(value))

    def test_invalid_phone_number(self):
        # Test invalid phone number with less than 11 digits
        value = '123456789'
        with self.assertRaises(ValidationError):
            validate_phone_number(value)

        # Test invalid phone number with more than 11 digits
        value = '123456789012'
        with self.assertRaises(ValidationError):
            validate_phone_number(value)

        # Test invalid phone number with non-numeric characters
        value = '12-34-56-78-90'
        with self.assertRaises(ValidationError):
            validate_phone_number(value)