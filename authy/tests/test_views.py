import unittest

from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from authy.generics import check_email_username

from authy.validators import validate_phone_number
from rest_framework import status
from rest_framework.test import APIClient

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


class DeleteUserTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = UserModel.objects.create(
            username="testuser", email="testuser@test.com"
        )

    def test_delete_by_username(self):
        data = {"username": "testuser"}
        response = self.client.delete("/users/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_deleted)
        self.assertFalse(self.user.is_active)

    def test_delete_by_email(self):
        data = {"email": "testuser@test.com"}
        response = self.client.delete("/users/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_deleted)
        self.assertFalse(self.user.is_active)

    def test_delete_nonexistent_user(self):
        data = {"username": "nonexistentuser"}
        response = self.client.delete("/users/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(
            UserModel.objects.filter(username="nonexistentuser").exists()
        )

    def test_delete_invalid_username_email(self):
        data = {"username": "invalid_username", "email": "invalid_email"}
        with self.assertRaises(check_email_username.ValidationError):
            check_email_username(data)

    def tearDown(self):
        self.user.delete()
