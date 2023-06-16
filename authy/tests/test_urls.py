from django.test import SimpleTestCase
from django.urls import resolve, reverse

from authy.views import RegisterAPIView


class SignupViewTests(SimpleTestCase):
    def test_signup_view_status_code(self):
        url = reverse("auth:signup")
        response = self.client.post(url)
        self.assertEquals(response.status_code, 200)

    def test_signup_url_resolves_signup_view(self):
        view = resolve("/api/v1/auth/signup/")
        self.assertEquals(view.func.view_class, RegisterAPIView)

    def test_csrf(self):
        url = reverse("auth:signup")
        response = self.client.post(url)
        self.assertContains(response, "csrfmiddlewaretoken")

    def test_contains_form(self):
        url = reverse("auth:signup")
        response = self.client.get(url)
        form = response.context.get("form")
        self.assertIsInstance(form, "UserCreationForm")
