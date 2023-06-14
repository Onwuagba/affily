from django.http import Http404
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response


class CustomAPIResponse:
    def __init__(self, message, status_code, status):
        if not all([message, status_code, status]):
            raise ValidationError("message and status code cannot br empty")

        self.data = {"status": status}
        if status == "failed":
            if isinstance(message, (ValidationError, ValueError)):
                self.data["message"] = message.args[0]
            elif isinstance(message, dict):
                self.data["message"] = self.convert_to_string(message)
            else:
                self.data["message"] = message
        else:
            self.data["data"] = message
        self.status_code = status_code

    def send(self) -> Response:
        """
        Sends data back as a HTTP response.

        Args:
            self: The instance of the class.

        Returns:
            A Response object with the data and status code.
        """
        return Response(self.data, status=self.status_code)

    def convert_to_string(self, message):
        """
        Convert a dictionary to a formatted string.

        Args:
            message (dict): A dictionary containing key-value pairs to format.

        Returns:
            str: A formatted string containing the dictionary's key-value pairs.
        """
        res = []
        for key, value in message.items():
            if isinstance(value, list):
                value = " ".join(value)
            res.append(f"{key.upper().replace('_', ' ')}: {value}")
        return "| ".join(res)
