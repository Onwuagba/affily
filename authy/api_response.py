from rest_framework.exceptions import ValidationError
from rest_framework.response import Response


class CustomAPIResponse:
    def __init__(self, message, status_code, status):
        self.data = {"status": status}
        if status == "failed":
            if isinstance(message, (ValidationError, ValueError)):
                self.data["message"] = message.args[0]
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
