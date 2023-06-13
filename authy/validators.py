import re

from django.core.exceptions import ValidationError


def validate_phone_number(value):
    """
    Validate a phone number.

    :param value: A string representing the phone number to be validated.
    :raises ValidationError: If the phone number is not valid.
    """
    if not re.match(r"^\d{11}$", value):
        raise ValidationError("Invalid phone number. Must be 11 digits.")


class CustomPasswordValidator:
    def validate(self, password: str, user=None) -> None:
        """
        Validates a given password according to the specified criteria.

        Args:
            password (str): The password to be validated.

        Raises:
            ValueError: If the given password is not at least 8 characters long, \
                or does not contain at least one uppercase letter, \
                    one lowercase letter, one digit, and one special character.
        """
        regex = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$"
        if not re.match(regex, password):
            raise ValueError(
                "Password must be at least 8 characters \
                    and contain at least one uppercase letter, \
                        one lowercase letter, one digit, and one special character."
            )

    def get_help_text(self):
        return "Your password must be at least 8 characters,\
                containing 1 uppercase , 1 lowercase \
                    1 special character and 1 number."
