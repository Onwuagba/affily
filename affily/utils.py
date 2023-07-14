import base64
from Crypto.Cipher import AES
import os, codecs
from dotenv import load_dotenv

load_dotenv()

# decode the escaped string & obtain the byte string
KEY = codecs.escape_decode(os.getenv('KEY'))[0]
IV = codecs.escape_decode(os.getenv('IV'))[0]

data = {
    "key": KEY, 
    "iv": IV,
}


def encrypt(input_string):
    """
    function to encrypt a string
    """
    # Create an AES cipher object with CBC mode
    cipher = AES.new(data["key"], AES.MODE_CBC, data["iv"])

    # Pad the input string to a multiple of 16 bytes (the AES block size)
    padded_input = input_string + (16 - len(input_string) % 16) * chr(
        16 - len(input_string) % 16
    )

    # Encrypt the padded input string using the cipher
    encrypted_data = cipher.encrypt(padded_input.encode())

    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt_data(encrypted_data_b64):
    """
    function to decrypt a Base64-encoded string[]
    """
    if not data.get("key"):
        raise ValueError("Missing key")

    if encrypted_data_b64:
        # Convert the Base64-encoded encrypted data string to bytes
        encrypted_data = base64.b64decode(encrypted_data_b64.encode("utf-8"))

        # Create an AES cipher object with CBC mode
        cipher = AES.new(data["key"], AES.MODE_CBC, data["iv"])

        # Decrypt the encrypted data using the cipher
        decrypted_padded_data = cipher.decrypt(encrypted_data)

        # Unpad the decrypted data by removing the padding bytes
        unpadded_data = decrypted_padded_data[: -decrypted_padded_data[-1]]

        # Convert the decrypted data to a string and return it
        return unpadded_data.decode("utf-8")
    raise ValueError("Could not read data")
