import base64

from Crypto.Cipher import AES

data = {
    "key": (
        b"\xc1I\xd1\xcf\x07\x82\xd8k\x8e%\xec\xc6\x0e\x8c\x06"
        b"\xf1\xa8\xe6\x8aBO\x14Y\xb1\xdd\xce*\x1b\x8f\x05\xfd\xbe"
    ),  # this is nt a tuple oo...single line string broken into 2 cos of flake8
    "iv": b"cy]& \xd3\xef\xafE\xf1+\x90\xb9\xdf\x1f1",
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
