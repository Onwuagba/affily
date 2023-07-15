# from cryptography.fernet import Fernet
import hashlib


# idea of hashing token is to prevent admin from viewing the generated token
def hash_string(data: str):
    hash_algorithm = hashlib.sha256()
    hash_algorithm.update(data.encode("utf8"))
    return (hash_algorithm.digest()[:8]).hex() # picking the first 8 char cos token model allows only 16


# def decrypt_string(encrypted: bytes, key: bytes) -> str:
#     cipher = Fernet(key)
#     decrypted = cipher.decrypt(encrypted)
#     return decrypted.decode()
