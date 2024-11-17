import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Device:
    def __init__(self):
        self.device_id = "device123"
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.session_key = None

    def generate_identifier(self):
        return hashlib.sha256(self.device_id.encode()).hexdigest()

    def set_session_key(self, session_key):
        self.session_key = session_key

    def generate_auth_request(self):
        timestamp = os.urandom(16).hex()
        iv = os.urandom(12)
        aesgcm = AESGCM(self.session_key)
        encrypted_message = aesgcm.encrypt(iv, timestamp.encode(), None)
        return timestamp, iv, encrypted_message[:-16], encrypted_message[-16:]
