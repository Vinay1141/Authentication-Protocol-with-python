import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Server:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.registered_devices = {}

    def register_device(self, device_id, device_public_key):
        shared_key = self.private_key.exchange(ec.ECDH(), device_public_key)
        derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"session key").derive(shared_key)
        self.registered_devices[device_id] = {"public_key": device_public_key, "session_key": derived_key}
        return derived_key

    def authenticate_device(self, device_id, iv, encrypted_message, tag):
        if device_id not in self.registered_devices:
            return False

        session_key = self.registered_devices[device_id]["session_key"]
        aesgcm = AESGCM(session_key)

        try:
            decrypted_message = aesgcm.decrypt(iv, encrypted_message + tag, None)
            print(f"Decrypted Message: {decrypted_message}")
            return True
        except Exception as e:
            print(f"Decryption failed: {e}")
            return False
