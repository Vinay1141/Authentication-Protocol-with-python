import os
from security import hash_data, encrypt_message, generate_ec_key_pair, derive_aes_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
import logging
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

device_logger = logging.getLogger("Device")

class Device:
    def __init__(self, device_id, password):
        self.device_id = device_id
        self.password = password
        self.private_key, self.public_key = generate_ec_key_pair()
        self.session_key = None
        self.timestamp = None
        device_logger.info("Device initialized with ECC keys.")

    def register(self):
        identifier = hash_data(f"{self.device_id}{self.password}".encode())
        serialized_public_key = self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        device_logger.info(f"Step 1: Generated identifier Ii: {identifier.hex()}")
        device_logger.info("Step 1: Serialized device public key for registration.")
        return {"identifier": identifier, "public_key": serialized_public_key}

    def receive_registration_info(self, server_data):
        server_public_key = load_pem_public_key(server_data.get("server_public_key"))
        shared_key = self.private_key.exchange(ec.ECDH(), server_public_key)
        self.session_key = derive_aes_key(shared_key)
        device_logger.info(f"Step 3: Shared session key derived: {self.session_key.hex()}")

    def authenticate(self):
        self.timestamp = os.urandom(4)
        iv, encrypted_message, tag = encrypt_message(self.session_key, self.timestamp)
        device_logger.info(f"Step 1: Generated timestamp: {self.timestamp.hex()}")
        device_logger.info(f"Step 2: Encrypted timestamp with IV: {iv.hex()}, Tag: {tag.hex()}")
        return iv, encrypted_message, tag
