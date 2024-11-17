from security import hash_data, decrypt_message, generate_ec_key_pair, derive_aes_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
import logging

server_logger = logging.getLogger("Server")

class Server:
    def __init__(self):
        self.private_key, self.public_key = generate_ec_key_pair()
        self.registered_devices = {}
        server_logger.info("Server initialized with ECC keys.")

    def register_device(self, device_id, registration_data):
        # Serialize the server's public key
        identifier = registration_data["identifier"]
        serialized_public_key = registration_data["public_key"]
        device_public_key = load_pem_public_key(serialized_public_key)
        self.registered_devices[device_id] = {"Ii": identifier, "public_key": device_public_key}
        serialized_server_public_key = self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        server_logger.info(f"Registered device {device_id} with ECC.")

        return {"server_public_key": serialized_server_public_key}


    def authenticate_device(self, device_id, iv, encrypted_message, tag):
        shared_key = self.private_key.exchange(ec.ECDH(), self.registered_devices[device_id]["public_key"])
        session_key = derive_aes_key(shared_key)
        server_logger.info(f"Derived session key for {device_id}: {session_key.hex()}")

        try:
            decrypted_message = decrypt_message(session_key, iv, encrypted_message, tag)
            server_logger.info(f"Decrypted timestamp: {decrypted_message.hex()}")
            return True
        except Exception as e:
            server_logger.error(f"Decryption failed: {str(e)}")
            return False
