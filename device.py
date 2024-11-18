import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import time

class Device:
    def __init__(self, logger, device_id, password):
        self.device_id = device_id
        self.password = password
        self.identifier = None
        self.stored_data = {}
        self.logger = logger
        self.logger("[Device] Initialized with Device ID and password.")

    def generate_identifier(self):
        combined = f"{self.device_id}{self.password}".encode('utf-8')
        self.identifier = hashlib.sha256(combined).hexdigest()
        self.logger(f"[Device] Generated identifier I_i: {self.identifier}")
        return self.identifier

    def store_registration_data(self, pid_i, a_prime_i, r_prime_i, c_prime_k):
        self.stored_data = {
            "I_i": self.identifier,
            "Pid_i": pid_i,
            "A'_i": a_prime_i,
            "R'_i": r_prime_i,
            "C'_k": c_prime_k,
        }
        self.logger(f"[Device] Stored registration data: {self.stored_data}")

    def set_session_key(self, session_key):
        self.session_key = session_key
        self.logger(f"[Device] Session key set: {self.session_key.hex()}")

    def start_authentication(self):
        """Step 1: Compute A_i, R_i, N_i, E_i and send to the server."""
        A_i = self.stored_data["A'_i"]  # From registration phase
        R_prime_i = self.stored_data["R'_i"]  # From registration phase
        I_i = bytes.fromhex(self.identifier)

        # Compute R_i by reversing XOR operation
        R_i = bytes(a ^ b for a, b in zip(R_prime_i, I_i))
        self.logger(f"[Device] Computed R_i from R'_i: {R_i.hex()}")

        # Generate N_i (nonce) and timestamp T_i
        N_i = os.urandom(16)
        T_i = int(time.time())
        self.logger(f"[Device] Generated nonce N_i: {N_i.hex()}")
        self.logger(f"[Device] Generated timestamp T_i: {T_i}")

        # Encrypt (A_i || R_i || N_i || T_i) to form E_i
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        data = f"{A_i.hex()}{R_i.hex()}{N_i.hex()}{T_i}".encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        E_i = encryptor.update(padded_data) + encryptor.finalize()

        self.logger(f"[Device] Computed E_i: {E_i.hex()} with IV: {iv.hex()}")

        # Send N_i, T_i, E_i to the server
        return N_i, T_i, E_i, iv
    
    def process_server_response(self, encrypted_T2, iv):
        """Step 3: Decrypt T2 from the server and validate it."""
        self.logger(f"[Device] Received response IV: {iv.hex()} (size: {len(iv)} bytes)")
        
        # Validate IV size
        if len(iv) != 16:
            raise ValueError(f"Invalid IV size: {len(iv)} bytes. Expected 16 bytes.")
        
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_T2_padded = decryptor.update(encrypted_T2) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_T2 = unpadder.update(decrypted_T2_padded) + unpadder.finalize()

        T2 = int(decrypted_T2.decode('utf-8'))
        self.logger(f"[Device] Decrypted T2 from server: {T2}")

        # Validate T2
        if T2 > time.time() - 60:  # T2 should be recent
            self.logger("[Device] T2 is valid. Authentication successful.")
            return True
        else:
            self.logger("[Device] T2 is invalid. Authentication failed.")
            return False
