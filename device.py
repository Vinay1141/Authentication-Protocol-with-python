import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class Device:
    def __init__(self, logger, device_id, password):
        self.device_id = device_id
        self.password = password
        self.identifier = None
        self.stored_data = {}
        self.logger = logger
        self.logger("[Device] Initialized with Device ID and password.")

        self.ecc_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecc_public_key = self.ecc_private_key.public_key()
        self.logger("[Device] ECC key pair generated.")

    def generate_identifier(self):
        combined = f"{self.device_id}{self.password}".encode('utf-8')
        self.identifier = hashlib.sha256(combined).hexdigest()
        self.logger(f"[Device] Generated identifier I_i: {self.identifier}")
        return self.identifier

    def generate_identifier_new(self, id, password):
        combined = f"{id}{password}".encode('utf-8')
        I_i = hashlib.sha256(combined).hexdigest()
        self.logger(f"[Device] Generated identifier I*_i: {I_i}")
        return I_i

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

    def start_authentication(self, server_public_key, auth_id, auth_password):
        """Step 1: Compute A_i, R_i, N_i, E_i and send to the server."""
        I_i_new = self.generate_identifier_new(auth_id, auth_password)
        self.logger(f"[Device] I*_i (I_i_new): {I_i_new}")

        I_i = bytes.fromhex(self.identifier)

        if I_i_new != self.identifier:
            self.logger("[Device] Mismatch: I_i_new does not match stored I_i. Possible incorrect ID or password.")
            raise ValueError("Authentication failed: Incorrect ID or password.")

        C_prime_k = self.stored_data["C'_k"]
        C_k = bytes(a ^ b for a, b in zip(C_prime_k, I_i))

        A_prime_i = self.stored_data["A'_i"]
        A_i = bytes(a ^ b for a, b in zip(A_prime_i, I_i))

        R_prime_i = self.stored_data["R'_i"]
        R_i = bytes(a ^ b for a, b in zip(R_prime_i, I_i))
        self.logger(f"[Device] Computed R_i from R'_i: {R_i.hex()}")

        Pid_i = self.stored_data["Pid_i"]

        # Step 2: Compute the shared secret and encode N_i as an uncompressed point
        ecc_input = f"{Pid_i}{R_i.hex()}".encode('utf-8')
        shared_secret = self.ecc_private_key.exchange(ec.ECDH(), server_public_key)
        self.logger(f"[Device] Computed ECC shared secret: {shared_secret.hex()}")

        # Serialize the server's public key as N_i (uncompressed format)
        N_i = server_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        self.logger(f"[Device] Computed N_i (encoded as uncompressed point): {N_i.hex()}")

        # Step 3: Generate timestamp T_i
        T_1 = int(time.time())
        self.logger(f"[Device] Generated timestamp T_i: {T_1}")

        # Step 4: Compute E_i = ENC_{C_k}(e_i, T_i, A_i)
        e_i = os.urandom(16)
        iv = os.urandom(16)
        if len(C_k) < 16:
            C_k = hashlib.sha256(C_k).digest()[:16]
        cipher = Cipher(algorithms.AES(C_k), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        data = f"{e_i.hex()}{T_1}{A_i.hex()}".encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        E_i = encryptor.update(padded_data) + encryptor.finalize()

        self.logger(f"[Device] Computed E_i: {E_i.hex()} with IV: {iv.hex()}")

        return N_i, T_1, E_i, iv

    def process_server_response(self, Ti, T2, iv):
        self.logger(f"[Device] Received Ti: {Ti.hex()}, T2: {T2} with IV: {iv.hex()}")

        I_i = bytes.fromhex(self.identifier)
        A_prime_i = self.stored_data["A'_i"]
        A_i = bytes(a ^ b for a, b in zip(A_prime_i, I_i))
        
        if abs(int(time.time()) - T2) > 60:
            self.logger("[Server] Validation failed: T2 is not fresh.")
            return None
        T3 = int(time.time())

        cipher = Cipher(algorithms.AES(A_i), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_ti = decryptor.update(Ti) + decryptor.finalize()
        self.logger(f"[Server] {padded_ti}")

        unpadder = padding.PKCS7(128).unpadder()

        decrypted_ti = unpadder.update(padded_ti) + unpadder.finalize()
        self.logger(f"[Server] Decrypted T_i: {decrypted_ti.hex()}")



        return T3
