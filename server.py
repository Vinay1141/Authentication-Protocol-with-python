from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac
import os
import time


class Server:
    def __init__(self, logger, server_id, master_key):
        self.server_id = server_id
        self.master_key = master_key
        self.database = {}
        self.logger = logger
        self.logger("[Server] Server initialized with ID and master key.")

    def register_device(self, i_i):
        # Generate a random number r_cs
        r_cs = os.urandom(16)
        self.logger(f"[Server] Generated random number r_cs: {r_cs.hex()}")

        session_key = hashlib.sha256(f"{i_i}{r_cs.hex()}".encode('utf-8')).digest()
        self.logger(f"[Server] Computed session key: {session_key.hex()}")
        # Compute Pid_i
        pid_i_hash_input = f"{i_i}{self.server_id}{r_cs.hex()}".encode('utf-8')
        pid_i = hashlib.sha256(pid_i_hash_input).hexdigest()
        pid_i_xor = bytes.fromhex(pid_i)[:16]  # XOR only uses first 16 bytes
        self.logger(f"[Server] Computed Pid_i: {pid_i_xor.hex()}")

        # Compute other values (A'_i, R'_i, C'_k)
        et = "server-specific-time".encode('utf-8')
        c_k_hash_input = f"{self.master_key}{pid_i}{et.decode()}{r_cs.hex()}".encode('utf-8')
        c_k = hashlib.sha256(c_k_hash_input).digest()
        c_prime_k = bytes(a ^ b for a, b in zip(c_k[:16], bytes.fromhex(i_i)[:16]))
        self.logger(f"[Server] Computed C'_k: {c_prime_k.hex()}")

        a_i_data = f"{pid_i}{et.decode()}".encode('utf-8')

        # Pad the data to a multiple of the block size
        padder = padding.PKCS7(128).padder()
        padded_a_i_data = padder.update(a_i_data) + padder.finalize()

        # Encrypt the padded data
        cipher = Cipher(algorithms.AES(self.master_key.encode('utf-8')), modes.ECB())
        encryptor = cipher.encryptor()
        a_i = encryptor.update(padded_a_i_data) + encryptor.finalize()
        a_prime_i = bytes(a ^ b for a, b in zip(a_i[:16], bytes.fromhex(i_i)[:16]))
        self.logger(f"[Server] Computed A'_i: {a_prime_i.hex()}")
        self.logger(f"[Server] r_cs during registration: {r_cs.hex()}")
        self.logger(f"[Server] SHA-256 hash of Pid_i: {hashlib.sha256(pid_i.encode('utf-8')).hexdigest()}")
        r_i = bytes(a ^ b for a, b in zip(r_cs, hashlib.sha256(pid_i.encode('utf-8')).digest()[:16]))
        self.logger(f"[Server] Computed R_i during registration: {r_i.hex()}")
        r_prime_i = bytes(a ^ b for a, b in zip(r_i[:16], bytes.fromhex(i_i)[:16]))
        self.logger(f"[Server] Sent R'_i to device: {r_prime_i.hex()}")
        # self.logger(f"[Server] R_i stored during registration: {r_i.hex()}")
        # Store {R_i, Et, Pid_i} in the database
        self.database[pid_i] = {
            "R_i": r_i,
            "Et": et,
            "Pid_i": pid_i,
            "Session_Key": session_key,
            "Random_Value": r_cs
        }
        self.logger(f"[Server] Stored registration data for Pid_i: {pid_i}")

        return pid_i, a_prime_i, r_prime_i, c_prime_k

    # def authenticate_device(self, device_id, iv, encrypted_message, tag):
    #     if device_id not in self.registered_devices:
    #         self.logger("[Server] Authentication failed: Device not registered.")
    #         return False

    #     session_key = self.registered_devices[device_id]
    #     self.logger(f"[Server] Retrieved session key for device {device_id}: {session_key.hex()}")

    #     # Verify HMAC for message integrity
    #     expected_tag = hmac.new(session_key, encrypted_message, hashlib.sha256).digest()
    #     self.logger(f"[Server] Calculated expected HMAC tag: {expected_tag.hex()}")
    #     if not hmac.compare_digest(tag, expected_tag):
    #         self.logger("[Server] HMAC verification failed.")
    #         return False

    #     # Decrypt the encrypted message (timestamp)
    #     cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    #     decryptor = cipher.decryptor()
    #     padded_timestamp = decryptor.update(encrypted_message) + decryptor.finalize()
    #     self.logger(f"[Server] Decrypted padded timestamp: {padded_timestamp.hex()}")

    #     # Unpad the decrypted timestamp
    #     unpadder = padding.PKCS7(128).unpadder()
    #     timestamp = unpadder.update(padded_timestamp) + unpadder.finalize()
    #     self.logger(f"[Server] Unpadded timestamp: {timestamp.hex()}")

    #     # Simulated check for timestamp validity
    #     self.logger("[Server] Authentication successful.")
    #     return True

    def process_auth_request(self, identifier, N_i, T_i, E_i, iv):
        """Step 2: Validate E_i, compute S_i, and respond."""
        self.logger(f"[Server] Received E_i: {E_i.hex()}")
        self.logger(f"[Server] Database: {self.database}")
        if identifier not in self.database:
            self.logger("[Server] Authentication failed: Device not registered.")
            return None

        # Retrieve session key, R_i, and A_i
        session_key = self.database[identifier]["Session_Key"]
        R_i = self.database[identifier]["R_i"]

        self.logger(f"[Server] Received N_i: {N_i.hex()}")
        self.logger(f"[Server] Received T_i: {T_i}")

        if T_i <= time.time() - 60:
            self.logger("[Server] T_i is invalid (stale timestamp). Authentication failed.")
            return None

        # Decrypt E_i
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(E_i) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        self.logger(f"[Server] data: {data}")

        received_A_i = bytes.fromhex(data[:32].decode('utf-8'))
        received_R_i = bytes.fromhex(data[32:64].decode('utf-8'))
        self.logger(f"[Server] Expected R_i: {R_i.hex()}")
        self.logger(f"[Server] Decrypted A_i: {received_A_i.hex()}")
        self.logger(f"[Server] Decrypted R_i: {received_R_i.hex()}")

        if received_R_i != R_i:
            self.logger("[Server] R_i mismatch. Authentication failed.")
            return None

        # Generate S_i (response nonce) and compute response
        S_i = os.urandom(16)
        self.logger(f"[Server] Generated response nonce S_i: {S_i.hex()}")

        # Encrypt response (S_i || N_i) to form R_e
        response_iv = os.urandom(16)
        self.logger(f"[Server] Generated response IV: {response_iv.hex()}")
        response_data = f"{S_i.hex()}{N_i.hex()}".encode('utf-8')
        
        padder = padding.PKCS7(128).padder()
        padded_response = padder.update(response_data) + padder.finalize()

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(response_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        R_e = encryptor.update(padded_response) + encryptor.finalize()

        self.logger(f"[Server] Computed R_e: {R_e.hex()} with IV: {response_iv.hex()}")

        return S_i, R_e, response_iv