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

        # Step 2: Compute N_i = ECC_{Pcs}(Pid_i || R_i)
        ecc_input = f"{Pid_i}{R_i.hex()}".encode('utf-8')
        shared_secret = self.ecc_private_key.exchange(ec.ECDH(), server_public_key)
        self.logger(f"[Device] Computed ECC(N_i): {shared_secret.hex()}")

        N_i = hashlib.sha256(f"{shared_secret.hex()}{ecc_input.decode()}".encode()).digest()
        self.logger(f"[Device] Computed hashed N_i: {N_i.hex()}")

        # Step 3: Generate timestamp T_i
        T_i = int(time.time())
        self.logger(f"[Device] Generated timestamp T_i: {T_i}")

        # Step 4: Compute E_i = ENC_{C_k}(e_i, T_i, A_i)
        e_i = os.urandom(16)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        data = f"{e_i.hex()}{T_i}{A_i.hex()}".encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        E_i = encryptor.update(padded_data) + encryptor.finalize()

        self.logger(f"[Device] Computed E_i: {E_i.hex()} with IV: {iv.hex()}")

        return N_i, T_i, E_i, iv

    
    def process_server_response(self, Ti, T2, iv):
        """Step 3: Decrypt T2 from the server and validate it."""
        self.logger(f"[Device] Received response Ti: {Ti.hex()}, T2: {T2}, IV: {iv.hex()}")
        
        # Validate IV size
        if len(iv) != 16:
            raise ValueError(f"Invalid IV size: {len(iv)} bytes. Expected 16 bytes.")
        
        # Decrypt Ti using A_i
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        try:
            padded_data = decryptor.update(Ti) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
        except Exception as e:
            self.logger(f"[Device] Error decrypting Ti: {e}")
            return False

        # Parse decrypted data
        si = bytes.fromhex(decrypted_data[:32].decode())
        wi_received = bytes.fromhex(decrypted_data[32:64].decode())
        T2_received = int(decrypted_data[64:].decode())
        self.logger(f"[Device] Decrypted si: {si.hex()}, wi: {wi_received.hex()}, T2: {T2_received}")

        # Step 1: Validate T2 (freshness check)
        if abs(int(time.time()) - T2_received) > 60:
            self.logger("[Device] Validation failed: T2 is not fresh.")
            return False
        
        # Step 2: Compute A_i from stored data
        I_i = bytes.fromhex(self.identifier)  # Retrieve stored I_i
        A_prime_i = self.stored_data["A'_i"]
        A_i = bytes(a ^ b for a, b in zip(A_prime_i, I_i))
        self.logger(f"[Device] Computed A_i: {A_i.hex()}")
        
        # Step 3: Compute wi locally and compare
        wi_computed = hashlib.sha256(f"{self.stored_data['Pid_i']}{self.e_i.hex()}".encode()).digest()
        self.logger(f"[Device] Computed wi: {wi_computed.hex()}")

        if wi_computed != wi_received:
            self.logger("[Device] Validation failed: wi mismatch.")
            return False
        
        # Step 4: Compute Qi = hash(A_i || Ck)
        Ck = self.session_key
        qi = bytes(a ^ b for a, b in zip(si, Ck))
        Qi = hashlib.sha256(f"{Ck.hex()}{qi.hex()}".encode()).digest()
        self.logger(f"[Device] Computed Qi: {Qi.hex()}")

        # Step 5: Derive final session key
        R_prime_i = self.stored_data["R'_i"]
        R_i = bytes(a ^ b for a, b in zip(R_prime_i, I_i))
        session_key = hashlib.sha256(f"{self.e_i.hex()}{Ck.hex()}{Qi.hex()}{R_i.hex()}".encode()).digest()
        self.logger(f"[Device] Derived session key: {session_key.hex()}")

        self.logger("[Device] Session key successfully updated. Authentication complete.")
        return True