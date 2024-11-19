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
        self.logger = logger
        self.device_id = device_id
        self.password = password
        self.identifier = None
        self.stored_data = {}
        self.ecc_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecc_public_key = self.ecc_private_key.public_key()

    def generate_identifier(self):
        self.identifier = hashlib.sha512(f"{self.device_id}{self.password}".encode('utf-8')).hexdigest()
        self.logger(" ")
        self.logger(f"[Device] Generated identifier I_i: {self.identifier}, length: {len(self.identifier)}")
        self.logger(" ")
        return self.identifier
    
    def generate_identifier_new(self, id, pw):
        identifier = hashlib.sha512(f"{id}{pw}".encode('utf-8')).hexdigest()
        self.logger(" ")
        self.logger(f"[Device] Generated identifier I_i_new: {identifier}")
        self.logger(" ")
        return identifier

    def store_registration_data(self, Pid_i, A_prime_i, R_prime_i, C_k):
        self.stored_data = {"Pid_i": Pid_i, "A'_i": A_prime_i, "R'_i": R_prime_i, "C'_k": C_k}
        self.logger(" ")
        self.logger(f"[Device] Stored registration data: {self.stored_data}")
        self.logger(" ")

    def start_authentication(self, server_public_key, auth_id, auth_password):
        self.logger(" ")
        """Step 1: Start authentication by computing N_i and E_i."""

        # Compute I*_i (New Identifier)
        I_i_new = self.generate_identifier_new(auth_id, auth_password)
        self.logger(f"[Device] I*_i (I_i_new): {I_i_new}")

        # Ensure I*_i matches stored I_i
        if I_i_new != self.identifier:
            self.logger("[Device] Mismatch: I_i_new does not match stored I_i. Possible incorrect ID or password.")
            raise ValueError("Authentication failed: Incorrect ID or password.")

        # Retrieve necessary stored values
        C_prime_k = self.stored_data["C'_k"]
        I_i = bytes.fromhex(self.identifier)
        C_k = bytes(a ^ b for a, b in zip(C_prime_k, I_i))  # Derive C_k

        A_prime_i = self.stored_data["A'_i"]
        A_i = bytes(a ^ b for a, b in zip(A_prime_i, I_i))  # Derive A_i
        self.stored_data["A_i"] = A_i
        self.logger(f"[Device] A_i: {A_i.hex()}, A'_i: {A_prime_i.hex()}")

        R_prime_i = self.stored_data["R'_i"]
        R_i = bytes(a ^ b for a, b in zip(R_prime_i, I_i))  # Derive R_i
        self.logger(f"[Device] Computed R_i from R'_i: {R_i.hex()}")
        self.stored_data.__setitem__('R_i', R_i)

        Pid_i = self.stored_data["Pid_i"]
        plaintext = Pid_i + R_i
        self.logger(f"[Device] Plaintext for ECC encryption: {plaintext.hex()}")

        # Compute shared secret and N_i
        shared_secret = self.ecc_private_key.exchange(ec.ECDH(), server_public_key)
        self.logger(f"[Device] ECC shared secret: {shared_secret.hex()}")
        encryption_key = hashlib.sha256(shared_secret).digest()[:16]
        self.logger(f"[Device] Derived encryption key: {encryption_key.hex()}")
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        encrypted_value = encryptor.update(padded_plaintext) + encryptor.finalize()
        self.logger(f"[Device] Encrypted (Pid_i || R_i): {encrypted_value.hex()}, IV: {iv.hex()}")

        N_i = encrypted_value

        # Generate timestamp T_i
        T_i = int(time.time())
        self.logger(f"[Device] Generated timestamp T_i: {T_i}")
        self.logger(f"[Device] C_k: {C_k.hex()}, Length: {len(C_k)}")
        self.stored_data.__setitem__('C_k', C_k)

        # Compute E_i = ENC_{C_k}(e_i || T_i || A_i)
        e_i = os.urandom(16)  # Random nonce
        self.stored_data.__setitem__('e_i', e_i)
        cipher = Cipher(algorithms.AES(C_k), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Prepare data
        e_i_data = e_i + T_i.to_bytes(8, "big") + A_i
        padder = padding.PKCS7(128).padder()
        padded_e_i_data = padder.update(e_i_data) + padder.finalize()

        E_i = encryptor.update(padded_e_i_data) + encryptor.finalize()
        self.logger(f"[Device] Computed E_i: {E_i.hex()} with IV: {iv.hex()}")

        self.logger(" ")
        return N_i, T_i, E_i, iv


    def process_server_response(self, Ti, T2, response_iv):
        self.logger(" ")
        Ai = self.stored_data["A_i"]
        self.logger(f"[Device] Ai: {Ai.hex()} with IV: {response_iv.hex()}")

        if abs(int(time.time()) - T2) > 60:
            self.logger("[Device] Validation failed: T2 is not fresh.")
            return None
        T3 = int(time.time())

        cipher = Cipher(algorithms.AES(Ai[:16]), modes.CBC(response_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_ti = decryptor.update(Ti) + decryptor.finalize()
        self.logger(f"[Device] {padded_ti}")

        unpadder = padding.PKCS7(128).unpadder()

        decrypted_ti = unpadder.update(padded_ti) + unpadder.finalize()
        self.logger(f"[Device] Decrypted T_i: {decrypted_ti}")

        si = decrypted_ti[:32]
        wi = decrypted_ti[32:96]
        T2_dash = decrypted_ti[96:]

        self.logger(f"[Device] si: {si} wi: {wi} T2: {T2_dash}")

        Pid_i = self.stored_data["Pid_i"]
        e_i = self.stored_data["e_i"]
        w_dash_i = hashlib.sha256(f"{Pid_i.hex()}{e_i.hex()}".encode()).digest()

        self.logger(f"[Device] w'_i: {w_dash_i.hex()}")

        C_k = self.stored_data["C_k"]
        if not isinstance(si, bytes):
            si = bytes.fromhex(si)
        if not isinstance(C_k, bytes):
            C_k = bytes.fromhex(C_k)
        self.logger(f"[Device] C_k: {C_k.hex()}")
        si = bytes.fromhex(si.decode())
        q_dash_i = bytes(a ^ b for a, b in zip(si, C_k))
        self.logger(f"[Device] si (type): {type(si)}, si (raw): {si}, si (hex): {si.hex()}")


        Q_i = hashlib.sha256(f"{Ai.hex()}{C_k.hex()}".encode()).digest()
        self.logger(f"[device] Q_i: {Q_i.hex()}")

        R_i = self.stored_data["R_i"]
        sk_i = hashlib.sha256(f"{e_i.hex()}{C_k.hex()}{Q_i.hex()}{R_i.hex()}{si.hex()}".encode()).digest()
        self.logger(f"[device] sk_i: {sk_i.hex()}")

        self.logger(f"[device] sk_i: {sk_i.hex()}, q'i: {q_dash_i.hex()}, si: {si}, Q_i: {Q_i.hex()}")
        MN_i = hashlib.sha256(f"{sk_i.hex()}{q_dash_i.hex()}{si.hex()}{Q_i.hex()}".encode()).digest()

        self.logger(f"[device] MN_i: {MN_i.hex()}")

        self.logger(" ")
        return MN_i, Pid_i, T3
    