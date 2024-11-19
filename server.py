from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac
import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization



class Server:
    def __init__(self, logger, server_id, master_key):
        self.server_id = server_id
        self.master_key = master_key
        self.database = {}
        self.logger = logger
        self.logger("[Server] Server initialized with ID and master key.")
        self.ck = None

        self.ecc_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecc_public_key = self.ecc_private_key.public_key()
        self.logger("[Server] ECC key pair generated.")

    def register_device(self, i_i):
        """
        Registers a device by computing and sharing necessary parameters with it.
        """
        # Step 1: Generate a random number r_cs
        r_cs = os.urandom(16)
        self.logger(f"[Server] Generated random number r_cs: {r_cs.hex()}")

        # Step 2: Compute session key (not shared with the device)
        session_key = hashlib.sha256(f"{i_i}{r_cs.hex()}".encode('utf-8')).digest()
        self.logger(f"[Server] Computed session key: {session_key.hex()}")

        # Step 3: Compute Pid_i
        pid_i_hash_input = f"{i_i}{self.server_id}{r_cs.hex()}".encode('utf-8')
        pid_i_hash = hashlib.sha256(pid_i_hash_input).digest()
        server_id_bytes = self.server_id.encode('utf-8')  # Convert server_id to bytes

        # XOR Pid_i with the server ID
        pid_i = bytes(a ^ b for a, b in zip(pid_i_hash, server_id_bytes))
        self.logger(f"[Server] Computed Pid_i: {pid_i.hex()}")

        # Step 4: Compute C_k
        current_time = int(time.time())
        validity_period = 3600  # 1 hour validity
        et = current_time + validity_period
        self.logger(f"[Server] Computed expiration time (Et): {et} (UNIX timestamp)")
        c_k_hash_input = f"{self.master_key}{pid_i.hex()}{et}{r_cs.hex()}".encode('utf-8')
        c_k = hashlib.sha256(c_k_hash_input).digest()

        # XOR C_k with server_id (Id_cs)
        server_id_bytes = self.server_id.encode('utf-8')  # Convert server_id to bytes
        c_k_xor = bytes(a ^ b for a, b in zip(c_k, server_id_bytes))
        self.logger(f"[Server] Computed C_k (after XOR with Id_cs): {c_k_xor.hex()}")
        self.ck = c_k_xor
        # Compute C'_k by XORing with I_i
        c_prime_k = bytes(a ^ b for a, b in zip(c_k_xor, bytes.fromhex(i_i)))
        self.logger(f"[Server] Computed C'_k: {c_prime_k.hex()}")

        # Step 5: Compute A'_i (anonymized authentication value)
        a_i_data = f"{pid_i.hex()}{et}".encode('utf-8')    

        # Encrypt A_i
        padder = padding.PKCS7(128).padder()
        padded_a_i_data = padder.update(a_i_data) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.master_key.encode('utf-8')), modes.ECB())
        encryptor = cipher.encryptor()
        a_i = encryptor.update(padded_a_i_data) + encryptor.finalize()

        a_prime_i = bytes(a ^ b for a, b in zip(a_i, bytes.fromhex(i_i)))
        self.logger(f"[Server] Computed A'_i: {a_prime_i.hex()}")

        # Step 6: Compute R'_i
        r_i_hash_input = f"{self.master_key}{pid_i.hex()}".encode('utf-8')  # X_cs || Pid_i
        r_i_hash = hashlib.sha256(r_i_hash_input).digest()
        r_i = bytes(a ^ b for a, b in zip(r_cs, r_i_hash))
        self.logger(f"[Server] Computed R_i: {r_i.hex()}")

        r_prime_i = bytes(a ^ b for a, b in zip(r_i, bytes.fromhex(i_i)))
        self.logger(f"[Server] Computed R'_i: {r_prime_i.hex()}")

        # Step 7: Store {R_i, Et, Pid_i} securely in the database
        self.database[pid_i.hex()] = {
            "R_i": r_i,
            "Et": et,
            "Pid_i": pid_i.hex(),
            "Session_Key": session_key,
            "Random_Value": r_cs,
        }
        self.logger(f"[Server] Stored registration data for Pid_i: {pid_i.hex()}")

        # Return {Pid_i, A'_i, R'_i, C'_k} to the device
        return pid_i.hex(), a_prime_i, r_prime_i, c_prime_k


    def process_auth_request(self, identifier, N_i, T1, Ei, iv):
        self.logger(f"[Server] Database state: {self.database}")

        # Step 1: Verify if the identifier exists in the database
        if identifier not in self.database:
            self.logger("[Server] Authentication failed: Device not registered.")
            return None

        # Retrieve stored values
        session_key = self.database[identifier]["Session_Key"]
        R_i_stored = self.database[identifier]["R_i"]
        Pid_i_stored = self.database[identifier]["Pid_i"]
        Et_stored = self.database[identifier]["Et"]

        # Step 2: Verify T1 (freshness)
        current_time = int(time.time())
        if abs(current_time - T1) > 60:
            self.logger("[Server] Authentication failed: T1 is not fresh.")
            return None

        # Step 3: Compute \( C_k \)
        r_cs = self.database[identifier]["Random_Value"]
        c_k_hash_input = f"{self.master_key}{Pid_i_stored}{Et_stored}{r_cs.hex()}".encode('utf-8')
        C_k = hashlib.sha256(c_k_hash_input).digest()
        self.logger(f"[Server] Computed C_k: {C_k.hex()}")

        if len(C_k) < 16:  # Ensure valid AES key length
            C_k = hashlib.sha256(C_k).digest()[:16]
            self.logger(f"[Server] Adjusted C_k for AES compatibility: {C_k.hex()}")

        # Step 4: Validate \( E_i \)
        cipher = Cipher(algorithms.AES(C_k), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            padded_ei = decryptor.update(Ei) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_ei = unpadder.update(padded_ei) + unpadder.finalize()
            self.logger(f"[Server] Decrypted E_i: {decrypted_ei.hex()}")
        except Exception as e:
            self.logger(f"[Server] Failed to decrypt E_i: {e}")
            return None

        # Step 5: Extract components from \( E_i \)
        extracted_e_i = decrypted_ei[:16]  # First 16 bytes
        extracted_T1 = int(decrypted_ei[16:32].decode('utf-8'))  # Next 16 bytes as integer
        extracted_A_i = decrypted_ei[32:]  # Remaining bytes
        self.logger(f"[Server] Extracted e_i: {extracted_e_i.hex()}, T1: {extracted_T1}, A*_i: {extracted_A_i.hex()}")

        # Step 6: Validate \( A^*_i \)
        A_prime_i = extracted_A_i  # Assuming \( A^*_i \) is provided directly
        Pid_star = Pid_i_stored  # Stored \( Pid_i \)
        Et_star = Et_stored  # Stored \( Et \)
        self.logger(f"[Server] Extracted Pid*: {Pid_star}, Et*: {Et_star}")

        # Check \( Et^* \) for expiration
        if int(Et_star) < current_time:
            self.logger("[Server] Validation failed: Et* has expired.")
            return None

        # Step 7: Compute response {T_i, T2}
        T2 = int(time.time())
        qi = os.urandom(16)  # Generate random \( q_i \)
        Qi = hashlib.sha256(f"{C_k.hex()}{qi.hex()}".encode()).digest()
        si = bytes(a ^ b for a, b in zip(qi, C_k))  # XOR operation
        wi = hashlib.sha256(f"{Pid_star}{extracted_e_i.hex()}".encode()).digest()

        # Store \( Q_i \) in the database
        self.database[identifier]["Qi"] = Qi
        self.logger(f"[Server] Stored Qi: {Qi.hex()} in database for identifier {identifier}")

        # Step 8: Encrypt response {T_i}
        response_iv = os.urandom(16)
        Ti_data = f"{si.hex()}{wi.hex()}{T2}".encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded_Ti = padder.update(Ti_data) + padder.finalize()

        cipher = Cipher(algorithms.AES(A_prime_i[:16]), modes.CBC(response_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        Ti = encryptor.update(padded_Ti) + encryptor.finalize()

        self.logger(f"[Server] Computed Ti: {Ti.hex()}, T2: {T2}")

        return Ti, T2, response_iv

