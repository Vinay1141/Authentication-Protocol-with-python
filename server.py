import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import time
class Server:
    def __init__(self, logger, server_id, master_key):
        self.logger = logger
        self.server_id = server_id
        self.master_key = master_key.encode('utf-8')
        self.database = {}
        self.logger("[Server] Initialized with server ID and master key.")
        self.ecc_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecc_public_key = self.ecc_private_key.public_key()

    def register_device(self, I_i):
        self.logger(" ")
        self.logger(f"[server] server_id: {self.server_id.encode('utf-8')}, length: {len(self.server_id.encode('utf-8'))}")
        r_cs = os.urandom(16)
        session_key = hashlib.sha256(f"{I_i}{r_cs.hex()}".encode('utf-8')).digest()

        Pid_i = hashlib.sha256(f"{I_i}{self.server_id}{r_cs.hex()}".encode('utf-8')).digest()[:16]
        Pid_i = bytes(a ^ b for a, b in zip(Pid_i, self.server_id.encode('utf-8')))

        Et = int(time.time()) + 3600

        C_k = hashlib.sha256(f"{self.master_key.hex()}{Pid_i.hex()}{Et}{r_cs.hex()}".encode('utf-8')).digest()[:16]
        C_k = bytes(a ^ b for a, b in zip(C_k, self.server_id.encode('utf-8')))
        self.logger(f"[server] C_k: {C_k.hex()}")

        C_prime_k = bytes(a ^ b for a, b in zip(C_k, bytes.fromhex(I_i)))

        A_i_data = f"{Pid_i}{Et}".encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded_A_i_data = padder.update(A_i_data) + padder.finalize()

        self.logger(f"[server] X_cs: {self.master_key}")
        cipher = Cipher(algorithms.AES(self.master_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        A_i = encryptor.update(padded_A_i_data) + encryptor.finalize()
        self.logger(f"[Server] Computed A_i: {A_i.hex()}, length: {len(A_i)}")

        A_prime_i = bytes(a ^ b for a, b in zip(A_i, bytes.fromhex(I_i)))
        self.logger(f"[Server] Computed A'_i: {A_prime_i.hex()}")

        R_i = hashlib.sha256(f"{self.master_key.hex()}{Pid_i.hex()}".encode('utf-8')).digest()[:16]
        R_i = bytes(a ^ b for a, b in zip(r_cs, R_i))
        R_prime_i = bytes(a ^ b for a, b in zip(R_i, bytes.fromhex(I_i)))

        self.database[Pid_i.hex()] = {"R_i": R_i, "Et": Et, "Session_Key": session_key, "Pid_i": Pid_i}
        self.logger(f"[Server] Database: {self.database}")
        self.logger(f"[Server] Registered device: Pid_i={Pid_i.hex()}, R_i={R_i.hex()}")

        self.logger(" ")
        return I_i, Pid_i, A_prime_i, R_prime_i, C_prime_k

    def process_auth_request(self, device_public_key, N_i, T1, E_i, iv):
        self.logger(" ")
        T2 = int(time.time())
        if abs(T2 - T1) > 60:
            self.logger("[Device] Validation failed: T2 is not fresh.")
            return False
        shared_secret = self.ecc_private_key.exchange(ec.ECDH(), device_public_key)
        self.logger(f"[Device] ECC shared secret: {shared_secret.hex()}")

        decryption_key = hashlib.sha256(shared_secret).digest()[:16]
        self.logger(f"[Server] Derived decryption key: {decryption_key.hex()}")

        cipher = Cipher(algorithms.AES(decryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        padded_plaintext = decryptor.update(N_i) + decryptor.finalize()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        Pid_i = plaintext[:16]
        R_i = plaintext[16:]
        self.logger(f"[Server] Decrypted Pid_i: {Pid_i.hex()}, R_i: {R_i.hex()}")


        self.logger(f"[Server] Decrypted Pid_i and R_i are verified.")

        if Pid_i.hex() not in self.database:
            self.logger("[Server] Authentication failed: Device not registered.")
            return None

        stored_data = self.database[Pid_i.hex()]
        # R_i = stored_data['R_i']

        rcs_computed = hashlib.sha256(f"{self.master_key.hex()}{Pid_i.hex()}".encode('utf-8')).digest()[:16]
        rcs_computed = bytes(a ^ b for a, b in zip(R_i, rcs_computed))
        E_t = stored_data['Et']
        self.logger(f"[server] C_k computation: {self.master_key.hex()}, {Pid_i.hex()}, {E_t}, {rcs_computed.hex()}")
        R_i = stored_data["R_i"]
        C_k = hashlib.sha256(f"{self.master_key.hex()}{Pid_i.hex()}{stored_data['Et']}{rcs_computed.hex()}".encode('utf-8')).digest()[:16]
        C_k = bytes(a ^ b for a, b in zip(C_k, self.server_id.encode('utf-8')))
        self.logger(f"[Server] C_k: {C_k.hex()}, length: {len(C_k)}")
        try:
            cipher = Cipher(algorithms.AES(C_k), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(E_i) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
            self.logger(f"[Server] Decrypted E_i: {decrypted_data.hex()}")
            decrypted_e_prime_i = decrypted_data[:16]
            decrypted_T_prime_1 = int.from_bytes(decrypted_data[16:24], "big")
            decrypted_A_prime_i = decrypted_data[24:]
            self.logger(f"[Server] Extracted e_i: {decrypted_e_prime_i.hex()}, T*_1: {decrypted_T_prime_1}, A'_i: {decrypted_A_prime_i.hex()}")

            self.logger(f"[server] X_cs: {self.master_key}")
            cipher = Cipher(algorithms.AES(self.master_key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(decrypted_A_prime_i) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
            self.logger(f"[Server] Decrypted A'_i: {decrypted_data.hex()}")
            Pid_prime_i = decrypted_data[:16]
            E_prime_t = decrypted_data[16:]
            
            if not Pid_prime_i or not E_prime_t:
                self.logger("[Server] Authentication failed: Pid_i and E_t are not verified.")
                return None

            qi = os.urandom(16)
            Qi = hashlib.sha256(f"{decrypted_A_prime_i.hex()}{C_k.hex()}".encode()).digest()
            si = bytes(a ^ b for a, b in zip(qi, C_k))
            wi = hashlib.sha256(f"{Pid_i.hex()}{decrypted_e_prime_i.hex()}".encode()).digest()
            self.logger(f"[Server] wi: {wi.hex()}")
            self.logger(f"[Server] si : {si.hex()}, qi : {qi.hex()}")

            self.database[Pid_i.hex()].__setitem__("si", si)
            self.database[Pid_i.hex()].__setitem__("C_k", C_k)
            self.database[Pid_i.hex()].__setitem__("Q_i", Qi)
            self.database[Pid_i.hex()].__setitem__("qi", qi)
            self.database[Pid_i.hex()].__setitem__("e_prime_i", decrypted_e_prime_i)

            response_iv = os.urandom(16)
            Ti_data = f"{si.hex()}{wi.hex()}{T2}".encode('utf-8')
            padder = padding.PKCS7(128).padder()
            padded_Ti = padder.update(Ti_data) + padder.finalize()

            self.logger(f"[Server] A*_i: {decrypted_A_prime_i.hex()}, iv: {response_iv.hex()}")

            cipher = Cipher(algorithms.AES(decrypted_A_prime_i[:16]), modes.CBC(response_iv), backend=default_backend())
            encryptor = cipher.encryptor()
            Ti = encryptor.update(padded_Ti) + encryptor.finalize()

            self.logger(f"[Server] Computed Ti: {Ti.hex()}, T2: {T2}")

            self.logger(" ")
            return Ti, T2, response_iv

        except Exception as e:
            self.logger(f"[Server] Decryption failed: {e}")
            self.logger(" ")
            return None


    def final_check(self, MN_i, Pid_i, T3):
        self.logger(" ")
        T4 = int(time.time())   
        if abs(T4 - T3) > 60:
            self.logger("[Device] Validation failed: T2 is not fresh.")
            return False
        stored_data = self.database[Pid_i.hex()]
        R_i = stored_data["R_i"]
        C_k = stored_data["C_k"]
        Q_i = stored_data["Q_i"]
        qi = stored_data["qi"]
        si = stored_data["si"]
        e_prime_i = stored_data["e_prime_i"]
        sk_cs = hashlib.sha256(f"{e_prime_i.hex()}{C_k.hex()}{Q_i.hex()}{R_i.hex()}{si.hex()}".encode()).digest()

        self.logger(f"[server] sk_cs: {sk_cs.hex()}, qi: {qi.hex()}, si: {si.hex()}, Q_i: {Q_i.hex()}")
        MN_dash_i = hashlib.sha256(f"{sk_cs.hex()}{qi.hex()}{si.hex()}{Q_i.hex()}".encode()).digest()

        self.logger(f"[server] MN'_i: {MN_dash_i.hex()}, MN_i: {MN_i.hex()}")
        self.logger(" ")

        if MN_dash_i == MN_i: return True