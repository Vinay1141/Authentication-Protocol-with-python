from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

def hash_data(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def generate_ec_key_pair():
    from cryptography.hazmat.primitives.asymmetric import ec
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()

def derive_aes_key(shared_key):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"session key")
    return hkdf.derive(shared_key)

def encrypt_message(key, message):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def decrypt_message(key, iv, ciphertext, tag):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
