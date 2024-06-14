from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

SALT_LENGTH = 8
IV_LENGTH = 16

def derive_encryption_algorithm(payload):
    if len(payload) == 0:
        raise ValueError("Unable to derive encryption algorithm")

    if payload[0] != b'*':
        return 'aes-cfb', payload  # backwards compatibility

    payload = payload[1:]
    alg_delim = payload.index(b'*')
    alg_b64 = payload[:alg_delim]
    payload = payload[alg_delim+1:]

    alg = base64.standard_b64decode(alg_b64)
    return alg.decode(), payload

def decrypt_gcm(key, payload):
    nonce = payload[:SALT_LENGTH]
    ciphertext = payload[SALT_LENGTH:]
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(b'')
    return decryptor.update(ciphertext) + decryptor.finalize()

def decrypt_cfb(key, payload):
    iv = payload[:IV_LENGTH]
    ciphertext = payload[IV_LENGTH:]
    decryptor = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def decrypt(payload, secret):
    alg, payload = derive_encryption_algorithm(payload)

    if len(payload) < SALT_LENGTH:
        raise ValueError("Unable to compute salt")
    salt = payload[:SALT_LENGTH]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    key = kdf.derive(secret.encode())

    if alg == 'aes-gcm':
        return decrypt_gcm(key, payload[SALT_LENGTH:])
    else:
        return decrypt_cfb(key, payload[SALT_LENGTH:])

def encrypt(payload, secret):
    salt = os.urandom(SALT_LENGTH)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    key = kdf.derive(secret.encode())

    iv = os.urandom(IV_LENGTH)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(payload) + encryptor.finalize()

    return salt + iv + ciphertext

# decode base64str
grafanaIni_secretKey = "SW2YcwTIb9zpOOhoPsMm"
dataSourcePassword = "R3pMVVh1UHLoUkTJOl+Z/sFymLqolUOVtxCtQL/y+Q=="
encrypted = base64.standard_b64decode(dataSourcePassword)
pwd_bytes = decrypt(encrypted, grafanaIni_secretKey)
print("[*] grafanaIni_secretKey= " + grafanaIni_secretKey)
print("[*] DataSourcePassword= " + dataSourcePassword)
print("[*] plainText= " + pwd_bytes.decode())

print("\n")
# encode str (dataSourcePassword)
plain_text = "jas502n"
encrypted_byte = encrypt(plain_text.encode(), grafanaIni_secretKey)
encrypted_str = base64.standard_b64encode(encrypted_byte).decode()
print("[*] grafanaIni_secretKey= " + grafanaIni_secretKey)
print("[*] PlainText= " + plain_text)
print("[*] EncodePassword= " + encrypted_str)
