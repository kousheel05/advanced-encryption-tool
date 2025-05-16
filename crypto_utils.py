from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib


# === AES-128 (Fernet) ===
def generate_symmetric_key():
    return Fernet.generate_key()


def encrypt_symmetric(key, message):
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()


def decrypt_symmetric(key, token):
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()


# === AES-256 CBC ===
def generate_aes256_key_iv():
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    return base64.b64encode(key).decode(), base64.b64encode(iv).decode()


def encrypt_aes256(message, key_b64, iv_b64):
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(ciphertext).decode()


def decrypt_aes256(ciphertext_b64, key_b64, iv_b64):
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


# === RSA ===
def generate_asymmetric_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_asymmetric(public_key, message):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def decrypt_asymmetric(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()


def serialize_keys(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode(), public_pem.decode()


# === HASHING ===
def hash_sha256(message):
    return hashlib.sha256(message.encode()).hexdigest()


def hash_sha512(message):
    return hashlib.sha512(message.encode()).hexdigest()


# === Base64 ===
def base64_encode(message):
    return base64.b64encode(message.encode()).decode()


def base64_decode(encoded):
    return base64.b64decode(encoded).decode()
