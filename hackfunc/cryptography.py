import os
import base64
import hashlib
import secrets
import string
import zlib
import binascii
from typing import Tuple, List, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding, ec, dsa, ed25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.twofactor import totp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.constant_time import bytes_eq

class AdvancedCryptography:
    def __init__(self):
        self.backend = default_backend()

    def generate_key(self, password: str, salt: bytes = None, iterations: int = 100000) -> bytes:
        if salt is None:
            salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt_aes_gcm(self, plaintext: str, key: bytes) -> Tuple[bytes, bytes, bytes]:
        nonce = os.urandom(12)
        aad = os.urandom(16)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)
        return ciphertext, nonce, aad

    def decrypt_aes_gcm(self, ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes) -> str:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext.decode()

    def encrypt_chacha20_poly1305(self, plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
        nonce = os.urandom(12)
        algorithm = ChaCha20Poly1305(key)
        ciphertext = algorithm.encrypt(nonce, plaintext.encode(), None)
        return ciphertext, nonce

    def decrypt_chacha20_poly1305(self, ciphertext: bytes, key: bytes, nonce: bytes) -> str:
        algorithm = ChaCha20Poly1305(key)
        plaintext = algorithm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    def generate_rsa_key_pair(self, key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def rsa_encrypt(self, plaintext: str, public_key: rsa.RSAPublicKey) -> bytes:
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def rsa_decrypt(self, ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> str:
        plaintext = private_key.decrypt(
            ciphertext,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def hash_password_argon2(self, password: str) -> str:
        salt = os.urandom(16)
        argon2_hasher = hashlib.argon2id
        hash_result = argon2_hasher(password.encode(), salt=salt, time_cost=4, memory_cost=65536, parallelism=8)
        return base64.b64encode(salt + hash_result).decode('utf-8')

    def verify_password_argon2(self, password: str, hashed_password: str) -> bool:
        decoded = base64.b64decode(hashed_password.encode('utf-8'))
        salt = decoded[:16]
        stored_hash = decoded[16:]
        argon2_hasher = hashlib.argon2id
        computed_hash = argon2_hasher(password.encode(), salt=salt, time_cost=4, memory_cost=65536, parallelism=8)
        return bytes_eq(computed_hash, stored_hash)

    def generate_totp_secret(self) -> bytes:
        return os.urandom(20)

    def generate_totp(self, secret: bytes, time_step: int = 30) -> str:
        totp_instance = totp.TOTP(secret, 6, hashes.SHA1(), time_step)
        return totp_instance.generate().decode()

    def verify_totp(self, secret: bytes, token: str, time_step: int = 30) -> bool:
        totp_instance = totp.TOTP(secret, 6, hashes.SHA1(), time_step)
        try:
            totp_instance.verify(token.encode())
            return True
        except InvalidSignature:
            return False

    def secure_random_bytes(self, n: int) -> bytes:
        return secrets.token_bytes(n)

    def secure_random_string(self, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
        return ''.join(secrets.choice(alphabet) for _ in range(n))

    def generate_dh_parameters(self, key_size: int = 2048) -> Tuple[int, int]:
        parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=self.backend)
        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g
        return p, g

    def generate_dh_private_key(self, p: int, g: int) -> int:
        return secrets.randbelow(p - 2) + 2

    def generate_dh_public_key(self, p: int, g: int, private_key: int) -> int:
        return pow(g, private_key, p)

    def generate_dh_shared_secret(self, p: int, public_key: int, private_key: int) -> int:
        return pow(public_key, private_key, p)

    def xor_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        return bytes([p ^ k for p, k in zip(plaintext, key * (len(plaintext) // len(key) + 1))])

    def xor_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return self.xor_encrypt(ciphertext, key)  # XOR encryption is symmetric

    def generate_hmac(self, key: bytes, message: bytes, algorithm: hashes.HashAlgorithm = hashes.SHA256()) -> bytes:
        h = hashes.Hash(algorithm, backend=self.backend)
        h.update(key + message + key)  # Simple HMAC construction
        return h.finalize()

    def verify_hmac(self, key: bytes, message: bytes, hmac: bytes, algorithm: hashes.HashAlgorithm = hashes.SHA256()) -> bool:
        computed_hmac = self.generate_hmac(key, message, algorithm)
        return secrets.compare_digest(computed_hmac, hmac)

    def generate_key_pair_ecdsa(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_ecdsa(self, private_key, message: bytes):
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_ecdsa(self, public_key, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    def encrypt_file(self, file_path: str, key: bytes) -> None:
        fernet = Fernet(base64.urlsafe_b64encode(key))
        with open(file_path, 'rb') as file:
            data = file.read()
        encrypted_data = fernet.encrypt(data)
        with open(file_path + '.encrypted', 'wb') as file:
            file.write(encrypted_data)

    def decrypt_file(self, file_path: str, key: bytes) -> None:
        fernet = Fernet(base64.urlsafe_b64encode(key))
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path[:-10], 'wb') as file:
            file.write(decrypted_data)

    def generate_key_pair_ecdh(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def perform_ecdh(self, private_key, peer_public_key):
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_key

    def derive_key_from_password(self, password: str, salt: bytes, length: int, iterations: int = 100000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt_aes_ctr(self, plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return ciphertext, nonce

    def decrypt_aes_ctr(self, ciphertext: bytes, key: bytes, nonce: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

    def generate_dsa_key_pair(self, key_size: int = 3072):
        private_key = dsa.generate_private_key(key_size=key_size, backend=self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_dsa(self, private_key, message: bytes):
        signature = private_key.sign(
            message,
            hashes.SHA256()
        )
        return signature

    def verify_dsa(self, public_key, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def generate_elgamal_key_pair(self, key_size: int = 3072):
        params = dh.generate_parameters(generator=2, key_size=key_size, backend=self.backend)
        private_key = params.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def elgamal_encrypt(self, public_key, plaintext: bytes):
        shared_key = self.perform_ecdh(self.generate_key_pair_ecdh()[0], public_key)
        key = self.derive_key_from_password(shared_key.hex(), b'elgamal', 32)
        return self.encrypt_aes_gcm(plaintext.decode(), key)

    def elgamal_decrypt(self, private_key, ciphertext: bytes, nonce: bytes, aad: bytes):
        shared_key = self.perform_ecdh(private_key, self.generate_key_pair_ecdh()[1])
        key = self.derive_key_from_password(shared_key.hex(), b'elgamal', 32)
        return self.decrypt_aes_gcm(ciphertext, key, nonce, aad)

    def generate_key_pair_eddsa(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_eddsa(self, private_key, message: bytes):
        return private_key.sign(message)

    def verify_eddsa(self, public_key, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def encrypt_aes_ecb(self, plaintext: str, key: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_aes_ecb(self, ciphertext: bytes, key: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_aes_cbc(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_aes_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_aes_cfb(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_aes_cfb(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

    def encrypt_aes_ofb(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_aes_ofb(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

    def encrypt_3des_ecb(self, plaintext: str, key: bytes) -> bytes:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_3des_ecb(self, ciphertext: bytes, key: bytes) -> str:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_3des_cbc(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_3des_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_blowfish_ecb(self, plaintext: str, key: bytes) -> bytes:
        cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_blowfish_ecb(self, ciphertext: bytes, key: bytes) -> str:
        cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_blowfish_cbc(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(8)
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_blowfish_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_camellia_ecb(self, plaintext: str, key: bytes) -> bytes:
        cipher = Cipher(algorithms.Camellia(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_camellia_ecb(self, ciphertext: bytes, key: bytes) -> str:
        cipher = Cipher(algorithms.Camellia(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_camellia_cbc(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(16)
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_camellia_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_cast5_ecb(self, plaintext: str, key: bytes) -> bytes:
        cipher = Cipher(algorithms.CAST5(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_cast5_ecb(self, ciphertext: bytes, key: bytes) -> str:
        cipher = Cipher(algorithms.CAST5(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_cast5_cbc(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(8)
        cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_cast5_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_idea_ecb(self, plaintext: str, key: bytes) -> bytes:
        cipher = Cipher(algorithms.IDEA(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_idea_ecb(self, ciphertext: bytes, key: bytes) -> str:
        cipher = Cipher(algorithms.IDEA(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_idea_cbc(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(8)
        cipher = Cipher(algorithms.IDEA(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_idea_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.IDEA(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_seed_ecb(self, plaintext: str, key: bytes) -> bytes:
        cipher = Cipher(algorithms.SEED(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_seed_ecb(self, ciphertext: bytes, key: bytes) -> str:
        cipher = Cipher(algorithms.SEED(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    def encrypt_seed_cbc(self, plaintext: str, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(16)
        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    def decrypt_seed_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=self.backend)
    def hash_password(self, password: str) -> str:
        salt = os.urandom(16)
        key = self.generate_key(password, salt)
        return base64.b64encode(salt + key).decode('utf-8')

    def verify_password(self, password: str, hashed_password: str) -> bool:
        decoded = base64.b64decode(hashed_password.encode('utf-8'))
        salt = decoded[:16]
        stored_key = decoded[16:]
        key = self.generate_key(password, salt)
        return key == stored_key

    def secure_random_bytes(self, n: int) -> bytes:
        return os.urandom(n)

    def secure_random_string(self, n: int) -> str:
        return base64.b64encode(self.secure_random_bytes(n)).decode('utf-8')
