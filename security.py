import hashlib
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

class SecurityManager:
    def __init__(self):
        # Get encryption key from environment or generate one
        self.encryption_key = self._get_or_create_encryption_key()
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get encryption key from env or generate and save a new one"""
        key = os.getenv('ENCRYPTION_KEY')
        
        if not key:
            # Generate a new key
            key = base64.urlsafe_b64encode(os.urandom(32)).decode()
            print(f"\n  NEW ENCRYPTION KEY GENERATED. Add this to your .env file:")
            print(f"ENCRYPTION_KEY={key}")
            print(f"ENCRYPTION_KEY_HASH={hashlib.sha256(key.encode()).hexdigest()}\n")
        
        # Ensure key is proper length for AES-256
        key_bytes = key.encode()
        if len(key_bytes) not in [16, 24, 32]:
            # Pad or truncate to 32 bytes for AES-256
            key_bytes = key_bytes.ljust(32, b'0')[:32]
        
        return key_bytes
    
    def encrypt(self, data: str) -> str:
        """Encrypt data using AES"""
        try:
            # Generate a random IV
            iv = os.urandom(16)
            
            # Pad the data
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data.encode()) + padder.finalize()
            
            # Encrypt
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), 
                          backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data
            combined = iv + encrypted_data
            return base64.b64encode(combined).decode()
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data using AES"""
        try:
            # Decode from base64
            combined = base64.b64decode(encrypted_data.encode())
            
            # Extract IV and encrypted data
            iv = combined[:16]
            encrypted_data = combined[16:]
            
            # Decrypt
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), 
                          backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data.decode()
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

# Create security manager instance
security_manager = SecurityManager()