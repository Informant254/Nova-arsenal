import base64
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from .key_manager import KeyManager, KeySize

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    pass


@dataclass
class SecureEnvelope:
    ciphertext: str
    iv: str
    encrypted_key: str
    key_fingerprint: str
    algorithm: str = "AES-256-GCM+RSA-4096"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sender_id: str = ""
    recipient_id: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "ciphertext": self.ciphertext,
            "iv": self.iv,
            "encrypted_key": self.encrypted_key,
            "key_fingerprint": self.key_fingerprint,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class Cipher:
    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager

    def encrypt(self, plaintext: str, recipient_public_key_pem: str,
                sender_id: str = "", recipient_id: str = "",
                aad: Optional[bytes] = None) -> SecureEnvelope:
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        iv = os.urandom(12)

        pt_bytes = plaintext.encode("utf-8")
        aad_bytes = aad or b"nova-arsenal-e2e-v1"
        ciphertext = aesgcm.encrypt(iv, pt_bytes, aad_bytes)

        public_key = serialization.load_pem_public_key(
            recipient_public_key_pem.encode(), backend=default_backend()
        )
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise EncryptionError("Recipient key is not an RSA public key")

        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        fp = hashes.Hash(hashes.SHA256(), backend=default_backend())
        fp.update(recipient_public_key_pem.encode())
        fingerprint = fp.finalize().hex()[:16]

        return SecureEnvelope(
            ciphertext=base64.b64encode(ciphertext).decode(),
            iv=base64.b64encode(iv).decode(),
            encrypted_key=base64.b64encode(encrypted_key).decode(),
            key_fingerprint=fingerprint,
            sender_id=sender_id,
            recipient_id=recipient_id,
        )

    def decrypt(self, envelope: SecureEnvelope,
                private_key_pem: str,
                aad: Optional[bytes] = None) -> str:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None, backend=default_backend()
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise EncryptionError("Provided key is not an RSA private key")

        encrypted_key = base64.b64decode(envelope.encrypted_key)
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        iv = base64.b64decode(envelope.iv)
        ciphertext = base64.b64decode(envelope.ciphertext)
        aad_bytes = aad or b"nova-arsenal-e2e-v1"

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, aad_bytes)
        return plaintext.decode("utf-8")

    def encrypt_message(self, message: Dict[str, Any],
                        recipient_public_key_pem: str,
                        sender_id: str = "nova") -> SecureEnvelope:
        return self.encrypt(
            json.dumps(message),
            recipient_public_key_pem,
            sender_id=sender_id,
        )

    def decrypt_message(self, envelope: SecureEnvelope,
                        private_key_pem: str) -> Dict[str, Any]:
        plaintext = self.decrypt(envelope, private_key_pem)
        return json.loads(plaintext)
