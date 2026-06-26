import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class KeySize(Enum):
    AES_128 = 16
    AES_192 = 24
    AES_256 = 32
    RSA_2048 = 2048
    RSA_4096 = 4096


@dataclass
class KeyPair:
    public_key_pem: str
    private_key_pem: str
    key_size: KeySize
    created_at: str
    fingerprint: str


class KeyManager:
    def __init__(self, storage_dir: str = "/workspace/keys") -> None:
        self.storage_dir = storage_dir
        self._active_key_id: Optional[str] = None
        self._keys: Dict[str, KeyPair] = {}
        self._symmetric_keys: Dict[str, bytes] = {}
        os.makedirs(storage_dir, exist_ok=True)

    def generate_rsa_keypair(self, key_size: KeySize = KeySize.RSA_4096,
                             key_id: Optional[str] = None) -> KeyPair:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size.value,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        fp = hashes.Hash(hashes.SHA256(), backend=default_backend())
        fp.update(public_pem.encode())
        fingerprint = fp.finalize().hex()[:16]

        from datetime import datetime, timezone
        kp = KeyPair(
            public_key_pem=public_pem,
            private_key_pem=private_pem,
            key_size=key_size,
            created_at=datetime.now(timezone.utc).isoformat(),
            fingerprint=fingerprint,
        )

        kid = key_id or f"rsa-{fingerprint[:8]}"
        self._keys[kid] = kp
        self._active_key_id = kid
        self._save_key_to_disk(kid, kp)
        logger.info(f"Generated RSA-{key_size.value} keypair: {kid}")
        return kp

    def generate_aes_key(self, key_size: KeySize = KeySize.AES_256,
                         key_id: Optional[str] = None) -> bytes:
        key = AESGCM.generate_key(bit_length=key_size.value * 8)
        kid = key_id or f"aes-{key.hex()[:8]}"
        self._symmetric_keys[kid] = key
        logger.info(f"Generated AES-{key_size.value * 8} key: {kid}")
        return key

    def load_keypair(self, key_id: str) -> Optional[KeyPair]:
        path = os.path.join(self.storage_dir, f"{key_id}.json")
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
                kp = KeyPair(**data)
                kp.key_size = KeySize(kp.key_size) if isinstance(kp.key_size, int) else kp.key_size
                self._keys[key_id] = kp
                return kp
        return None

    def _save_key_to_disk(self, key_id: str, kp: KeyPair) -> None:
        path = os.path.join(self.storage_dir, f"{key_id}.json")
        data = {
            "public_key_pem": kp.public_key_pem,
            "private_key_pem": kp.private_key_pem,
            "key_size": kp.key_size.value,
            "created_at": kp.created_at,
            "fingerprint": kp.fingerprint,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def get_active_key_id(self) -> Optional[str]:
        return self._active_key_id

    def get_public_key(self, key_id: Optional[str] = None) -> Optional[str]:
        kid = key_id or self._active_key_id
        if kid and kid in self._keys:
            return self._keys[kid].public_key_pem
        return None

    def list_keys(self) -> List[Dict[str, str]]:
        keys = []
        for kid, kp in self._keys.items():
            keys.append({
                "key_id": kid,
                "type": "rsa",
                "size": str(kp.key_size.value),
                "fingerprint": kp.fingerprint,
                "created_at": kp.created_at,
            })
        for kid in self._symmetric_keys:
            keys.append({
                "key_id": kid,
                "type": "aes",
                "size": str(len(self._symmetric_keys[kid]) * 8),
            })
        return keys

    def rotate_key(self) -> KeyPair:
        kp = self.generate_rsa_keypair()
        logger.info(f"Key rotated: {self._active_key_id}")
        return kp
