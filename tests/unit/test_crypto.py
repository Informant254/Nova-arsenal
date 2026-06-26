"""Tests for E2E Encryption module."""

import pytest
import json
from nova_arsenal.crypto import KeyManager, KeySize, Cipher, SecureEnvelope, EncryptionError


class TestKeyManager:
    def test_initialization(self):
        km = KeyManager("/tmp/test_keys")
        assert km.get_active_key_id() is None
        assert km.list_keys() == []

    def test_generate_rsa_keypair(self):
        km = KeyManager("/tmp/test_keys")
        kp = km.generate_rsa_keypair(KeySize.RSA_2048)
        assert kp.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert kp.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert kp.fingerprint
        assert len(kp.fingerprint) == 16

    def test_generate_rsa_4096(self):
        km = KeyManager("/tmp/test_keys")
        kp = km.generate_rsa_keypair(KeySize.RSA_4096)
        assert kp.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert len(kp.public_key_pem) > 500
        assert km.get_active_key_id() is not None

    def test_generate_aes_key(self):
        km = KeyManager("/tmp/test_keys")
        key = km.generate_aes_key(KeySize.AES_256)
        assert len(key) == 32  # 256 bits = 32 bytes

    def test_generate_aes_128(self):
        km = KeyManager("/tmp/test_keys")
        key = km.generate_aes_key(KeySize.AES_128)
        assert len(key) == 16

    def test_list_keys(self):
        km = KeyManager("/tmp/test_keys")
        km.generate_rsa_keypair(KeySize.RSA_2048)
        km.generate_aes_key(KeySize.AES_256)
        keys = km.list_keys()
        assert len(keys) >= 2
        type_rsa = [k for k in keys if k["type"] == "rsa"]
        type_aes = [k for k in keys if k["type"] == "aes"]
        assert len(type_rsa) >= 1
        assert len(type_aes) >= 1

    def test_get_public_key(self):
        km = KeyManager("/tmp/test_keys")
        kp = km.generate_rsa_keypair()
        pub = km.get_public_key()
        assert pub == kp.public_key_pem

    def test_get_public_key_none(self):
        km = KeyManager("/tmp/test_keys")
        assert km.get_public_key() is None

    def test_rotate_key(self):
        km = KeyManager("/tmp/test_keys")
        kp1 = km.generate_rsa_keypair()
        kid1 = km.get_active_key_id()
        kp2 = km.rotate_key()
        kid2 = km.get_active_key_id()
        assert kid2 != kid1
        assert kp2.fingerprint != kp1.fingerprint

    def test_keypair_has_created_at(self):
        km = KeyManager("/tmp/test_keys")
        kp = km.generate_rsa_keypair()
        assert kp.created_at


class TestCipher:
    def test_encrypt_decrypt_roundtrip(self):
        km = KeyManager("/tmp/test_keys")
        cipher = Cipher(km)
        kp = km.generate_rsa_keypair(KeySize.RSA_2048)

        plaintext = "Hello Nova Arsenal E2E!"
        envelope = cipher.encrypt(plaintext, kp.public_key_pem)
        assert envelope.ciphertext
        assert envelope.iv
        assert envelope.encrypted_key
        assert envelope.algorithm == "AES-256-GCM+RSA-4096"

        decrypted = cipher.decrypt(envelope, kp.private_key_pem)
        assert decrypted == plaintext

    def test_encrypt_message_dict(self):
        km = KeyManager("/tmp/test_keys")
        cipher = Cipher(km)
        kp = km.generate_rsa_keypair(KeySize.RSA_2048)

        msg = {"command": "nmap -sV target", "sender": "nova", "id": 42}
        envelope = cipher.encrypt_message(msg, kp.public_key_pem)
        assert envelope.sender_id == "nova"

        decrypted = cipher.decrypt_message(envelope, kp.private_key_pem)
        assert decrypted["command"] == "nmap -sV target"
        assert decrypted["id"] == 42

    def test_envelope_to_dict(self):
        km = KeyManager("/tmp/test_keys")
        cipher = Cipher(km)
        kp = km.generate_rsa_keypair(KeySize.RSA_2048)

        envelope = cipher.encrypt("test", kp.public_key_pem, sender_id="alice", recipient_id="bob")
        d = envelope.to_dict()
        assert d["sender_id"] == "alice"
        assert d["recipient_id"] == "bob"
        assert d["algorithm"] == "AES-256-GCM+RSA-4096"
        assert d["ciphertext"]

    def test_envelope_to_json(self):
        km = KeyManager("/tmp/test_keys")
        cipher = Cipher(km)
        kp = km.generate_rsa_keypair(KeySize.RSA_2048)

        envelope = cipher.encrypt("json test", kp.public_key_pem)
        json_str = envelope.to_json()
        parsed = json.loads(json_str)
        assert parsed["algorithm"] == "AES-256-GCM+RSA-4096"

    def test_encrypt_with_aad(self):
        km = KeyManager("/tmp/test_keys")
        cipher = Cipher(km)
        kp = km.generate_rsa_keypair(KeySize.RSA_2048)

        aad = b"custom-aad-context"
        plaintext = "authenticated encryption test"
        envelope = cipher.encrypt(plaintext, kp.public_key_pem, aad=aad)
        decrypted = cipher.decrypt(envelope, kp.private_key_pem, aad=aad)
        assert decrypted == plaintext

    def test_decrypt_wrong_key_fails(self):
        km1 = KeyManager("/tmp/test_keys")
        km2 = KeyManager("/tmp/test_keys")
        cipher = Cipher(km1)
        kp1 = km1.generate_rsa_keypair(KeySize.RSA_2048)
        kp2 = km2.generate_rsa_keypair(KeySize.RSA_2048)

        envelope = cipher.encrypt("secret", kp1.public_key_pem)
        with pytest.raises(Exception):
            cipher.decrypt(envelope, kp2.private_key_pem)

    def test_wrong_aad_fails(self):
        km = KeyManager("/tmp/test_keys")
        cipher = Cipher(km)
        kp = km.generate_rsa_keypair(KeySize.RSA_2048)

        envelope = cipher.encrypt("secret", kp.public_key_pem, aad=b"correct-aad")
        with pytest.raises(Exception):
            cipher.decrypt(envelope, kp.private_key_pem, aad=b"wrong-aad")

    def test_long_message(self):
        km = KeyManager("/tmp/test_keys")
        cipher = Cipher(km)
        kp = km.generate_rsa_keypair(KeySize.RSA_2048)

        long_msg = "A" * 10000
        envelope = cipher.encrypt(long_msg, kp.public_key_pem)
        decrypted = cipher.decrypt(envelope, kp.private_key_pem)
        assert decrypted == long_msg
