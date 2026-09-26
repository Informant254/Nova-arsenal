"""Central password hashing policy for Nova-Arsenal authentication."""

from __future__ import annotations

from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

# Argon2 is the current policy. Bcrypt remains only to verify and transparently
# upgrade hashes created by older Nova releases.
password_hash = PasswordHash((Argon2Hasher(), BcryptHasher()))
DUMMY_PASSWORD_HASH = password_hash.hash("nova-auth-dummy-password")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against Argon2 or legacy bcrypt."""
    try:
        return password_hash.verify(plain_password, hashed_password)
    except Exception:
        return False


def verify_and_upgrade_password(
    plain_password: str,
    hashed_password: str,
) -> tuple[bool, str | None]:
    """Verify and return a new Argon2 hash when the stored hash is legacy."""
    try:
        return password_hash.verify_and_update(plain_password, hashed_password)
    except Exception:
        return False, None


def get_password_hash(password: str) -> str:
    """Hash a password using the current Argon2 policy."""
    return password_hash.hash(password)
