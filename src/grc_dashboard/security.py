from __future__ import annotations

import hashlib
import hmac
import re
import secrets

PASSWORD_ITERATIONS = 600_000
PASSWORD_MIN_LENGTH = 12
ROLES = ("administrator", "editor", "viewer")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.@-]{2,63}$")


def validate_username(username: str) -> str:
    normalized = username.strip().lower()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Usernames must be 3-64 characters and contain only letters, numbers, "
            "periods, underscores, @, or hyphens."
        )
    return normalized


def validate_password(password: str) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Passwords must contain at least {PASSWORD_MIN_LENGTH} characters.")
    if len(password) > 1024:
        raise ValueError("Passwords must contain no more than 1024 characters.")


def hash_password(password: str) -> str:
    validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iteration_count = int(iterations)
        if not 100_000 <= iteration_count <= 2_000_000:
            return False
        expected = bytes.fromhex(digest_hex)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, TypeError):
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iteration_count,
        dklen=len(expected),
    )
    return hmac.compare_digest(actual, expected)


def can_manage_users(role: str) -> bool:
    return role == "administrator"


def can_edit_controls(role: str) -> bool:
    return role in ("administrator", "editor")
