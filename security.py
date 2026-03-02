"""Security helpers."""

import base64
import hashlib
import hmac
import secrets
from typing import Tuple

# PBKDF2 parameters (can tune)
_PBKDF2_ITERS = 200_000
_SALT_BYTES = 16
_DKLEN = 32


def hash_password(password: str) -> str:
    """
    Returns a password hash string:
      pbkdf2_sha256$<iters>$<salt_b64>$<dk_b64>
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERS,
        dklen=_DKLEN,
    )
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ITERS,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(dk).decode("ascii").rstrip("="),
    )


def verify_password(password: str, stored: str) -> bool:
    """
    Verify password against:
      - new pbkdf2_sha256$... format
      - legacy md5 hex (compat only; should be migrated)
    """
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters_s, salt_b64, dk_b64 = stored.split("$", 3)
            iters = int(iters_s)
            salt = base64.urlsafe_b64decode(salt_b64 + "==")
            dk_expected = base64.urlsafe_b64decode(dk_b64 + "==")
        except Exception:
            return False

        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iters,
            dklen=len(dk_expected),
        )
        return hmac.compare_digest(dk, dk_expected)

    # Legacy MD5 compare (teaching / migration only)
    legacy = hashlib.md5(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy, stored)


def make_session_token(username: str, secret_key: str) -> str:
    """
    Signed session token: base64url(payload).base64url(sig)
    payload = username|nonce
    """
    nonce = secrets.token_urlsafe(16)
    payload = f"{username}|{nonce}".encode("utf-8")
    sig = hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).digest()

    return "{}.{}".format(
        base64.urlsafe_b64encode(payload).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(sig).decode("ascii").rstrip("="),
    )


def verify_session_token(token: str, secret_key: str) -> Tuple[bool, str]:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = base64.urlsafe_b64decode(payload_b64 + "==")
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception:
        return False, ""

    expected = hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return False, ""

    try:
        username, _nonce = payload.decode("utf-8").split("|", 1)
        return True, username
    except Exception:
        return False, ""