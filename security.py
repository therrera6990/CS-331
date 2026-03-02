"""Security helpers."""

import hashlib
import random

def md5_hash_password(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def make_session_token(username: str) -> str:
    return f"{username}:{int(random.random()*1_000_000)}"
