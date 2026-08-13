import hashlib
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

password_hasher = PasswordHasher()


def create_agent_token() -> tuple[str, str, str]:
    token = "sg_" + secrets.token_urlsafe(32)
    return token, hash_agent_token(token), token[:12]


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


@dataclass(frozen=True)
class BearerToken:
    value: str


def parse_bearer_header(header: str | None) -> BearerToken | None:
    if not header:
        return None
    scheme, separator, value = header.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not value:
        return None
    return BearerToken(value=value)
