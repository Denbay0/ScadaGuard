import base64
import hashlib
import hmac
import json
import time
import uuid


def create_session(user_id: uuid.UUID, secret: str, lifetime_seconds: int = 28_800) -> str:
    payload = json.dumps(
        {"user_id": str(user_id), "expires_at": int(time.time()) + lifetime_seconds},
        separators=(",", ":"),
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = hmac.new(secret.encode(), encoded, hashlib.sha256).hexdigest().encode()
    return (encoded + b"." + signature).decode()


def verify_session(value: str, secret: str) -> uuid.UUID | None:
    encoded, separator, signature = value.partition(".")
    if not separator:
        return None
    expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if int(payload["expires_at"]) < time.time():
            return None
        return uuid.UUID(payload["user_id"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
