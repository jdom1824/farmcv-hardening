import base64
import hashlib
import json
import os
import stat

from cryptography.fernet import Fernet


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return "0x" + hashlib.sha256(value).hexdigest()


def encrypt_json(value: object, key: bytes) -> str:
    return Fernet(key).encrypt(canonical_json(value)).decode("ascii")


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")


class EncryptionUnavailable(RuntimeError):
    pass


def load_server_key() -> bytes:
    from .config import settings
    try:
        fd = os.open(settings.cv_encryption_key_file, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise ValueError("unsafe key file")
            key = stream.read(128).strip()
        Fernet(key)
        return key
    except (OSError, ValueError, TypeError) as exc:
        raise EncryptionUnavailable("server encryption is unavailable") from exc


def prepare_encrypted_payload(payload):
    from .models import FarmCVRequest
    key = load_server_key()
    # Hash the same normalized canonical bytes that are encrypted.
    cv = payload.cv.model_dump(mode="json")
    cv["farm_id"] = payload.farm_id.lower()
    polygon = payload.polygon.model_dump(mode="json")
    return FarmCVRequest(farm_id=payload.farm_id,
        encrypted_cv=encrypt_json(cv, key), encrypted_polygon=encrypt_json(polygon, key),
        cv_hash=sha256_hex(canonical_json(cv)), polygon_hash=sha256_hex(canonical_json(polygon)))
