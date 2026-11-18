"""Provision a persistent server encryption key once. Never prints/replaces it."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import settings
from app.crypto_service import load_server_key
from cryptography.fernet import Fernet

path = settings.cv_encryption_key_file
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    load_server_key()
    print("Existing encryption key validated; unchanged.")
else:
    with os.fdopen(fd, "wb") as stream:
        stream.write(Fernet.generate_key() + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    load_server_key()
    print("Persistent encryption key created (permissions 600). Back it up securely.")
