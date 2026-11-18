from ipaddress import ip_network
from pathlib import Path
from urllib.parse import urlsplit

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr, field_validator


API_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    app_name: str = "FarmCV API"
    environment: str = "hardhat"
    chain_id: int = 31337
    rpc_url: str = "http://127.0.0.1:8545"
    contract_address: str = ""
    public_base_url: str = ""
    admin_username: str = "admin"
    admin_password_hash: str = ""
    jwt_secret: str
    trusted_proxy_cidrs: str = ""
    jwt_expire_minutes: int = 15
    blockchain_private_key: SecretStr = SecretStr("")
    rpc_timeout_seconds: float = Field(default=5, gt=0, le=30)
    confirmations_required: int = Field(default=1, ge=1)
    contract_deployment_block: int = Field(default=0, ge=0)
    cv_encryption_key_file: Path = API_DIR / ".secrets" / "cv-fernet.key"
    transaction_db_file: Path = API_DIR / "storage" / "transactions" / "operations.sqlite3"
    transaction_poll_seconds: float = Field(default=2, ge=0.1, le=60)

    model_config = SettingsConfigDict(env_file=API_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def validate_trusted_proxy_cidrs(cls, value: str) -> str:
        entries = [item.strip() for item in value.split(",") if item.strip()]
        for entry in entries:
            network = ip_network(entry, strict=False)
            if network.prefixlen == 0:
                raise ValueError("trusted proxy CIDRs cannot be a catch-all route")
        return ",".join(entries)

    @field_validator("public_base_url")
    @classmethod
    def validate_public_base_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return ""
        parsed = urlsplit(value)
        host = parsed.hostname
        local_http = parsed.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}
        if (
            not host
            or (parsed.scheme != "https" and not local_http)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("public_base_url must be an HTTPS origin (or loopback HTTP for local testing)")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("public_base_url has an invalid port") from exc
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


settings = Settings()
