"""Portal integration check for an isolated, local Hardhat 31337 chain.

Run only when the coordinator has started the disposable Hardhat node and
deployed FarmCVRegistry, passing FARMCV_TEST_CONTRACT_ADDRESS and
FARMCV_TEST_PRIVATE_KEY from that synthetic harness. This script has a strict
loopback RPC guard and never falls back to another endpoint.

Example (from api/, with the two synthetic harness variables set):
    .venv/bin/python tests/validate_hardhat_portal.py

The sanitized result is written to test-results/. The ASGI lifespan is not
started, so no indexer/background worker is launched by this check.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "test-results"
RPC_REQUIRED = "http://127.0.0.1:18545"
RUN_ID = secrets.token_hex(8)
FARM_ID = "0x" + secrets.token_hex(32)
checks: list[dict[str, object]] = []
started_at = time.perf_counter()


class CheckFailure(AssertionError):
    """An expected integration check failed; carries no response body."""


def record(name: str, passed: bool, **safe_fields: object) -> None:
    checks.append({"name": name, "passed": bool(passed), **safe_fields})
    print(f"{name}: {'PASS' if passed else 'FAIL'}", flush=True)
    if not passed:
        raise CheckFailure(name)


def require_local_rpc(url: str) -> None:
    parts = urlsplit(url)
    valid = (
        url == RPC_REQUIRED
        and parts.scheme == "http"
        and parts.hostname == "127.0.0.1"
        and parts.port == 18545
        and parts.username is None
        and parts.password is None
        and not parts.query
        and not parts.fragment
    )
    if not valid:
        raise CheckFailure("rpc_endpoint_must_be_exact_loopback_hardhat")


def configure_synthetic_process() -> tuple[str, str, str]:
    """Validate harness inputs, then install ephemeral API credentials."""
    rpc_url = os.environ.get("RPC_URL", "")
    require_local_rpc(rpc_url)

    contract_address = os.environ.get("FARMCV_TEST_CONTRACT_ADDRESS", "")
    private_key = os.environ.get("FARMCV_TEST_PRIVATE_KEY", "")
    if not Web3.is_address(contract_address) or not private_key:
        raise CheckFailure("synthetic_hardhat_contract_and_signer_required")

    password = secrets.token_urlsafe(32)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    password_hash = (
        base64.urlsafe_b64encode(salt).decode()
        + "$"
        + base64.urlsafe_b64encode(digest).decode()
    )

    # Override every setting used by this check, even if a developer .env is
    # present. The only signing material is an explicit synthetic harness key.
    os.environ.update(
        {
            "ENVIRONMENT": "hardhat",
            "CHAIN_ID": "31337",
            "RPC_URL": RPC_REQUIRED,
            "CONTRACT_ADDRESS": Web3.to_checksum_address(contract_address),
            "BLOCKCHAIN_PRIVATE_KEY": private_key,
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD_HASH": password_hash,
            "JWT_SECRET": secrets.token_urlsafe(48),
            "CONFIRMATIONS_REQUIRED": "1",
            "TRANSACTION_POLL_SECONDS": "0.2",
            "TRANSACTION_DB_FILE": str(
                RESULTS_DIR / f"portal-outbox-{RUN_ID}.sqlite3"
            ),
            "TRUSTED_PROXY_CIDRS": "",
        }
    )
    return password, Web3.to_checksum_address(contract_address), private_key


def hardhat_guard(contract_address: str, private_key: str) -> dict[str, object]:
    """Read-only chain/client/contract checks before importing the API."""
    provider = Web3(Web3.HTTPProvider(RPC_REQUIRED, request_kwargs={"timeout": 3}))
    if not provider.is_connected():
        raise CheckFailure("hardhat_loopback_unreachable")
    chain_id = provider.eth.chain_id
    client = provider.client_version
    record("hardhat_chain_guard", chain_id == 31337, chain_id=chain_id)
    record("hardhat_client_guard", "hardhat" in client.lower(), client=client)

    artifact_path = ROOT / "abi" / "FarmCVRegistry.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    contract = provider.eth.contract(
        address=Web3.to_checksum_address(contract_address), abi=artifact["abi"]
    )
    code = provider.eth.get_code(contract.address)
    owner = contract.functions.owner().call()
    signer = Web3().eth.account.from_key(private_key).address
    record("contract_code_present", len(code) > 0, code_bytes=len(code))
    record(
        "synthetic_signer_is_contract_owner",
        owner.lower() == signer.lower(),
    )
    # Some web3.py HTTPProvider versions expose disconnect(); newer versions
    # close their request session when the short-lived process exits.
    disconnect = getattr(provider.provider, "disconnect", None)
    if callable(disconnect):
        disconnect()
    return {"chain_id": chain_id, "client": client, "contract": contract.address}


async def run_portal(password: str, metadata: dict[str, object]) -> None:
    sys.path.insert(0, str(ROOT))
    from app import admin_portal  # noqa: PLC0415
    from app.config import settings  # noqa: PLC0415

    record(
        "portal_settings_guard",
        settings.chain_id == 31337 and settings.rpc_url == RPC_REQUIRED,
        chain_id=settings.chain_id,
        rpc_loopback=settings.rpc_url == RPC_REQUIRED,
    )
    transport = httpx.ASGITransport(app=admin_portal.app)
    timeout = httpx.Timeout(15.0)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://portal.test", timeout=timeout
    ) as client:
        async def request(name: str, method: str, path: str, expected: set[int], **kwargs):
            before = time.perf_counter()
            response = await client.request(method, path, **kwargs)
            elapsed_ms = round((time.perf_counter() - before) * 1000, 2)
            record(
                name,
                response.status_code in expected,
                http_status=response.status_code,
                latency_ms=elapsed_ms,
            )
            return response

        home = await request("public_home_without_login", "GET", "/", {200})
        del home  # Do not persist or print page contents.
        await request("admin_check_requires_login", "GET", "/admin/check", {401})
        await request(
            "write_requires_login",
            "POST",
            "/farm-cv",
            {401},
            json={},
        )

        exists_path = f"/farm-cv/{FARM_ID}/exists"
        preexisting = await request(
            "public_farm_lookup_without_login", "GET", exists_path, {200}
        )
        record(
            "synthetic_farm_id_is_unused",
            preexisting.json().get("exists") is False,
        )

        login = await request(
            "synthetic_admin_login",
            "POST",
            "/auth/login",
            {200},
            json={"username": "admin", "password": password},
        )
        csrf = login.json().get("csrf")
        record("login_returns_csrf_token", isinstance(csrf, str) and len(csrf) >= 16)
        await request("admin_check_after_login", "GET", "/admin/check", {200})

        auth_headers = {"X-CSRF-Token": csrf}
        registration = {
            "farm_id": FARM_ID,
            "encrypted_cv": "synthetic-ciphertext-cv-" + RUN_ID,
            "encrypted_polygon": "synthetic-ciphertext-polygon-" + RUN_ID,
            "cv_hash": "0x" + secrets.token_hex(32),
            "polygon_hash": "0x" + secrets.token_hex(32),
        }
        register_key = "portal-register-" + RUN_ID
        idem_headers = {**auth_headers, "Idempotency-Key": register_key}
        first = await request(
            "admin_register_synthetic_farm",
            "POST",
            "/farm-cv",
            {200, 202},
            headers=idem_headers,
            json=registration,
        )
        first_data = first.json()
        operation_id = first_data.get("operationId")
        tx_hash = first_data.get("txHash")
        record(
            "registration_returns_operation_and_tx",
            isinstance(operation_id, str)
            and isinstance(tx_hash, str)
            and tx_hash.startswith("0x")
            and len(tx_hash) == 66,
        )

        replay = await request(
            "registration_idempotent_replay",
            "POST",
            "/farm-cv",
            {200, 202},
            headers=idem_headers,
            json=registration,
        )
        replay_data = replay.json()
        record(
            "replay_keeps_same_operation_and_hash",
            replay_data.get("operationId") == operation_id
            and replay_data.get("txHash") == tx_hash,
        )
        changed = {**registration, "encrypted_cv": "different-synthetic-cv-" + RUN_ID}
        conflict = await request(
            "idempotency_key_rejects_changed_payload",
            "POST",
            "/farm-cv",
            {409},
            headers=idem_headers,
            json=changed,
        )
        del conflict

        async def poll_confirmed(name: str, tx: str, operation: str) -> dict[str, object]:
            deadline = time.monotonic() + 45
            last_status = "unavailable"
            while time.monotonic() < deadline:
                tx_response = await client.get("/transactions/" + tx)
                op_response = await client.get("/operations/" + operation)
                if tx_response.status_code == 200:
                    tx_data = tx_response.json()
                    last_status = str(tx_data.get("status", "unknown"))
                    if last_status == "confirmed":
                        record(
                            name,
                            True,
                            http_status=tx_response.status_code,
                            final_status=last_status,
                        )
                        return tx_data
                    if last_status in {"failed", "rejected", "replaced"}:
                        break
                if op_response.status_code not in {200, 202}:
                    last_status = f"operation_http_{op_response.status_code}"
                    break
                await asyncio.sleep(0.2)
            record(name, False, final_status=last_status)
            raise CheckFailure(name)

        receipt = await poll_confirmed("registration_receipt_confirmed", tx_hash, operation_id)
        operation_response = await request(
            "public_operation_lookup", "GET", "/operations/" + operation_id, {200}
        )
        operation_data = operation_response.json()
        record(
            "operation_state_confirmed",
            operation_data.get("status") == "confirmed",
            final_status=operation_data.get("status"),
        )
        farm = await request(
            "public_farm_read_after_confirmation",
            "GET",
            f"/farm-cv/{FARM_ID}",
            {200},
        )
        record(
            "registered_farm_is_active",
            farm.json().get("status") in (0, "Active", "active"),
            status=farm.json().get("status"),
        )

        # Exercise the cookie-authenticated, CSRF-protected administrator write
        # and verify the actual on-chain state/event through public reads.
        status_key = "portal-status-" + RUN_ID
        status_headers = {**auth_headers, "Idempotency-Key": status_key}
        suspended = await request(
            "admin_status_transition_to_suspended",
            "PATCH",
            f"/farm-cv/{FARM_ID}/status",
            {200, 202},
            headers=status_headers,
            json={"status": "Suspended"},
        )
        suspended_data = suspended.json()
        status_operation = suspended_data.get("operationId")
        status_tx = suspended_data.get("txHash")
        record(
            "status_write_returns_operation_and_tx",
            isinstance(status_operation, str)
            and isinstance(status_tx, str)
            and len(status_tx) == 66,
        )
        status_receipt = await poll_confirmed(
            "status_receipt_confirmed", status_tx, status_operation
        )
        suspended_farm = await request(
            "public_read_suspended_status",
            "GET",
            f"/farm-cv/{FARM_ID}",
            {200},
        )
        record(
            "suspended_state_persisted",
            suspended_farm.json().get("status") in (1, "Suspended", "suspended"),
            status=suspended_farm.json().get("status"),
        )

        status_replay = await request(
            "status_idempotent_replay",
            "PATCH",
            f"/farm-cv/{FARM_ID}/status",
            {200, 202},
            headers=status_headers,
            json={"status": "Suspended"},
        )
        record(
            "status_replay_keeps_same_operation_and_hash",
            status_replay.json().get("operationId") == status_operation
            and status_replay.json().get("txHash") == status_tx,
        )

        # Restore the synthetic record to Active, leaving test chain state tidy.
        active_headers = {**auth_headers, "Idempotency-Key": "portal-reactivate-" + RUN_ID}
        active = await request(
            "admin_status_transition_back_to_active",
            "PATCH",
            f"/farm-cv/{FARM_ID}/status",
            {200, 202},
            headers=active_headers,
            json={"status": "Active"},
        )
        active_data = active.json()
        active_receipt = await poll_confirmed(
            "reactivation_receipt_confirmed",
            active_data.get("txHash"),
            active_data.get("operationId"),
        )
        final_farm = await request(
            "public_read_active_after_reactivation",
            "GET",
            f"/farm-cv/{FARM_ID}",
            {200},
        )
        record(
            "active_state_restored",
            final_farm.json().get("status") in (0, "Active", "active"),
            status=final_farm.json().get("status"),
        )

        # Retain only non-sensitive evidence needed for the report.
        metadata["farm_id"] = FARM_ID
        metadata["transactions"] = [
            {"kind": "register", "hash": tx_hash, "block": receipt.get("blockNumber")},
            {"kind": "suspend", "hash": status_tx, "block": status_receipt.get("blockNumber")},
            {
                "kind": "reactivate",
                "hash": active_data.get("txHash"),
                "block": active_receipt.get("blockNumber"),
            },
        ]


def write_result(error_type: str | None, metadata: dict[str, object]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    passed = all(item.get("passed") for item in checks)
    payload = {
        "schema_version": 1,
        "test": "hardhat_portal_validation",
        "status": "passed" if error_type is None and passed else "failed",
        "error_type": error_type,
        "duration_seconds": round(time.perf_counter() - started_at, 3),
        "environment": "local-hardhat",
        "rpc_loopback": RPC_REQUIRED,
        "metadata": metadata,
        "checks": checks,
        "checks_passed": sum(bool(item.get("passed")) for item in checks),
        "checks_total": len(checks),
    }
    destination = RESULTS_DIR / f"hardhat-portal-validation-{RUN_ID}.json"
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


async def main() -> int:
    metadata: dict[str, object] = {}
    error_type: str | None = None
    password = contract_address = private_key = None
    try:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        password, contract_address, private_key = configure_synthetic_process()
        metadata.update(hardhat_guard(contract_address, private_key))
        await run_portal(password, metadata)
    except Exception as exc:  # sanitize error; never include exception text/values
        error_type = type(exc).__name__
        print(f"RUN_FAILED: {error_type}", flush=True)
    finally:
        # Drop references as soon as practical; no secret is written to disk.
        password = private_key = None
        result_path = write_result(error_type, metadata)
        print(f"Sanitized report: {result_path}", flush=True)
    return 0 if error_type is None and all(item.get("passed") for item in checks) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
