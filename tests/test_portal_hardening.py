"""Synthetic regressions for public exposure, login throttling and RPC errors."""

import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import admin_portal, auth, main, public_cv
from app.web3_adapter import RPCUnavailable


FARM_ID = "0x" + "12" * 32
PHOTO_BYTES = b"synthetic-photo-payload"
PHOTO_HASH = hashlib.sha256(PHOTO_BYTES).hexdigest()


class FakeEth:
    def __init__(self):
        self.fail_rpc = False

    @property
    def chain_id(self):
        async def result():
            if self.fail_rpc:
                raise OSError("synthetic local RPC outage")
            return 84532

        return result()

    async def get_code(self, address):
        if self.fail_rpc:
            raise OSError("synthetic local RPC outage")
        return b"\x01"


class FakeAdapter:
    def __init__(self, record):
        self.record = record
        self.w3 = SimpleNamespace(eth=FakeEth())

    async def farm_exists(self, farm_id):
        return True

    async def get_farm(self, farm_id):
        return dict(self.record)

    async def verify_farm(self, farm_id, cv_hash, polygon_hash):
        return True

    async def _read(self, operation):
        try:
            return await operation()
        except (OSError, TimeoutError) as exc:
            raise RPCUnavailable("blockchain RPC unavailable") from exc


class PortalHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temp_path = Path(self.temporary.name)

        # Reset only process-local demo middleware state; no real session is used.
        admin_portal.requests_by_client.clear()
        admin_portal.login_attempts_by_client.clear()
        admin_portal.login_in_flight_by_client.clear()
        admin_portal.login_in_flight_total = 0
        admin_portal.sessions.clear()
        self.addCleanup(admin_portal.requests_by_client.clear)
        self.addCleanup(admin_portal.login_attempts_by_client.clear)
        self.addCleanup(admin_portal.login_in_flight_by_client.clear)
        self.addCleanup(lambda: setattr(admin_portal, "login_in_flight_total", 0))
        self.addCleanup(admin_portal.sessions.clear)

        self.key = Fernet.generate_key()
        cv = {
            "identification": {"farmName": "Finca sintética"},
            "location": {"municipality": "Rionegro", "department": "Santander"},
            "quality": {"publicProfileConsent": True, "publicPolygonConsent": False},
            "photos": [{"sha256": PHOTO_HASH, "caption": "Foto sintética"}],
        }
        encrypted_cv = Fernet(self.key).encrypt(json.dumps(cv).encode()).decode()
        encrypted_polygon = Fernet(self.key).encrypt(b"{}").decode()
        self.record = {
            "farmId": FARM_ID,
            "encryptedCV": encrypted_cv,
            "encryptedPolygon": encrypted_polygon,
            "cvHash": "0x" + hashlib.sha256(json.dumps(cv).encode()).hexdigest(),
            "polygonHash": "0x" + hashlib.sha256(b"{}").hexdigest(),
            "version": 1,
            "status": 0,
        }
        self.adapter = FakeAdapter(self.record)
        self.photo_file = self.temp_path / "synthetic.jpg"
        self.photo_file.write_bytes(PHOTO_BYTES)

        self.enterContext(patch.object(public_cv, "adapter", self.adapter))
        self.enterContext(patch.object(public_cv, "load_server_key", return_value=self.key))
        self.enterContext(patch.object(public_cv, "photo_path", return_value=self.photo_file))
        self.client = TestClient(
            admin_portal.app,
            base_url="https://testserver",
            raise_server_exceptions=False,
        )
        self.addCleanup(self.client.close)

    def test_inactive_direct_profile_and_photo_are_not_published(self):
        profile = f"/fincas/{FARM_ID}"
        photo = f"/fincas/{FARM_ID}/fotos/{PHOTO_HASH}.jpg"

        self.record["status"] = 0
        self.assertEqual(self.client.get(profile).status_code, 200)
        self.assertEqual(self.client.get(photo).status_code, 200)

        for inactive_status in (1, 2):
            with self.subTest(status=inactive_status):
                self.record["status"] = inactive_status
                observed = (
                    self.client.get(profile).status_code,
                    self.client.get(photo).status_code,
                )
                self.assertEqual(observed, (404, 404))

    def test_inactive_record_remains_verifiable_as_inactive(self):
        self.record["status"] = 2
        response = self.client.get(f"/fincas/{FARM_ID}/verificar")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertFalse(result["verified"])
        status_check = next(item for item in result["checks"] if item["label"] == "Estado de la finca")
        self.assertFalse(status_check["passed"])

    def test_rpc_transport_error_in_public_verification_is_normalized(self):
        self.adapter.w3.eth.fail_rpc = True
        response = self.client.get(f"/fincas/{FARM_ID}/verificar")
        self.assertEqual(response.status_code, 503)

    def test_successful_logins_do_not_consume_failed_attempt_quota(self):
        settings = SimpleNamespace(
            admin_username="admin",
            admin_password_hash="synthetic-hash",
            jwt_secret="synthetic-test-secret-only-0123456789",
        )
        with patch.object(admin_portal, "settings", settings), patch.object(
            admin_portal, "verify_password", side_effect=lambda password, _: password == "correct"
        ):
            client = TestClient(
                admin_portal.app,
                base_url="https://testserver",
                raise_server_exceptions=False,
                client=("192.0.2.10", 1234),
            )
            self.addCleanup(client.close)
            for _ in range(12):
                response = client.post("/auth/login", json={"username": "admin", "password": "correct"})
                self.assertEqual(response.status_code, 200)

    def test_login_failure_quota_is_per_client_not_global(self):
        settings = SimpleNamespace(
            admin_username="admin",
            admin_password_hash="synthetic-hash",
            jwt_secret="synthetic-test-secret-only-0123456789",
        )
        with patch.object(admin_portal, "settings", settings), patch.object(
            admin_portal, "verify_password", side_effect=lambda password, _: password == "correct"
        ):
            blocked_client = TestClient(
                admin_portal.app,
                base_url="https://testserver",
                raise_server_exceptions=False,
                client=("192.0.2.11", 1234),
            )
            other_client = TestClient(
                admin_portal.app,
                base_url="https://testserver",
                raise_server_exceptions=False,
                client=("192.0.2.12", 1234),
            )
            self.addCleanup(blocked_client.close)
            self.addCleanup(other_client.close)

            for _ in range(10):
                response = blocked_client.post("/auth/login", json={"username": "admin", "password": "wrong"})
                self.assertEqual(response.status_code, 401)
            self.assertEqual(
                blocked_client.post("/auth/login", json={"username": "admin", "password": "wrong"}).status_code,
                429,
            )
            self.assertEqual(
                blocked_client.post("/auth/login", json={"username": "admin", "password": "correct"}).status_code,
                429,
            )
            self.assertEqual(
                other_client.post("/auth/login", json={"username": "admin", "password": "correct"}).status_code,
                200,
            )

    def test_authenticated_body_remains_available_to_route(self):
        settings = SimpleNamespace(
            admin_username="admin",
            admin_password_hash="synthetic-hash",
            jwt_secret="synthetic-test-secret-only-0123456789",
        )
        with patch.object(admin_portal, "settings", settings), patch.object(
            auth, "settings", settings
        ), patch.object(
            admin_portal, "verify_password", return_value=True
        ):
            client = TestClient(
                admin_portal.app,
                base_url="https://testserver",
                raise_server_exceptions=False,
            )
            self.addCleanup(client.close)
            login = client.post("/auth/login", json={"username": "admin", "password": "correct"})
            token = login.json()["access_token"]
            response = client.post(
                "/farm-cv",
                headers={"Authorization": "Bearer " + token, "Idempotency-Key": "test-key-123"},
                json={},
            )
        self.assertEqual(response.status_code, 422)
        self.assertIn("farm_id", response.text)

    def test_authenticated_body_size_limit_remains_enforced(self):
        settings = SimpleNamespace(
            admin_username="admin",
            admin_password_hash="synthetic-hash",
            jwt_secret="synthetic-test-secret-only-0123456789",
        )
        with patch.object(admin_portal, "settings", settings), patch.object(
            admin_portal, "verify_password", return_value=True
        ):
            client = TestClient(
                admin_portal.app,
                base_url="https://testserver",
                raise_server_exceptions=False,
            )
            self.addCleanup(client.close)
            login = client.post("/auth/login", json={"username": "admin", "password": "correct"})
            token = login.json()["access_token"]
            with patch.object(admin_portal, "MAX_REQUEST_BYTES", 32):
                response = client.post(
                    "/farm-cv",
                    headers={"Authorization": "Bearer " + token, "Idempotency-Key": "test-key-123"},
                    content=b"x" * 33,
                )
        self.assertEqual(response.status_code, 413)

    def test_prevalidation_is_public_and_still_body_capped(self):
        response = self.client.post("/validation/farm-cv", json={})
        self.assertEqual(response.status_code, 422)

        with patch.object(admin_portal, "MAX_REQUEST_BYTES", 16):
            oversized = self.client.post("/validation/farm-cv", content=b"x" * 17)
        self.assertEqual(oversized.status_code, 413)

    def test_read_only_api_routes_are_public_but_writes_remain_protected(self):
        class Transactions:
            scope = "84532:0x" + "ab" * 20

            async def transaction(self, tx_hash):
                return {"txHash": tx_hash, "status": "pending"}

            async def lookup(self, operation_id):
                return {"operationId": operation_id}

            async def db(self, method, *args):
                return []

        with patch.object(main, "adapter", self.adapter), patch.object(
            main, "transactions", return_value=Transactions()
        ):
            self.assertEqual(self.client.get("/health").status_code, 200)
            self.assertEqual(self.client.get("/networks").status_code, 200)
            self.assertEqual(self.client.get(f"/farm-cv/{FARM_ID}/exists").status_code, 200)
            self.assertEqual(self.client.get(f"/farm-cv/{FARM_ID}").status_code, 200)
            self.assertEqual(
                self.client.post(
                    f"/farm-cv/{FARM_ID}/verify",
                    json={"cv_hash": "0x" + "00" * 32, "polygon_hash": "0x" + "00" * 32},
                ).status_code,
                200,
            )
            self.assertEqual(self.client.get("/transactions/0x" + "ab" * 32).status_code, 200)
            operation_id = "123e4567-e89b-12d3-a456-426614174000"
            self.assertEqual(self.client.get(f"/operations/{operation_id}").status_code, 200)
            self.assertEqual(self.client.get(f"/farm-cv/{FARM_ID}/transactions").status_code, 200)

        self.assertEqual(self.client.post("/farm-cv", json={}).status_code, 401)
        self.assertEqual(self.client.patch(f"/farm-cv/{FARM_ID}/status", json={}).status_code, 401)
        self.assertEqual(self.client.get("/admin/farms").status_code, 401)

    def test_successful_login_resets_subthreshold_failure_bucket(self):
        settings = SimpleNamespace(
            admin_username="admin",
            admin_password_hash="synthetic-hash",
            jwt_secret="synthetic-test-secret-only-0123456789",
        )
        with patch.object(admin_portal, "settings", settings), patch.object(
            admin_portal, "verify_password", side_effect=lambda password, _: password == "correct"
        ):
            client = TestClient(
                admin_portal.app,
                base_url="https://testserver",
                raise_server_exceptions=False,
                client=("192.0.2.13", 1234),
            )
            self.addCleanup(client.close)
            for _ in range(9):
                self.assertEqual(
                    client.post("/auth/login", json={"username": "admin", "password": "wrong"}).status_code,
                    401,
                )
            self.assertEqual(
                client.post("/auth/login", json={"username": "admin", "password": "correct"}).status_code,
                200,
            )
            self.assertNotIn("192.0.2.13", admin_portal.login_attempts_by_client)

    def test_unauthenticated_request_is_rejected_before_body_read(self):
        reads = 0

        async def receive():
            nonlocal reads
            reads += 1
            return {"type": "http.request", "body": b"x" * 1024, "more_body": False}

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/farm-cv",
            "raw_path": b"/farm-cv",
            "query_string": b"",
            "headers": [(b"host", b"testserver"), (b"content-length", b"1024")],
            "client": ("198.51.100.10", 1234),
            "server": ("127.0.0.1", 443),
        }
        request = Request(scope, receive)

        async def unexpected_call_next(_request):
            self.fail("unauthenticated request must not reach the route")

        response = asyncio.run(admin_portal.protect(request, unexpected_call_next))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(reads, 0)


if __name__ == "__main__":
    unittest.main()
