"""Independent QA checks for portal cookie sessions and concurrent login limits.

All credentials are synthetic; ASGI requests never contact a network service.
"""

import asyncio
import unittest
from collections import OrderedDict
import threading
import jwt
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from app import admin_portal, auth


def test_settings():
    return SimpleNamespace(
        admin_username="qa-admin",
        admin_password_hash="synthetic-hash",
        jwt_secret="qa-only-secret-not-for-production-0123456789",
    )


class PortalSessionQATests(unittest.TestCase):
    def setUp(self):
        self.state = patch.multiple(
            admin_portal,
            login_attempts_by_client=OrderedDict(),
            login_in_flight_by_client={},
            requests_by_client=OrderedDict(),
            sessions={},
        )
        self.state.start()
        self.addCleanup(self.state.stop)
        self.settings = test_settings()
        self.settings_patch = patch.object(admin_portal, "settings", self.settings)
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)
        self.auth_settings_patch = patch.object(auth, "settings", self.settings)
        self.auth_settings_patch.start()
        self.addCleanup(self.auth_settings_patch.stop)
        self.password_patch = patch.object(admin_portal, "verify_password", return_value=True)
        self.password_patch.start()
        self.addCleanup(self.password_patch.stop)

    def test_cookie_write_requires_csrf_and_valid_csrf_reaches_route(self):
        client = TestClient(admin_portal.app, base_url="https://testserver", raise_server_exceptions=False)
        self.addCleanup(client.close)
        login = client.post("/auth/login", json={"username": "qa-admin", "password": "synthetic"})
        self.assertEqual(login.status_code, 200)
        cookie = login.headers["set-cookie"].lower()
        self.assertIn("secure", cookie)
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertIn("path=/", cookie)

        without_csrf = client.post("/farm-cv", json={})
        self.assertEqual(without_csrf.status_code, 403)

        with_csrf = client.post(
            "/farm-cv",
            json={},
            headers={"X-CSRF-Token": login.json()["csrf"], "Idempotency-Key": "qa-test-0001"},
        )
        self.assertEqual(with_csrf.status_code, 422)

    def test_new_login_revokes_previous_cookie_session(self):
        first = TestClient(admin_portal.app, base_url="https://testserver", raise_server_exceptions=False)
        second = TestClient(admin_portal.app, base_url="https://testserver", raise_server_exceptions=False)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        login1 = first.post("/auth/login", json={"username": "qa-admin", "password": "synthetic"})
        self.assertEqual(login1.status_code, 200)
        self.assertEqual(first.get("/admin/check").status_code, 200)

        login2 = second.post("/auth/login", json={"username": "qa-admin", "password": "synthetic"})
        self.assertEqual(login2.status_code, 200)
        self.assertEqual(first.get("/admin/check").status_code, 401)
        self.assertEqual(second.get("/admin/check").status_code, 200)

    def test_jwt_expires_in_900_seconds_and_expired_session_is_rejected(self):
        client = TestClient(admin_portal.app, base_url="https://testserver", raise_server_exceptions=False)
        self.addCleanup(client.close)
        login = client.post("/auth/login", json={"username": "qa-admin", "password": "synthetic"})
        self.assertEqual(login.status_code, 200)

        claims = jwt.decode(login.json()["access_token"], self.settings.jwt_secret, algorithms=["HS256"])
        self.assertEqual(claims["exp"] - claims["iat"], 900)
        session = admin_portal.sessions[claims["sid"]]
        self.assertEqual(session["exp"], claims["exp"])

        expired_clock = SimpleNamespace(
            time=lambda: session["exp"] + 1,
            monotonic=admin_portal.time.monotonic,
        )
        with patch.object(admin_portal, "time", expired_clock):
            self.assertEqual(client.get("/admin/check").status_code, 401)


class ConcurrentLoginLimitQATests(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_login_checks_respect_inflight_cap(self):
        # Login bodies may be parsed, but a request beyond the global in-flight
        # cap must be rejected before password verification/PBKDF starts.
        limit = admin_portal.MAX_CONCURRENT_LOGIN_CHECKS
        started = threading.Event()
        release = threading.Event()
        entered_lock = threading.Lock()
        verify_count = 0
        body_count = 0
        failure_buckets = OrderedDict()
        original_bounded_body = admin_portal.bounded_body

        async def gated_bounded_body(request, maximum):
            nonlocal body_count
            body_count += 1
            return await original_bounded_body(request, maximum)

        def gated_verify_password(_password, _encoded):
            nonlocal verify_count
            with entered_lock:
                verify_count += 1
                if verify_count == limit:
                    started.set()
            if not release.wait(timeout=3):
                raise TimeoutError("synthetic password-check barrier timed out")
            return False

        settings = test_settings()
        with patch.object(admin_portal, "settings", settings), \
                patch.object(admin_portal, "login_attempts_by_client", failure_buckets), \
                patch.object(admin_portal, "login_in_flight_by_client", {}), \
                patch.object(admin_portal, "login_in_flight_total", 0), \
                patch.object(admin_portal, "requests_by_client", OrderedDict()), \
                patch.object(admin_portal, "client_identity", return_value="qa-client"), \
                patch.object(admin_portal, "sessions", {}), \
                patch.object(admin_portal, "bounded_body", gated_bounded_body), \
                patch.object(admin_portal, "verify_password", side_effect=gated_verify_password):
            transport = httpx.ASGITransport(app=admin_portal.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
                first_checks = [
                    asyncio.create_task(client.post("/auth/login", json={"username": "qa-admin", "password": "wrong"}))
                    for _ in range(limit)
                ]
                self.assertTrue(await asyncio.wait_for(asyncio.to_thread(started.wait, 2), timeout=2.5))
                overflow = asyncio.create_task(
                    client.post("/auth/login", json={"username": "qa-admin", "password": "wrong"})
                )
                try:
                    overflow_response = await asyncio.wait_for(asyncio.shield(overflow), timeout=1)
                except asyncio.TimeoutError:
                    # A regression would let the overflow request enter
                    # PBKDF. Release all workers before failing the assertion.
                    reached_password_check = True
                    release.set()
                    overflow_response = await overflow
                else:
                    reached_password_check = False
                finally:
                    release.set()
                first_responses = await asyncio.gather(*first_checks)

        self.assertEqual([response.status_code for response in first_responses], [401] * limit)
        self.assertEqual(overflow_response.status_code, 429)
        self.assertEqual(overflow_response.headers.get("retry-after"), "1")
        self.assertFalse(reached_password_check, "overflow request reached password verification")
        self.assertEqual(verify_count, limit)
        self.assertEqual(body_count, limit + 1)
        self.assertEqual(len(failure_buckets["qa-client"]), limit)
        self.assertEqual(admin_portal.login_in_flight_total, 0)

    async def test_transient_global_capacity_429_does_not_lock_out_other_ips(self):
        limit = admin_portal.MAX_CONCURRENT_LOGIN_CHECKS
        started = threading.Event()
        release = threading.Event()
        verify_lock = threading.Lock()
        verify_count = 0

        def gated_verify_password(password, _encoded):
            nonlocal verify_count
            if password == "correct":
                return True
            with verify_lock:
                verify_count += 1
                if verify_count == limit:
                    started.set()
            if not release.wait(timeout=3):
                raise TimeoutError("synthetic cross-client barrier timed out")
            return False

        settings = test_settings()
        clients = [
            httpx.AsyncClient(
                transport=httpx.ASGITransport(
                    app=admin_portal.app,
                    raise_app_exceptions=False,
                    client=(f"192.0.2.{index + 1}", 50000 + index),
                ),
                base_url="https://testserver",
            )
            for index in range(limit + 1)
        ]
        with patch.object(admin_portal, "settings", settings), \
                patch.object(admin_portal, "login_attempts_by_client", OrderedDict()), \
                patch.object(admin_portal, "login_in_flight_by_client", {}), \
                patch.object(admin_portal, "login_in_flight_total", 0), \
                patch.object(admin_portal, "requests_by_client", OrderedDict()), \
                patch.object(admin_portal, "sessions", {}), \
                patch.object(admin_portal, "verify_password", side_effect=gated_verify_password):
            try:
                active = [
                    asyncio.create_task(client.post("/auth/login", json={"username": "qa-admin", "password": "wrong"}))
                    for client in clients[:limit]
                ]
                self.assertTrue(await asyncio.wait_for(asyncio.to_thread(started.wait, 2), timeout=2.5))
                overflow = await clients[-1].post("/auth/login", json={"username": "qa-admin", "password": "wrong"})
                self.assertEqual(overflow.status_code, 429)
                self.assertEqual(overflow.headers.get("retry-after"), "1")
                self.assertEqual(verify_count, limit)
                release.set()
                active_results = await asyncio.gather(*active)
                self.assertEqual([response.status_code for response in active_results], [401] * limit)
                self.assertEqual(admin_portal.login_in_flight_total, 0)
                # The client rejected only for short-lived process capacity can
                # immediately authenticate after the active checks finish.
                recovered = await clients[-1].post("/auth/login", json={"username": "qa-admin", "password": "correct"})
                self.assertEqual(recovered.status_code, 200)
            finally:
                release.set()
                for client in clients:
                    await client.aclose()


if __name__ == "__main__":
    unittest.main()
