"""Validate direct-peer and explicitly trusted proxy identity handling."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from starlette.requests import Request

from app import admin_portal
from app.config import Settings
from pydantic import ValidationError


def make_request(peer, forwarded=()):
    headers = [(b"host", b"testserver")]
    headers.extend((b"x-forwarded-for", value.encode()) for value in forwarded)
    path = "/"
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "client": (peer, 50000),
        "server": ("testserver", 443),
    }
    return Request(scope)


class ClientIdentityTests(unittest.TestCase):
    def test_unset_proxy_allowlist_ignores_forwarded_header(self):
        with patch.object(admin_portal, "settings", SimpleNamespace(trusted_proxy_cidrs="")):
            request = make_request("10.1.2.3", ["203.0.113.8"])
            self.assertEqual(admin_portal.client_identity(request), "10.1.2.3")

    def test_untrusted_peer_cannot_choose_identity_with_forwarded_header(self):
        settings = SimpleNamespace(trusted_proxy_cidrs="10.0.0.0/8")
        with patch.object(admin_portal, "settings", settings):
            request = make_request("198.51.100.4", ["203.0.113.8"])
            self.assertEqual(admin_portal.client_identity(request), "198.51.100.4")

    def test_trusted_proxy_chain_selects_nearest_untrusted_hop(self):
        settings = SimpleNamespace(trusted_proxy_cidrs="10.0.0.0/8")
        with patch.object(admin_portal, "settings", settings):
            request = make_request(
                "10.0.0.2",
                ["192.0.2.99, 203.0.113.7", "10.0.0.1"],
            )
            self.assertEqual(admin_portal.client_identity(request), "203.0.113.7")

    def test_malformed_forwarded_chain_falls_back_to_peer(self):
        settings = SimpleNamespace(trusted_proxy_cidrs="10.0.0.0/8")
        with patch.object(admin_portal, "settings", settings):
            request = make_request("10.0.0.2", ["not-an-ip, 203.0.113.7"])
            self.assertEqual(admin_portal.client_identity(request), "10.0.0.2")

    def test_invalid_trusted_proxy_cidr_is_rejected_at_configuration_load(self):
        for value in ("not-a-cidr", "0.0.0.0/0", "::/0"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                Settings(jwt_secret="synthetic-config-test-secret-which-is-long-enough", trusted_proxy_cidrs=value)

    def test_general_request_limit_tracks_repeated_requests_per_client(self):
        from collections import OrderedDict

        buckets = OrderedDict()
        self.assertFalse(admin_portal.limited_by_client(buckets, "192.0.2.1", 2, 60))
        self.assertFalse(admin_portal.limited_by_client(buckets, "192.0.2.2", 2, 60))
        self.assertFalse(admin_portal.limited_by_client(buckets, "192.0.2.1", 2, 60))
        self.assertTrue(admin_portal.limited_by_client(buckets, "192.0.2.1", 2, 60))
        self.assertFalse(admin_portal.limited_by_client(buckets, "192.0.2.2", 2, 60))

    def test_request_bucket_map_is_bounded_with_lru_eviction(self):
        from collections import OrderedDict

        buckets = OrderedDict()
        with patch.object(admin_portal, "MAX_TRACKED_CLIENTS", 2), \
                patch.object(admin_portal.time, "monotonic", side_effect=[10, 11, 12, 73]):
            self.assertFalse(admin_portal.limited_by_client(buckets, "192.0.2.1", 2, 60))
            self.assertFalse(admin_portal.limited_by_client(buckets, "192.0.2.2", 2, 60))
            self.assertFalse(admin_portal.limited_by_client(buckets, "192.0.2.3", 2, 60))
            self.assertEqual(len(buckets), 2)
            # Client 1 was least recently used and was evicted at capacity.
            self.assertFalse(admin_portal.limited_by_client(buckets, "192.0.2.1", 2, 60))

    def test_login_failure_bucket_expires_after_window(self):
        from collections import OrderedDict

        attempts = OrderedDict()
        in_flight = {}
        identity = "192.0.2.9"
        with patch.object(admin_portal, "login_attempts_by_client", attempts), \
                patch.object(admin_portal, "login_in_flight_by_client", in_flight), \
                patch.object(admin_portal, "login_in_flight_total", 0), \
                patch.object(admin_portal.time, "monotonic", return_value=10):
            for _ in range(admin_portal.MAX_LOGIN_FAILURES_PER_MINUTE):
                self.assertIsNone(admin_portal.reserve_login_slot(identity))
                admin_portal.finish_login_slot(identity, failed=True)
            self.assertEqual(admin_portal.reserve_login_slot(identity), "client_limit")

        with patch.object(admin_portal.time, "monotonic", return_value=71):
            self.assertIsNone(admin_portal.reserve_login_slot(identity))
            admin_portal.finish_login_slot(identity)


if __name__ == "__main__":
    unittest.main()
