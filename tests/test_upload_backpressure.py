"""Bound concurrent authenticated photo uploads in the portal middleware."""

import asyncio
import time
import unittest

import jwt
from starlette.requests import Request
from starlette.responses import Response

from app import admin_portal
from app.config import settings


class PhotoUploadBackpressureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        admin_portal.requests_by_client.clear()
        admin_portal.login_attempts_by_client.clear()
        admin_portal.login_in_flight_by_client.clear()
        admin_portal.login_in_flight_total = 0
        admin_portal.sessions.clear()
        self.sid = "synthetic-upload-test-session"
        admin_portal.sessions[self.sid] = {"exp": time.time() + 900, "csrf": "synthetic"}
        self.token = jwt.encode(
            {
                "sub": settings.admin_username,
                "iat": int(time.time()),
                "exp": int(time.time()) + 900,
                "sid": self.sid,
            },
            settings.jwt_secret,
            algorithm="HS256",
        )

    async def asyncTearDown(self):
        admin_portal.requests_by_client.clear()
        admin_portal.login_attempts_by_client.clear()
        admin_portal.login_in_flight_by_client.clear()
        admin_portal.login_in_flight_total = 0
        admin_portal.sessions.clear()

    async def invoke_middleware(self, call_next, prefix="/admin/farms"):
        path = prefix + "/0x" + "12" * 32 + "/photos"

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [
                (b"host", b"testserver"),
                (b"content-length", b"0"),
                (b"authorization", f"Bearer {self.token}".encode()),
            ],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 443),
        }
        return await admin_portal.protect(Request(scope, receive), call_next)

    async def test_third_authenticated_upload_is_rejected_until_a_slot_frees(self):
        active = 0
        both_slots_occupied = asyncio.Event()
        release = asyncio.Event()

        async def call_next(_request):
            nonlocal active
            active += 1
            if active == 2:
                both_slots_occupied.set()
            await release.wait()
            active -= 1
            return Response("accepted", status_code=200)

        first = asyncio.create_task(self.invoke_middleware(call_next))
        second = asyncio.create_task(self.invoke_middleware(call_next))
        try:
            await asyncio.wait_for(both_slots_occupied.wait(), timeout=1)
            overflow = await self.invoke_middleware(call_next, prefix="/farm-cv")
            self.assertEqual(overflow.status_code, 429)
            self.assertEqual(overflow.headers.get("retry-after"), "1")
        finally:
            release.set()

        self.assertEqual([response.status_code for response in await asyncio.gather(first, second)], [200, 200])


if __name__ == "__main__":
    unittest.main()
