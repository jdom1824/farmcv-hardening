"""Public CV consent regressions using a fake adapter and synthetic Fernet key."""

import json
import os
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET", "qa-only-consent-test-secret-not-production")

from app import admin_portal, public_cv


FARM_ID = "0x" + "34" * 32
PHOTO_HASH = "ab" * 32


class FakeAdapter:
    def __init__(self, record):
        self.record = record

    async def farm_exists(self, _farm_id):
        return True

    async def get_farm(self, _farm_id):
        return dict(self.record)


class PublicConsentQATests(unittest.TestCase):
    def setUp(self):
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.polygon = {
            "type": "Polygon",
            "coordinates": [[[-74.12345, 4.98765], [-74.12000, 4.98765], [-74.12345, 4.98765]]],
        }
        self.cv = {
            "identification": {"farmName": "Finca sintética de QA"},
            "location": {"municipality": "Rionegro", "department": "Santander"},
            "production": {},
            "quality": {"publicProfileConsent": True, "publicPolygonConsent": False},
            "photos": [{"sha256": PHOTO_HASH, "caption": "Foto sintética"}],
        }
        self.record = self._record(self.cv)
        self.adapter = FakeAdapter(self.record)
        self.public_cv_patches = [
            patch.object(public_cv, "adapter", self.adapter),
            patch.object(public_cv, "load_server_key", return_value=self.key),
        ]
        for item in self.public_cv_patches:
            item.start()
            self.addCleanup(item.stop)
        self.client = TestClient(
            admin_portal.app,
            base_url="https://testserver",
            raise_server_exceptions=False,
        )
        self.addCleanup(self.client.close)

    def _record(self, cv):
        return {
            "farmId": FARM_ID,
            "encryptedCV": self.fernet.encrypt(json.dumps(cv).encode()).decode(),
            "encryptedPolygon": self.fernet.encrypt(json.dumps(self.polygon).encode()).decode(),
            "cvHash": "0x" + "cd" * 32,
            "polygonHash": "0x" + "ef" * 32,
            "version": 1,
            "status": 0,
        }

    def test_profile_and_photo_are_hidden_without_profile_consent(self):
        private_cv = {
            **self.cv,
            "quality": {"publicProfileConsent": False, "publicPolygonConsent": False},
        }
        self.adapter.record = self._record(private_cv)

        profile = self.client.get(f"/fincas/{FARM_ID}")
        photo = self.client.get(f"/fincas/{FARM_ID}/fotos/{PHOTO_HASH}.jpg")

        self.assertEqual(profile.status_code, 404)
        self.assertEqual(photo.status_code, 404)
        self.assertNotIn("Finca sintética de QA", profile.text)

    def test_polygon_content_is_not_in_public_page_without_polygon_consent(self):
        self.cv["quality"]["publicProfileConsent"] = True
        self.cv["quality"]["publicPolygonConsent"] = False
        self.adapter.record = self._record(self.cv)

        response = self.client.get(f"/fincas/{FARM_ID}")

        self.assertEqual(response.status_code, 200)
        self.assertIn("El polígono de esta finca no está autorizado para publicación.", response.text)
        self.assertNotIn('id="farm-map"', response.text)
        self.assertNotIn("-74.12345", response.text)
        self.assertNotIn("4.98765", response.text)


if __name__ == "__main__":
    unittest.main()
