import os
import unittest

os.environ.setdefault("JWT_SECRET", "synthetic-print-card-config-test-secret")

from app.config import Settings
from app.print_card import build_card


class PublicBaseUrlTests(unittest.TestCase):
    def test_accepts_https_origin_and_normalizes_trailing_slash(self):
        settings = Settings(jwt_secret="synthetic-config-test-secret", public_base_url="https://farmcv.example/")
        self.assertEqual(settings.public_base_url, "https://farmcv.example")

    def test_accepts_loopback_http_for_local_testing(self):
        settings = Settings(jwt_secret="synthetic-config-test-secret", public_base_url="http://127.0.0.1:8010")
        self.assertEqual(settings.public_base_url, "http://127.0.0.1:8010")

    def test_rejects_non_loopback_http_and_non_origin_urls(self):
        for value in (
            "http://farmcv.example",
            "https://farmcv.example/private-path",
            "https://user:password@farmcv.example",
            "https://farmcv.example?token=example",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Settings(jwt_secret="synthetic-config-test-secret", public_base_url=value)

    def test_print_card_uses_explicit_public_origin(self):
        farm_id = "0x" + "ab" * 32
        html = build_card(
            {"identification": {"farmName": "Finca de prueba"}, "location": {"municipality": "Rionegro"}},
            farm_id,
            "https://farmcv.example",
        )
        self.assertIn(f'href="https://farmcv.example/fincas/{farm_id}"', html)
        self.assertIn("data:image/png;base64,", html)


if __name__ == "__main__":
    unittest.main()
