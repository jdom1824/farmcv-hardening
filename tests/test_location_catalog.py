import asyncio
import json
import unittest

from fastapi import HTTPException

from app.location_catalog import is_valid_colombian_location, load_location_catalog
from app.models import PlainFarmCVRequest
from app.public_cv import map_asset, register_public_farm


class LocationCatalogTests(unittest.TestCase):
    def test_catalog_contains_current_vendored_divipola_entries(self):
        catalog = load_location_catalog()
        self.assertEqual(catalog["department_count"], 33)
        self.assertEqual(catalog["municipality_count"], 1104)
        self.assertEqual(sum(len(item["municipalities"]) for item in catalog["departments"]), 1104)
        self.assertIn("datos.gov.co", catalog["source_url"])

    def test_department_must_contain_selected_municipality(self):
        self.assertTrue(is_valid_colombian_location("Santander", "Rionegro"))
        self.assertTrue(is_valid_colombian_location("bogota d.c.", "bogotá d.c."))
        self.assertFalse(is_valid_colombian_location("Antioquia", "Bucaramanga"))
        self.assertFalse(is_valid_colombian_location("Departamento inventado", "Rionegro"))
        self.assertFalse(is_valid_colombian_location("Santander", ""))

    def test_portal_uses_cascading_location_selects_and_multi_variety_controls(self):
        from pathlib import Path

        page = Path(__file__).parents[1] / "app" / "portal.html"
        html = page.read_text(encoding="utf-8")
        self.assertIn('id="farm-region" required disabled', html)
        self.assertIn('id="farm-municipality" required disabled', html)
        self.assertIn("/assets/colombia-divipola.json", html)
        self.assertIn('value="other">Otro (escribir)', html)
        self.assertIn("selectedVarieties", html)
        self.assertIn("image/png,image/webp", html)

    def test_catalog_is_served_as_a_local_asset(self):
        response = asyncio.run(map_asset("colombia-divipola.json"))
        self.assertEqual(response.media_type, "application/json")
        self.assertEqual(json.loads(response.body)["municipality_count"], 1104)

    def test_registration_rejects_municipality_outside_department(self):
        payload = PlainFarmCVRequest(
            farm_id="0x" + "12" * 32,
            cv={
                "identification": {"farmName": "Synthetic"},
                "location": {"department": "Antioquia", "municipality": "Bucaramanga"},
            },
            polygon={
                "type": "Polygon",
                "coordinates":[[[-74, 4], [-73.99, 4], [-73.99, 4.01], [-74, 4]]],
            },
        )
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(register_public_farm(payload, key="synthetic-key"))
        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("department and municipality", raised.exception.detail)

    def test_valid_location_passes_catalog_check_before_photo_validation(self):
        payload = PlainFarmCVRequest(
            farm_id="0x" + "12" * 32,
            cv={
                "identification": {"farmName": "Synthetic"},
                "location": {"department": "Santander", "municipality": "Rionegro"},
                "quality": {"publicProfileConsent": True},
            },
            polygon={
                "type": "Polygon",
                "coordinates":[[[-74, 4], [-73.99, 4], [-73.99, 4.01], [-74, 4]]],
            },
        )
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(register_public_farm(payload, key="synthetic-key"))
        self.assertEqual(raised.exception.status_code, 422)
        self.assertEqual(raised.exception.detail, "one or two photographs required")


if __name__ == "__main__":
    unittest.main()
