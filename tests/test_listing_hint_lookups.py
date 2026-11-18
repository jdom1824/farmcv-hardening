"""Verify read_listing hint semantics without scanning every indexed farm ID."""

import json
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet

from app import admin_farms


class ListingHintLookupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        settings = SimpleNamespace(
            transaction_db_file=Path(temporary.name) / "operations.sqlite3",
            chain_id=31337,
            contract_address="0x" + "ab" * 20,
            contract_deployment_block=0,
        )
        self.enterContext(patch.object(admin_farms, "settings", settings))
        self.key = Fernet.generate_key()
        self.enterContext(patch.object(admin_farms, "load_server_key", return_value=self.key))
        self.enterContext(patch.object(admin_farms, "scan_status", "ready"))
        self.enterContext(patch.object(admin_farms, "refresh_failed", False))
        admin_farms.initialize_index()

    def add_farm(self, number):
        farm_id = "0x" + f"{number:064x}"
        cv = {
            "identification": {"farmName": f"Finca {number}"},
            "location": {"municipality": "Rionegro", "department": "Santander"},
            "quality": {"publicProfileConsent": True},
        }
        encrypted = Fernet(self.key).encrypt(json.dumps(cv).encode()).decode()
        record = {"encryptedCV": encrypted, "status": 0, "version": 1}
        admin_farms.save_record(farm_id, number, record, time.time())
        return farm_id

    def test_empty_hints_do_not_select_every_farm_id(self):
        self.add_farm(1)
        statements = []
        original_index_db = admin_farms.index_db

        @contextmanager
        def traced_index_db():
            with original_index_db() as db:
                db.set_trace_callback(statements.append)
                yield db

        with patch.object(admin_farms, "confirmed_hints", return_value={}), patch.object(
            admin_farms, "index_db", traced_index_db
        ):
            listing = admin_farms.read_listing(0, 20)

        self.assertEqual(listing["indexStatus"], "ready")
        self.assertEqual(listing["total"], 1)
        self.assertFalse(
            any(statement.strip().upper().startswith("SELECT ID FROM FARMS") for statement in statements),
            statements,
        )

    def test_confirmed_hint_already_in_index_does_not_mark_pending(self):
        farm_id = self.add_farm(2)
        with patch.object(admin_farms, "confirmed_hints", return_value={farm_id: (time.time() - 1, 500)}):
            listing = admin_farms.read_listing(0, 20)

        self.assertEqual(listing["indexStatus"], "ready")

    def test_confirmed_hint_missing_from_index_marks_pending(self):
        farm_id = "0x" + f"{3:064x}"
        with patch.object(admin_farms, "confirmed_hints", return_value={farm_id: (time.time(), 500)}):
            listing = admin_farms.read_listing(0, 20)

        self.assertEqual(listing["indexStatus"], "syncing")

    def test_hint_without_registration_block_does_not_mark_pending(self):
        farm_id = "0x" + f"{4:064x}"
        with patch.object(admin_farms, "confirmed_hints", return_value={farm_id: (time.time(), None)}):
            listing = admin_farms.read_listing(0, 20)

        self.assertEqual(listing["indexStatus"], "ready")

    def test_large_hint_set_uses_bounded_batches_and_detects_last_missing_id(self):
        farm_ids = ["0x" + f"{number:064x}" for number in range(1, 502)]
        updated = time.time()
        cv = {"identification": {"farmName": "Finca sintética"}, "location": {}, "quality": {"publicProfileConsent": False}}
        encrypted = Fernet(self.key).encrypt(json.dumps(cv).encode()).decode()
        record = json.dumps({"encryptedCV": encrypted, "status": 0, "version": 1})
        with admin_farms.index_db() as db:
            db.executemany("INSERT INTO farms(id, block) VALUES(?, ?)", ((fid, number) for number, fid in enumerate(farm_ids[:-1], 1)))
            db.executemany(
                "INSERT INTO records(id, data, checked_at) VALUES(?, ?, ?)",
                ((fid, record, updated + 1) for fid in farm_ids[:-1]),
            )
        hints = {fid: (updated, 500 + number) for number, fid in enumerate(farm_ids, 1)}
        statements = []
        original_index_db = admin_farms.index_db

        @contextmanager
        def traced_index_db():
            with original_index_db() as db:
                db.set_trace_callback(statements.append)
                yield db

        with patch.object(admin_farms, "confirmed_hints", return_value=hints), patch.object(
            admin_farms, "index_db", traced_index_db
        ):
            listing = admin_farms.read_listing(0, 20)

        self.assertEqual(listing["indexStatus"], "syncing")
        membership_queries = [s for s in statements if "SELECT COUNT(*) FROM farms WHERE id IN" in s]
        self.assertEqual(len(membership_queries), 2, membership_queries)

        # Adding the last ID makes both bounded membership batches complete.
        with admin_farms.index_db() as db:
            db.execute("INSERT INTO farms(id, block) VALUES(?, ?)", (farm_ids[-1], 1000))
            db.execute("INSERT INTO records(id, data, checked_at) VALUES(?, ?, ?)", (farm_ids[-1], record, updated + 1))
        with patch.object(admin_farms, "confirmed_hints", return_value=hints):
            listing = admin_farms.read_listing(0, 20)
        self.assertEqual(listing["indexStatus"], "ready")


if __name__ == "__main__":
    unittest.main()
