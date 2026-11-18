"""Safety and invalidation checks for the process-local public card projection."""
import json
import sqlite3
import tempfile
import time
import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet

from app import admin_farms, public_home
from app.transaction_store import TransactionStore


CONTRACT = "0x" + "ab" * 20
SIGNER = "0x" + "cd" * 20
SCOPE = f"31337:{CONTRACT}"


class PublicSnapshotCacheTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "operations.sqlite3"
        self.config = SimpleNamespace(
            transaction_db_file=self.path,
            chain_id=31337,
            contract_address=CONTRACT,
            contract_deployment_block=0,
        )
        self.enterContext(patch.object(admin_farms, "settings", self.config))
        self.enterContext(patch.object(public_home, "settings", self.config))
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.enterContext(patch.object(public_home, "load_server_key", return_value=self.key))
        self.store = TransactionStore(self.path)
        admin_farms.initialize_index()
        public_home._public_snapshot_cache = None

    def fid(self, number):
        return "0x" + f"{number:064x}"

    def record(self, name, *, consent=True, status=0):
        cv = {
            "identification": {"farmName": name, "producerName": "PRIVATE_SYNTHETIC"},
            "location": {"municipality": "Rionegro", "department": "Santander"},
            "quality": {"publicProfileConsent": consent},
            "photos": [{"sha256": "cd" * 32}],
        }
        return {
            "encryptedCV": self.cipher.encrypt(json.dumps(cv).encode()).decode(),
            "status": status,
            "version": 1,
        }

    def save(self, number, name, *, consent=True, status=0, checked_at=None, block=None):
        fid = self.fid(number)
        admin_farms.save_record(fid, block if block is not None else number,
                                self.record(name, consent=consent, status=status),
                                time.time() if checked_at is None else checked_at)
        return fid

    def catalog_revision(self):
        with sqlite3.connect(admin_farms.index_path()) as db:
            return db.execute("SELECT revision FROM public_catalog_meta WHERE id=1").fetchone()[0]

    def operation(self, farm_id):
        row = self.store.create(
            SCOPE, f"idem-{farm_id}", f"fingerprint-{farm_id}", 31337,
            CONTRACT, SIGNER, farm_id, "register", {"synthetic": True},
        )
        return row

    def test_warm_hit_avoids_redecrypt_and_keeps_order_search_and_pages(self):
        ids = [self.save(i, f"Finca Águila {i}", block=i) for i in range(1, 10)]
        with patch.object(public_home, "_build_public_snapshot", wraps=public_home._build_public_snapshot) as build:
            first, more = public_home.public_cards("aguila Rionegro", 1)
            second, second_more = public_home.public_cards("aguila Rionegro", 2)

        self.assertEqual(len(first), 6)
        self.assertTrue(more)
        self.assertEqual(len(second), 3)
        self.assertFalse(second_more)
        self.assertEqual(first[0][0], ids[-1])
        self.assertEqual(second[-1][0], ids[0])
        self.assertEqual(build.call_count, 1, "warm search/page reads should reuse decoded public-only snapshot")
        serialized = json.dumps(public_home._public_snapshot_cache[1])
        self.assertNotIn("PRIVATE_SYNTHETIC", serialized)
        self.assertNotIn("encryptedCV", serialized)

    def test_concurrent_cold_requests_share_one_snapshot_build(self):
        self.save(10, "Cold cache needle")
        admin_farms.confirmed_hints_snapshot()  # isolate the public snapshot cold miss
        barrier = threading.Barrier(8)

        def request():
            barrier.wait(timeout=2)
            return public_home.public_cards("needle", 1)

        with patch.object(public_home, "_build_public_snapshot", wraps=public_home._build_public_snapshot) as build:
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _index: request(), range(8)))

        self.assertTrue(all(cards == results[0][0] and has_more is False for cards, has_more in results))
        self.assertEqual(len(results[0][0]), 1)
        self.assertEqual(build.call_count, 1)

    def test_save_record_revoking_consent_invalidates_immediately(self):
        fid = self.save(1, "Publica", consent=True)
        with patch.object(public_home, "_build_public_snapshot", wraps=public_home._build_public_snapshot) as build:
            self.assertEqual(len(public_home.public_cards()[0]), 1)
            before = self.catalog_revision()
            self.save(1, "Publica", consent=False, checked_at=time.time() + 0.01)
            self.assertGreater(self.catalog_revision(), before)
            self.assertEqual(public_home.public_cards()[0], [])
        self.assertEqual(build.call_count, 2)
        self.assertEqual(fid, self.fid(1))

    def test_save_record_suspending_farm_invalidates_immediately(self):
        self.save(2, "Activa", status=0)
        with patch.object(public_home, "_build_public_snapshot", wraps=public_home._build_public_snapshot) as build:
            self.assertEqual(len(public_home.public_cards()[0]), 1)
            self.save(2, "Suspendida", status=1, checked_at=time.time() + 0.01)
            self.assertEqual(public_home.public_cards()[0], [])
        self.assertEqual(build.call_count, 2)

    def test_commit_batch_reorg_invalidates_and_removes_public_card(self):
        fid = self.save(3, "Reorganizada", block=30)
        with patch.object(public_home, "_build_public_snapshot", wraps=public_home._build_public_snapshot) as build:
            self.assertEqual(public_home.public_cards()[0][0][0], fid)
            before = self.catalog_revision()
            admin_farms.commit_batch(0, 100, {})
            self.assertGreater(self.catalog_revision(), before)
            self.assertEqual(public_home.public_cards()[0], [])
        self.assertEqual(build.call_count, 2)

    def test_new_confirmed_hint_invalidates_without_index_write(self):
        fid = self.save(4, "Awaiting fresh data", checked_at=time.time() - 10)
        operation = self.operation(fid)
        with patch.object(public_home, "_build_public_snapshot", wraps=public_home._build_public_snapshot) as build:
            self.assertEqual(len(public_home.public_cards()[0]), 1)
            before_catalog = self.catalog_revision()
            self.store.update(operation["id"], state="confirmed", result=json.dumps({"blockNumber": 900}))
            self.assertEqual(self.catalog_revision(), before_catalog)
            self.assertEqual(public_home.public_cards()[0], [])
        self.assertEqual(build.call_count, 2)

    def test_snapshot_expires_when_nearest_record_exceeds_freshness(self):
        base = time.time()
        self.save(5, "Near expiry", checked_at=base - public_home.MAX_AGE + 1)
        clock = [base]
        with patch.object(public_home.time, "time", side_effect=lambda: clock[0]), \
                patch.object(public_home, "_build_public_snapshot", wraps=public_home._build_public_snapshot) as build:
            self.assertEqual(len(public_home.public_cards()[0]), 1)
            clock[0] = base + 2
            self.assertEqual(public_home.public_cards()[0], [])
        self.assertEqual(build.call_count, 2)

    def test_missing_index_revision_falls_back_to_original_streaming_path(self):
        self.save(6, "Legacy snapshot")
        with sqlite3.connect(admin_farms.index_path()) as db:
            db.execute("DROP TABLE public_catalog_meta")
        public_home._public_snapshot_cache = None
        with patch.object(public_home, "_build_public_snapshot", wraps=public_home._build_public_snapshot) as build:
            self.assertEqual(len(public_home.public_cards()[0]), 1)
            self.assertEqual(len(public_home.public_cards()[0]), 1)
        self.assertEqual(build.call_count, 0, "missing revision metadata must bypass the cache")

    def test_oversized_snapshot_falls_back_without_truncating_results(self):
        self.save(7, "Limit one", block=1)
        self.save(8, "Limit two", block=2)
        public_home._public_snapshot_cache = None
        with patch.object(public_home, "MAX_PUBLIC_SNAPSHOT_PROFILES", 1):
            cards, more = public_home.public_cards()
        self.assertEqual(len(cards), 2)
        self.assertFalse(more)
        self.assertIsNone(public_home._public_snapshot_cache)


if __name__ == "__main__":
    unittest.main()
