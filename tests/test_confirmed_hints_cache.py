"""Revision-invalidated confirmed-operation hint cache regressions."""
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import admin_farms, public_home
from app.transaction_store import TransactionStore


CONTRACT = "0x" + "ab" * 20
SIGNER = "0x" + "cd" * 20
FARM_ID = "0x" + "12" * 32


class ConfirmedHintsCacheTests(unittest.TestCase):
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
        self.store = TransactionStore(self.path)
        self.scope = f"{self.config.chain_id}:{CONTRACT}"
        admin_farms._confirmed_hints_cache.clear()

    def add_operation(self, *, kind="register", farm_id=FARM_ID, key="synthetic-key"):
        return self.store.create(
            self.scope, key, f"fingerprint-{key}", self.config.chain_id,
            CONTRACT, SIGNER, farm_id, kind, {"synthetic": True},
        )

    def revision(self):
        with sqlite3.connect(self.path) as db:
            return db.execute("SELECT revision FROM confirmed_hints_meta WHERE id=1").fetchone()[0]

    def test_cache_hit_and_immediate_invalidation_on_state_and_result_changes(self):
        operation = self.add_operation()
        with patch.object(admin_farms, "_query_confirmed_hints", wraps=admin_farms._query_confirmed_hints) as scan:
            self.assertEqual(admin_farms.confirmed_hints(), {})
            self.assertEqual(admin_farms.confirmed_hints(), {})
            self.assertEqual(scan.call_count, 1, "unchanged revision should avoid a second aggregate scan")

            self.store.update(operation["id"], state="confirmed", result=json.dumps({"blockNumber": 700}))
            self.assertEqual(admin_farms.confirmed_hints(), {FARM_ID: (self.store.get(operation["id"], self.scope)["updated"], 700)})
            self.assertEqual(scan.call_count, 2, "transition to confirmed must invalidate synchronously")
            self.assertEqual(admin_farms.confirmed_hints()[FARM_ID][1], 700)
            self.assertEqual(scan.call_count, 2)

            old_revision = self.revision()
            self.store.update(operation["id"], state="confirmed", result=json.dumps({"blockNumber": 701}))
            self.assertGreater(self.revision(), old_revision)
            self.assertEqual(admin_farms.confirmed_hints()[FARM_ID][1], 701)
            self.assertEqual(scan.call_count, 3, "confirmed result changes must invalidate synchronously")

            self.store.update(operation["id"], state="failed")
            self.assertEqual(admin_farms.confirmed_hints(), {})
            self.assertEqual(scan.call_count, 4, "leaving confirmed state must remove the hint")

    def test_idempotent_replay_does_not_create_or_revise_a_second_operation(self):
        operation = self.add_operation()
        self.store.update(operation["id"], state="confirmed", result=json.dumps({"blockNumber": 700}))
        before = self.revision()

        replay = self.store.create(
            self.scope, "synthetic-key", "fingerprint-synthetic-key", self.config.chain_id,
            CONTRACT, SIGNER, FARM_ID, "register", {"synthetic": True},
        )

        self.assertEqual(replay["id"], operation["id"])
        self.assertEqual(self.revision(), before)
        self.assertEqual(admin_farms.confirmed_hints()[FARM_ID][1], 700)

    def test_direct_confirmed_insert_and_delete_invalidate_revision(self):
        with patch.object(admin_farms, "_query_confirmed_hints", wraps=admin_farms._query_confirmed_hints) as scan:
            self.assertEqual(admin_farms.confirmed_hints(), {})
            now = time.time()
            with sqlite3.connect(self.path) as db:
                db.execute('''INSERT INTO operations
                    (id,scope,idem,fingerprint,chain_id,contract,signer,farm_id,kind,payload,state,result,created,updated)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    ("direct-confirmed", self.scope, "direct-confirmed", "direct-fingerprint",
                     self.config.chain_id, CONTRACT, SIGNER, FARM_ID, "register", "{}", "confirmed",
                     json.dumps({"blockNumber": 701}), now, now))
            self.assertEqual(admin_farms.confirmed_hints()[FARM_ID][1], 701)
            self.assertEqual(scan.call_count, 2, "confirmed inserts must invalidate the cached revision")

            with sqlite3.connect(self.path) as db:
                db.execute("DELETE FROM operations WHERE id='direct-confirmed'")
            self.assertEqual(admin_farms.confirmed_hints(), {})
            self.assertEqual(scan.call_count, 3, "deleting a confirmed operation must invalidate the cache")

    def test_index_reorg_remains_visible_despite_cached_confirmed_hint(self):
        operation = self.add_operation()
        self.store.update(operation["id"], state="confirmed", result=json.dumps({"blockNumber": 700}))
        admin_farms.initialize_index()
        admin_farms.commit_batch(0, 1000, {FARM_ID: 700})
        self.assertEqual(admin_farms.confirmed_hints()[FARM_ID][1], 700)

        # The chain indexer rechecks an overlapping range and removes the event.
        # The outbox hint remains confirmed, so the admin view must report syncing;
        # the public catalog must not keep serving the removed indexed farm.
        admin_farms.commit_batch(0, 1000, {})
        listing = admin_farms.read_listing(0, 20)
        cards, has_more = public_home.public_cards()

        self.assertEqual(listing["total"], 0)
        self.assertEqual(listing["indexStatus"], "syncing")
        self.assertEqual(cards, [])
        self.assertFalse(has_more)
        self.assertEqual(admin_farms.confirmed_hints()[FARM_ID][1], 700)

    def test_legacy_database_without_revision_metadata_uses_uncached_fallback(self):
        operation = self.add_operation()
        self.store.update(operation["id"], state="confirmed", result=json.dumps({"blockNumber": 700}))
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER operations_hints_insert_v1")
            db.execute("DROP TRIGGER operations_hints_update_v1")
            db.execute("DROP TRIGGER operations_hints_delete_v1")
            db.execute("DROP TABLE confirmed_hints_meta")
        admin_farms._confirmed_hints_cache.clear()

        with patch.object(admin_farms, "_query_confirmed_hints", wraps=admin_farms._query_confirmed_hints) as scan:
            first = admin_farms.confirmed_hints()
            second = admin_farms.confirmed_hints()

        self.assertEqual(first, second)
        self.assertEqual(first[FARM_ID][1], 700)
        self.assertEqual(scan.call_count, 2, "legacy metadata absence must favor fresh direct reads")


if __name__ == "__main__":
    unittest.main()
