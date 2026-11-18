"""Exercise durable progress and cached listing without contacting a blockchain."""
import asyncio
import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from app import admin_farms as inventory


class InventoryCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        settings = SimpleNamespace(transaction_db_file=Path(folder.name) / 'outbox.sqlite3',
            chain_id=84532, contract_address='0x' + 'ab' * 20, contract_deployment_block=0)
        settings_patch = patch.object(inventory, 'settings', settings)
        settings_patch.start()
        self.addCleanup(settings_patch.stop)
        self.key = Fernet.generate_key()
        key_patch = patch.object(inventory, 'load_server_key', return_value=self.key)
        key_patch.start()
        self.addCleanup(key_patch.stop)
        self.fid = '0x' + '12' * 32

    def test_legacy_index_and_rpc_free_listing(self):
        # Preserve the existing deployment's SQLite tables and cursor.
        with closing(sqlite3.connect(inventory.index_path())) as db, db:
            db.execute('CREATE TABLE farms(id TEXT PRIMARY KEY, block INTEGER NOT NULL)')
            db.execute('CREATE TABLE cursor(block INTEGER NOT NULL)')
            db.execute('INSERT INTO farms VALUES(?,50)', (self.fid,))
            db.execute('INSERT INTO cursor VALUES(99)')
        inventory.initialize_index()
        cv = {'identification': {'farmName': 'Finca de prueba', 'producerName': 'no exponer'},
              'location': {'municipality': 'Rionegro', 'department': 'Santander'},
              'quality': {'publicProfileConsent': True}}
        encrypted = Fernet(self.key).encrypt(json.dumps(cv).encode()).decode()
        inventory.save_record(self.fid, None, {'encryptedCV': encrypted, 'status': 0, 'version': 2}, time.time())
        with patch.object(inventory, 'adapter', None):
            response = inventory.read_listing(0, 20)
        self.assertEqual(response['total'], 1)
        self.assertEqual(response['scannedToBlock'], 99)
        self.assertEqual(response['items'][0]['name'], 'Finca de prueba')
        self.assertNotIn('no exponer', json.dumps(response))
        self.assertNotIn(encrypted, json.dumps(response))

    def test_confirmed_write_is_refreshed_before_historical_scan_finishes(self):
        inventory.initialize_index()
        hints = {self.fid: (100, 500000)}
        self.assertEqual(inventory.refresh_candidates(hints), [(self.fid, 500000)])
        cv = Fernet(self.key).encrypt(b'{}').decode()
        inventory.save_record(self.fid, 500000, {'encryptedCV': cv, 'status': 0, 'version': 1}, 101)
        with patch.object(inventory, 'confirmed_hints', return_value={self.fid: (102, 500000)}):
            listing = inventory.read_listing(0, 20)
        self.assertEqual(listing['total'], 1)
        self.assertEqual(listing['items'][0]['status'], 'Unknown')
        self.assertEqual(listing['indexStatus'], 'syncing')

    async def test_resume_after_failed_batch_preserves_indexed_farms(self):
        inventory.initialize_index()
        inventory.commit_batch(0, 99, {self.fid: 50})
        ranges = []

        async def head():
            return 399

        async def read(operation):
            return await operation()

        async def get_logs(*, from_block, to_block):
            ranges.append((from_block, to_block))
            if len(ranges) == 3:
                raise TimeoutError('simulated RPC outage')
            if from_block <= 50 <= to_block:
                return [{'args': {'farmId': bytes.fromhex(self.fid[2:])}, 'blockNumber': 50}]
            return []

        async def sleep(seconds):
            if seconds == 15:
                self.assertEqual(inventory.read_cursor(), 199)
                self.assertEqual(inventory.read_listing(0, 20)['total'], 1)
            if seconds == 30:
                raise asyncio.CancelledError

        class Eth:
            @property
            def block_number(self):
                return head()
        fake = SimpleNamespace(w3=SimpleNamespace(eth=Eth()), _read=read)
        fake._contract = lambda: SimpleNamespace(events=SimpleNamespace(FarmCVRegistered=SimpleNamespace(get_logs=get_logs)))
        with patch.object(inventory, 'adapter', fake), patch.object(inventory.asyncio, 'sleep', sleep):
            with self.assertRaises(asyncio.CancelledError):
                await inventory.scan_registrations()
        self.assertEqual(ranges, [(0, 99), (100, 199), (200, 299), (200, 299), (300, 399)])
        self.assertEqual(inventory.read_cursor(), 399)
