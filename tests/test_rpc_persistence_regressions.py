"""Regression checks for transient RPC failures and a lagging indexer head.

All filesystem effects use temporary SQLite databases; RPC failures are synthetic.
"""
import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

os.environ["JWT_SECRET"] = "test-only-rpc-persistence-regressions"

from app import admin_farms
from app.config import settings
from app.transaction_service import TERMINAL, TransactionService
from app.web3_adapter import FarmCVAdapter, RPCUnavailable, SubmissionUncertain
from eth_account import Account
from web3 import AsyncWeb3
from web3.exceptions import (
    ContractLogicError,
    ProviderConnectionError,
    TransactionNotFound,
    Web3RPCError,
)


CONTRACT = "0x" + "11" * 20
FARM_ID = "0x" + "22" * 32
SIGNER = "0x" + "33" * 20


class FakeEth:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = 0

    @property
    def chain_id(self):
        async def read_chain_id():
            self.calls += 1
            result = self.outcome(self.calls)
            if isinstance(result, BaseException):
                raise result
            return result

        return read_chain_id()


class AdapterWithFakeChainId:
    def __init__(self, outcome):
        self.w3 = SimpleNamespace(eth=FakeEth(outcome))

    async def _read(self, operation):
        return await FarmCVAdapter._read(self, operation)


def rate_limit_error(_attempt=0):
    return Web3RPCError(
        "provider rate limit",
        {"error": {"code": -32005, "message": "request rate limited"}},
    )


class RpcFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_retries_transient_json_rpc_error(self):
        adapter = AdapterWithFakeChainId(lambda attempt: rate_limit_error() if attempt < 3 else 31337)

        chain_id = await adapter._read(lambda: adapter.w3.eth.chain_id)

        self.assertEqual(chain_id, 31337)
        self.assertEqual(adapter.w3.eth.calls, 3)

    async def test_transaction_not_found_passes_through_without_retry(self):
        adapter = AdapterWithFakeChainId(lambda _attempt: TransactionNotFound("synthetic hash not found"))

        with self.assertRaises(TransactionNotFound):
            await adapter._read(lambda: adapter.w3.eth.chain_id)

        self.assertEqual(adapter.w3.eth.calls, 1)

    async def test_transient_rpc_error_keeps_intent_retryable(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(settings, "transaction_db_file", Path(folder) / "outbox.sqlite3"), \
                    patch.object(settings, "chain_id", 31337), \
                    patch.object(settings, "contract_address", CONTRACT):
                adapter = AdapterWithFakeChainId(lambda _attempt: rate_limit_error())
                service = TransactionService(adapter)
                row = await service.db(
                    "create", service.scope, "synthetic-key", "synthetic-fingerprint",
                    31337, CONTRACT, SIGNER, FARM_ID, "register", {"synthetic": True},
                )

                await service.process(row["id"])

                stored = await service.db("get", row["id"], service.scope)
                self.assertEqual(stored["state"], "queued")
                self.assertEqual(stored["http_error"], 503)
                self.assertNotIn(stored["state"], TERMINAL)
                self.assertGreater(stored["next_attempt"], time.time())

                await service.db("update", row["id"], next_attempt=time.time() - 1)
                active = await service.db("active", service.scope)
                self.assertIn(row["id"], {item["id"] for item in active})

    async def test_contract_logic_error_remains_terminal_rejection(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(settings, "transaction_db_file", Path(folder) / "outbox.sqlite3"), \
                    patch.object(settings, "chain_id", 31337), \
                    patch.object(settings, "contract_address", CONTRACT):
                adapter = AdapterWithFakeChainId(lambda _attempt: ContractLogicError("execution reverted"))
                service = TransactionService(adapter)
                row = await service.db(
                    "create", service.scope, "synthetic-key", "synthetic-fingerprint",
                    31337, CONTRACT, SIGNER, FARM_ID, "register", {"synthetic": True},
                )

                await service.process(row["id"])

                stored = await service.db("get", row["id"], service.scope)
                self.assertEqual(stored["state"], "rejected")
                self.assertEqual(stored["http_error"], 400)
                self.assertIn(stored["state"], TERMINAL)

    async def test_provider_disconnect_before_broadcast_is_uncertain(self):
        raw_tx = "0x01"
        tx_hash = "0x" + "ab" * 32
        send = AsyncMock(side_effect=ProviderConnectionError("synthetic disconnect"))
        adapter = FarmCVAdapter.__new__(FarmCVAdapter)
        adapter.w3 = SimpleNamespace(eth=SimpleNamespace(send_raw_transaction=send))

        with self.assertRaises(SubmissionUncertain) as raised:
            await adapter.broadcast(raw_tx, tx_hash)

        self.assertEqual(raised.exception.tx_hash, tx_hash)
        self.assertEqual(send.await_count, 1)

    async def test_confirmed_receipt_removed_by_reorg_returns_to_unknown_reconciliation(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(settings, "transaction_db_file", Path(folder) / "outbox.sqlite3"), \
                    patch.object(settings, "chain_id", 31337), \
                    patch.object(settings, "contract_address", CONTRACT):
                account = Account.create()
                signed = account.sign_transaction({
                    "nonce": 0,
                    "gas": 21_000,
                    "gasPrice": 2_000_000_000,
                    "to": "0x" + "44" * 20,
                    "value": 0,
                    "chainId": 31337,
                })
                raw_tx = AsyncWeb3.to_hex(signed.raw_transaction)
                tx_hash = AsyncWeb3.to_hex(signed.hash).lower()

                class FakeEthWithUnusedNonce:
                    @property
                    def chain_id(self):
                        async def read():
                            return 31337

                        return read()

                    def get_transaction_count(self, _address, _block):
                        async def read():
                            return 0

                        return read()

                class MissingReceiptAdapter:
                    def __init__(self):
                        self.w3 = SimpleNamespace(eth=FakeEthWithUnusedNonce())
                        self.transaction = AsyncMock(side_effect=TransactionNotFound("synthetic reorg"))
                        self.broadcast = AsyncMock()

                    async def _read(self, operation):
                        return await operation()

                adapter = MissingReceiptAdapter()
                service = TransactionService(adapter)
                row = await service.db(
                    "create", service.scope, "reorg-key", "reorg-fingerprint",
                    31337, CONTRACT, account.address.lower(), FARM_ID, "register", {"synthetic": True},
                )
                await service.db(
                    "update", row["id"], state="confirmed", nonce=0,
                    tx_hash=tx_hash, raw_tx=raw_tx,
                    result='{"txHash":"' + tx_hash + '","status":"confirmed","blockNumber":7}',
                    next_attempt=time.time() - 1,
                )
                stored_before = await service.db("get", row["id"], service.scope)
                self.assertTrue(
                    AsyncWeb3.to_hex(AsyncWeb3.keccak(hexstr=stored_before["raw_tx"])).lower()
                    == stored_before["tx_hash"]
                )
                self.assertTrue(
                    Account.recover_transaction(stored_before["raw_tx"]).lower()
                    == stored_before["signer"].lower()
                )
                self.assertEqual(await adapter._read(lambda: adapter.w3.eth.chain_id), stored_before["chain_id"])

                await service.process(row["id"], refresh=True)

                stored = await service.db("get", row["id"], service.scope)
                history = await service.db("history", service.scope, FARM_ID, 10, 0)
                active = await service.db("active", service.scope)
                self.assertEqual(
                    stored["state"], "unknown",
                    f"sanitized_error={stored['error']!r}; receipt_lookups={adapter.transaction.await_count}",
                )
                self.assertIsNone(stored["result"])
                self.assertTrue(stored["tx_hash"] == tx_hash)
                self.assertTrue(stored["raw_tx"] == raw_tx)
                self.assertEqual(stored["nonce"], 0)
                self.assertIn(row["id"], {item["operationId"] for item in history})
                self.assertIn(row["id"], {item["id"] for item in active})
                self.assertIn("unknown", {item["state"] for item in history[0]["history"]})
                adapter.broadcast.assert_not_awaited()

    async def test_read_only_lookup_does_not_broadcast_prepared_transaction(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(settings, "transaction_db_file", Path(folder) / "outbox.sqlite3"), \
                    patch.object(settings, "chain_id", 31337), \
                    patch.object(settings, "contract_address", CONTRACT):
                account = Account.create()
                signed = account.sign_transaction({
                    "nonce": 0,
                    "gas": 21_000,
                    "gasPrice": 2_000_000_000,
                    "to": "0x" + "44" * 20,
                    "value": 0,
                    "chainId": 31337,
                })
                raw_tx = AsyncWeb3.to_hex(signed.raw_transaction)
                tx_hash = AsyncWeb3.to_hex(signed.hash).lower()

                class FakeEthWithUnusedNonce:
                    @property
                    def chain_id(self):
                        async def read():
                            return 31337

                        return read()

                    def get_transaction_count(self, _address, _block):
                        async def read():
                            return 0

                        return read()

                class MissingReceiptAdapter:
                    def __init__(self):
                        self.w3 = SimpleNamespace(eth=FakeEthWithUnusedNonce())
                        self.transaction = AsyncMock(side_effect=TransactionNotFound("synthetic missing tx"))
                        self.broadcast = AsyncMock()

                    async def _read(self, operation):
                        return await operation()

                adapter = MissingReceiptAdapter()
                service = TransactionService(adapter)
                row = await service.db(
                    "create", service.scope, "prepared-key", "prepared-fingerprint",
                    31337, CONTRACT, account.address.lower(), FARM_ID, "register", {"synthetic": True},
                )
                await service.db(
                    "update", row["id"], state="prepared", nonce=0,
                    tx_hash=tx_hash, raw_tx=raw_tx,
                )

                await service.process(row["id"], refresh=True)

                stored = await service.db("get", row["id"], service.scope)
                self.assertEqual(stored["state"], "prepared")
                self.assertEqual(stored["tx_hash"], tx_hash)
                adapter.broadcast.assert_not_awaited()


class IndexerLaggingHeadTests(unittest.IsolatedAsyncioTestCase):
    async def test_cursor_ahead_of_head_degrades_without_truncating_index(self):
        with tempfile.TemporaryDirectory() as folder:
            config = SimpleNamespace(
                transaction_db_file=Path(folder) / "outbox.sqlite3",
                chain_id=31337,
                contract_address=CONTRACT,
                contract_deployment_block=0,
            )
            old_globals = (admin_farms.chain_head, admin_farms.scan_status, admin_farms.refresh_failed)
            with patch.object(admin_farms, "settings", config):
                admin_farms.initialize_index()
                admin_farms.commit_batch(0, 199, {FARM_ID: 150})
                reads = []
                sleeps = []

                class Eth:
                    @property
                    def block_number(self):
                        async def read_head():
                            reads.append(150)
                            return 150

                        return read_head()

                async def read(operation):
                    return await operation()

                async def get_logs(**_kwargs):
                    self.fail("scanner must not query logs while cursor exceeds head")

                async def sleep(seconds):
                    sleeps.append(seconds)
                    if len(sleeps) == 2:
                        raise asyncio.CancelledError()

                fake = SimpleNamespace(w3=SimpleNamespace(eth=Eth()), _read=read)
                fake._contract = lambda: SimpleNamespace(
                    events=SimpleNamespace(FarmCVRegistered=SimpleNamespace(get_logs=get_logs))
                )

                try:
                    with patch.object(admin_farms, "adapter", fake), \
                            patch.object(admin_farms, "asyncio", SimpleNamespace(sleep=sleep)):
                        with self.assertRaises(asyncio.CancelledError):
                            await admin_farms.scan_registrations()

                    self.assertEqual(len(reads), 2)
                    self.assertEqual(sleeps, [15, 15])
                    self.assertEqual(admin_farms.scan_status, "degraded")
                    self.assertEqual(admin_farms.read_cursor(), 199)
                    with admin_farms.index_db() as db:
                        self.assertEqual(db.execute("SELECT id, block FROM farms").fetchall(), [(FARM_ID, 150)])
                finally:
                    admin_farms.chain_head, admin_farms.scan_status, admin_farms.refresh_failed = old_globals


if __name__ == "__main__":
    unittest.main()
