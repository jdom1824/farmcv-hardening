"""Persistent submission and reconciliation, single-host coordinated writer."""
import asyncio
import fcntl
import hashlib
import json
import logging
import os
import time
from eth_account import Account
from web3 import AsyncWeb3
from web3.exceptions import ContractLogicError, TransactionNotFound, Web3RPCError, BadFunctionCallOutput
from .config import settings
from .crypto_service import canonical_json
from .transaction_store import TransactionStore
from .web3_adapter import RPCUnavailable, SubmissionUncertain, ContractConfigurationUnavailable

log=logging.getLogger(__name__)
TERMINAL={"confirmed","failed","rejected","replaced"}


class TransactionService:
    def __init__(self, adapter):
        self.adapter=adapter
        self.scope=f"{settings.chain_id}:{settings.contract_address.lower()}"
        self.store=None
        self.lock=asyncio.Lock()
        self.init_lock=asyncio.Lock()

    async def init(self):
        async with self.init_lock:
            if self.store is None:
                self.store=await asyncio.to_thread(TransactionStore,settings.transaction_db_file)

    async def db(self, method, *args, **kwargs):
        await self.init()
        job=asyncio.create_task(asyncio.to_thread(getattr(self.store,method),*args,**kwargs))
        try:
            return await asyncio.shield(job)
        except asyncio.CancelledError:
            # A thread cannot be cancelled. Keep the writer lock until its commit
            # finishes; otherwise another request could reserve the same nonce.
            await job
            raise

    async def submit(self, kind, farm, source, key, prepare, defer=False):
        fingerprint=hashlib.sha256(canonical_json({"kind":kind,"farm":farm.lower(),"source":source})).hexdigest()
        row=await self.db("find_key",self.scope,key,fingerprint)
        if row is None:
            payload=await prepare()
            signer=Account.from_key(settings.blockchain_private_key.get_secret_value()).address.lower()
            row=await self.db("create",self.scope,key,fingerprint,settings.chain_id,settings.contract_address.lower(),signer,farm.lower(),kind,payload)
        # Durable before any RPC. Confirmations are never awaited by this request.
        if row["state"] not in TERMINAL and not defer:
            await self.process(row["id"],retry_configuration=True)
        row=await self.db("get",row["id"],self.scope)
        return row,await self.db("public",row)

    async def process(self, op_id, refresh=False, retry_configuration=False):
        await self.init()
        async with self.lock:
            fd=os.open(str(settings.transaction_db_file)+".writer.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:
                try:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:
                    return
                row=await self.db("get",op_id,self.scope)
                if not row or (row["state"] in TERMINAL and not (refresh and row["state"] in {"confirmed","failed"})):
                    return
                # Only an authenticated same-key submission can retry this state.
                # Scope and signer checks below prevent retargeting the saved intent.
                if row["state"] == "blocked_configuration" and not retry_configuration:
                    return
                try:
                    await self._process_locked(row,read_only=refresh)
                except (ContractConfigurationUnavailable, BadFunctionCallOutput):
                    await self.db("update",op_id,state="blocked_configuration",error="configured contract unavailable or incompatible; correct configuration and retry the same intent",http_error=503)
                except RPCUnavailable:
                    await self.db("update",op_id,error="blockchain RPC unavailable; operation retained",http_error=503,next_attempt=time.time()+5)
                except (ContractLogicError,Web3RPCError) as exc:
                    if row.get("raw_tx"):
                        # A rejection of a broadcast is not proof that it was never accepted.
                        await self.db("update",op_id,state="unknown",error="broadcast unresolved; retained for reconciliation",http_error=503,next_attempt=time.time()+5)
                    else:
                        code=409 if "ya esta registrada" in str(exc) else 400
                        await self.db("update",op_id,state="rejected",error="contract rejected transaction",http_error=code)
                except RuntimeError:
                    await self.db("update",op_id,error="signer or network configuration unavailable",http_error=503,next_attempt=time.time()+5)
            finally:
                os.close(fd)

    async def _process_locked(self,row,read_only=False):
        op_id=row["id"]
        if await self.adapter._read(lambda:self.adapter.w3.eth.chain_id)!=row["chain_id"]:
            raise RuntimeError("chain ID mismatch")
        if not row["raw_tx"]:
            if read_only:
                return
            if Account.from_key(settings.blockchain_private_key.get_secret_value()).address.lower()!=row["signer"]:
                raise RuntimeError("signer changed")
            if row["kind"]=="status" and not await self.adapter.farm_exists(row["farm_id"]):
                await self.db("update",op_id,state="rejected",error="farm not found",http_error=404)
                return
            reserved=await self.db("reserved_nonce",row["chain_id"],row["signer"])
            fn=self.adapter.operation_function(row["kind"],json.loads(row["payload"]))
            prepared=await self.adapter.prepare_signed(fn,None if reserved is None else reserved+1)
            # COMMIT signed bytes + hash + nonce BEFORE broadcasting, including after restart.
            await self.db("update",op_id,state="prepared",**prepared,error=None,http_error=None)
            row.update(prepared,state="prepared")
        else:
            if AsyncWeb3.to_hex(AsyncWeb3.keccak(hexstr=row["raw_tx"])).lower()!=row["tx_hash"] or Account.recover_transaction(row["raw_tx"]).lower()!=row["signer"]:
                raise RuntimeError("stored signed transaction integrity failure")
            try:
                result=await self.adapter.transaction(row["tx_hash"])
            except TransactionNotFound:
                latest=await self.adapter._read(lambda:self.adapter.w3.eth.get_transaction_count(AsyncWeb3.to_checksum_address(row["signer"]),"latest"))
                if latest>row["nonce"]:
                    await self.db("update",op_id,state="replaced",error="nonce consumed by another transaction; operator review required",http_error=409)
                    return
                if read_only:
                    if row["state"] in {"confirmed", "failed"}:
                        # A previously terminal receipt can disappear after a
                        # chain reorganization. Stop reporting it as canonical,
                        # retaining the signed intent for the single writer.
                        await self.db(
                            "update", op_id, state="unknown", result=None,
                            error="previously observed receipt is absent; retained for canonical-chain reconciliation",
                            http_error=None, next_attempt=time.time(),
                        )
                    # GET may reconcile a missing terminal receipt, but it must
                    # never submit a prepared transaction as a side effect.
                    return
            else:
                await self.db("update",op_id,state=result["status"],result=json.dumps(result),error=None,http_error=None,next_attempt=time.time()+settings.transaction_poll_seconds)
                return
        attempts=row["attempts"]+1
        # Saving attempt first covers a process killed inside the RPC call.
        await self.db("update",op_id,attempts=attempts,state="prepared")
        try:
            await self.adapter.broadcast(row["raw_tx"],row["tx_hash"])
        except SubmissionUncertain:
            await self.db("update",op_id,state="unknown",error="submission outcome unknown; same signed transaction retained",http_error=503,next_attempt=time.time()+min(60,2**min(attempts,5)))
        else:
            await self.db("update",op_id,state="submitted",error=None,http_error=None,next_attempt=time.time()+settings.transaction_poll_seconds)

    async def reconcile(self):
        for row in await self.db("active",self.scope):
            await self.process(row["id"])

    async def worker(self):
        while True:
            try:
                await self.reconcile()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Only exception type: no body, RPC credentials, raw tx or key in logs.
                log.error("transaction reconciliation unavailable (%s)",type(exc).__name__)
            await asyncio.sleep(settings.transaction_poll_seconds)

    async def lookup(self,op_id):
        row=await self.db("get",op_id,self.scope)
        return await self.db("public",row) if row else None

    async def transaction(self,tx_hash):
        row=await self.db("by_hash",self.scope,tx_hash)
        if row:
            await self.process(row["id"],refresh=True)
            return await self.lookup(row["id"])
        return await self.adapter.transaction(tx_hash)
