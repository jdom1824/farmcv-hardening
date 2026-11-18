"""Async adapter for a single API process owning the signer."""
import asyncio
import json
from pathlib import Path
from aiohttp import ClientError
from eth_account import Account
from web3 import AsyncWeb3, AsyncHTTPProvider
from web3.exceptions import (
    BadFunctionCallOutput,
    ContractLogicError,
    ProviderConnectionError,
    TransactionNotFound,
    Web3RPCError,
)
from .config import settings


class RPCUnavailable(RuntimeError):
    pass


class ContractConfigurationUnavailable(RuntimeError):
    """Contract cannot satisfy the adapter's basic read interface; never broadcast."""
    pass


class SubmissionUncertain(RuntimeError):
    def __init__(self, tx_hash):
        self.tx_hash = tx_hash
        super().__init__("submission outcome unknown; query transaction before retrying")


class FarmCVAdapter:
    def __init__(self):
        # Disable provider retries (its default allowlist includes sendRawTransaction).
        # This adapter retries only reads and exposes uncertain writes to the client.
        self.w3 = AsyncWeb3(AsyncHTTPProvider(settings.rpc_url, request_kwargs={"timeout": settings.rpc_timeout_seconds}, exception_retry_configuration=None))
        abi_path = Path(__file__).resolve().parents[1] / "abi" / "FarmCVRegistry.json"
        self.abi = json.loads(abi_path.read_text(encoding="utf-8"))["abi"] if abi_path.exists() else []
        self._write_lock = asyncio.Lock()

    def _contract(self):
        if not settings.contract_address or not self.abi:
            raise RuntimeError("contract ABI/address not configured")
        return self.w3.eth.contract(address=AsyncWeb3.to_checksum_address(settings.contract_address), abi=self.abi)

    async def _read(self, operation):
        # Only idempotent reads are retried; each attempt has a deadline.
        for attempt in range(3):
            try:
                return await asyncio.wait_for(operation(), timeout=settings.rpc_timeout_seconds)
            except TransactionNotFound:
                # This is a semantic not-found result (e.g. a tx hash not yet
                # indexed), not a transient provider outage. Callers decide
                # whether it means HTTP 404 or a pending receipt.
                raise
            except (ClientError, OSError, TimeoutError, ProviderConnectionError, Web3RPCError) as exc:
                if attempt == 2:
                    raise RPCUnavailable("blockchain RPC unavailable") from exc
                await asyncio.sleep(0.1 * (attempt + 1))

    async def farm_exists(self, farm_id):
        return bool(await self._read(lambda: self._contract().functions.farmExists(farm_id).call()))

    async def get_farm(self, farm_id):
        value = await self._read(lambda: self._contract().functions.getFarmCV(farm_id).call())
        fields = ("farmId", "encryptedCV", "encryptedPolygon", "cvHash", "polygonHash", "version", "timestamp", "status", "registeredBy", "updatedBy")
        return {k: AsyncWeb3.to_hex(v) if isinstance(v, bytes) else v for k, v in zip(fields, value)}

    async def verify_farm(self, farm_id, cv_hash, polygon_hash):
        return bool(await self._read(lambda: self._contract().functions.verifyFarmCV(farm_id, cv_hash, polygon_hash).call()))

    async def _send(self, fn):
        async with self._write_lock:
            prepared = await self.prepare_signed(fn)
            return await self.broadcast(prepared["raw_tx"], prepared["tx_hash"])

    async def prepare_signed(self, fn, nonce_floor=None):
        private_key = settings.blockchain_private_key.get_secret_value()
        if not private_key:
            raise RuntimeError("blockchain signer not configured")
        chain = await self._read(lambda: self.w3.eth.chain_id)
        if chain != settings.chain_id:
            raise RuntimeError("chain ID mismatch")
        account = Account.from_key(private_key)
        owner = await self.validate_contract()
        if owner.lower() != account.address.lower():
            raise RuntimeError("signer is not contract owner")
        nonce = await self._read(lambda: self.w3.eth.get_transaction_count(account.address, "pending"))
        if nonce_floor is not None:
            nonce=max(nonce,nonce_floor)
        estimate = await self._read(lambda: fn.estimate_gas({"from": account.address}))
        gas = (estimate * 120 + 99) // 100
        block = await self._read(lambda: self.w3.eth.get_block("latest"))
        if gas > block["gasLimit"]:
            raise RuntimeError("required gas exceeds block limit")
        tx = await self._read(lambda: fn.build_transaction({"from": account.address, "nonce": nonce, "chainId": chain, "gas": gas}))
        signed = account.sign_transaction(tx)
        tx_hash = AsyncWeb3.to_hex(signed.hash)
        return {"tx_hash":tx_hash,"raw_tx":AsyncWeb3.to_hex(signed.raw_transaction),"nonce":nonce}

    async def validate_contract(self):
        contract = self._contract()
        if not await self._read(lambda: self.w3.eth.get_code(contract.address)):
            raise ContractConfigurationUnavailable("configured address has no contract code")
        try:
            owner = await self._read(lambda: contract.functions.owner().call())
            await self._read(lambda: contract.functions.farmExists(bytes(32)).call())
        except (BadFunctionCallOutput, ContractLogicError) as exc:
            raise ContractConfigurationUnavailable("contract read interface is incompatible") from exc
        return owner

    async def broadcast(self, raw_tx, tx_hash):
        try:
            returned=await asyncio.wait_for(self.w3.eth.send_raw_transaction(bytes.fromhex(raw_tx[2:])),timeout=settings.rpc_timeout_seconds)
        except (ClientError,OSError,TimeoutError,ProviderConnectionError) as exc:
            raise SubmissionUncertain(tx_hash) from exc
        if AsyncWeb3.to_hex(returned).lower()!=tx_hash.lower():
            raise SubmissionUncertain(tx_hash)
        return tx_hash

    def operation_function(self, kind, payload):
        c=self._contract()
        if kind=="register":
            return c.functions.registerFarmCV(*self._payload_args(payload))
        if kind=="update":
            return c.functions.updateFarmCV(*self._payload_args(payload))
        if kind=="status":
            return c.functions.changeFarmStatus(payload["farm_id"],("Active","Suspended","Revoked").index(payload["status"]))
        raise ValueError("unsupported operation")

    def _payload_args(self, p):
        return [p[k] for k in ("farm_id", "encrypted_cv", "encrypted_polygon", "cv_hash", "polygon_hash")]

    async def register_farm(self, payload):
        return await self._send(self._contract().functions.registerFarmCV(*self._payload_args(payload)))

    async def update_farm(self, payload):
        return await self._send(self._contract().functions.updateFarmCV(*self._payload_args(payload)))

    async def change_status(self, farm_id, new_status):
        status = ("Active", "Suspended", "Revoked").index(new_status)
        return await self._send(self._contract().functions.changeFarmStatus(farm_id, status))

    async def transaction(self, tx_hash):
        tx = await self._read(lambda: self.w3.eth.get_transaction(tx_hash))
        if not tx.get("to") or tx["to"].lower() != settings.contract_address.lower():
            raise TransactionNotFound("transaction is not for this contract")
        result = {"txHash": tx_hash, "network": settings.environment, "status": "pending", "confirmations": 0}
        try:
            receipt = await self._read(lambda: self.w3.eth.get_transaction_receipt(tx_hash))
        except TransactionNotFound:
            return result
        height = await self._read(lambda: self.w3.eth.block_number)
        confirmations = max(0, height - receipt["blockNumber"] + 1)
        state = "failed" if receipt["status"] == 0 else ("confirmed" if confirmations >= settings.confirmations_required else "confirming")
        events = []
        contract = self._contract()
        for log in receipt["logs"]:
            if log["address"].lower() != settings.contract_address.lower():
                continue
            for name in ("FarmCVRegistered", "FarmCVUpdated", "FarmStatusChanged"):
                signature = next(x for x in self.abi if x.get("type") == "event" and x["name"] == name)
                topic = AsyncWeb3.keccak(text=name + "(" + ",".join(x["type"] for x in signature["inputs"]) + ")")
                if log["topics"][0] == topic:
                    args = dict(getattr(contract.events, name)().process_log(log)["args"])
                    events.append({"event": name, "args": {k: AsyncWeb3.to_hex(v) if isinstance(v, bytes) else v for k, v in args.items()}})
        result.update(status=state, confirmations=confirmations, blockNumber=receipt["blockNumber"], gasUsed=receipt["gasUsed"], gasLimit=tx["gas"], receiptStatus=receipt["status"], events=events)
        return result
