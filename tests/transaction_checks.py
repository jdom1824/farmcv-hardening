"""Persistent outbox, idempotency and real process crash checks on Hardhat only."""
import asyncio
import copy
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch
import httpx
from app import main as api
from app.config import settings
from app.transaction_service import TransactionService
from app.web3_adapter import SubmissionUncertain, RPCUnavailable


async def run_transaction_checks(check,client,headers,w3,track,template):
    body=copy.deepcopy(template);body["farm_id"]="0x"+secrets.token_hex(32)
    fid=body["farm_id"]
    keyed={**headers,"Idempotency-Key":secrets.token_hex(16)}
    missing=await client.post("/farm-cv",headers=headers,json=body)
    check("outbox_key_required",missing.status_code==422)
    first=await client.post("/farm-cv",headers=keyed,json=body)
    check("outbox_accepts_request",first.status_code==200)
    await track("outbox_first_receipt",first)
    again=await client.post("/farm-cv",headers=keyed,json=body)
    check("outbox_replay_same_id_and_hash",again.status_code==200 and again.json()["operationId"]==first.json()["operationId"] and again.json()["txHash"]==first.json()["txHash"])
    check("outbox_replay_does_not_modify",(await client.get("/farm-cv/"+fid)).json()["version"]==1)
    other=copy.deepcopy(body);other["cv"]["identification"]["farmName"]+=" changed"
    conflict=await client.post("/farm-cv",headers=keyed,json=other)
    check("outbox_key_conflict",conflict.status_code==409)
    cross=await client.put("/farm-cv/"+fid,headers=keyed,json=body)
    check("outbox_key_cannot_change_action",cross.status_code==409)
    concurrent_headers={**headers,"Idempotency-Key":secrets.token_hex(16)}
    batch=await asyncio.gather(*(client.put("/farm-cv/"+fid,headers=concurrent_headers,json=body) for _ in range(5)))
    check("outbox_parallel_replays_one_operation",all(r.status_code==200 for r in batch) and len({r.json()["operationId"] for r in batch})==1 and len({r.json()["txHash"] for r in batch})==1)
    await track("outbox_concurrent_receipt",batch[0])
    check("outbox_parallel_replays_one_update",(await client.get("/farm-cv/"+fid)).json()["version"]==2)
    op=(await client.get("/operations/"+first.json()["operationId"])).json()
    check("outbox_public_operation",op["status"]=="confirmed" and {h["state"] for h in op["history"]}>={"queued","prepared","submitted","confirmed"})
    history=(await client.get(f"/farm-cv/{fid}/transactions?limit=1")).json()
    check("outbox_history_pagination",len(history["items"])==1 and history["limit"]==1)
    check("outbox_history_limit_validated",(await client.get(f"/farm-cv/{fid}/transactions?limit=1000")).status_code==422)
    check("outbox_public_no_raw_payload",all(x not in json.dumps(history) for x in ["raw_tx","payload","fingerprint",keyed["Idempotency-Key"],body["cv"]["identification"]["farmName"]]))
    check("outbox_unknown_operation_404",(await client.get("/operations/00000000-0000-0000-0000-000000000000")).status_code==404)
    fresh=TransactionService(api.adapter)
    check("outbox_reopened_db_same_operation",(await fresh.lookup(op["operationId"]))["txHash"]==op["txHash"])

    # The node accepted the raw transaction, but the HTTP response was lost.
    broadcast=api.adapter.broadcast
    sent=[]
    async def accepted_then_lost(raw,tx_hash):
        sent.append(tx_hash)
        await broadcast(raw,tx_hash)
        raise SubmissionUncertain(tx_hash)
    with patch.object(api.adapter,"broadcast",accepted_then_lost):
        lost=await client.put("/farm-cv/"+fid,headers={**headers,"Idempotency-Key":secrets.token_hex(16)},json=body)
    check("outbox_response_loss_retained",lost.status_code==503 and lost.json()["status"]=="unknown")
    recovered=TransactionService(api.adapter)
    with patch.object(api.adapter,"broadcast",accepted_then_lost):
        await recovered.process(lost.json()["operationId"])
    data=await recovered.lookup(lost.json()["operationId"])
    check("outbox_response_loss_no_rebroadcast",data["status"]=="confirmed" and len(sent)==1 and data["txHash"]==lost.json()["txHash"])
    check("outbox_response_loss_one_update",(await client.get("/farm-cv/"+fid)).json()["version"]==3)

    # Cancellation after durable signed bytes, before network I/O.
    cancel_key=secrets.token_hex(16)
    async def cancelled(raw,tx_hash):
        raise asyncio.CancelledError()
    try:
        with patch.object(api.adapter,"broadcast",cancelled):
            await client.put("/farm-cv/"+fid,headers={**headers,"Idempotency-Key":cancel_key},json=body)
    except asyncio.CancelledError:
        pass
    stored=(await client.get(f"/farm-cv/{fid}/transactions?limit=1")).json()["items"][0]
    check("outbox_cancel_preserves_signed_hash",stored["status"]=="prepared" and bool(stored["txHash"]))
    async def forbidden_broadcast(*args,**kwargs):
        raise AssertionError("public GET must not broadcast")
    with patch.object(api.adapter,"broadcast",forbidden_broadcast):
        passive=await client.get("/transactions/"+stored["txHash"])
    check("outbox_public_get_never_broadcasts",passive.status_code==200 and passive.json()["status"]=="prepared")
    await TransactionService(api.adapter).process(stored["operationId"])
    retried=await client.put("/farm-cv/"+fid,headers={**headers,"Idempotency-Key":cancel_key},json=body)
    check("outbox_cancel_recovery_same_hash",retried.status_code==200 and retried.json()["txHash"]==stored["txHash"])
    await track("outbox_cancel_recovery_receipt",retried)
    check("outbox_cancel_recovery_one_update",(await client.get("/farm-cv/"+fid)).json()["version"]==4)

    # Persist failure must stop before broadcast; retry the same durable intention.
    svc=api.transactions();db=svc.db;calls=[]
    async def fail_commit(method,*args,**kwargs):
        if method=="update" and "raw_tx" in kwargs:
            raise OSError("simulated storage failure")
        return await db(method,*args,**kwargs)
    async def count_broadcast(raw,tx_hash):
        calls.append(tx_hash);return await broadcast(raw,tx_hash)
    disk_key=secrets.token_hex(16)
    try:
        with patch.object(svc,"db",fail_commit),patch.object(api.adapter,"broadcast",count_broadcast):
            await client.put("/farm-cv/"+fid,headers={**headers,"Idempotency-Key":disk_key},json=body)
    except OSError:
        pass
    check("outbox_disk_failure_no_broadcast",not calls)
    retry=await client.put("/farm-cv/"+fid,headers={**headers,"Idempotency-Key":disk_key},json=body)
    await track("outbox_disk_recovery_receipt",retry)
    check("outbox_disk_recovery_one_update",(await client.get("/farm-cv/"+fid)).json()["version"]==5)
    async_key=secrets.token_hex(16)
    async def no_rpc(*args,**kwargs):
        raise AssertionError("RPC must not run before async acceptance")
    with patch.object(api.adapter,"_read",no_rpc):
        queued=await client.put("/farm-cv/"+fid,headers={**headers,"Idempotency-Key":async_key,"Prefer":"respond-async"},json=body)
    check("outbox_async_accepts_without_rpc",queued.status_code==202 and queued.json()["status"]=="queued" and queued.json()["txHash"] is None)
    check("outbox_async_location",queued.headers["Location"]=="/operations/"+queued.json()["operationId"])
    await TransactionService(api.adapter).process(queued.json()["operationId"])
    await track("outbox_async_receipt",await client.get(queued.headers["Location"]))
    check("outbox_async_one_update",(await client.get("/farm-cv/"+fid)).json()["version"]==6)
    async def unavailable(*args,**kwargs):
        raise RPCUnavailable("simulated outage")
    with patch.object(api.adapter,"_read",unavailable):
        saved=await client.get(queued.headers["Location"])
        history=await client.get(f"/farm-cv/{fid}/transactions")
    check("outbox_history_available_offline",saved.status_code==200 and saved.json()["status"]=="confirmed" and history.status_code==200)
    await check_commit_cancellation(check)
    return fid


async def check_commit_cancellation(check):
    with tempfile.TemporaryDirectory() as folder, patch.object(settings,"transaction_db_file",Path(folder)/"test.sqlite3"):
        svc=TransactionService(api.adapter)
        row=await svc.db("create",svc.scope,"test-key","fixture",31337,settings.contract_address,"fixture-signer","fixture-farm","status",{})
        started=threading.Event();release=threading.Event();unlocked=asyncio.Event()
        original=svc.store.update
        def delayed(*args,**kwargs):
            started.set()
            if not release.wait(5):raise TimeoutError("fixture timeout")
            return original(*args,**kwargs)
        async def write():
            async with svc.lock:
                try:
                    await svc.db("update",row["id"],state="prepared",nonce=1)
                finally:
                    unlocked.set()
        with patch.object(svc.store,"update",delayed):
            task=asyncio.create_task(write())
            try:
                check("outbox_commit_thread_started",await asyncio.to_thread(started.wait,2))
                task.cancel();await asyncio.sleep(.05)
                check("outbox_cancel_keeps_lock_until_commit",not unlocked.is_set() and not task.done())
            finally:
                release.set()
                try:await task
                except asyncio.CancelledError:pass
        persisted=await svc.db("get",row["id"],svc.scope)
        check("outbox_cancel_waits_for_durable_commit",persisted["state"]=="prepared" and persisted["nonce"]==1 and unlocked.is_set())


async def run_process_crash(check,headers,w3,fid,root):
    env={**os.environ,"JWT_SECRET":settings.jwt_secret,"ADMIN_PASSWORD_HASH":settings.admin_password_hash,"CONTRACT_ADDRESS":settings.contract_address,"TRANSACTION_POLL_SECONDS":"0.2"}
    processes=[]
    async def start():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        p=await asyncio.create_subprocess_exec(sys.executable,"-m","uvicorn","app.main:app","--host","127.0.0.1","--port",str(port),"--log-level","error",cwd=root,env=env,stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        processes.append(p)
        client=httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}",timeout=30)
        for _ in range(100):
            try:
                if (await client.get("/health")).status_code==200:
                    return p,client
            except httpx.TransportError:
                pass
            await asyncio.sleep(.1)
        await client.aclose()
        raise AssertionError("Uvicorn did not start")
    clients=[]
    await w3.provider.make_request("evm_setAutomine",[False])
    try:
        p,live=await start();clients.append(live)
        key=secrets.token_hex(16)
        r=await live.patch(f"/farm-cv/{fid}/status",headers={**headers,"Idempotency-Key":key,"Prefer":"respond-async"},json={"status":"Suspended"})
        check("outbox_live_async_submit",r.status_code==202)
        op_id=r.json()["operationId"]
        for _ in range(100):
            prepared=(await live.get("/operations/"+op_id)).json()
            if prepared.get("txHash"):break
            await asyncio.sleep(.2)
        tx_hash=prepared["txHash"]
        check("outbox_worker_prepares_async",bool(tx_hash))
        check("outbox_live_pending_seen",(await live.get("/transactions/"+tx_hash)).json()["status"]=="pending")
        p.kill();await p.wait()
        check("outbox_process_killed",p.returncode<0)
        await w3.provider.make_request("evm_mine",[])
        p2,live2=await start();clients.append(live2)
        for _ in range(100):
            data=(await live2.get("/operations/"+op_id)).json()
            if data.get("status")=="confirmed":break
            await asyncio.sleep(.2)
        check("outbox_worker_recovers_after_sigkill",data.get("status")=="confirmed" and data["txHash"]==tx_hash)
        account=(await w3.eth.accounts)[0];nonce=await w3.eth.get_transaction_count(account,"pending")
        replay=await live2.patch(f"/farm-cv/{fid}/status",headers={**headers,"Idempotency-Key":key},json={"status":"Suspended"})
        check("outbox_replay_after_process_restart",replay.status_code==200 and replay.json()["operationId"]==op_id and replay.json()["txHash"]==tx_hash)
        check("outbox_restart_no_second_transaction",nonce==await w3.eth.get_transaction_count(account,"pending"))
        check("outbox_restart_chain_state",(await live2.get("/farm-cv/"+fid)).json()["status"]==1)
    finally:
        await w3.provider.make_request("evm_setAutomine",[True])
        for client in clients:await client.aclose()
        for process in processes:
            if process.returncode is None:
                process.terminate();await asyncio.wait_for(process.wait(),10)
