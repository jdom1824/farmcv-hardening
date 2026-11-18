"""Reproducible integration validation; only runs against Hardhat chain 31337.

Run from api/: ../.venv/bin/python tests/validate_hardhat.py
Uses an isolated contract and ephemeral admin credentials in this process.
Never prints signing, encryption, or authentication secrets.
"""
import asyncio
import base64
import hashlib
import io
import importlib.metadata
import json
import os
import secrets
import socket
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import jwt
from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
from web3 import AsyncWeb3, AsyncHTTPProvider

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import main as api
from app.config import settings
from app.crypto_service import canonical_json, encrypt_json, sha256_hex
from app.web3_adapter import FarmCVAdapter, RPCUnavailable
from auto_encryption_checks import run_auto_checks, assert_encrypted_record
from transaction_checks import run_transaction_checks, run_process_crash

results = []
transactions = []
started = time.time()


def check(name, condition, **evidence):
    results.append({"test": name, "passed": bool(condition), **evidence})
    print(name + (": PASS" if condition else ": FAIL"), flush=True)
    if not condition:
        raise AssertionError(name)


async def run():
    w3 = api.adapter.w3
    check("hardhat_chain_guard", await w3.eth.chain_id == 31337 and settings.chain_id == 31337)
    check("hardhat_client_guard", "hardhat" in (await w3.client_version).lower())
    check("automining_initially_enabled", (await w3.provider.make_request("hardhat_getAutomine", []))["result"] is True)
    artifact = json.loads((ROOT / "abi/FarmCVRegistry.json").read_text())
    account = w3.eth.account.from_key(settings.blockchain_private_key.get_secret_value())
    factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    deployment = await factory.constructor().build_transaction({"from": account.address, "nonce": await w3.eth.get_transaction_count(account.address, "pending"), "chainId": 31337})
    signed = account.sign_transaction(deployment)
    receipt = await w3.eth.wait_for_transaction_receipt(await w3.eth.send_raw_transaction(signed.raw_transaction), timeout=30)
    check("isolated_contract_deployment", receipt["status"] == 1)
    settings.contract_address = receipt["contractAddress"]
    api.adapter = FarmCVAdapter()
    adapter = api.adapter
    contract = adapter._contract()
    password = secrets.token_urlsafe(32)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    settings.admin_password_hash = base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()
    settings.jwt_secret = secrets.token_urlsafe(48)
    fid = "0x" + secrets.token_hex(32)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://api.test") as client:
        async def request(name, method, url, expected, **kwargs):
            if method in {"POST","PUT","PATCH"} and url.startswith("/farm-cv"):
                kwargs["headers"]={"Idempotency-Key":secrets.token_hex(16),**kwargs.get("headers",{})}
            before = time.perf_counter()
            response = await client.request(method, url, **kwargs)
            check(name, response.status_code == expected, http_status=response.status_code, latency_ms=round((time.perf_counter()-before)*1000, 2))
            return response

        await request("health_public", "GET", "/health", 200)
        await request("networks_public", "GET", "/networks", 200)
        await request("bad_login", "POST", "/auth/login", 401, json={"username": "admin", "password": "wrong"})
        login = await request("valid_login", "POST", "/auth/login", 200, json={"username": "admin", "password": password})
        headers = {"Authorization": "Bearer " + login.json()["access_token"]}
        claims = jwt.decode(login.json()["access_token"], settings.jwt_secret, algorithms=["HS256"])
        check("jwt_lifetime_15_minutes", claims["exp"] - claims["iat"] == 900)
        await request("valid_admin_token", "GET", "/admin/check", 200, headers=headers)
        outsider = jwt.encode({"sub":"reader", "iat":int(time.time()), "exp":int(time.time())+60}, settings.jwt_secret, algorithm="HS256")
        await request("non_admin_subject_rejected", "GET", "/admin/check", 403, headers={"Authorization":"Bearer " + outsider})
        for name, token in [("tampered", login.json()["access_token"] + "x"), ("missing_exp", jwt.encode({"sub":"admin", "iat":int(time.time())}, settings.jwt_secret, algorithm="HS256")), ("expired", jwt.encode({"sub":"admin", "iat":int(time.time())-60, "exp":int(time.time())-1}, settings.jwt_secret, algorithm="HS256"))]:
            await request("jwt_" + name, "PATCH", f"/farm-cv/{fid}/status", 401, headers={"Authorization": "Bearer " + token}, json={"status":"Suspended"})
        short = jwt.encode({"sub":"admin", "iat":int(time.time()), "exp":int(time.time())+2}, settings.jwt_secret, algorithm="HS256")
        short_headers = {"Authorization":"Bearer " + short}
        await request("short_token_before_expiry", "GET", "/admin/check", 200, headers=short_headers)
        await asyncio.sleep(2.2)
        await request("same_token_after_real_expiry", "GET", "/admin/check", 401, headers=short_headers)
        for method, path in [("POST","/farm-cv"),("PUT",f"/farm-cv/{fid}"),("PATCH",f"/farm-cv/{fid}/status")]:
            await request("expired_write_"+method, method, path, 401, headers=short_headers, json={})
        for method, path, body in [("POST", "/farm-cv", {}), ("PUT", f"/farm-cv/{fid}", {}), ("PATCH", f"/farm-cv/{fid}/status", {"status":"Revoked"})]:
            await request("unauth_"+method, method, path, 401, json=body)
        await request("invalid_path_identifier", "GET", "/farm-cv/not-hex", 422)
        await request("invalid_hash_input", "POST", f"/farm-cv/{fid}/verify", 422, json={"cv_hash":"bad", "polygon_hash":"bad"})
        await request("missing_fields", "POST", "/farm-cv", 422, headers=headers, json={})
        await request("unknown_farm", "GET", f"/farm-cv/{fid}", 404)
        await request("unknown_status_change", "PATCH", f"/farm-cv/{fid}/status", 404, headers=headers, json={"status":"Revoked"})
        await request("invalid_status", "PATCH", f"/farm-cv/{fid}/status", 422, headers=headers, json={"status":99})

        image = io.BytesIO()
        Image.new("RGB", (16,16), color=(60,110,35)).save(image, format="JPEG")
        jpg = image.getvalue()
        photo_path = f"/farm-cv/{fid}/photos"
        await request("photo_requires_auth", "POST", photo_path, 401, files={"file":("a.jpg", jpg, "image/jpeg")})
        await request("fake_jpeg_rejected", "POST", photo_path, 415, headers=headers, files={"file":("a.jpg", b"\xff\xd8\xffjunk", "image/jpeg")})
        await request("wrong_mime_rejected", "POST", photo_path, 415, headers=headers, files={"file":("a.txt", b"abc", "text/plain")})
        await request("oversize_photo_rejected", "POST", photo_path, 413, headers=headers, files={"file":("a.jpg", b"x"*(10*1024*1024+1), "image/jpeg")})
        await request("unsafe_photo_identifier", "POST", "/farm-cv/..%5Cbad/photos", 422, headers=headers, files={"file":("a.jpg", jpg, "image/jpeg")})
        photo = (await request("real_jpeg_upload", "POST", photo_path, 200, headers=headers, files={"file":("a.jpg", jpg, "image/jpeg")})).json()
        stored = ROOT / "storage/photos" / fid / (photo["photoId"] + ".jpg")
        check("photo_persisted_hash", hashlib.sha256(stored.read_bytes()).hexdigest() == photo["sha256"])
        check("photo_tampering_detected", hashlib.sha256(jpg+b"changed").hexdigest() != photo["sha256"])
        cv = {"schemaVersion":"1.0", "farmId":fid, "identification":{"farmName":"Synthetic cacao " + secrets.token_hex(4)}, "photos":[photo]}
        polygon = {"type":"Polygon", "coordinates":[[[0,0],[1,0],[1,1],[0,0]]]}
        key = Fernet.generate_key()
        payload = {"farm_id":fid, "encrypted_cv":encrypt_json(cv,key), "encrypted_polygon":encrypt_json(polygon,key), "cv_hash":sha256_hex(canonical_json(cv)), "polygon_hash":sha256_hex(canonical_json(polygon))}
        await request("public_validation", "POST", "/validation/farm-cv", 200, json=payload)
        await request("zero_hash_rejected", "POST", "/farm-cv", 422, headers=headers, json={**payload,"cv_hash":"0x"+"00"*32})
        await request("signed_hex_rejected", "POST", "/farm-cv", 422, headers=headers, json={**payload,"farm_id":"0x+"+"a"*63})

        async def track(name, response):
            tx_hash = response.json()["txHash"]
            for _ in range(40):
                data = (await client.get("/transactions/"+tx_hash)).json()
                if data.get("status") in ("confirmed","failed"):
                    break
                await asyncio.sleep(.1)
            check(name, data.get("status") == "confirmed", transaction=data)
            check(name+"_gas_sufficient", data["gasLimit"] >= data["gasUsed"] > 0)
            transactions.append(data)
            return data

        registered = await request("encrypted_register", "POST", "/farm-cv", 200, headers=headers, json=payload)
        reg = await track("registration_receipt", registered)
        check("registration_event", reg["events"][0]["event"] == "FarmCVRegistered")
        settings.confirmations_required = 2
        try:
            confirming = (await client.get("/transactions/"+reg["txHash"])).json()
            check("confirming_before_threshold", confirming["status"]=="confirming" and confirming["confirmations"]==1)
            await w3.provider.make_request("evm_mine", [])
            confirmed = (await client.get("/transactions/"+reg["txHash"])).json()
            check("confirmed_at_threshold", confirmed["status"]=="confirmed" and confirmed["confirmations"]>=2)
        finally:
            settings.confirmations_required = 1
        read = (await request("public_read", "GET", f"/farm-cv/{fid}", 200)).json()
        check("encrypted_cv_roundtrip", json.loads(Fernet(key).decrypt(read["encryptedCV"].encode())) == cv)
        check("encrypted_polygon_roundtrip", json.loads(Fernet(key).decrypt(read["encryptedPolygon"].encode())) == polygon)
        hashes = {"cv_hash":payload["cv_hash"],"polygon_hash":payload["polygon_hash"]}
        verified = await request("public_verify", "POST", f"/farm-cv/{fid}/verify", 200, json=hashes)
        check("hashes_match", verified.json()["valid"] is True)
        bad = await client.post(f"/farm-cv/{fid}/verify",json={**hashes,"cv_hash":"0x"+"aa"*32})
        check("changed_hash_detected", bad.json()["valid"] is False)
        await request("duplicate_conflict", "POST", "/farm-cv", 409, headers=headers, json=payload)
        cv["identification"]["farmName"] += " updated"
        payload.update(encrypted_cv=encrypt_json(cv,key), cv_hash=sha256_hex(canonical_json(cv)))
        await track("update_receipt", await request("update_encrypted_cv", "PUT", f"/farm-cv/{fid}", 200, headers=headers, json=payload))
        check("version_two", (await client.get(f"/farm-cv/{fid}")).json()["version"] == 2)
        for old, name, number in [(0,"Suspended",1),(1,"Revoked",2)]:
            rec = await track("receipt_"+name, await request("change_"+name, "PATCH", f"/farm-cv/{fid}/status", 200, headers=headers, json={"status":name}))
            event = rec["events"][0]
            check("event_"+name, event["event"]=="FarmStatusChanged" and event["args"]["previousStatus"]==old and event["args"]["newStatus"]==number and event["args"]["farmId"]==fid)
            check("read_"+name, (await client.get(f"/farm-cv/{fid}")).json()["status"]==number)
        await request("revoked_update_blocked", "PUT", f"/farm-cv/{fid}", 400, headers=headers, json=payload)
        check("rejected_update_preserves_version", (await client.get(f"/farm-cv/{fid}")).json()["version"]==2)
        await request("transaction_unknown", "GET", "/transactions/0x"+"ab"*32, 404)
        await request("transaction_bad_id", "GET", "/transactions/invalid", 422)
        # Real pending and failed receipts on this disposable Hardhat instance.
        await w3.provider.make_request("evm_setAutomine", [False])
        try:
            pending = await request("pending_status_submission", "PATCH", f"/farm-cv/{fid}/status", 200, headers=headers, json={"status":"Active"})
            data = (await client.get("/transactions/"+pending.json()["txHash"])).json()
            check("pending_receipt_state", data["status"]=="pending")
            await w3.provider.make_request("evm_mine", [])
            await track("pending_becomes_confirmed", pending)
            check("reactivated_read", (await client.get(f"/farm-cv/{fid}")).json()["status"]==0)
            others = await w3.eth.accounts
            bad_hash = await contract.functions.changeFarmStatus(fid,1).transact({"from":others[1],"gas":200000})
            await w3.provider.make_request("evm_mine", [])
            failed = (await request("failed_transaction_query", "GET", "/transactions/"+AsyncWeb3.to_hex(bad_hash), 200)).json()
            check("failed_receipt_state", failed["status"]=="failed" and failed["receiptStatus"]==0)
            transactions.append(failed)
        finally:
            await w3.provider.make_request("evm_setAutomine", [True])

        async def concurrent_register():
            return await client.post("/farm-cv", headers={**headers,"Idempotency-Key":secrets.token_hex(16)}, json={**payload,"farm_id":"0x"+secrets.token_hex(32)})
        batch = await asyncio.gather(*(concurrent_register() for _ in range(3)))
        check("concurrent_writes_accepted", all(x.status_code==200 for x in batch))
        for idx, response in enumerate(batch):
            await track("concurrent_receipt_"+str(idx), response)
        nonces = [(await w3.eth.get_transaction(x.json()["txHash"]))["nonce"] for x in batch]
        check("concurrent_nonces_unique", len(set(nonces))==3)
        uncertain_send = AsyncMock(side_effect=TimeoutError("simulated transport timeout"))
        with patch.object(adapter.w3.eth, "send_raw_transaction", uncertain_send):
            uncertain = await request("ambiguous_submission_503", "PATCH", f"/farm-cv/{fid}/status", 503, headers=headers, json={"status":"Active"})
        check("ambiguous_submission_not_retried", uncertain_send.await_count==1 and len(uncertain.json()["txHash"])==66)
        await api.transactions().process(uncertain.json()["operationId"])
        await track("ambiguous_same_hash_recovered",uncertain)

        attempts = 0
        async def intermittent():
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise OSError("simulated transient RPC failure")
            return 31337
        check("read_retry_recovers", await adapter._read(intermittent)==31337 and attempts==3)
        previous_timeout = settings.rpc_timeout_seconds
        settings.rpc_timeout_seconds = .15
        offline = FarmCVAdapter()
        offline.w3 = AsyncWeb3(AsyncHTTPProvider("http://127.0.0.1:1", request_kwargs={"timeout":.1}))
        try:
            with patch.object(api, "adapter", offline):
                await request("unavailable_rpc_503", "GET", f"/farm-cv/{fid}/exists", 503)
            async def slow():
                await asyncio.sleep(2)
            try:
                await adapter._read(slow)
            except RPCUnavailable:
                check("slow_rpc_bounded", True)
            else:
                check("slow_rpc_bounded", False)
        finally:
            settings.rpc_timeout_seconds = previous_timeout
            await offline.w3.provider.disconnect()
        await request("rpc_recovery", "GET", f"/farm-cv/{fid}/exists", 200)
        changed = bytearray(read["encryptedCV"].encode()); changed[-10] ^= 1
        try:
            Fernet(key).decrypt(bytes(changed))
        except InvalidToken:
            check("ciphertext_tampering_detected", True)
        else:
            check("ciphertext_tampering_detected", False)
        auto_body, server_key = await run_auto_checks(check, request, client, headers, w3, track)
        transaction_fid = await run_transaction_checks(check,client,headers,w3,track,auto_body)
        # Separate Uvicorn processes exercise actual HTTP and persistent disk/chain state.
        env = {**os.environ, "JWT_SECRET": settings.jwt_secret, "ADMIN_PASSWORD_HASH":settings.admin_password_hash, "CONTRACT_ADDRESS":settings.contract_address}
        for attempt in range(2):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1",0))
                port = sock.getsockname()[1]
            process = await asyncio.create_subprocess_exec(sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "error", cwd=ROOT, env=env, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            try:
                async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=20) as live:
                    ready = False
                    for _ in range(100):
                        try:
                            ready = (await live.get("/health")).status_code==200
                            if ready:
                                break
                        except httpx.TransportError:
                            pass
                        await asyncio.sleep(.1)
                    check("live_http_ready_"+str(attempt), ready)
                    live_read = await live.get(f"/farm-cv/{fid}")
                    check("live_http_chain_read_"+str(attempt), live_read.status_code==200 and live_read.json()["version"]==2 and live_read.json()["status"]==0)
                    denied = await live.patch(f"/farm-cv/{fid}/status",json={"status":"Suspended"})
                    check("live_http_auth_enforced_"+str(attempt), denied.status_code==401)
                    check("photo_survives_process_restart_"+str(attempt), stored.exists() and hashlib.sha256(stored.read_bytes()).hexdigest()==photo["sha256"])
                    auto_body["cv"]["identification"]["farmName"]="AUTO-HTTP-"+secrets.token_hex(8)
                    live_update=await live.put("/farm-cv/"+auto_body["farm_id"],headers={**headers,"Idempotency-Key":secrets.token_hex(16)},json=auto_body)
                    check("auto_live_update_"+str(attempt),live_update.status_code==200)
                    await track("auto_live_receipt_"+str(attempt),live_update)
                    auto_record=(await live.get("/farm-cv/"+auto_body["farm_id"])).json()
                    assert_encrypted_record(check,"auto_live_after_restart_"+str(attempt),auto_record,auto_body,server_key)
                    check("auto_live_version_"+str(attempt),auto_record["version"]==3+attempt)
            finally:
                if process.returncode is None:
                    process.terminate()
                await asyncio.wait_for(process.wait(), timeout=10)
        await run_process_crash(check,headers,w3,transaction_fid,ROOT)
    await adapter.w3.provider.disconnect()
    await w3.provider.disconnect()


if __name__ == "__main__":
    failure = None
    try:
        asyncio.run(run())
    except Exception as exc:
        failure = type(exc).__name__ + ": " + str(exc)[:300]
        print("RUN_FAILED: " + failure, flush=True)
    finally:
        out = ROOT / "test-results"
        out.mkdir(exist_ok=True)
        report = {"started_unix":started,"duration_seconds":round(time.time()-started,2),"passed":sum(x["passed"] for x in results),"total":len(results),"failure":failure,"tests":results,"transactions":transactions,"scope":"isolated Hardhat; ASGI and live HTTP; Uvicorn restarts and SIGKILL; persistent outbox, idempotency and server encryption", "python":sys.version, "dependencies":{name:importlib.metadata.version(name) for name in ["fastapi","uvicorn","pydantic-settings","web3","PyJWT","cryptography","python-multipart","Pillow","httpx"]}, "source_sha256":{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*sorted((ROOT/"app").glob("*.py")), *sorted((ROOT/"tests").glob("*.py")), ROOT/"abi/FarmCVRegistry.json"]}}
        (out / "hardhat-validation.json").write_text(json.dumps(report,indent=2))
        print(f"RESULT {report['passed']}/{report['total']}; report: {out / 'hardhat-validation.json'}")
    sys.exit(1 if failure else 0)
