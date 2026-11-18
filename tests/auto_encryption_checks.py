"""Integration checks for server-side encryption; synthetic data only."""
import copy
import hashlib
import json
import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch
from cryptography.fernet import Fernet, InvalidToken
from app.config import settings
from app.crypto_service import load_server_key, canonical_json, sha256_hex
from app.models import PlainFarmCVRequest


def expected_documents(body):
    parsed = PlainFarmCVRequest.model_validate(body)
    cv = parsed.cv.model_dump(mode="json")
    cv["farm_id"] = body["farm_id"].lower()
    return cv, parsed.polygon.model_dump(mode="json")


def assert_encrypted_record(check, name, record, body, key):
    cv, polygon = expected_documents(body)
    check(name+"_cv_decrypts", json.loads(Fernet(key).decrypt(record["encryptedCV"].encode())) == cv)
    check(name+"_polygon_decrypts", json.loads(Fernet(key).decrypt(record["encryptedPolygon"].encode())) == polygon)
    check(name+"_hashes_match_plaintext", record["cvHash"]==sha256_hex(canonical_json(cv)) and record["polygonHash"]==sha256_hex(canonical_json(polygon)))
    check(name+"_not_plaintext", body["cv"]["identification"]["farmName"] not in json.dumps(record) and key.decode() not in json.dumps(record))


async def run_auto_checks(check, request, client, headers, w3, track):
    fid = "0x"+secrets.token_hex(32)
    body = {"farm_id":fid, "cv":{"identification":{"farmName":"AUTO-SECRET-"+secrets.token_hex(8)}, "location":{"municipality":"Synthetic"}}, "polygon":{"type":"Polygon","coordinates":[[[-74,4],[-73.99,4],[-73.99,4.01],[-74,4]]]}}
    key = load_server_key()
    nonce = await w3.eth.get_transaction_count((await w3.eth.accounts)[0], "pending")
    await request("auto_plaintext_auth_required", "POST", "/farm-cv", 401, json=body)
    await request("auto_plaintext_public_validation", "POST", "/validation/farm-cv", 200, json=body)
    invalid = copy.deepcopy(body); invalid["polygon"]["coordinates"][0][-1]=[-75,4]
    await request("auto_open_ring_rejected", "POST", "/farm-cv", 422, headers=headers, json=invalid)
    invalid = copy.deepcopy(body); invalid["polygon"]["coordinates"][0][1]=[190,4]
    await request("auto_invalid_coordinates", "POST", "/farm-cv", 422, headers=headers, json=invalid)
    await request("auto_client_key_rejected", "POST", "/farm-cv", 422, headers=headers, json={**body,"encryption_key":"not-accepted"})
    await request("auto_mixed_envelope_rejected", "POST", "/farm-cv", 422, headers=headers, json={**body,"encrypted_cv":"not-accepted"})
    invalid=copy.deepcopy(body); invalid["cv"]["identification"]["farmName"]="x"*17000
    await request("auto_oversize_document", "POST", "/farm-cv", 422, headers=headers, json=invalid)
    with tempfile.TemporaryDirectory() as folder:
        missing=Path(folder)/"missing.key"
        with patch.object(settings, "cv_encryption_key_file", missing):
            await request("auto_missing_key_blocks_write", "POST", "/farm-cv", 503, headers=headers, json=body)
            await request("auto_validation_needs_no_key", "POST", "/validation/farm-cv", 200, json=body)
        invalid_key=Path(folder)/"invalid.key"
        invalid_key.write_bytes(b"invalid")
        invalid_key.chmod(0o600)
        with patch.object(settings, "cv_encryption_key_file", invalid_key):
            await request("auto_invalid_key_blocks_write", "POST", "/farm-cv", 503, headers=headers, json=body)
        invalid_key.write_bytes(Fernet.generate_key())
        invalid_key.chmod(0o644)
        with patch.object(settings, "cv_encryption_key_file", invalid_key):
            await request("auto_insecure_key_permissions", "POST", "/farm-cv", 503, headers=headers, json=body)
    check("auto_rejections_did_not_send", nonce==await w3.eth.get_transaction_count((await w3.eth.accounts)[0], "pending"))
    response=await request("auto_register_plaintext", "POST", "/farm-cv", 200, headers=headers, json=body)
    rec=await track("auto_register_receipt", response)
    record=(await request("auto_public_encrypted_read", "GET", "/farm-cv/"+fid, 200)).json()
    assert_encrypted_record(check,"auto_registered",record,body,key)
    tx=await w3.eth.get_transaction(rec["txHash"])
    check("auto_calldata_has_no_plaintext_or_key", body["cv"]["identification"]["farmName"].encode() not in bytes(tx["input"]) and key not in bytes(tx["input"]))
    verified=await request("auto_public_hash_verify", "POST", f"/farm-cv/{fid}/verify", 200, json={"cv_hash":record["cvHash"],"polygon_hash":record["polygonHash"]})
    check("auto_public_hashes_valid", verified.json()["valid"] is True)
    await track("auto_update_receipt",await request("auto_update_same_plaintext", "PUT", "/farm-cv/"+fid, 200, headers=headers,json=body))
    updated=(await client.get("/farm-cv/"+fid)).json()
    check("auto_randomized_ciphertext_stable_hash", updated["encryptedCV"]!=record["encryptedCV"] and updated["cvHash"]==record["cvHash"] and updated["version"]==2)
    assert_encrypted_record(check,"auto_updated",updated,body,key)
    try:
        Fernet(Fernet.generate_key()).decrypt(updated["encryptedCV"].encode())
    except InvalidToken:
        check("auto_wrong_key_cannot_decrypt",True)
    else:
        check("auto_wrong_key_cannot_decrypt",False)
    return body, key
