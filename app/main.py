import hashlib
import asyncio
from contextlib import asynccontextmanager, suppress
from uuid import UUID
from starlette.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pathlib import Path
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, status, Header, Query
from pydantic import BaseModel

from .auth import create_access_token, require_admin, verify_password
from .config import settings
from .models import FarmCVRequest, PlainFarmCVRequest, VerifyRequest, Bytes32, StatusRequest
from .crypto_service import prepare_encrypted_payload, EncryptionUnavailable
from .validation import validate_farm_payload
from .web3_adapter import FarmCVAdapter, RPCUnavailable, SubmissionUncertain
from .transaction_service import TransactionService
from .transaction_store import IdempotencyConflict
from .image_service import UnsupportedPhoto, normalize_photo
from web3.exceptions import ContractLogicError, TransactionNotFound, Web3RPCError

adapter = FarmCVAdapter()
_transaction_service = None


def transactions():
    global _transaction_service
    scope=f"{settings.chain_id}:{settings.contract_address.lower()}"
    if _transaction_service is None or _transaction_service.adapter is not adapter or _transaction_service.scope!=scope:
        _transaction_service=TransactionService(adapter)
    return _transaction_service


@asynccontextmanager
async def lifespan(app):
    task=asyncio.create_task(transactions().worker())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        await adapter.w3.provider.disconnect()


app = FastAPI(title=settings.app_name, version="0.2.0", lifespan=lifespan)


def require_idempotency(idempotency_key: str | None=Header(default=None), _:str=Depends(require_admin)):
    if idempotency_key is None or not 8<=len(idempotency_key)<=128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:." for c in idempotency_key):
        raise HTTPException(status_code=422,detail="Idempotency-Key required (8-128 ASCII letters, digits or -_:.); reuse only for the same operation")
    return idempotency_key


@app.exception_handler(IdempotencyConflict)
async def idempotency_conflict(request,exc):
    return JSONResponse(status_code=409,content={"detail":"Idempotency-Key already used with different data"})


async def submit_operation(kind,farm,payload,key,prefer=None):
    async def prepare():
        if kind=="status":
            return {"farm_id":farm,"status":payload.status}
        return (await prepare_write(payload)).model_dump(mode="json")
    defer=prefer is not None and "respond-async" in [item.strip().lower() for item in prefer.split(",")]
    row,result=await transactions().submit(kind,farm,payload.model_dump(mode="json"),key,prepare,defer=defer)
    result["network"]=settings.environment
    code=row["http_error"] or (202 if row["state"] in {"queued","prepared","unknown"} or (defer and row["state"] not in {"confirmed","failed","rejected","replaced"}) else 200)
    response_headers={"Location":"/operations/"+row["id"]}
    if defer:
        response_headers["Preference-Applied"]="respond-async"
    return JSONResponse(status_code=code,content=result,headers=response_headers)


@app.exception_handler(EncryptionUnavailable)
async def encryption_unavailable(request, exc):
    return JSONResponse(status_code=503, content={"detail": "server encryption is unavailable"})


async def prepare_write(payload):
    if isinstance(payload, PlainFarmCVRequest):
        return await run_in_threadpool(prepare_encrypted_payload, payload)
    return payload


@app.exception_handler(RPCUnavailable)
async def rpc_unavailable(request, exc):
    return JSONResponse(status_code=503, content={"detail": "blockchain RPC unavailable"})


@app.exception_handler(SubmissionUncertain)
async def uncertain_submission(request, exc):
    return JSONResponse(status_code=503, content={"detail": "submission outcome unknown; query transaction before retrying", "txHash": exc.tx_hash})


@app.exception_handler(TransactionNotFound)
async def transaction_missing(request, exc):
    return JSONResponse(status_code=404, content={"detail": "transaction not found for this contract"})


@app.exception_handler(Web3RPCError)
async def rpc_error(request, exc):
    return JSONResponse(status_code=502, content={"detail": "blockchain RPC rejected request"})


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(request: LoginRequest) -> dict[str, object]:
    if request.username != settings.admin_username or not verify_password(request.password, settings.admin_password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    return {"access_token": create_access_token(request.username), "token_type": "bearer", "expires_in": settings.jwt_expire_minutes * 60}


@app.get("/admin/check")
async def admin_check(_: str = Depends(require_admin)) -> dict[str, str]:
    return {"status": "authenticated"}


@app.get("/health")
async def health() -> dict[str, object]:
    return {"status": "ok", "environment": settings.environment, "chain_id": settings.chain_id}


@app.get("/networks")
async def networks() -> dict[str, object]:
    return {"environment": settings.environment, "chain_id": settings.chain_id, "rpc_configured": bool(settings.rpc_url)}


@app.get("/farm-cv/{farm_id}/exists")
async def farm_exists(farm_id: Bytes32) -> dict[str, object]:
    return {"farmId": farm_id, "exists": await adapter.farm_exists(farm_id)}


@app.get("/farm-cv/{farm_id}")
async def get_farm(farm_id: Bytes32) -> dict[str, object]:
    if not await adapter.farm_exists(farm_id):
        raise HTTPException(status_code=404, detail="farm not found")
    return await adapter.get_farm(farm_id)


@app.post("/farm-cv/{farm_id}/verify")
async def verify_farm(farm_id: Bytes32, request: VerifyRequest) -> dict[str, object]:
    return {"farmId": farm_id, "valid": await adapter.verify_farm(farm_id, request.cv_hash, request.polygon_hash)}


@app.post("/farm-cv")
async def register_farm(payload: PlainFarmCVRequest | FarmCVRequest, key:str=Depends(require_idempotency),prefer:str|None=Header(default=None)):
    return await submit_operation("register",payload.farm_id,payload,key,prefer)


@app.post("/farm-cv/{farm_id}/photos")
async def upload_photo(farm_id: Bytes32, file: UploadFile = File(...), _: str = Depends(require_admin)) -> dict[str, object]:
    data = await file.read(10 * 1024 * 1024 + 1)
    if not data or len(data) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="file must be between 1 byte and 10 MB")
    try:
        data = await run_in_threadpool(normalize_photo, data, file.content_type)
    except UnsupportedPhoto as exc:
        raise HTTPException(status_code=415, detail="Use a valid JPEG, PNG or WebP image (maximum 20 megapixels)") from exc
    digest = hashlib.sha256(data).hexdigest()
    photo_id = digest[:24]
    path = private_photo_path(farm_id, photo_id)
    def persist_photo():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with path.open("xb") as stream:
                stream.write(data)
        except FileExistsError:
            # Concurrent retries of the same content-addressed upload are idempotent.
            pass
    await run_in_threadpool(persist_photo)
    return {"farmId": farm_id, "photoId": photo_id, "uri": f"storage://photos/{farm_id.lower()}/{photo_id}.jpg", "sha256": digest, "bytes": len(data)}


def private_photo_path(farm_id: str, photo_id: str) -> Path:
    root = Path(__file__).resolve().parents[1] / "storage" / "photos" / farm_id.lower()
    return root / f"{photo_id}.jpg"


@app.put("/farm-cv/{farm_id}")
async def update_farm(farm_id: Bytes32, payload: PlainFarmCVRequest | FarmCVRequest, key:str=Depends(require_idempotency),prefer:str|None=Header(default=None)):
    if payload.farm_id.lower() != farm_id.lower():
        raise HTTPException(status_code=400, detail="farm_id mismatch")
    return await submit_operation("update",farm_id,payload,key,prefer)


@app.patch("/farm-cv/{farm_id}/status")
async def change_status(farm_id: Bytes32, request: StatusRequest, key:str=Depends(require_idempotency),prefer:str|None=Header(default=None)):
    return await submit_operation("status",farm_id,request,key,prefer)


@app.get("/transactions/{tx_hash}")
async def get_transaction(tx_hash: Bytes32):
    return await transactions().transaction(tx_hash.lower())


@app.get("/operations/{operation_id}")
async def get_operation(operation_id: UUID):
    result=await transactions().lookup(str(operation_id))
    if result is None:
        raise HTTPException(status_code=404,detail="operation not found")
    return result


@app.get("/farm-cv/{farm_id}/transactions")
async def farm_transactions(farm_id: Bytes32,limit:int=Query(default=20,ge=1,le=100),offset:int=Query(default=0,ge=0)):
    service=transactions()
    return {"items":await service.db("history",service.scope,farm_id,limit,offset),"limit":limit,"offset":offset}


@app.post("/validation/farm-cv")
async def prevalidate(payload: PlainFarmCVRequest | FarmCVRequest):
    if isinstance(payload, FarmCVRequest):
        validate_farm_payload(payload)
    return {"valid": True}
