"""Opt-in public projection; never expose the full decrypted CV or polygon."""
import hashlib
import json
import re
import asyncio
import time
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import Depends, File, Header, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, Response
from starlette.concurrency import run_in_threadpool

from .main import app, adapter, require_idempotency, submit_operation
from .auth import require_admin
from .crypto_service import load_server_key
from .models import Bytes32, PlainFarmCVRequest, GeoPolygon
from .config import settings
from .image_service import UnsupportedPhoto, normalize_photo
from .location_catalog import is_valid_colombian_location

ROOT = Path(__file__).resolve().parents[1] / 'storage' / 'public-photos'
PUBLIC_PATH = re.compile(r'^/fincas/0x[0-9a-f]{64}(?:/verificar|/fotos/[0-9a-f]{64}\.jpg)?$')
PUBLIC_ASSETS = {'/assets/leaflet.js': 'text/javascript', '/assets/leaflet.css': 'text/css', '/assets/farm-map.js': 'text/javascript', '/assets/verify-cv.js': 'text/javascript'}
PUBLIC_ASSETS['/assets/orika-home.css'] = 'text/css'
PUBLIC_ASSETS['/assets/orika-territorio-v2.jpg'] = 'image/jpeg'
PUBLIC_ASSETS['/assets/orika-palette.css'] = 'text/css'
PUBLIC_ASSETS['/assets/colombia-divipola.json'] = 'application/json'

def verify_documents(record, cv, farm_id):
    """Only return integrity results; never return decrypted private content."""
    checks=[]
    cipher=Fernet(load_server_key())
    for field, hash_field, label in [('encryptedCV','cvHash','Documento de la finca'),('encryptedPolygon','polygonHash','Polígono geográfico')]:
        start=time.perf_counter()
        try:
            digest='0x'+hashlib.sha256(cipher.decrypt(record[field].encode())).hexdigest()
            passed=digest.lower()==record[hash_field].lower()
        except Exception:
            passed=False
        checks.append({'label':label,'passed':passed,'detail':'SHA-256 coincide con el contrato.' if passed else 'No se pudo demostrar la integridad del documento.', 'durationMs':round((time.perf_counter()-start)*1000)})
    photos=cv.get('photos',[])
    for index,photo in enumerate(photos[:2],1):
        start=time.perf_counter()
        try:
            digest=photo['sha256']
            path=photo_path(farm_id,digest)
            passed=path.is_file() and path.stat().st_size<=10*1024*1024 and hashlib.sha256(path.read_bytes()).hexdigest()==digest
        except Exception:
            passed=False
        checks.append({'label':f'Fotografía {index}','passed':passed,'detail':'Archivo coincide con el hash del CV registrado.' if passed else 'Archivo ausente o hash diferente.', 'durationMs':round((time.perf_counter()-start)*1000)})
    if not photos:
        checks.append({'label':'Fotografías','passed':False,'detail':'No hay fotografías verificables.'})
    return checks

@app.get('/fincas/{farm_id}/verificar')
async def verify_public_cv(farm_id: Bytes32):
    async def perform():
        start=time.perf_counter()
        cv,record=await published(farm_id)
        actual_chain=await adapter._read(lambda: adapter.w3.eth.chain_id)
        code=await adapter._read(lambda: adapter.w3.eth.get_code(settings.contract_address))
        checks=[{'label':'Registro en el contrato','passed':actual_chain==settings.chain_id and bool(code),'detail':f'Red {actual_chain} · versión {record["version"]}.','durationMs':round((time.perf_counter()-start)*1000)}]
        checks.extend(await run_in_threadpool(verify_documents,record,cv,farm_id))
        # Refuse an all-green result if the record changed during verification.
        latest=await adapter.get_farm(farm_id)
        stable=all(latest[k]==record[k] for k in ['version','cvHash','polygonHash','status'])
        checks.append({'label':'Consistencia de la consulta','passed':stable,'detail':'La versión no cambió durante la comprobación.' if stable else 'El registro cambió; vuelve a verificar.'})
        checks.append({'label':'Estado de la finca','passed':record['status']==0,'detail':{0:'Activa',1:'Suspendida',2:'Revocada'}.get(record['status'],'Desconocido')})
        return {'verified':all(c['passed'] for c in checks),'checks':checks,'checkedAt':datetime.now(timezone.utc).isoformat(),'durationMs':round((time.perf_counter()-start)*1000),'farmId':farm_id.lower(),'version':record['version'],'chainId':actual_chain,'network':settings.environment,'contract':settings.contract_address,'demo':actual_chain in {31337,84532},'scope':'Integridad técnica comprobada por la API contra su nodo configurado. No es certificación agrícola, auditoría externa ni prueba independiente del proveedor.'}
    try:
        return await asyncio.wait_for(perform(),timeout=25)
    except asyncio.TimeoutError as exc:
        raise HTTPException(503,'verification timed out; try again') from exc

@app.get('/assets/{name}')
async def map_asset(name: str):
    media = PUBLIC_ASSETS.get('/assets/' + name)
    if not media:
        raise HTTPException(404, 'asset not found')
    return Response(Path(__file__).with_name('assets').joinpath(name).read_bytes(), media_type=media)

def photo_path(farm, digest):
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise HTTPException(422, 'invalid photo hash')
    return ROOT / farm.lower() / (digest + '.jpg')

@app.post('/admin/farms/{farm_id}/photos')
async def upload_public_photo(farm_id: Bytes32, file: UploadFile = File(...), _: str = Depends(require_admin)):
    raw = await file.read(10 * 1024 * 1024 + 1)
    if not raw or len(raw) > 10 * 1024 * 1024:
        raise HTTPException(413, 'Image must be between 1 byte and 10 MB')
    try:
        clean = await run_in_threadpool(normalize_photo, raw, file.content_type)
    except UnsupportedPhoto as exc:
        raise HTTPException(415, 'Use a valid JPEG, PNG or WebP image (maximum 20 megapixels)') from exc
    digest = hashlib.sha256(clean).hexdigest()
    path = photo_path(farm_id, digest)
    def persist():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Content addressed, so retries cannot change an existing photograph.
        try:
            with path.open('xb') as stream:
                stream.write(clean)
        except FileExistsError:
            # Concurrent retries of the same content-addressed upload are idempotent.
            pass
    await run_in_threadpool(persist)
    return {'sha256': digest, 'bytes': len(clean), 'uri': f'public-photo://{farm_id.lower()}/{digest}.jpg'}

@app.post('/admin/farms')
async def register_public_farm(payload: PlainFarmCVRequest, key: str = Depends(require_idempotency), prefer: str | None = Header(default=None)):
    location = payload.cv.location
    if not is_valid_colombian_location(location.get('department'), location.get('municipality')):
        raise HTTPException(422, 'Select a valid Colombian department and municipality')
    description = payload.cv.identification.get('description', '')
    if not isinstance(description, str) or len(description) > 2000:
        raise HTTPException(422, 'description must be text, maximum 2000 characters')
    if payload.cv.quality.get('publicProfileConsent') is not True:
        raise HTTPException(422, 'explicit public profile consent required')
    if not 1 <= len(payload.cv.photos) <= 2:
        raise HTTPException(422, 'one or two photographs required')
    for photo in payload.cv.photos:
        digest = photo.get('sha256')
        if not isinstance(digest, str):
            raise HTTPException(422, 'photo hash required')
        path = photo_path(payload.farm_id, digest)
        if not path.is_file() or hashlib.sha256(await run_in_threadpool(path.read_bytes)).hexdigest() != digest:
            raise HTTPException(422, 'photograph missing or integrity mismatch')
    return await submit_operation('register', payload.farm_id, payload, key, prefer)

async def published(farm_id, *, require_active=False):
    if not await adapter.farm_exists(farm_id):
        raise HTTPException(404, 'public profile not found')
    record = await adapter.get_farm(farm_id)
    if require_active and record.get('status') != 0:
        raise HTTPException(404, 'public profile not found')
    def decode():
        return json.loads(Fernet(load_server_key()).decrypt(record['encryptedCV'].encode()))
    try:
        cv = await run_in_threadpool(decode)
    except Exception as exc:
        raise HTTPException(404, 'public profile unavailable') from exc
    if cv.get('quality', {}).get('publicProfileConsent') is not True:
        raise HTTPException(404, 'public profile not found')
    return cv, record

@app.get('/fincas/{farm_id}/fotos/{digest}.jpg')
async def public_photo(farm_id: Bytes32, digest: str):
    cv, _ = await published(farm_id, require_active=True)
    if digest not in [p.get('sha256') for p in cv.get('photos', [])[:2]]:
        raise HTTPException(404, 'photo not published')
    path = photo_path(farm_id, digest)
    if not path.is_file():
        raise HTTPException(404, 'photo unavailable')
    data = await run_in_threadpool(path.read_bytes)
    if hashlib.sha256(data).hexdigest() != digest:
        raise HTTPException(409, 'photo integrity mismatch')
    return Response(data, media_type='image/jpeg')

@app.get('/fincas/{farm_id}', response_class=HTMLResponse)
async def public_farm(farm_id: Bytes32):
    cv, record = await published(farm_id, require_active=True)
    def safe(value):
        return escape(str(value)[:300])
    name = safe(cv.get('identification', {}).get('farmName', 'Finca de cacao'))
    location = cv.get('location', {})
    production = cv.get('production', {})
    description = escape(str(cv.get('identification', {}).get('description') or 'Esta finca aún no tiene una descripción pública.')[:2000])
    map_html = '<p>El polígono de esta finca no está autorizado para publicación.</p>'
    if cv.get('quality', {}).get('publicPolygonConsent') is True:
        def decode_polygon():
            raw = Fernet(load_server_key()).decrypt(record['encryptedPolygon'].encode())
            return GeoPolygon.model_validate_json(raw).model_dump(mode='json')
        polygon = await run_in_threadpool(decode_polygon)
        encoded = escape(json.dumps(polygon, allow_nan=False), quote=True)
        map_html = f'<div id="farm-map" data-polygon="{encoded}" role="region" aria-label="Mapa del polígono de la finca"></div><p id="map-status" role="status">Cargando mapa…</p><p class="notice">Límite declarado por el administrador, no levantamiento catastral. El mapa base lo proporciona OpenStreetMap; al cargarlo, tu navegador solicita las teselas de esta zona a ese servicio.</p><noscript>Activa JavaScript para visualizar el mapa.</noscript>'
    gallery = ''
    hero = ''
    for index, photo in enumerate(cv.get('photos', [])[:2], 1):
        digest = photo.get('sha256', '')
        if isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest):
            caption = safe(photo.get('caption', f'Fotografía {index}'))
            credits = ''
            if photo.get('author'):
                credits += ' · Autor: ' + safe(photo['author'])
            for key, label in [('source', 'Fuente'), ('licenseUrl', str(photo.get('license', 'Licencia')))]:
                url = photo.get(key, '')
                if isinstance(url, str) and url.startswith('https://'):
                    credits += f' · <a href="{escape(url[:1000], quote=True)}" rel="noopener noreferrer">{safe(label)}</a>'
            if photo.get('changes'):
                credits += ' · ' + safe(photo['changes'])
            figure = f'<figure><img src="/fincas/{farm_id.lower()}/fotos/{digest}.jpg" alt="{caption}" loading="lazy"><figcaption>{caption}{credits}</figcaption></figure>'
            gallery += figure
            if not hero:
                hero = figure.replace('loading="lazy"', 'loading="eager" fetchpriority="high"', 1)
    status = {0: 'Activa', 1: 'Suspendida', 2: 'Revocada'}.get(record['status'], 'Desconocido')
    template = Path(__file__).with_name('public_cv.html').read_text()
    values = {'NAME': name, 'LOCATION': safe(location.get('municipality', '')) + ', ' + safe(location.get('department', '')),
              'AREA': safe(production.get('cultivatedAreaHa', 'No especificada')), 'VARIETY': safe(production.get('variety') or 'No especificada'),
              'STATUS': status, 'STATUS_CLASS': {0:'Active',1:'Suspended',2:'Revoked'}.get(record['status'],'Unknown'), 'HERO': hero,
              'FARM_ID': farm_id.lower(), 'VERSION': safe(record['version']), 'GALLERY': gallery, 'DESCRIPTION': description, 'MAP': map_html}
    # Single substitution pass: user content can never introduce template tokens.
    return HTMLResponse(re.sub(r'\{\{([A-Z_]+)\}\}', lambda m: values[m[1]], template))
