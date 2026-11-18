"""Public, read-only Oriká entry point and consent-filtered directory."""

import json
import logging
import re
import sqlite3
import threading
import time
import unicodedata
from functools import lru_cache
from html import escape
from pathlib import Path
from urllib.parse import urlencode

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Query, Request
from fastapi.responses import HTMLResponse

from . import admin_farms
from .config import settings
from .crypto_service import load_server_key
from .main import app

HERE = Path(__file__).parent
PUBLIC_PAGES = {'/', '/fincas'}
PAGE_SIZE = 6
MAX_AGE = admin_farms.RECORD_MAX_AGE * 2
MAX_PUBLIC_SNAPSHOT_PROFILES = 20_000
ID = re.compile(r'0x[0-9a-f]{64}')
DIGEST = re.compile(r'[0-9a-f]{64}')
LOGO = re.compile(r'<img class="brand-logo" src="(data:image/png;base64,[A-Za-z0-9+/=]+)"')
log = logging.getLogger(__name__)
_public_snapshot_cache = None
_public_snapshot_lock = threading.Lock()


@lru_cache(maxsize=1)
def templates():
    portal = (HERE / 'portal.html').read_text(encoding='utf-8')
    logo = LOGO.search(portal)
    return (
        (HERE / 'public_home.html').read_text(encoding='utf-8'),
        logo.group(1) if logo else '',
        portal.replace(
            '<div class="topbar-brand"><img class="brand-logo"',
            '<div class="topbar-brand"><a href="/" aria-label="Volver a Oriká"><img class="brand-logo"',
            1,
        ).replace('alt="Oriká"><span class="brand-divider">', 'alt="Oriká"></a><span class="brand-divider">', 1),
    )


def folded(value):
    return ''.join(c for c in unicodedata.normalize('NFKD', value.casefold()) if not unicodedata.combining(c))


def _legacy_public_cards(db, query, page, hints, now):
    """Original streaming projection; used when revision metadata is unavailable/too large."""
    threshold = now - MAX_AGE
    tokens = folded(query).split()
    start = (page - 1) * PAGE_SIZE
    items = []
    matched = 0
    cipher = None
    rows = db.execute('''SELECT farms.id, records.data, records.checked_at
        FROM farms JOIN records USING(id)
        WHERE records.checked_at >= ?
        ORDER BY farms.block DESC, farms.id DESC''', (threshold,))
    for farm_id, raw, checked_at in rows:
        if not ID.fullmatch(farm_id) or (farm_id in hints and checked_at < hints[farm_id][0]):
            continue
        try:
            record = json.loads(raw)
            if record.get('status') != 0:
                continue
        except (ValueError, TypeError, AttributeError):
            continue
        if cipher is None:
            cipher = Fernet(load_server_key())
        try:
            cv = json.loads(cipher.decrypt(record['encryptedCV'].encode()))
            if cv.get('quality', {}).get('publicProfileConsent') is not True:
                continue
            name = str(cv.get('identification', {}).get('farmName') or 'Finca de cacao')[:150]
            location = cv.get('location', {})
            municipality = str(location.get('municipality') or '')[:100]
            department = str(location.get('department') or '')[:100]
            photo = next((p['sha256'] for p in cv.get('photos', [])[:2]
                          if isinstance(p.get('sha256'), str) and DIGEST.fullmatch(p['sha256'])), None)
        except (InvalidToken, ValueError, TypeError, KeyError, AttributeError):
            continue
        if any(term not in folded(f'{name} {municipality} {department}') for term in tokens):
            continue
        if matched >= start:
            items.append((farm_id, name, municipality, department, photo))
            if len(items) > PAGE_SIZE:
                break
        matched += 1
    return items[:PAGE_SIZE], len(items) > PAGE_SIZE


def _build_public_snapshot(db, hints, now):
    """Build only the consented public projection; never retain encrypted/raw CV."""
    threshold = now - MAX_AGE
    rows = db.execute('''SELECT farms.id, records.data, records.checked_at
        FROM farms JOIN records USING(id)
        WHERE records.checked_at >= ?
        ORDER BY farms.block DESC, farms.id DESC''', (threshold,))
    snapshot = []
    expires_at = None
    cipher = None
    for farm_id, raw, checked_at in rows:
        if not ID.fullmatch(farm_id) or (farm_id in hints and checked_at < hints[farm_id][0]):
            continue
        try:
            record = json.loads(raw)
            if record.get('status') != 0:
                continue
        except (ValueError, TypeError, AttributeError):
            continue
        if cipher is None:
            cipher = Fernet(load_server_key())
        try:
            cv = json.loads(cipher.decrypt(record['encryptedCV'].encode()))
            if cv.get('quality', {}).get('publicProfileConsent') is not True:
                continue
            name = str(cv.get('identification', {}).get('farmName') or 'Finca de cacao')[:150]
            location = cv.get('location', {})
            municipality = str(location.get('municipality') or '')[:100]
            department = str(location.get('department') or '')[:100]
            photo = next((p['sha256'] for p in cv.get('photos', [])[:2]
                          if isinstance(p.get('sha256'), str) and DIGEST.fullmatch(p['sha256'])), None)
        except (InvalidToken, ValueError, TypeError, KeyError, AttributeError):
            continue
        if len(snapshot) >= MAX_PUBLIC_SNAPSHOT_PROFILES:
            return None
        searchable = folded(f'{name} {municipality} {department}')
        snapshot.append((farm_id, name, municipality, department, photo, searchable, checked_at))
        expiration = checked_at + MAX_AGE
        expires_at = expiration if expires_at is None else min(expires_at, expiration)
    return tuple(snapshot), expires_at


def _page_from_snapshot(snapshot, query, page):
    tokens = folded(query).split()
    start = (page - 1) * PAGE_SIZE
    items = []
    matched = 0
    for farm_id, name, municipality, department, photo, searchable, _checked_at in snapshot:
        if any(term not in searchable for term in tokens):
            continue
        if matched >= start:
            items.append((farm_id, name, municipality, department, photo))
            if len(items) > PAGE_SIZE:
                break
        matched += 1
    return items[:PAGE_SIZE], len(items) > PAGE_SIZE


def public_cards(query='', page=1):
    """Serve fresh consented public cards from a revision-bound in-memory projection."""
    global _public_snapshot_cache
    hints, hints_version = admin_farms.confirmed_hints_snapshot()
    now = time.time()
    path = admin_farms.index_path()
    with admin_farms.index_db() as db:
        db.execute('BEGIN')
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='public_catalog_meta'"
        )}
        if not tables or hints_version is None:
            return _legacy_public_cards(db, query, page, hints, now)
        try:
            revision_row = db.execute('SELECT revision FROM public_catalog_meta WHERE id=1').fetchone()
        except sqlite3.Error:
            revision_row = None
        if revision_row is None:
            return _legacy_public_cards(db, query, page, hints, now)

        resolved = path.resolve()
        stat = resolved.stat()
        schema_version = db.execute('PRAGMA schema_version').fetchone()[0]
        snapshot_key = (str(resolved), stat.st_dev, stat.st_ino, schema_version,
                        revision_row[0], hints_version)
        use_fallback = False
        with _public_snapshot_lock:
            cached = _public_snapshot_cache
            if (cached is not None and cached[0] == snapshot_key and
                    (cached[2] is None or time.time() <= cached[2])):
                snapshot = cached[1]
            else:
                built = _build_public_snapshot(db, hints, now)
                if built is None:
                    # Never truncate: oversized catalogs retain the previous exact streaming behavior.
                    use_fallback = True
                    snapshot = None
                else:
                    snapshot, expires_at = built
                    if expires_at is not None and time.time() > expires_at:
                        use_fallback = True
                    else:
                        _public_snapshot_cache = (snapshot_key, snapshot, expires_at)
        if use_fallback:
            return _legacy_public_cards(db, query, page, hints, time.time())
        return _page_from_snapshot(snapshot, query, page)


def render_cards(cards):
    result = []
    for farm_id, name, municipality, department, photo in cards:
        url = '/fincas/' + farm_id
        location = ' · '.join(filter(None, (municipality, department))) or 'Ubicación no indicada'
        image = (f'<img src="{url}/fotos/{photo}.jpg" alt="" loading="lazy" decoding="async">' if photo else '')
        demo = '<span class="demo-tag">Demostración</span>' if settings.chain_id in {31337, 84532} else ''
        result.append(f'''<article class="farm-card">
          <a class="farm-link" href="{url}">
            <div class="farm-photo">{image}{demo}</div>
            <div class="farm-body"><p class="location">{escape(location)}</p><h2>{escape(name)}</h2>
              <span class="farm-action">Ver CV <span aria-hidden="true">↗</span></span>
            </div>
          </a>
        </article>''')
    return ''.join(result)


@app.get('/admin', response_class=HTMLResponse, include_in_schema=False)
def admin_entry():
    return templates()[2]


@app.get('/', response_class=HTMLResponse, include_in_schema=False)
@app.get('/fincas', response_class=HTMLResponse, include_in_schema=False)
def public_entry(request: Request, q: str = Query('', max_length=120), page: int = Query(1, ge=1, le=1000)):
    template, logo, _ = templates()
    listing = request.url.path == '/fincas'
    demo = settings.chain_id in {31337, 84532}
    fields = {
        'TITLE': 'Fincas públicas' if listing else 'Trazabilidad del cacao',
        'LOGO': logo,
        'PROJECT_CURRENT': '' if listing else ' aria-current="page"',
        'FARMS_CURRENT': ' aria-current="page"' if listing else '',
        'ENVIRONMENT': '<span class="mode"><i></i> Entorno de demostración</span>' if demo else '',
        'VIEW': 'directory' if listing else 'project',
        'QUERY': escape(q),
        'CARDS': '',
        'PAGINATION': '',
        'NOTICE': '',
    }
    if listing:
        try:
            cards, has_more = public_cards(q.strip(), page)
        except (sqlite3.Error, ValueError, OSError, RuntimeError):
            log.warning('Public directory snapshot unavailable')
            fields['NOTICE'] = '<p class="notice">El catálogo no está disponible en este momento. Intenta de nuevo en unos minutos.</p>'
        else:
            fields['CARDS'] = render_cards(cards)
            if not cards:
                message = ('Prueba con otro nombre o municipio.' if q else
                           'Las fichas aparecerán aquí cuando estén activas y autorizadas para publicación.')
                fields['NOTICE'] = f'<div class="notice"><strong>No hay fincas para mostrar.</strong><p>{message}</p></div>'
            links = []
            if page > 1:
                links.append((page - 1, '‹ Anterior'))
            if has_more and page < 1000:
                links.append((page + 1, 'Siguiente ›'))
            fields['PAGINATION'] = ''.join(
                f'<a href="/fincas?{escape(urlencode({"q": q, "page": number}))}">{label}</a>'
                for number, label in links)
    return re.sub(r'\{\{([A-Z_]+)\}\}', lambda m: fields[m[1]], template)
