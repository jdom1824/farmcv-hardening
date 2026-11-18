"""Local inventory snapshots; RPC indexing and metadata refresh run off-request."""
import asyncio
import json
import logging
import os
import sqlite3
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from types import MappingProxyType

from cryptography.fernet import Fernet
from fastapi import Depends, Query
from starlette.concurrency import run_in_threadpool
from web3 import AsyncWeb3

from .auth import require_admin
from .config import settings
from .crypto_service import load_server_key
from .main import app, adapter

log = logging.getLogger(__name__)
BATCH_SIZE = 100  # The public Base RPC rejects large eth_getLogs ranges.
REORG_OVERLAP = 128
RECORD_MAX_AGE = 60
RECORD_BATCH_SIZE = 8
chain_head = None
scan_status = 'syncing'
refresh_failed = False
_confirmed_hints_cache = OrderedDict()
_confirmed_hints_cache_lock = threading.Lock()
_CONFIRMED_HINTS_CACHE_LIMIT = 16


def index_path():
    return settings.transaction_db_file.parent / f'farm-index-{settings.chain_id}-{settings.contract_address.lower()}.sqlite3'


@contextmanager
def index_db():
    db = sqlite3.connect(index_path(), timeout=5)
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize_index():
    path = index_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)
    with index_db() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS farms(id TEXT PRIMARY KEY, block INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS farms_by_block ON farms(block DESC, id DESC);
            CREATE TABLE IF NOT EXISTS cursor(block INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS scan_metadata(id INTEGER PRIMARY KEY, updated_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, data TEXT NOT NULL, checked_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS public_catalog_meta(id INTEGER PRIMARY KEY CHECK(id = 1), revision INTEGER NOT NULL);
            INSERT OR IGNORE INTO public_catalog_meta(id, revision) VALUES(1, 0);
        ''')


def read_cursor():
    with index_db() as db:
        row = db.execute('SELECT block FROM cursor').fetchone()
        return row[0] if row else settings.contract_deployment_block - 1


def commit_batch(first, last, events):
    """Replace only the inspected range and commit its checkpoint atomically."""
    with index_db() as db:
        db.execute('BEGIN IMMEDIATE')
        previous = {row[0]: row[1] for row in db.execute(
            'SELECT id, block FROM farms WHERE block BETWEEN ? AND ?', (first, last))}
        removed = set(previous).difference(events)
        db.executemany('DELETE FROM farms WHERE id=?', ((fid,) for fid in removed))
        db.executemany('DELETE FROM records WHERE id=?', ((fid,) for fid in removed))
        db.executemany('INSERT OR REPLACE INTO farms(id, block) VALUES(?, ?)', events.items())
        if previous != events:
            _bump_public_catalog_revision(db)
        db.execute('DELETE FROM cursor')
        db.execute('INSERT INTO cursor VALUES(?)', (last,))
        db.execute('INSERT OR REPLACE INTO scan_metadata VALUES(1, ?)', (time.time(),))


def _bump_public_catalog_revision(db):
    """Invalidate in-process public projections in the same write transaction."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='public_catalog_meta'").fetchone():
        return
    db.execute('INSERT OR IGNORE INTO public_catalog_meta(id, revision) VALUES(1, 0)')
    db.execute('UPDATE public_catalog_meta SET revision=revision+1 WHERE id=1')


def _query_confirmed_hints(db, scope):
    rows = db.execute('''SELECT farm_id, MAX(updated),
                MIN(CASE WHEN kind='register' THEN json_extract(result, '$.blockNumber') END)
            FROM operations WHERE scope=? AND state='confirmed' GROUP BY farm_id''', (scope,))
    return {fid: (updated, block) for fid, updated, block in rows}


def confirmed_hints_snapshot():
    """Discover confirmed writes; cache only while the SQLite revision is unchanged.

    The revision and aggregate are read from one SQLite snapshot. Older databases
    without the additive metadata fall back to the original uncached query until
    TransactionStore initializes its schema and triggers.
    """
    path = settings.transaction_db_file
    if not path.is_file():
        return {}, None
    scope = f'{settings.chain_id}:{settings.contract_address.lower()}'
    resolved = path.resolve()
    stat = resolved.stat()
    db = sqlite3.connect(resolved.as_uri() + '?mode=ro', uri=True, timeout=2)
    try:
        db.execute('BEGIN')
        schema_version = db.execute('PRAGMA schema_version').fetchone()[0]
        cache_key = (str(resolved), stat.st_dev, stat.st_ino, schema_version, scope)
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('operations', 'confirmed_hints_meta')"
        )}
        if 'operations' not in tables:
            return {}, None
        if 'confirmed_hints_meta' not in tables:
            return _query_confirmed_hints(db, scope), None
        try:
            revision_row = db.execute(
                'SELECT revision FROM confirmed_hints_meta WHERE id=1'
            ).fetchone()
        except sqlite3.Error:
            revision_row = None
        if revision_row is None:
            return _query_confirmed_hints(db, scope), None
        revision = revision_row[0]
        revision_token = (cache_key, revision)
        # Serialize cache misses so a burst of public reads causes at most one
        # aggregate scan for a given revision in this process.
        with _confirmed_hints_cache_lock:
            cached = _confirmed_hints_cache.get(cache_key)
            if cached is not None and cached[0] == revision:
                _confirmed_hints_cache.move_to_end(cache_key)
                return cached[1], revision_token
            hints = _query_confirmed_hints(db, scope)
            immutable_hints = MappingProxyType(hints)
            # A reader holding an older SQLite snapshot must not overwrite a
            # newer cache entry installed by another request.
            if cached is None or cached[0] <= revision:
                _confirmed_hints_cache[cache_key] = (revision, immutable_hints)
                _confirmed_hints_cache.move_to_end(cache_key)
                while len(_confirmed_hints_cache) > _CONFIRMED_HINTS_CACHE_LIMIT:
                    _confirmed_hints_cache.popitem(last=False)
            return immutable_hints, revision_token
    finally:
        db.close()


def confirmed_hints():
    return confirmed_hints_snapshot()[0]


def refresh_candidates(hints):
    now = time.time()
    with index_db() as db:
        known = dict(db.execute('SELECT farms.id, records.checked_at FROM farms LEFT JOIN records USING(id)'))
    candidates = []
    for fid, (updated, block) in hints.items():
        if (fid in known or block is not None) and (known.get(fid) is None or known[fid] < updated):
            candidates.append((fid, block))
    seen = {fid for fid, _ in candidates}
    for fid, checked_at in sorted(known.items(), key=lambda item: item[1] or 0):
        if fid not in seen and (checked_at is None or now - checked_at >= RECORD_MAX_AGE):
            candidates.append((fid, None))
    return candidates[:RECORD_BATCH_SIZE]


def save_record(fid, registered_block, record, checked_at):
    # The snapshot keeps only encrypted CV and the status/version used by the UI.
    data = json.dumps({key: record[key] for key in ('encryptedCV', 'status', 'version')})
    with index_db() as db:
        db.execute('BEGIN IMMEDIATE')
        existing_farm = db.execute('SELECT block FROM farms WHERE id=?', (fid,)).fetchone()
        existing_record = db.execute('SELECT data, checked_at FROM records WHERE id=?', (fid,)).fetchone()
        if registered_block is not None:
            db.execute('INSERT OR IGNORE INTO farms VALUES(?, ?)', (fid, registered_block))
        current_farm = db.execute('SELECT block FROM farms WHERE id=?', (fid,)).fetchone()
        if current_farm:
            db.execute('INSERT OR REPLACE INTO records VALUES(?, ?, ?)', (fid, data, checked_at))
            if existing_farm is None or existing_record != (data, checked_at):
                _bump_public_catalog_revision(db)


async def refresh_records():
    global refresh_failed
    while True:
        try:
            hints = await run_in_threadpool(confirmed_hints)
            candidates = await run_in_threadpool(refresh_candidates, hints)
            failed = False
            for fid, block in candidates:
                try:
                    checked_at = time.time()
                    record = await adapter.get_farm(fid)
                    await run_in_threadpool(save_record, fid, block, record, checked_at)
                except Exception as exc:
                    failed = True
                    log.warning('farm metadata refresh failed (%s)', type(exc).__name__)
            refresh_failed = failed
        except Exception as exc:
            refresh_failed = True
            log.warning('farm metadata cache unavailable (%s)', type(exc).__name__)
        await asyncio.sleep(5 if not refresh_failed else 15)


async def scan_registrations():
    global chain_head, scan_status
    rewind = True
    while True:
        try:
            head = await adapter._read(lambda: adapter.w3.eth.block_number)
            chain_head = head
            cursor = await run_in_threadpool(read_cursor)
            if cursor > head:
                raise RuntimeError('RPC head behind stored checkpoint')
            first = max(settings.contract_deployment_block, cursor + 1 - (REORG_OVERLAP if rewind else 0))
            scan_status = 'syncing'
            for start in range(first, head + 1, BATCH_SIZE):
                end = min(start + BATCH_SIZE - 1, head)
                logs = await adapter._read(lambda: adapter._contract().events.FarmCVRegistered.get_logs(from_block=start, to_block=end))
                events = {AsyncWeb3.to_hex(event['args']['farmId']).lower(): event['blockNumber'] for event in logs}
                await run_in_threadpool(commit_batch, start, end, events)
                rewind = False  # After failure, resume after the last committed batch.
                await asyncio.sleep(0.15)  # Leave RPC capacity for verification and writes.
            rewind = True
            scan_status = 'ready'
            await asyncio.sleep(30)
        except Exception as exc:
            scan_status = 'degraded'
            log.warning('farm index sync paused (%s)', type(exc).__name__)
            await asyncio.sleep(15)


def read_listing(offset, limit):
    with index_db() as db:
        db.execute('BEGIN')
        total = db.execute('SELECT COUNT(*) FROM farms').fetchone()[0]
        cursor = db.execute('SELECT block FROM cursor').fetchone()
        timestamp = db.execute('SELECT updated_at FROM scan_metadata WHERE id=1').fetchone()
        rows = db.execute('''SELECT farms.id, farms.block, records.data, records.checked_at
            FROM farms LEFT JOIN records USING(id)
            ORDER BY farms.block DESC, farms.id DESC LIMIT ? OFFSET ?''', (limit, offset)).fetchall()
        hints = confirmed_hints()
        hinted_ids = [fid for fid, (_, block) in hints.items() if block is not None]
        pending = False
        # Avoid both a full inventory materialization and one SELECT per hint.
        # Keep batches below SQLite's conservative bind-variable limit.
        for start in range(0, len(hinted_ids), 500):
            batch = hinted_ids[start:start + 500]
            placeholders = ','.join('?' for _ in batch)
            indexed = db.execute(
                f'SELECT COUNT(*) FROM farms WHERE id IN ({placeholders})', batch
            ).fetchone()[0]
            if indexed < len(batch):
                pending = True
                break
    items = []
    for fid, block, data, checked_at in rows:
        updating = not data or (fid in hints and (checked_at or 0) < hints[fid][0])
        pending |= updating
        record = json.loads(data) if data else {}
        try:
            cv = json.loads(Fernet(load_server_key()).decrypt(record['encryptedCV'].encode()))
        except Exception:
            cv = {}
        identification = cv.get('identification', {})
        location = cv.get('location', {})
        items.append({'farmId': fid, 'name': str(identification.get('farmName') or ('Finca sin nombre legible' if data else 'Finca registrada'))[:150],
            'municipality': str(location.get('municipality', ''))[:100], 'department': str(location.get('department', ''))[:100],
            'status': 'Unknown' if updating else {0: 'Active', 1: 'Suspended', 2: 'Revoked'}.get(record.get('status'), 'Unknown'),
            'version': record.get('version'), 'registeredBlock': block,
            'publicUrl': '/fincas/' + fid if cv.get('quality', {}).get('publicProfileConsent') is True else None})
    return {'items': items, 'total': total, 'offset': offset, 'limit': limit,
        'scannedToBlock': cursor[0] if cursor else max(0, settings.contract_deployment_block - 1),
        'indexUpdatedAt': datetime.fromtimestamp(timestamp[0], timezone.utc).isoformat() if timestamp else None,
        'indexStatus': 'degraded' if refresh_failed or scan_status == 'degraded' else ('syncing' if pending else scan_status),
        'chainHead': chain_head}


@app.get('/admin/farms')
async def list_farms(offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=50), _: str = Depends(require_admin)):
    return await run_in_threadpool(read_listing, offset, limit)
