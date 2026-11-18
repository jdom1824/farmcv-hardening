"""Durable outbox. No plaintext CV, private keys or JWTs are stored here."""
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class IdempotencyConflict(Exception):
    pass


class TransactionStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript('''
                CREATE TABLE IF NOT EXISTS operations (
                  id TEXT PRIMARY KEY, scope TEXT NOT NULL, idem TEXT NOT NULL,
                  fingerprint TEXT NOT NULL, chain_id INTEGER NOT NULL,
                  contract TEXT NOT NULL, signer TEXT NOT NULL, farm_id TEXT NOT NULL,
                  kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL,
                  nonce INTEGER, tx_hash TEXT, raw_tx TEXT, result TEXT,
                  error TEXT, http_error INTEGER, attempts INTEGER NOT NULL DEFAULT 0,
                  created REAL NOT NULL, updated REAL NOT NULL, next_attempt REAL NOT NULL DEFAULT 0,
                  UNIQUE(scope, idem));
                CREATE INDEX IF NOT EXISTS operations_farm ON operations(scope,farm_id,created);
                CREATE INDEX IF NOT EXISTS operations_hash ON operations(scope,tx_hash);
                CREATE TABLE IF NOT EXISTS transitions (
                  seq INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL,
                  state TEXT NOT NULL, at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS confirmed_hints_meta (
                  id INTEGER PRIMARY KEY CHECK(id = 1), revision INTEGER NOT NULL);
                INSERT OR IGNORE INTO confirmed_hints_meta(id, revision) VALUES(1, 0);

                -- The public/admin readers cache the aggregate by this monotonic
                -- revision. Bump only when a confirmed row can affect its result.
                -- New writes enter as queued; this trigger handles the rare direct
                -- insert of an already-confirmed row without adding a probe to every
                -- ordinary queued insert.
                CREATE TRIGGER IF NOT EXISTS operations_hints_insert_v1
                BEFORE INSERT ON operations
                WHEN NEW.state = 'confirmed'
                BEGIN
                  INSERT OR IGNORE INTO confirmed_hints_meta(id, revision) VALUES(1, 0);
                  UPDATE confirmed_hints_meta SET revision = revision + 1 WHERE id = 1;
                END;

                CREATE TRIGGER IF NOT EXISTS operations_hints_update_v1
                AFTER UPDATE OF scope, farm_id, kind, state, result, updated ON operations
                WHEN (OLD.state = 'confirmed' OR NEW.state = 'confirmed') AND (
                  OLD.scope IS NOT NEW.scope OR OLD.farm_id IS NOT NEW.farm_id OR
                  OLD.kind IS NOT NEW.kind OR OLD.state IS NOT NEW.state OR
                  OLD.result IS NOT NEW.result OR OLD.updated IS NOT NEW.updated
                )
                BEGIN
                  INSERT OR IGNORE INTO confirmed_hints_meta(id, revision) VALUES(1, 0);
                  UPDATE confirmed_hints_meta SET revision = revision + 1 WHERE id = 1;
                END;

                CREATE TRIGGER IF NOT EXISTS operations_hints_delete_v1
                AFTER DELETE ON operations
                WHEN OLD.state = 'confirmed'
                BEGIN
                  INSERT OR IGNORE INTO confirmed_hints_meta(id, revision) VALUES(1, 0);
                  UPDATE confirmed_hints_meta SET revision = revision + 1 WHERE id = 1;
                END;
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def find_key(self, scope, key, fingerprint):
        with self.connect() as db:
            row = db.execute("SELECT * FROM operations WHERE scope=? AND idem=?", (scope,key)).fetchone()
        if row and row["fingerprint"] != fingerprint:
            raise IdempotencyConflict()
        return dict(row) if row else None

    def create(self, scope, key, fingerprint, chain, contract, signer, farm, kind, payload):
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM operations WHERE scope=? AND idem=?", (scope,key)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint:
                    raise IdempotencyConflict()
                return dict(row)
            op_id = str(uuid.uuid4())
            db.execute('''INSERT INTO operations
              (id,scope,idem,fingerprint,chain_id,contract,signer,farm_id,kind,payload,state,created,updated)
              VALUES(?,?,?,?,?,?,?,?,?,?,'queued',?,?)''',
              (op_id,scope,key,fingerprint,chain,contract,signer,farm,kind,json.dumps(payload),now,now))
            db.execute("INSERT INTO transitions(operation_id,state,at) VALUES(?,'queued',?)",(op_id,now))
        return self.get(op_id,scope)

    def get(self, op_id, scope):
        with self.connect() as db:
            row=db.execute("SELECT * FROM operations WHERE id=? AND scope=?",(op_id,scope)).fetchone()
        return dict(row) if row else None

    def by_hash(self, scope, tx_hash):
        with self.connect() as db:
            row=db.execute("SELECT * FROM operations WHERE scope=? AND tx_hash=?",(scope,tx_hash.lower())).fetchone()
        return dict(row) if row else None

    def update(self, op_id, **values):
        allowed={"state","nonce","tx_hash","raw_tx","result","error","http_error","attempts","next_attempt"}
        if not set(values)<=allowed:
            raise ValueError("unsupported persistence field")
        values["updated"]=time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old=db.execute("SELECT state FROM operations WHERE id=?",(op_id,)).fetchone()
            db.execute("UPDATE operations SET "+",".join(k+"=?" for k in values)+" WHERE id=?",[*values.values(),op_id])
            if "state" in values and values["state"] != old["state"]:
                db.execute("INSERT INTO transitions(operation_id,state,at) VALUES(?,?,?)",(op_id,values["state"],values["updated"]))

    def active(self, scope):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM operations WHERE scope=? AND state NOT IN ('confirmed','failed','rejected','replaced','blocked_configuration') AND next_attempt<=? ORDER BY created LIMIT 100",(scope,time.time()))]

    def reserved_nonce(self, chain, signer):
        with self.connect() as db:
            return db.execute("SELECT MAX(nonce) FROM operations WHERE chain_id=? AND signer=? AND state IN ('prepared','unknown','submitted','pending','confirming')",(chain,signer)).fetchone()[0]

    def history(self, scope, farm, limit, offset):
        with self.connect() as db:
            rows=db.execute("SELECT * FROM operations WHERE scope=? AND farm_id=? ORDER BY created DESC,id LIMIT ? OFFSET ?",(scope,farm.lower(),limit,offset))
            return [self.public(dict(r), db) for r in rows]

    def public(self, row, db=None):
        result=json.loads(row["result"]) if row.get("result") else {}
        result.update(operationId=row["id"],farmId=row["farm_id"],kind=row["kind"],chainId=row["chain_id"],contract=row["contract"],status=row["state"],txHash=row["tx_hash"],createdAt=row["created"],updatedAt=row["updated"],attempts=row["attempts"])
        if row.get("error"):
            result["detail"]=row["error"]
        if row["state"] == "blocked_configuration":
            result["error"]={"code":"CONTRACT_UNAVAILABLE","message":row["error"]}
        if db is None:
            with self.connect() as conn:
                return self.public(row,conn)
        result["history"]=[dict(r) for r in db.execute("SELECT state,at FROM transitions WHERE operation_id=? ORDER BY seq",(row["id"],))]
        return result
