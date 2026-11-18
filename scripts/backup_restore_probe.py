"""Synthetic SQLite outbox and off-chain photo backup/restore integrity probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.transaction_store import IdempotencyConflict, TransactionStore


SCOPE = "31337:0x" + "ab" * 20
CONTRACT = "0x" + "ab" * 20
SIGNER = "0x" + "cd" * 20
STATES = {
    "queued": (),
    "prepared": ("prepared",),
    "submitted": ("prepared", "submitted"),
    "pending": ("prepared", "submitted", "pending"),
    "confirmed": ("prepared", "submitted", "pending", "confirming", "confirmed"),
}


def backup_sqlite(source_path: Path, destination_path: Path) -> None:
    source = sqlite3.connect(source_path)
    destination = sqlite3.connect(destination_path)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()


def integrity_check(path: Path) -> str:
    db = sqlite3.connect(path)
    try:
        return db.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        db.close()


def database_snapshot(path: Path) -> dict:
    db = sqlite3.connect(path)
    try:
        operations = db.execute(
            """SELECT id,scope,idem,fingerprint,chain_id,contract,signer,farm_id,kind,
                      state,nonce,tx_hash,raw_tx,result,attempts
               FROM operations ORDER BY idem"""
        ).fetchall()
        transitions = db.execute(
            "SELECT operation_id,state,at FROM transitions ORDER BY seq"
        ).fetchall()
        return {"operations": operations, "transitions": transitions}
    finally:
        db.close()


def create_synthetic_outbox(path: Path) -> tuple[TransactionStore, dict[str, str]]:
    store = TransactionStore(path)
    operation_ids = {}
    for number, (final_state, transitions) in enumerate(STATES.items(), 1):
        farm_id = "0x" + f"{number:064x}"
        idem = f"backup-probe-key-{final_state}"
        fingerprint = hashlib.sha256(f"synthetic:{final_state}".encode()).hexdigest()
        row = store.create(
            SCOPE, idem, fingerprint, 31337, CONTRACT, SIGNER, farm_id, "register",
            {"synthetic": True, "scenario": final_state},
        )
        operation_ids[final_state] = row["id"]
        if store.create(
            SCOPE, idem, fingerprint, 31337, CONTRACT, SIGNER, farm_id, "register",
            {"synthetic": True, "scenario": final_state},
        )["id"] != row["id"]:
            raise AssertionError("idempotent replay created a duplicate operation")
        try:
            store.create(
                SCOPE, idem, "different-synthetic-fingerprint", 31337, CONTRACT,
                SIGNER, farm_id, "register", {"synthetic": True},
            )
        except IdempotencyConflict:
            pass
        else:
            raise AssertionError("conflicting idempotency replay was accepted")

        tx_hash = "0x" + hashlib.sha256(f"synthetic-tx-{final_state}".encode()).hexdigest()
        raw_tx = "0x" + hashlib.sha256(f"synthetic-raw-{final_state}".encode()).hexdigest()
        nonce = number * 10
        for state in transitions:
            values = {"state": state, "nonce": nonce}
            if state in {"submitted", "pending", "confirming", "confirmed"}:
                values.update(tx_hash=tx_hash, raw_tx=raw_tx)
            if state == "confirmed":
                values["result"] = json.dumps(
                    {"blockNumber": number * 100, "receiptStatus": 1},
                    separators=(",", ":"),
                )
            store.update(row["id"], **values)
    return store, operation_ids


def run_probe() -> dict:
    with tempfile.TemporaryDirectory(prefix="farmcv-backup-restore-") as temporary:
        root = Path(temporary)
        source_db = root / "source" / "operations.sqlite3"
        backup_db = root / "backup" / "operations.sqlite3"
        restored_db = root / "restored" / "operations.sqlite3"
        source_photos = root / "source" / "photos"
        backup_photos = root / "backup" / "photos"
        restored_photos = root / "restored" / "photos"
        source_db.parent.mkdir(parents=True)
        backup_db.parent.mkdir(parents=True)
        restored_db.parent.mkdir(parents=True)

        store, operation_ids = create_synthetic_outbox(source_db)
        photo_hashes = {}
        for index in range(1, 4):
            payload = b"\xff\xd8\xffsynthetic-jpeg-" + str(index).encode() + b"\xff\xd9"
            digest = hashlib.sha256(payload).hexdigest()
            photo = source_photos / f"farm-{index}" / f"{digest}.jpg"
            photo.parent.mkdir(parents=True, exist_ok=True)
            photo.write_bytes(payload)
            photo_hashes[str(photo.relative_to(source_photos))] = digest

        source_snapshot = database_snapshot(source_db)
        source_integrity = integrity_check(source_db)
        if source_integrity != "ok":
            raise AssertionError(f"source integrity check failed: {source_integrity}")

        backup_sqlite(source_db, backup_db)
        shutil.copytree(source_photos, backup_photos)
        backup_integrity = integrity_check(backup_db)
        if backup_integrity != "ok" or database_snapshot(backup_db) != source_snapshot:
            raise AssertionError("SQLite backup differs from its source or failed integrity check")

        backup_sqlite(backup_db, restored_db)
        shutil.copytree(backup_photos, restored_photos)
        restored_integrity = integrity_check(restored_db)
        restored_snapshot = database_snapshot(restored_db)
        if restored_integrity != "ok" or restored_snapshot != source_snapshot:
            raise AssertionError("restored SQLite database differs from source")

        restored_store = TransactionStore(restored_db)
        active_ids = {row["id"] for row in restored_store.active(SCOPE)}
        expected_active = {operation_ids[name] for name in STATES if name != "confirmed"}
        if active_ids != expected_active:
            raise AssertionError("active/pending operations were not preserved")
        if restored_store.reserved_nonce(31337, SIGNER) != 40:
            raise AssertionError("reserved nonce state was not preserved")
        replay = restored_store.find_key(
            SCOPE, "backup-probe-key-pending",
            hashlib.sha256(b"synthetic:pending").hexdigest(),
        )
        if not replay or replay["id"] != operation_ids["pending"]:
            raise AssertionError("restored idempotency key did not resolve to its operation")

        restored_hashes = {}
        for path in restored_photos.rglob("*.jpg"):
            relative = str(path.relative_to(restored_photos))
            restored_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        if restored_hashes != photo_hashes:
            raise AssertionError("restored photo hashes do not match")

        if not source_db.exists() or database_snapshot(source_db) != source_snapshot:
            raise AssertionError("source database was altered or removed")
        return {
            "scope": "synthetic TemporaryDirectory; no live data, chain or network",
            "sqlite_integrity": {
                "source": source_integrity,
                "backup": backup_integrity,
                "restored": restored_integrity,
            },
            "operations_preserved": len(restored_snapshot["operations"]),
            "transitions_preserved": len(restored_snapshot["transitions"]),
            "operation_states": sorted({row[9] for row in restored_snapshot["operations"]}),
            "active_pending_operations_preserved": len(active_ids),
            "reserved_nonce": 40,
            "idempotency_replay_preserved": True,
            "synthetic_photo_count": len(restored_hashes),
            "synthetic_photo_hashes_match": True,
            "source_preserved": True,
            "store_created": bool(store),
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "test-results" / "backup-restore-validation.json",
    )
    args = parser.parse_args()
    result = run_probe()
    output = json.dumps(result, indent=2) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
