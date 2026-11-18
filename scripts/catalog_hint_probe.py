"""Offline end-to-end listing probe with 10k synthetic confirmed-operation hints."""

from __future__ import annotations

import json
import math
import platform
import resource
import statistics
import sys
import tempfile
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import admin_farms


FARMS = 50_000
HINTS = 10_000
SEQUENTIAL_REQUESTS = 8
CONCURRENT_REQUESTS = 16
CONCURRENT_WORKERS = 4
PAGE_SIZE = 20


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percent * len(ordered)) - 1)]


def run_scenario(*, present: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="farmcv-catalog-hints-") as folder:
        folder_path = Path(folder)
        settings = SimpleNamespace(
            transaction_db_file=folder_path / "operations.sqlite3",
            chain_id=31337,
            contract_address="0x" + "ab" * 20,
            contract_deployment_block=0,
        )
        with patch.object(admin_farms, "settings", settings), \
                patch.object(admin_farms, "load_server_key", return_value=Fernet.generate_key()), \
                patch.object(admin_farms, "scan_status", "ready"), \
                patch.object(admin_farms, "refresh_failed", False):
            admin_farms.initialize_index()
            now = time.time()
            key = admin_farms.load_server_key()
            cv = {
                "identification": {"farmName": "Synthetic cacao farm"},
                "location": {"municipality": "Rionegro", "department": "Santander"},
                "quality": {"publicProfileConsent": False},
            }
            encrypted = Fernet(key).encrypt(json.dumps(cv).encode()).decode()
            cache_record = json.dumps({"encryptedCV": encrypted, "status": 0, "version": 1})
            indexed = ["0x" + f"{number:064x}" for number in range(1, FARMS + 1)]
            hint_start = 1 if present else FARMS + 1
            hinted = ["0x" + f"{number:064x}" for number in range(hint_start, hint_start + HINTS)]
            with admin_farms.index_db() as db:
                db.executemany(
                    "INSERT INTO farms(id, block) VALUES(?, ?)",
                    ((farm_id, number) for number, farm_id in enumerate(indexed, 1)),
                )
                db.executemany(
                    "INSERT INTO records(id, data, checked_at) VALUES(?, ?, ?)",
                    ((farm_id, cache_record, now + 1) for farm_id in indexed[-PAGE_SIZE:]),
                )
                db.execute("INSERT INTO cursor(block) VALUES(?)", (FARMS,))
                db.execute("INSERT INTO scan_metadata(id, updated_at) VALUES(1, ?)", (now,))

            db = admin_farms.sqlite3.connect(settings.transaction_db_file)
            try:
                db.execute("""CREATE TABLE operations (
                    id TEXT PRIMARY KEY, scope TEXT NOT NULL, idem TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, chain_id INTEGER NOT NULL,
                    contract TEXT NOT NULL, signer TEXT NOT NULL, farm_id TEXT NOT NULL,
                    kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL,
                    nonce INTEGER, tx_hash TEXT, raw_tx TEXT, result TEXT,
                    error TEXT, http_error INTEGER, attempts INTEGER NOT NULL DEFAULT 0,
                    created REAL NOT NULL, updated REAL NOT NULL, next_attempt REAL NOT NULL DEFAULT 0,
                    UNIQUE(scope, idem)
                )""")
                db.execute("CREATE INDEX operations_farm ON operations(scope,farm_id,created)")
                db.execute("CREATE INDEX operations_hash ON operations(scope,tx_hash)")
                scope = f"{settings.chain_id}:{settings.contract_address.lower()}"
                db.executemany(
                    """INSERT INTO operations(
                        id,scope,idem,fingerprint,chain_id,contract,signer,farm_id,kind,payload,state,
                        result,created,updated
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    ((f"op-{n}", scope, f"idem-{n}", "synthetic-fingerprint", 31337,
                      settings.contract_address.lower(), "synthetic-signer", farm_id, "register", "{}",
                      "confirmed", json.dumps({"blockNumber": n}), now, now)
                     for n, farm_id in enumerate(hinted, 1)),
                )
                db.commit()
            finally:
                db.close()

            response = admin_farms.read_listing(0, PAGE_SIZE)
            expected_state = "ready" if present else "syncing"
            if response["indexStatus"] != expected_state or response["total"] != FARMS:
                raise AssertionError("synthetic listing state/count did not match scenario")

            sequential = []
            cpu_before = resource.getrusage(resource.RUSAGE_SELF)
            started = time.perf_counter()
            for _ in range(SEQUENTIAL_REQUESTS):
                sample = time.perf_counter()
                admin_farms.read_listing(0, PAGE_SIZE)
                sequential.append((time.perf_counter() - sample) * 1000)
            sequential_elapsed = time.perf_counter() - started
            cpu_after_sequential = resource.getrusage(resource.RUSAGE_SELF)

            def read() -> float:
                sample = time.perf_counter()
                result = admin_farms.read_listing(0, PAGE_SIZE)
                if result["indexStatus"] != expected_state:
                    raise AssertionError("concurrent listing changed index state")
                return (time.perf_counter() - sample) * 1000

            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as pool:
                concurrent = list(pool.map(lambda _: read(), range(CONCURRENT_REQUESTS)))
            concurrent_elapsed = time.perf_counter() - started
            cpu_after_concurrent = resource.getrusage(resource.RUSAGE_SELF)
            return {
                "hint_state": "present" if present else "absent",
                "indexed_farms": FARMS,
                "confirmed_hints": HINTS,
                "page_size": PAGE_SIZE,
                "sequential_requests": SEQUENTIAL_REQUESTS,
                "sequential_p95_ms": round(percentile(sequential, 0.95), 2),
                "sequential_throughput_rps": round(SEQUENTIAL_REQUESTS / sequential_elapsed, 2),
                "sequential_cpu_seconds": round(
                    (cpu_after_sequential.ru_utime - cpu_before.ru_utime)
                    + (cpu_after_sequential.ru_stime - cpu_before.ru_stime), 4
                ),
                "concurrent_requests": CONCURRENT_REQUESTS,
                "concurrent_workers": CONCURRENT_WORKERS,
                "concurrent_p95_ms": round(percentile(concurrent, 0.95), 2),
                "concurrent_throughput_rps": round(CONCURRENT_REQUESTS / concurrent_elapsed, 2),
                "concurrent_cpu_seconds": round(
                    (cpu_after_concurrent.ru_utime - cpu_after_sequential.ru_utime)
                    + (cpu_after_concurrent.ru_stime - cpu_after_sequential.ru_stime), 4
                ),
                "expected_index_status": expected_state,
            }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "test-results" / "catalog-hints.json")
    args = parser.parse_args()
    scenarios = [run_scenario(present=True), run_scenario(present=False)]
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss_bytes = rss if platform.system() == "Darwin" else rss * 1024
    report = {
        "scope": "offline synthetic SQLite read_listing including confirmed_hints; no RPC/network or real data",
        "python": platform.python_version(),
        "scenarios": scenarios,
        "process_peak_rss_mib": round(rss_bytes / (1024 * 1024), 2),
    }
    output = json.dumps(report, indent=2) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
