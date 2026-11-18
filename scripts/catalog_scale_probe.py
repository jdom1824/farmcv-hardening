"""Synthetic, offline scale probe for the SQLite public catalog projection."""

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


SIZES = (0, 1_000, 10_000, 50_000)
REPEATS = 20
CONCURRENT_REQUESTS = 40
CONCURRENT_WORKERS = 8
PAGE_SIZE = 20


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percent * len(ordered)) - 1)]


def run_size(size: int, key: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="farmcv-catalog-scale-") as folder:
        settings = SimpleNamespace(
            transaction_db_file=Path(folder) / "operations.sqlite3",
            chain_id=31337,
            contract_address="0x" + "ab" * 20,
            contract_deployment_block=0,
        )
        with patch.object(admin_farms, "settings", settings), \
                patch.object(admin_farms, "load_server_key", return_value=key), \
                patch.object(admin_farms, "adapter", None), \
                patch.object(admin_farms, "scan_status", "ready"), \
                patch.object(admin_farms, "refresh_failed", False):
            admin_farms.initialize_index()
            cv = {
                "identification": {"farmName": "Finca sintética"},
                "location": {"municipality": "Rionegro", "department": "Santander"},
                "quality": {"publicProfileConsent": True},
            }
            encrypted = Fernet(key).encrypt(json.dumps(cv, separators=(",", ":")).encode()).decode()
            record = json.dumps({"encryptedCV": encrypted, "status": 0, "version": 1})
            now = time.time()
            with admin_farms.index_db() as db:
                db.executemany(
                    "INSERT INTO farms(id, block) VALUES(?, ?)",
                    (("0x" + f"{number:064x}", number) for number in range(1, size + 1)),
                )
                db.executemany(
                    "INSERT INTO records(id, data, checked_at) VALUES(?, ?, ?)",
                    (("0x" + f"{number:064x}", record, now) for number in range(1, size + 1)),
                )
                if size:
                    db.execute("INSERT INTO cursor(block) VALUES(?)", (size,))
                    db.execute("INSERT INTO scan_metadata(id, updated_at) VALUES(1, ?)", (now,))

            admin_farms.read_listing(0, PAGE_SIZE)  # warm up SQLite and Fernet
            latencies = []
            cpu_before = resource.getrusage(resource.RUSAGE_SELF)
            started = time.perf_counter()
            for _ in range(REPEATS):
                sample = time.perf_counter()
                response = admin_farms.read_listing(0, PAGE_SIZE)
                latencies.append((time.perf_counter() - sample) * 1000)
                if response["total"] != size or len(response["items"]) != min(size, PAGE_SIZE):
                    raise AssertionError("catalog projection returned an unexpected row count")
            elapsed = time.perf_counter() - started
            cpu_after_sequential = resource.getrusage(resource.RUSAGE_SELF)

            def concurrent_read() -> float:
                sample = time.perf_counter()
                response = admin_farms.read_listing(0, PAGE_SIZE)
                latency = (time.perf_counter() - sample) * 1000
                if response["total"] != size or len(response["items"]) != min(size, PAGE_SIZE):
                    raise AssertionError("concurrent catalog projection returned an unexpected row count")
                return latency

            cpu_concurrent_before = resource.getrusage(resource.RUSAGE_SELF)
            concurrent_started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as pool:
                concurrent_latencies = list(pool.map(lambda _: concurrent_read(), range(CONCURRENT_REQUESTS)))
            concurrent_elapsed = time.perf_counter() - concurrent_started
            cpu_concurrent_after = resource.getrusage(resource.RUSAGE_SELF)
            return {
                "rows": size,
                "requests": REPEATS,
                "elapsed_seconds": round(elapsed, 4),
                "throughput_rps": round(REPEATS / elapsed, 2),
                "latency_ms_p50": round(statistics.median(latencies), 3),
                "latency_ms_p95": round(percentile(latencies, 0.95), 3),
                "latency_ms_max": round(max(latencies), 3),
                "process_cpu_seconds": round(
                    (cpu_after_sequential.ru_utime - cpu_before.ru_utime) +
                    (cpu_after_sequential.ru_stime - cpu_before.ru_stime),
                    4,
                ),
                "concurrent": {
                    "workers": CONCURRENT_WORKERS,
                    "requests": CONCURRENT_REQUESTS,
                    "elapsed_seconds": round(concurrent_elapsed, 4),
                    "throughput_rps": round(CONCURRENT_REQUESTS / concurrent_elapsed, 2),
                    "latency_ms_p50": round(statistics.median(concurrent_latencies), 3),
                    "latency_ms_p95": round(percentile(concurrent_latencies, 0.95), 3),
                    "process_cpu_seconds": round(
                        (cpu_concurrent_after.ru_utime - cpu_concurrent_before.ru_utime) +
                        (cpu_concurrent_after.ru_stime - cpu_concurrent_before.ru_stime),
                        4,
                    ),
                },
            }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "test-results" / "catalog-scale.json")
    args = parser.parse_args()
    key = Fernet.generate_key()
    measurements = [run_size(size, key) for size in SIZES]
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss_bytes = rss if platform.system() == "Darwin" else rss * 1024
    report = {
        "scope": "offline synthetic SQLite listing; no RPC/network, no production data",
        "page_size": PAGE_SIZE,
        "repeats_per_size": REPEATS,
        "concurrent_workers_per_size": CONCURRENT_WORKERS,
        "concurrent_requests_per_size": CONCURRENT_REQUESTS,
        "process_peak_rss_mib": round(rss_bytes / (1024 * 1024), 2),
        "python": platform.python_version(),
        "measurements": measurements,
    }
    output = json.dumps(report, indent=2) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
