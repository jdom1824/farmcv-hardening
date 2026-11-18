"""Bounded, loopback-only read load probe for the FarmCV admin portal.

The probe starts one local Uvicorn worker and only issues GET requests to the
public landing page and public farm catalog. It refuses non-loopback RPC or
HTTP destinations and requires a disposable Hardhat chain (31337).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import resource
import statistics
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from web3 import AsyncHTTPProvider, AsyncWeb3


ROOT = Path(__file__).resolve().parents[1]
LOCAL_RPC = "http://127.0.0.1:18545"
DEFAULT_HTTP = "http://127.0.0.1:18546"
PATHS = ("/", "/fincas?page=1")
CONCURRENCY = (1, 4, 8, 16, 32, 64)
REQUESTS_PER_PATH = 40


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percent * len(ordered)) - 1)]


async def check_hardhat() -> str:
    rpc_url = os.environ.get("RPC_URL", LOCAL_RPC)
    parsed = urlparse(rpc_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != 18545:
        raise RuntimeError("RPC_URL must be the isolated Hardhat loopback endpoint")
    web3 = AsyncWeb3(AsyncHTTPProvider(rpc_url, request_kwargs={"timeout": 2}))
    try:
        if await web3.eth.chain_id != 31337:
            raise RuntimeError("refusing to run unless RPC chainId is 31337")
        version = await web3.client_version
        if "hardhat" not in version.lower():
            raise RuntimeError("refusing to run against a non-Hardhat RPC client")
        return version
    finally:
        await web3.provider.disconnect()


async def run_stage(client: httpx.AsyncClient, path: str, concurrency: int, request_count: int) -> dict:
    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    statuses: dict[str, int] = {}
    errors: dict[str, int] = {}

    async def fetch() -> None:
        async with semaphore:
            started = time.perf_counter()
            try:
                response = await client.get(path)
                latencies.append((time.perf_counter() - started) * 1000)
                key = str(response.status_code)
                statuses[key] = statuses.get(key, 0) + 1
            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                key = type(exc).__name__
                errors[key] = errors.get(key, 0) + 1

    started = time.perf_counter()
    await asyncio.gather(*(fetch() for _ in range(request_count)))
    duration = time.perf_counter() - started
    result: dict = {
        "path": path,
        "concurrency": concurrency,
        "planned_requests": request_count,
        "responses": len(latencies),
        "duration_seconds": round(duration, 4),
        "throughput_rps": round(len(latencies) / duration, 2) if duration else 0,
        "http_statuses": statuses,
        "transport_errors": errors,
    }
    if latencies:
        result.update(
            latency_ms_p50=round(statistics.median(latencies), 2),
            latency_ms_p95=round(percentile(latencies, 0.95), 2),
            latency_ms_p99=round(percentile(latencies, 0.99), 2),
            latency_ms_max=round(max(latencies), 2),
        )
    return result


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=DEFAULT_HTTP)
    parser.add_argument("--output", type=Path, default=ROOT / "test-results" / "campaign-load.json")
    args = parser.parse_args()
    target = urlparse(args.base_url)
    if target.scheme != "http" or target.hostname != "127.0.0.1" or target.port != 18546:
        raise RuntimeError("HTTP target must be http://127.0.0.1:18546")

    rpc_client = await check_hardhat()
    # Do not inherit credentials or configuration from an interactive shell.
    # The benchmark is intentionally public/read-only and uses only synthetic
    # application state rooted in this isolated copy.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(ROOT),
        "PYTHONPATH": str(ROOT),
        "ENVIRONMENT": "hardhat",
        "CHAIN_ID": "31337",
        "RPC_URL": LOCAL_RPC,
        "CONTRACT_ADDRESS": "",
        "BLOCKCHAIN_PRIVATE_KEY": "",
        "JWT_SECRET": "campaign-only-disposable-secret-not-for-use-outside-test",
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD_HASH": "",
        "CV_ENCRYPTION_KEY_FILE": str(ROOT / ".secrets" / "cv-fernet.key"),
        "TRANSACTION_DB_FILE": str(ROOT / "storage" / "transactions" / "operations.sqlite3"),
        "RPC_TIMEOUT_SECONDS": "2",
        "CONFIRMATIONS_REQUIRED": "1",
    }
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    server = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "uvicorn",
        "app.admin_portal:app",
        "--host",
        "127.0.0.1",
        "--port",
        "18546",
        "--workers",
        "1",
        "--log-level",
        "critical",
        cwd=ROOT,
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        async with httpx.AsyncClient(base_url=args.base_url, timeout=10, limits=httpx.Limits(max_connections=64)) as client:
            ready = False
            readiness_requests = 0
            for _ in range(100):
                if server.returncode is not None:
                    raise RuntimeError("local Uvicorn exited before becoming ready")
                readiness_requests += 1
                try:
                    response = await client.get("/")
                    if response.status_code == 200:
                        ready = True
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.1)
            if not ready:
                raise RuntimeError("local Uvicorn did not become ready")

            samples = []
            for concurrency in CONCURRENCY:
                # Keep the standard stages comparable to baseline. The final
                # stage has enough work to exercise all 64 concurrent slots.
                request_count = 80 if concurrency == 64 else REQUESTS_PER_PATH
                for path in PATHS:
                    samples.append(await run_stage(client, path, concurrency, request_count))
    finally:
        if server.returncode is None:
            server.terminate()
        try:
            await asyncio.wait_for(server.wait(), timeout=10)
        except asyncio.TimeoutError:
            server.kill()
            await server.wait()

    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    rss_bytes = after.ru_maxrss if sys.platform == "darwin" else after.ru_maxrss * 1024
    report = {
        "scope": "loopback-only, read-only GET load; no blockchain transactions",
        "http_target": args.base_url,
        "rpc_chain_id": 31337,
        "rpc_client": rpc_client,
        "server_workers": 1,
        "stages": list(CONCURRENCY),
        "requests_per_path_by_concurrency": {
            str(level): 80 if level == 64 else REQUESTS_PER_PATH for level in CONCURRENCY
        },
        "paths": list(PATHS),
        "readiness_requests": readiness_requests,
        "total_requests_including_readiness": sum(x["responses"] for x in samples) + readiness_requests,
        "resource_usage": {
            "child_user_cpu_seconds": round(after.ru_utime - before.ru_utime, 4),
            "child_system_cpu_seconds": round(after.ru_stime - before.ru_stime, 4),
            "child_peak_rss_mib": round(rss_bytes / (1024 * 1024), 2),
            "note": "ru_maxrss is the server child peak; CPU is child user/system time over this run.",
        },
        "samples": samples,
        "unexpected_results": [
            {
                "path": item["path"],
                "concurrency": item["concurrency"],
                "non_200_statuses": {code: count for code, count in item["http_statuses"].items() if code != "200"},
                "transport_errors": item["transport_errors"],
            }
            for item in samples
            if item["transport_errors"] or any(code != "200" for code in item["http_statuses"])
        ],
        "python": sys.version.split()[0],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report["unexpected_results"]:
        raise RuntimeError("load probe recorded unexpected HTTP or transport errors")


if __name__ == "__main__":
    asyncio.run(main())
