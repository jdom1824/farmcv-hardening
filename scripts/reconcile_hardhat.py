"""Resume retained test operations only; refuses every network except Hardhat."""
import asyncio
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.config import settings
from app.web3_adapter import FarmCVAdapter
from app.transaction_service import TransactionService

async def main():
    adapter=FarmCVAdapter()
    assert settings.chain_id==31337 and await adapter.w3.eth.chain_id==31337
    assert "hardhat" in (await adapter.w3.client_version).lower()
    with sqlite3.connect(settings.transaction_db_file) as db:
        contracts=[r[0] for r in db.execute("SELECT DISTINCT contract FROM operations WHERE chain_id=31337 AND state NOT IN ('confirmed','failed','rejected','replaced')")]
    for address in contracts:
        settings.contract_address=address
        service=TransactionService(adapter)
        for row in await service.db("active",service.scope):
            await service.process(row["id"])
            result=await service.lookup(row["id"])
            print(result["operationId"],result["status"],result["txHash"],flush=True)
    await adapter.w3.provider.disconnect()

asyncio.run(main())
