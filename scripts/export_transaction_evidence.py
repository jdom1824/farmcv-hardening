"""Export public metadata of this test run; never exports payloads or signed bytes."""
import argparse
import json
import sqlite3
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument("--db",required=True)
parser.add_argument("--report",default="test-results/hardhat-validation.json")
parser.add_argument("--out",default="test-results/outbox-history.json")
args=parser.parse_args()
report=json.loads(Path(args.report).read_text())
first=report["transactions"][0]
scope=str(first["chainId"])+":"+first["contract"].lower()
with sqlite3.connect("file:"+str(Path(args.db).resolve())+"?mode=ro",uri=True) as db:
    db.row_factory=sqlite3.Row
    integrity=db.execute("PRAGMA integrity_check").fetchone()[0]
    records=[]
    for row in db.execute("SELECT id,kind,farm_id,state,tx_hash,nonce,attempts,created,updated,error,result FROM operations WHERE scope=? ORDER BY created",(scope,)):
        record=dict(row)
        record["result"]=json.loads(record["result"]) if record["result"] else None
        record["transitions"]=[dict(x) for x in db.execute("SELECT state,at FROM transitions WHERE operation_id=? ORDER BY seq",(row["id"],))]
        records.append(record)
Path(args.out).write_text(json.dumps({"scope":scope,"sqlite_integrity":integrity,"operations":records},indent=2))
print(json.dumps({"operations":len(records),"sqlite_integrity":integrity,"output":args.out}))
