import json,os,sqlite3
from pathlib import Path
DB=os.environ.get("ASFB_DB_PATH","/app/data/asfb.sqlite3")
def connect():
    Path(DB).parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(DB)
    db.execute("CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, data TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, data TEXT)")
    return db
def save(table,items):
    if table not in ("assets","jobs"): raise ValueError("Invalid table")
    with connect() as db:
        db.executemany(f"INSERT OR REPLACE INTO {table}(id,data) VALUES (?,?)",[(k,json.dumps(v)) for k,v in items.items()])
def load(table):
    if table not in ("assets","jobs"): raise ValueError("Invalid table")
    with connect() as db:
        return {k:json.loads(v) for k,v in db.execute(f"SELECT id,data FROM {table}")}
