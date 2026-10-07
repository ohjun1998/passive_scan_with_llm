import json
import os
import sqlite3
from dataclasses import asdict
from pathlib import Path

from .data import Request, digest


def private_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(path, 0o600)


class Store:
    def __init__(self, workspace):
        self.root = Path(workspace)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        path = self.root / "state.sqlite3"
        # Set permissions before SQLite can store any captures.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        self.db = sqlite3.connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS captures (id TEXT PRIMARY KEY, request_id TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS results (id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS calls (id TEXT PRIMARY KEY, status TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        row = self.db.execute("SELECT value FROM settings WHERE name='salt'").fetchone()
        self.salt = bytes.fromhex(row[0]) if row else os.urandom(32)
        if not row:
            self.db.execute("INSERT INTO settings VALUES ('salt',?)", (self.salt.hex(),))
            self.db.commit()

    def add(self, req, captured=None):
        self.db.execute("INSERT OR IGNORE INTO requests VALUES (?,?)", (req.id, json.dumps(asdict(req))))
        if captured:
            self.db.execute("INSERT OR IGNORE INTO captures VALUES (?,?,?)", (digest([req.id, captured]), req.id, json.dumps(captured)))
        self.db.commit()

    def requests(self):
        return [Request(**json.loads(r[0])) for r in self.db.execute("SELECT data FROM requests ORDER BY id")]

    def captures(self, rid):
        return [json.loads(r[0]) for r in self.db.execute("SELECT data FROM captures WHERE request_id=? ORDER BY id LIMIT 3", (rid,))]

    def get(self, table, key):
        if table not in ("results", "plans", "calls"):
            raise ValueError("Invalid table")
        row = self.db.execute(f"SELECT data FROM {table} WHERE id=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, table, key, data):
        if table not in ("results", "plans"):
            raise ValueError("Invalid table")
        self.db.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?)", (key, json.dumps(data)))
        self.db.commit()

    def all(self, table):
        if table not in ("results", "plans", "calls"):
            raise ValueError("Invalid table")
        return [json.loads(r[0]) for r in self.db.execute(f"SELECT data FROM {table} ORDER BY rowid")]

    def count(self, name):
        row = self.db.execute("SELECT value FROM counters WHERE name=?", (name,)).fetchone()
        return row[0] if row else 0

    def reserve(self, name, limit):
        # Reservation precedes IO; interrupted requests/calls still consume budget.
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO counters VALUES (?,0)", (name,))
            changed = self.db.execute("UPDATE counters SET value=value+1 WHERE name=? AND value<?", (name, limit)).rowcount
        return bool(changed)

    def call(self, key, status, data):
        self.db.execute("INSERT OR REPLACE INTO calls VALUES (?,?,?)", (key, status, json.dumps(data)))
        self.db.commit()
