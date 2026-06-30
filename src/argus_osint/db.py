from __future__ import annotations

import contextlib
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived','closed')),
    investigator TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_investigations_status ON investigations(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    title TEXT NOT NULL DEFAULT '', body TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, value TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 1.0 CHECK(confidence BETWEEN 0 AND 1),
    verified INTEGER NOT NULL DEFAULT 0, source_url TEXT NOT NULL DEFAULT '',
    attributes TEXT NOT NULL DEFAULT '{}', tags TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(investigation_id, kind, value)
);
CREATE INDEX IF NOT EXISTS ix_entities_kind_value ON entities(kind, value);
CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    source_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 0.5 CHECK(confidence BETWEEN 0 AND 1),
    verified INTEGER NOT NULL DEFAULT 0, source_url TEXT NOT NULL DEFAULT '',
    attributes TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
    UNIQUE(investigation_id, source_entity_id, target_entity_id, kind)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    title TEXT NOT NULL, original_path TEXT NOT NULL DEFAULT '', stored_path TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '', mime_type TEXT NOT NULL DEFAULT '', size INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}', notes TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 1.0 CHECK(confidence BETWEEN 0 AND 1),
    captured_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_evidence_sha256 ON evidence(sha256);
CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    title TEXT NOT NULL, url TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    occurred_at TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'event', source_url TEXT NOT NULL DEFAULT '',
    entity_id INTEGER REFERENCES entities(id) ON DELETE SET NULL, attributes TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_timeline_case_date ON timeline_events(investigation_id, occurred_at);
CREATE TABLE IF NOT EXISTS intelligence (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    collector TEXT NOT NULL, query TEXT NOT NULL, title TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '', data TEXT NOT NULL DEFAULT '{}',
    confidence REAL NOT NULL DEFAULT 0.5, collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY, investigation_id INTEGER REFERENCES investigations(id) ON DELETE CASCADE,
    query TEXT NOT NULL, filters TEXT NOT NULL DEFAULT '{}', result_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS saved_searches (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, query TEXT NOT NULL,
    filters TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY, investigation_id INTEGER REFERENCES investigations(id) ON DELETE SET NULL,
    action TEXT NOT NULL, object_type TEXT NOT NULL, object_id INTEGER,
    details TEXT NOT NULL DEFAULT '{}', actor TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_case_date ON audit_log(investigation_id, created_at DESC);
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plugins (
    plugin_id TEXT PRIMARY KEY, version TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    permissions TEXT NOT NULL DEFAULT '[]', config TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS global_fts USING fts5(
    object_type UNINDEXED, object_id UNINDEXED, investigation_id UNINDEXED,
    title, body, tags, tokenize='unicode61 remove_diacritics 2'
);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self.initialize()

    def _connection(self) -> sqlite3.Connection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            self._local.connection = connection
        return connection

    def initialize(self) -> None:
        self._connection().executescript(SCHEMA)

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connection()
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> sqlite3.Cursor:
        return self._connection().execute(sql, parameters)

    def all(self, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]:
        return [dict(row) for row in self.execute(sql, parameters).fetchall()]

    def one(self, sql: str, parameters: Sequence[Any] = ()) -> dict[str, Any] | None:
        row = self.execute(sql, parameters).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            connection.close()
            del self._local.connection
