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

CREATE TABLE IF NOT EXISTS collection_jobs (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    collector TEXT NOT NULL, query TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','running','completed','failed','cancelled')),
    progress REAL NOT NULL DEFAULT 0 CHECK(progress BETWEEN 0 AND 1),
    result_count INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '', options TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_jobs_case_status
    ON collection_jobs(investigation_id, status, created_at DESC);
CREATE TABLE IF NOT EXISTS collection_job_events (
    id INTEGER PRIMARY KEY,
    job_id INTEGER NOT NULL REFERENCES collection_jobs(id) ON DELETE CASCADE,
    level TEXT NOT NULL CHECK(level IN ('debug','info','warning','error')),
    message TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_job_events_job ON collection_job_events(job_id, id);

CREATE TABLE IF NOT EXISTS entity_aliases (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    alias TEXT NOT NULL, normalized TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'alias',
    source_url TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL DEFAULT 0.5,
    created_at TEXT NOT NULL,
    UNIQUE(investigation_id, entity_id, normalized, kind)
);
CREATE INDEX IF NOT EXISTS ix_aliases_normalized ON entity_aliases(investigation_id, normalized);

CREATE TABLE IF NOT EXISTS source_records (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    intelligence_id INTEGER REFERENCES intelligence(id) ON DELETE SET NULL,
    url TEXT NOT NULL, title TEXT NOT NULL DEFAULT '', publisher TEXT NOT NULL DEFAULT '',
    published_at TEXT, retrieved_at TEXT NOT NULL, content_hash TEXT NOT NULL,
    snapshot_path TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}',
    UNIQUE(investigation_id, url, content_hash)
);
CREATE INDEX IF NOT EXISTS ix_sources_case_url ON source_records(investigation_id, url);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    object_type TEXT NOT NULL, object_id INTEGER NOT NULL,
    body TEXT NOT NULL, author TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_comments_object
    ON comments(investigation_id, object_type, object_id, created_at);

CREATE TABLE IF NOT EXISTS locations (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    entity_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
    intelligence_id INTEGER REFERENCES intelligence(id) ON DELETE SET NULL,
    latitude REAL NOT NULL CHECK(latitude BETWEEN -90 AND 90),
    longitude REAL NOT NULL CHECK(longitude BETWEEN -180 AND 180),
    label TEXT NOT NULL DEFAULT '', source_url TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.5 CHECK(confidence BETWEEN 0 AND 1),
    attributes TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_locations_case ON locations(investigation_id, latitude, longitude);

CREATE TABLE IF NOT EXISTS correlation_suggestions (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    source_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relationship_kind TEXT NOT NULL, score REAL NOT NULL CHECK(score BETWEEN 0 AND 1),
    reasons TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected')),
    created_at TEXT NOT NULL, reviewed_at TEXT,
    UNIQUE(investigation_id, source_entity_id, target_entity_id, relationship_kind)
);
CREATE INDEX IF NOT EXISTS ix_correlations_case_status
    ON correlation_suggestions(investigation_id, status, score DESC);

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
        self._connections: set[sqlite3.Connection] = set()
        self._connections_lock = threading.Lock()
        self.initialize()

    def _connection(self) -> sqlite3.Connection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(
                self.path, timeout=30, isolation_level=None, check_same_thread=False
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            self._local.connection = connection
            with self._connections_lock:
                self._connections.add(connection)
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
        with self._connections_lock:
            connections = tuple(self._connections)
            self._connections.clear()
        for connection in connections:
            with contextlib.suppress(sqlite3.Error):
                connection.close()
        if getattr(self._local, "connection", None) is not None:
            del self._local.connection
