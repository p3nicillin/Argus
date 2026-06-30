from __future__ import annotations

import contextlib
import json
import re
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .db import Database


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def encode(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def decode_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    json_fields = {
        "tags",
        "metadata",
        "attributes",
        "data",
        "details",
        "filters",
        "permissions",
        "config",
    }
    for row in rows:
        for field in json_fields & row.keys():
            with contextlib.suppress(TypeError, json.JSONDecodeError):
                row[field] = json.loads(row[field])
        for field in ("verified", "enabled"):
            if field in row:
                row[field] = bool(row[field])
    return rows


class Repository:
    def __init__(self, db: Database, actor: str = "") -> None:
        self.db = db
        self.actor = actor

    def _audit(
        self,
        connection: sqlite3.Connection,
        action: str,
        object_type: str,
        object_id: int | None,
        investigation_id: int | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        connection.execute(
            "INSERT INTO audit_log(investigation_id,action,object_type,object_id,details,actor,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                investigation_id,
                action,
                object_type,
                object_id,
                encode(details or {}),
                self.actor,
                now(),
            ),
        )

    @staticmethod
    def _index(
        connection: sqlite3.Connection,
        object_type: str,
        object_id: int,
        investigation_id: int,
        title: str,
        body: str,
        tags: list[str] | None = None,
    ) -> None:
        connection.execute(
            "DELETE FROM global_fts WHERE object_type=? AND object_id=?", (object_type, object_id)
        )
        connection.execute(
            "INSERT INTO global_fts(object_type,object_id,investigation_id,title,body,tags) VALUES(?,?,?,?,?,?)",
            (object_type, object_id, investigation_id, title, body, " ".join(tags or [])),
        )

    def create_investigation(
        self,
        title: str,
        description: str = "",
        investigator: str = "",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        if not title.strip():
            raise ValueError("Investigation title is required")
        stamp = now()
        with self.db.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO investigations(title,description,investigator,tags,metadata,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (
                    title.strip(),
                    description.strip(),
                    investigator.strip(),
                    encode(tags or []),
                    encode(metadata or {}),
                    stamp,
                    stamp,
                ),
            )
            case_id = int(cursor.lastrowid)
            self._index(connection, "investigation", case_id, case_id, title, description, tags)
            self._audit(connection, "create", "investigation", case_id, case_id)
        return case_id

    def list_investigations(self, include_archived: bool = True) -> list[dict[str, Any]]:
        where = "" if include_archived else " WHERE status='active'"
        return decode_rows(
            self.db.all(f"SELECT * FROM investigations{where} ORDER BY updated_at DESC")
        )

    def investigation(self, case_id: int) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM investigations WHERE id=?", (case_id,))
        if row is None:
            raise KeyError(f"Investigation {case_id} does not exist")
        return decode_rows([row])[0]

    def update_investigation(self, case_id: int, **changes: Any) -> None:
        allowed = {"title", "description", "investigator", "status", "tags", "metadata"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"Unsupported fields: {', '.join(sorted(unknown))}")
        if not changes:
            return
        for key in ("tags", "metadata"):
            if key in changes:
                changes[key] = encode(changes[key])
        changes["updated_at"] = now()
        assignments = ",".join(f"{name}=?" for name in changes)
        with self.db.transaction() as connection:
            cursor = connection.execute(
                f"UPDATE investigations SET {assignments} WHERE id=?", (*changes.values(), case_id)
            )
            if not cursor.rowcount:
                raise KeyError(f"Investigation {case_id} does not exist")
            case = dict(
                connection.execute("SELECT * FROM investigations WHERE id=?", (case_id,)).fetchone()
            )
            self._index(
                connection,
                "investigation",
                case_id,
                case_id,
                case["title"],
                case["description"],
                json.loads(case["tags"]),
            )
            self._audit(connection, "update", "investigation", case_id, case_id, changes)

    def archive(self, case_id: int) -> None:
        self.update_investigation(case_id, status="archived")

    def reopen(self, case_id: int) -> None:
        self.update_investigation(case_id, status="active")

    def duplicate(self, case_id: int, title: str | None = None) -> int:
        source = self.investigation(case_id)
        new_id = self.create_investigation(
            title or f"{source['title']} (copy)",
            source["description"],
            source["investigator"],
            source["tags"],
            {**source["metadata"], "duplicated_from": case_id},
        )
        entity_map: dict[int, int] = {}
        with self.db.transaction() as connection:
            for table in ("notes", "bookmarks", "intelligence"):
                columns = [
                    r[1]
                    for r in connection.execute(f"PRAGMA table_info({table})")
                    if r[1] not in {"id", "investigation_id"}
                ]
                joined = ",".join(columns)
                connection.execute(
                    f"INSERT INTO {table}(investigation_id,{joined}) SELECT ?,{joined} FROM {table} WHERE investigation_id=?",
                    (new_id, case_id),
                )
            for entity in connection.execute(
                "SELECT * FROM entities WHERE investigation_id=?", (case_id,)
            ):
                cursor = connection.execute(
                    "INSERT INTO entities(investigation_id,kind,value,display_name,confidence,verified,source_url,attributes,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_id,
                        entity["kind"],
                        entity["value"],
                        entity["display_name"],
                        entity["confidence"],
                        entity["verified"],
                        entity["source_url"],
                        entity["attributes"],
                        entity["tags"],
                        now(),
                        now(),
                    ),
                )
                entity_map[entity["id"]] = int(cursor.lastrowid)
            for rel in connection.execute(
                "SELECT * FROM relationships WHERE investigation_id=?", (case_id,)
            ):
                connection.execute(
                    "INSERT INTO relationships(investigation_id,source_entity_id,target_entity_id,kind,confidence,verified,source_url,attributes,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        new_id,
                        entity_map[rel["source_entity_id"]],
                        entity_map[rel["target_entity_id"]],
                        rel["kind"],
                        rel["confidence"],
                        rel["verified"],
                        rel["source_url"],
                        rel["attributes"],
                        now(),
                    ),
                )
            for event in connection.execute(
                "SELECT * FROM timeline_events WHERE investigation_id=?", (case_id,)
            ):
                connection.execute(
                    "INSERT INTO timeline_events(investigation_id,occurred_at,title,description,kind,source_url,entity_id,attributes,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        new_id,
                        event["occurred_at"],
                        event["title"],
                        event["description"],
                        event["kind"],
                        event["source_url"],
                        entity_map.get(event["entity_id"]),
                        event["attributes"],
                        event["created_at"],
                    ),
                )
            self._audit(
                connection, "duplicate", "investigation", new_id, new_id, {"source": case_id}
            )
        self.rebuild_search_index(new_id)
        return new_id

    def merge(self, source_id: int, target_id: int) -> None:
        if source_id == target_id:
            raise ValueError("Source and target investigations must differ")
        self.investigation(source_id)
        self.investigation(target_id)
        with self.db.transaction() as connection:
            entity_map: dict[int, int] = {}
            for entity in connection.execute(
                "SELECT * FROM entities WHERE investigation_id=?", (source_id,)
            ):
                existing = connection.execute(
                    "SELECT id FROM entities WHERE investigation_id=? AND kind=? AND value=?",
                    (target_id, entity["kind"], entity["value"]),
                ).fetchone()
                if existing:
                    entity_map[entity["id"]] = existing["id"]
                else:
                    cursor = connection.execute(
                        "INSERT INTO entities(investigation_id,kind,value,display_name,confidence,verified,source_url,attributes,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            target_id,
                            entity["kind"],
                            entity["value"],
                            entity["display_name"],
                            entity["confidence"],
                            entity["verified"],
                            entity["source_url"],
                            entity["attributes"],
                            entity["tags"],
                            entity["created_at"],
                            now(),
                        ),
                    )
                    entity_map[entity["id"]] = int(cursor.lastrowid)
            for rel in connection.execute(
                "SELECT * FROM relationships WHERE investigation_id=?", (source_id,)
            ):
                connection.execute(
                    "INSERT OR IGNORE INTO relationships(investigation_id,source_entity_id,target_entity_id,kind,confidence,verified,source_url,attributes,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        target_id,
                        entity_map[rel["source_entity_id"]],
                        entity_map[rel["target_entity_id"]],
                        rel["kind"],
                        rel["confidence"],
                        rel["verified"],
                        rel["source_url"],
                        rel["attributes"],
                        rel["created_at"],
                    ),
                )
            for old_entity_id, new_entity_id in entity_map.items():
                connection.execute(
                    "UPDATE timeline_events SET entity_id=? WHERE investigation_id=? AND entity_id=?",
                    (new_entity_id, source_id, old_entity_id),
                )
            for table in (
                "notes",
                "evidence",
                "bookmarks",
                "timeline_events",
                "intelligence",
                "search_history",
            ):
                connection.execute(
                    f"UPDATE {table} SET investigation_id=? WHERE investigation_id=?",
                    (target_id, source_id),
                )
            connection.execute(
                "UPDATE investigations SET status='archived', updated_at=? WHERE id=?",
                (now(), source_id),
            )
            connection.execute(
                "UPDATE investigations SET updated_at=? WHERE id=?", (now(), target_id)
            )
            self._audit(
                connection,
                "merge_into",
                "investigation",
                source_id,
                source_id,
                {"target": target_id},
            )
            self._audit(
                connection,
                "merge_from",
                "investigation",
                target_id,
                target_id,
                {"source": source_id},
            )
        self.rebuild_search_index(source_id)
        self.rebuild_search_index(target_id)

    def add_note(self, case_id: int, title: str, body: str, tags: list[str] | None = None) -> int:
        if not body.strip():
            raise ValueError("Note body is required")
        stamp = now()
        with self.db.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO notes(investigation_id,title,body,tags,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (case_id, title.strip(), body.strip(), encode(tags or []), stamp, stamp),
            )
            item_id = int(cursor.lastrowid)
            self._index(connection, "note", item_id, case_id, title, body, tags)
            self._audit(connection, "create", "note", item_id, case_id)
        return item_id

    def add_entity(
        self,
        case_id: int,
        kind: str,
        value: str,
        display_name: str = "",
        confidence: float = 1.0,
        verified: bool = False,
        source_url: str = "",
        attributes: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> int:
        if not kind.strip() or not value.strip():
            raise ValueError("Entity type and value are required")
        stamp = now()
        with self.db.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO entities(investigation_id,kind,value,display_name,confidence,verified,source_url,attributes,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(investigation_id,kind,value) DO UPDATE SET display_name=excluded.display_name,confidence=MAX(entities.confidence,excluded.confidence),verified=MAX(entities.verified,excluded.verified),source_url=CASE WHEN excluded.source_url<>'' THEN excluded.source_url ELSE entities.source_url END,attributes=excluded.attributes,updated_at=excluded.updated_at RETURNING id",
                (
                    case_id,
                    kind.strip().lower(),
                    value.strip(),
                    display_name.strip(),
                    confidence,
                    int(verified),
                    source_url.strip(),
                    encode(attributes or {}),
                    encode(tags or []),
                    stamp,
                    stamp,
                ),
            )
            item_id = int(cursor.fetchone()[0])
            self._index(
                connection,
                "entity",
                item_id,
                case_id,
                display_name or value,
                f"{kind} {value} {source_url} {encode(attributes or {})}",
                tags,
            )
            self._audit(connection, "upsert", "entity", item_id, case_id)
        return item_id

    def add_relationship(
        self,
        case_id: int,
        source_id: int,
        target_id: int,
        kind: str,
        confidence: float = 0.5,
        verified: bool = False,
        source_url: str = "",
        attributes: dict[str, Any] | None = None,
    ) -> int:
        if source_id == target_id:
            raise ValueError("A relationship cannot point to itself")
        with self.db.transaction() as connection:
            members = connection.execute(
                "SELECT COUNT(*) FROM entities WHERE investigation_id=? AND id IN (?,?)",
                (case_id, source_id, target_id),
            ).fetchone()[0]
            if members != 2:
                raise ValueError("Both entities must belong to the investigation")
            cursor = connection.execute(
                "INSERT INTO relationships(investigation_id,source_entity_id,target_entity_id,kind,confidence,verified,source_url,attributes,created_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(investigation_id,source_entity_id,target_entity_id,kind) DO UPDATE SET confidence=excluded.confidence,verified=excluded.verified,source_url=excluded.source_url,attributes=excluded.attributes RETURNING id",
                (
                    case_id,
                    source_id,
                    target_id,
                    kind.strip(),
                    confidence,
                    int(verified),
                    source_url,
                    encode(attributes or {}),
                    now(),
                ),
            )
            item_id = int(cursor.fetchone()[0])
            self._audit(connection, "upsert", "relationship", item_id, case_id)
        return item_id

    def add_timeline_event(
        self,
        case_id: int,
        occurred_at: str,
        title: str,
        description: str = "",
        kind: str = "event",
        source_url: str = "",
        entity_id: int | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> int:
        with self.db.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO timeline_events(investigation_id,occurred_at,title,description,kind,source_url,entity_id,attributes,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    case_id,
                    occurred_at,
                    title,
                    description,
                    kind,
                    source_url,
                    entity_id,
                    encode(attributes or {}),
                    now(),
                ),
            )
            item_id = int(cursor.lastrowid)
            self._index(
                connection, "timeline", item_id, case_id, title, f"{description} {source_url}"
            )
            self._audit(connection, "create", "timeline", item_id, case_id)
        return item_id

    def add_intelligence(
        self,
        case_id: int,
        collector: str,
        query: str,
        title: str,
        data: dict[str, Any],
        source_url: str = "",
        confidence: float = 0.5,
    ) -> int:
        with self.db.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO intelligence(investigation_id,collector,query,title,source_url,data,confidence,collected_at) VALUES(?,?,?,?,?,?,?,?)",
                (case_id, collector, query, title, source_url, encode(data), confidence, now()),
            )
            item_id = int(cursor.lastrowid)
            self._index(
                connection,
                "intelligence",
                item_id,
                case_id,
                title,
                f"{query} {source_url} {encode(data)}",
            )
            self._audit(
                connection, "collect", "intelligence", item_id, case_id, {"collector": collector}
            )
        return item_id

    def rows(self, table: str, case_id: int) -> list[dict[str, Any]]:
        allowed = {
            "notes",
            "entities",
            "relationships",
            "evidence",
            "bookmarks",
            "timeline_events",
            "intelligence",
            "audit_log",
        }
        if table not in allowed:
            raise ValueError("Unsupported table")
        order = "occurred_at" if table == "timeline_events" else "id"
        return decode_rows(
            self.db.all(
                f"SELECT * FROM {table} WHERE investigation_id=? ORDER BY {order}", (case_id,)
            )
        )

    def search(
        self, query: str, case_id: int | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        terms = [term for term in re.findall(r"[\w@.:-]+", query, re.UNICODE) if term]
        if not terms:
            return []
        fts_query = " AND ".join(f'"{term.replace(chr(34), chr(34) * 2)}"*' for term in terms)
        where = "global_fts MATCH ?"
        parameters: list[Any] = [fts_query]
        if case_id is not None:
            where += " AND investigation_id=?"
            parameters.append(case_id)
        parameters.append(limit)
        rows = self.db.all(
            f"SELECT object_type,object_id,investigation_id,title,snippet(global_fts,4,'<b>','</b>',' … ',20) AS excerpt,bm25(global_fts) AS rank FROM global_fts WHERE {where} ORDER BY rank LIMIT ?",
            parameters,
        )
        with self.db.transaction() as connection:
            connection.execute(
                "INSERT INTO search_history(investigation_id,query,result_count,created_at) VALUES(?,?,?,?)",
                (case_id, query, len(rows), now()),
            )
        return rows

    def rebuild_search_index(self, case_id: int | None = None) -> None:
        clause, parameters = (" WHERE investigation_id=?", (case_id,)) if case_id else ("", ())
        with self.db.transaction() as connection:
            if case_id:
                connection.execute("DELETE FROM global_fts WHERE investigation_id=?", (case_id,))
            else:
                connection.execute("DELETE FROM global_fts")
            for row in connection.execute(
                f"SELECT * FROM investigations{' WHERE id=?' if case_id else ''}", parameters
            ):
                self._index(
                    connection,
                    "investigation",
                    row["id"],
                    row["id"],
                    row["title"],
                    row["description"],
                    json.loads(row["tags"]),
                )
            mapping = {
                "notes": ("note", "title", "body"),
                "entities": ("entity", "display_name", "value"),
                "evidence": ("evidence", "title", "notes"),
                "bookmarks": ("bookmark", "title", "description"),
                "timeline_events": ("timeline", "title", "description"),
                "intelligence": ("intelligence", "title", "data"),
            }
            for table, (object_type, title_field, body_field) in mapping.items():
                for row in connection.execute(f"SELECT * FROM {table}{clause}", parameters):
                    title = row[title_field] or (row["value"] if table == "entities" else "")
                    tags = json.loads(row["tags"]) if "tags" in row else []
                    self._index(
                        connection,
                        object_type,
                        row["id"],
                        row["investigation_id"],
                        title,
                        row[body_field],
                        tags,
                    )
