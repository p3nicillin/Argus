from __future__ import annotations

import json
import re
import unicodedata
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .repository import Repository, encode, now


def normalize_value(kind: str, value: str) -> str:
    """Return a conservative comparison key without asserting identity."""
    kind = kind.casefold().strip()
    value = unicodedata.normalize("NFKC", value).strip()
    if kind in {"email", "domain", "username", "steam_id", "discord_server"}:
        return value.casefold().rstrip(".")
    if kind == "phone":
        digits = re.sub(r"\D", "", value)
        return f"+{digits}" if value.lstrip().startswith("+") else digits
    if kind == "url":
        parsed = urlsplit(value if "://" in value else "https://" + value)
        host = (parsed.hostname or "").casefold().encode("idna").decode("ascii")
        port = f":{parsed.port}" if parsed.port and parsed.port not in {80, 443} else ""
        path = re.sub(r"/{2,}", "/", parsed.path or "/").rstrip("/") or "/"
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
        return urlunsplit((parsed.scheme.casefold() or "https", host + port, path, query, ""))
    if kind == "file_hash":
        return re.sub(r"\s", "", value).casefold()
    return re.sub(r"\s+", " ", value).casefold()


class CorrelationEngine:
    """Builds explainable suggestions; it never silently asserts an identity link."""

    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def generate(self, case_id: int) -> list[dict[str, Any]]:
        entities = self.repository.rows("entities", case_id)
        alias_index: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
        for entity in entities:
            normalized = normalize_value(entity["kind"], entity["value"])
            self.repository.add_alias(
                case_id,
                entity["id"],
                entity["value"],
                normalized,
                entity["kind"],
                entity["source_url"],
                entity["confidence"],
            )
            alias_index[normalized].append((entity, "same normalized public value"))
            if entity["kind"] == "email" and "@" in normalized:
                alias_index[normalized.split("@", 1)[0]].append(
                    (entity, "email local part matches a public handle")
                )
            display_name = normalize_value("person", entity["display_name"])
            if display_name and display_name != normalized:
                alias_index[display_name].append((entity, "same normalized display name"))

        suggestions: dict[tuple[int, int, str], tuple[float, set[str]]] = {}
        for matches in alias_index.values():
            unique = {item[0]["id"]: item for item in matches}
            items = list(unique.values())
            for index, (source, source_reason) in enumerate(items):
                for target, target_reason in items[index + 1 :]:
                    if source["id"] == target["id"]:
                        continue
                    first, second = sorted((source["id"], target["id"]))
                    same_kind = source["kind"] == target["kind"]
                    relationship = "possible_duplicate" if same_kind else "possible_identity_match"
                    score = 0.78 if same_kind else 0.62
                    if source["verified"] and target["verified"]:
                        score = min(score + 0.08, 0.9)
                    reasons = {source_reason, target_reason}
                    key = (first, second, relationship)
                    previous = suggestions.get(key)
                    if previous:
                        suggestions[key] = (max(score, previous[0]), previous[1] | reasons)
                    else:
                        suggestions[key] = (score, reasons)

        with self.repository.db.transaction() as connection:
            for (source_id, target_id, relationship), (score, reasons) in suggestions.items():
                connection.execute(
                    "INSERT INTO correlation_suggestions(investigation_id,source_entity_id,target_entity_id,relationship_kind,score,reasons,status,created_at) VALUES(?,?,?,?,?,?,'pending',?) "
                    "ON CONFLICT(investigation_id,source_entity_id,target_entity_id,relationship_kind) DO UPDATE SET score=excluded.score,reasons=excluded.reasons,status=CASE WHEN correlation_suggestions.status='rejected' THEN 'rejected' ELSE correlation_suggestions.status END",
                    (
                        case_id,
                        source_id,
                        target_id,
                        relationship,
                        score,
                        encode(sorted(reasons)),
                        now(),
                    ),
                )
            self.repository._audit(
                connection,
                "generate",
                "correlation_suggestions",
                None,
                case_id,
                {"count": len(suggestions)},
            )
        return self.pending(case_id)

    def pending(self, case_id: int) -> list[dict[str, Any]]:
        rows = self.repository.db.all(
            "SELECT c.*,s.kind AS source_kind,s.value AS source_value,t.kind AS target_kind,t.value AS target_value "
            "FROM correlation_suggestions c JOIN entities s ON s.id=c.source_entity_id JOIN entities t ON t.id=c.target_entity_id "
            "WHERE c.investigation_id=? ORDER BY CASE c.status WHEN 'pending' THEN 0 ELSE 1 END,c.score DESC,c.id DESC",
            (case_id,),
        )
        for row in rows:
            row["reasons"] = json.loads(row["reasons"])
        return rows

    def review(self, suggestion_id: int, accept: bool) -> None:
        suggestion = self.repository.db.one(
            "SELECT * FROM correlation_suggestions WHERE id=?", (suggestion_id,)
        )
        if not suggestion:
            raise KeyError(f"Correlation suggestion {suggestion_id} does not exist")
        status = "accepted" if accept else "rejected"
        with self.repository.db.transaction() as connection:
            connection.execute(
                "UPDATE correlation_suggestions SET status=?,reviewed_at=? WHERE id=?",
                (status, now(), suggestion_id),
            )
            self.repository._audit(
                connection,
                status,
                "correlation_suggestion",
                suggestion_id,
                suggestion["investigation_id"],
            )
        if accept:
            self.repository.add_relationship(
                suggestion["investigation_id"],
                suggestion["source_entity_id"],
                suggestion["target_entity_id"],
                suggestion["relationship_kind"],
                suggestion["score"],
                False,
                attributes={"reasons": json.loads(suggestion["reasons"]), "reviewed": True},
            )
