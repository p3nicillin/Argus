from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from .collectors import CollectorContext, CollectorRegistry, Finding
from .correlation import CorrelationEngine, normalize_value
from .repository import Repository, encode, now


class OperationManager:
    """Persistent, auditable execution of collectors and result normalization."""

    def __init__(
        self,
        repository: Repository,
        registry: CollectorRegistry,
        context: CollectorContext,
    ) -> None:
        self.repository = repository
        self.registry = registry
        self.context = context
        self.correlation = CorrelationEngine(repository)

    def create_job(
        self,
        case_id: int,
        collector_id: str,
        query: str,
        options: dict[str, Any] | None = None,
    ) -> int:
        self.repository.investigation(case_id)
        self.registry.get(collector_id)
        if not query.strip():
            raise ValueError("Collection query is required")
        with self.repository.db.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO collection_jobs(investigation_id,collector,query,options,created_at) VALUES(?,?,?,?,?)",
                (case_id, collector_id, query.strip(), encode(options or {}), now()),
            )
            job_id = int(cursor.lastrowid)
            self._event(connection, job_id, "info", "Collection job queued")
            self.repository._audit(
                connection, "queue", "collection_job", job_id, case_id, {"collector": collector_id}
            )
        return job_id

    async def run_job(self, job_id: int) -> list[Finding]:
        job = self.repository.db.one("SELECT * FROM collection_jobs WHERE id=?", (job_id,))
        if not job:
            raise KeyError(f"Collection job {job_id} does not exist")
        if job["status"] == "cancelled":
            return []
        if job["status"] not in {"pending", "failed"}:
            raise RuntimeError(f"Collection job {job_id} is already {job['status']}")
        collector = self.registry.get(job["collector"])
        with self.repository.db.transaction() as connection:
            connection.execute(
                "UPDATE collection_jobs SET status='running',progress=0.05,error='',started_at=?,finished_at=NULL WHERE id=?",
                (now(), job_id),
            )
            self._event(connection, job_id, "info", f"Started {collector.name}")
        try:
            findings = await collector.collect(job["query"], self.context)
            current = self.repository.db.one(
                "SELECT status FROM collection_jobs WHERE id=?", (job_id,)
            )
            if current and current["status"] == "cancelled":
                return []
            self._set_progress(job_id, 0.65, "Collector returned results")
            self._archive(job_id, job["investigation_id"], job["collector"], job["query"], findings)
            self.correlation.generate(job["investigation_id"])
            with self.repository.db.transaction() as connection:
                connection.execute(
                    "UPDATE collection_jobs SET status='completed',progress=1,result_count=?,finished_at=? WHERE id=?",
                    (len(findings), now(), job_id),
                )
                self._event(
                    connection,
                    job_id,
                    "info",
                    "Collection completed",
                    {"findings": len(findings)},
                )
                self.repository._audit(
                    connection,
                    "complete",
                    "collection_job",
                    job_id,
                    job["investigation_id"],
                    {"findings": len(findings)},
                )
            return findings
        except Exception as exc:
            with self.repository.db.transaction() as connection:
                connection.execute(
                    "UPDATE collection_jobs SET status='failed',error=?,finished_at=? WHERE id=?",
                    (str(exc)[:4000], now(), job_id),
                )
                self._event(connection, job_id, "error", str(exc)[:2000])
                self.repository._audit(
                    connection,
                    "fail",
                    "collection_job",
                    job_id,
                    job["investigation_id"],
                    {"error": str(exc)[:1000]},
                )
            raise

    async def run_batch(
        self,
        case_id: int,
        requests: Iterable[tuple[str, str]],
        concurrency: int = 3,
    ) -> list[dict[str, Any]]:
        semaphore = asyncio.Semaphore(max(1, min(concurrency, 10)))
        jobs = [self.create_job(case_id, collector, query) for collector, query in requests]

        async def execute(job_id: int) -> dict[str, Any]:
            async with semaphore:
                try:
                    findings = await self.run_job(job_id)
                    return {"job_id": job_id, "ok": True, "finding_count": len(findings)}
                except Exception as exc:
                    return {"job_id": job_id, "ok": False, "error": str(exc)}

        return await asyncio.gather(*(execute(job_id) for job_id in jobs))

    def cancel(self, job_id: int) -> None:
        job = self.repository.db.one("SELECT * FROM collection_jobs WHERE id=?", (job_id,))
        if not job:
            raise KeyError(f"Collection job {job_id} does not exist")
        if job["status"] in {"completed", "failed", "cancelled"}:
            return
        with self.repository.db.transaction() as connection:
            connection.execute(
                "UPDATE collection_jobs SET status='cancelled',finished_at=? WHERE id=?",
                (now(), job_id),
            )
            self._event(connection, job_id, "warning", "Cancellation requested")

    def retry(self, job_id: int) -> int:
        job = self.repository.db.one("SELECT * FROM collection_jobs WHERE id=?", (job_id,))
        if not job:
            raise KeyError(f"Collection job {job_id} does not exist")
        return self.create_job(
            job["investigation_id"], job["collector"], job["query"], json.loads(job["options"])
        )

    def events(self, job_id: int) -> list[dict[str, Any]]:
        rows = self.repository.db.all(
            "SELECT * FROM collection_job_events WHERE job_id=? ORDER BY id", (job_id,)
        )
        for row in rows:
            row["data"] = json.loads(row["data"])
        return rows

    def _archive(
        self,
        job_id: int,
        case_id: int,
        collector_id: str,
        query: str,
        findings: list[Finding],
    ) -> None:
        for finding in findings:
            intelligence_id = self.repository.add_intelligence(
                case_id,
                collector_id,
                query,
                finding.title,
                finding.data,
                finding.source_url,
                finding.confidence,
            )
            entity_ids: list[int] = []
            for raw_entity in finding.entities:
                entity = dict(raw_entity)
                entity_confidence = float(entity.pop("confidence", finding.confidence))
                entity_source = str(entity.pop("source_url", finding.source_url))
                entity_id = self.repository.add_entity(
                    case_id,
                    confidence=entity_confidence,
                    source_url=entity_source,
                    **entity,
                )
                entity_ids.append(entity_id)
                self.repository.add_alias(
                    case_id,
                    entity_id,
                    str(entity["value"]),
                    normalize_value(str(entity["kind"]), str(entity["value"])),
                    str(entity["kind"]),
                    entity_source,
                    entity_confidence,
                )
            self._source_record(case_id, intelligence_id, finding)
            self._extract_locations(case_id, intelligence_id, entity_ids, finding)
        self._set_progress(job_id, 0.9, "Findings normalized and archived")

    def _source_record(self, case_id: int, intelligence_id: int, finding: Finding) -> None:
        if not finding.source_url:
            return
        payload = json.dumps(finding.data, sort_keys=True, ensure_ascii=False, default=str)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        publisher = urlparse(finding.source_url).hostname or ""
        self.repository.db.execute(
            "INSERT OR IGNORE INTO source_records(investigation_id,intelligence_id,url,title,publisher,retrieved_at,content_hash,metadata) VALUES(?,?,?,?,?,?,?,?)",
            (
                case_id,
                intelligence_id,
                finding.source_url,
                finding.title,
                publisher,
                now(),
                digest,
                encode({"collector_confidence": finding.confidence}),
            ),
        )

    def _extract_locations(
        self,
        case_id: int,
        intelligence_id: int,
        entity_ids: list[int],
        finding: Finding,
    ) -> None:
        candidates: list[tuple[float, float, str, dict[str, Any]]] = []

        def walk(value: Any, path: str = "") -> None:
            if isinstance(value, dict):
                latitude = value.get("latitude", value.get("lat"))
                longitude = value.get("longitude", value.get("lon", value.get("lng")))
                if isinstance(latitude, (int, float)) and isinstance(longitude, (int, float)):
                    label = str(
                        value.get("city")
                        or value.get("region")
                        or value.get("country")
                        or finding.title
                    )
                    candidates.append((float(latitude), float(longitude), label, {"path": path}))
                for key, child in value.items():
                    walk(child, f"{path}.{key}" if path else str(key))
            elif isinstance(value, list):
                for index, child in enumerate(value[:1000]):
                    walk(child, f"{path}[{index}]")

        walk(finding.data)
        seen: set[tuple[float, float, str]] = set()
        for latitude, longitude, label, attributes in candidates[:250]:
            key = (round(latitude, 6), round(longitude, 6), label)
            if key in seen or not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                continue
            seen.add(key)
            self.repository.add_location(
                case_id,
                latitude,
                longitude,
                label,
                entity_id=entity_ids[0] if len(entity_ids) == 1 else None,
                intelligence_id=intelligence_id,
                source_url=finding.source_url,
                confidence=finding.confidence,
                attributes=attributes,
            )

    def _set_progress(self, job_id: int, progress: float, message: str) -> None:
        with self.repository.db.transaction() as connection:
            connection.execute(
                "UPDATE collection_jobs SET progress=? WHERE id=?", (progress, job_id)
            )
            self._event(connection, job_id, "info", message, {"progress": progress})

    @staticmethod
    def _event(
        connection: Any,
        job_id: int,
        level: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        connection.execute(
            "INSERT INTO collection_job_events(job_id,level,message,data,created_at) VALUES(?,?,?,?,?)",
            (job_id, level, message, encode(data or {}), now()),
        )
