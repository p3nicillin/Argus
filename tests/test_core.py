from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from argus_osint.collectors import CollectorContext, CollectorRegistry, PhoneCollector
from argus_osint.config import Settings
from argus_osint.db import Database
from argus_osint.evidence import EvidenceManager, sha256_file
from argus_osint.reports import ReportEngine
from argus_osint.repository import Repository


@pytest.fixture()
def repository(tmp_path: Path):
    value = Repository(Database(tmp_path / "test.sqlite3"), "analyst")
    yield value
    value.db.close()


def test_investigation_lifecycle_and_search(repository: Repository) -> None:
    case_id = repository.create_investigation(
        "Project Northstar", "Public-source review", "analyst", ["priority"]
    )
    repository.add_note(case_id, "Scope", "Review the example.org infrastructure", ["scope"])
    entity_id = repository.add_entity(case_id, "domain", "example.org", verified=True)
    repository.add_timeline_event(
        case_id, "2026-06-30T10:00:00+00:00", "Domain observed", entity_id=entity_id
    )

    assert repository.investigation(case_id)["status"] == "active"
    assert repository.search("example", case_id)
    repository.archive(case_id)
    assert repository.investigation(case_id)["status"] == "archived"
    repository.reopen(case_id)
    assert repository.investigation(case_id)["status"] == "active"


def test_duplicate_remaps_entity_links(repository: Repository) -> None:
    source = repository.create_investigation("Source")
    first = repository.add_entity(source, "person", "Alice")
    second = repository.add_entity(source, "domain", "example.org")
    repository.add_relationship(source, first, second, "owns", 0.8)
    repository.add_timeline_event(source, "2026-01-01T00:00:00+00:00", "Observed", entity_id=first)

    copied = repository.duplicate(source)
    copied_entities = repository.rows("entities", copied)
    copied_ids = {item["id"] for item in copied_entities}
    relationship = repository.rows("relationships", copied)[0]
    event = repository.rows("timeline_events", copied)[0]
    assert relationship["source_entity_id"] in copied_ids
    assert relationship["target_entity_id"] in copied_ids
    assert event["entity_id"] in copied_ids


def test_merge_deduplicates_entities(repository: Repository) -> None:
    source = repository.create_investigation("Source")
    target = repository.create_investigation("Target")
    repository.add_entity(source, "domain", "example.org")
    repository.add_entity(target, "domain", "example.org")
    repository.add_note(source, "Finding", "Merge me")
    repository.merge(source, target)

    assert len(repository.rows("entities", target)) == 1
    assert len(repository.rows("notes", target)) == 1
    assert repository.investigation(source)["status"] == "archived"


def test_evidence_is_content_addressed_and_verified(repository: Repository, tmp_path: Path) -> None:
    case_id = repository.create_investigation("Evidence")
    source = tmp_path / "artifact.txt"
    source.write_text("immutable bytes", encoding="utf-8")
    manager = EvidenceManager(repository, tmp_path / "managed")
    evidence_id = manager.ingest(case_id, source)
    record = repository.rows("evidence", case_id)[0]

    assert Path(record["stored_path"]).is_file()
    assert record["sha256"] == sha256_file(source)
    assert manager.verify(evidence_id)[0]


def test_reports_export_json_html_markdown_and_csv(repository: Repository, tmp_path: Path) -> None:
    case_id = repository.create_investigation("Report case", "A concise summary")
    repository.add_entity(case_id, "email", "person@example.org", confidence=0.75)
    engine = ReportEngine(repository)
    for suffix in ("json", "html", "md", "csv", "txt", "pdf", "docx"):
        output = tmp_path / f"report.{suffix}"
        engine.export(case_id, output)
        assert output.stat().st_size > 20
    assert (
        json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["investigation"]["title"]
        == "Report case"
    )


def test_collector_registry_and_offline_phone_analysis(repository: Repository) -> None:
    registry = CollectorRegistry()
    ids = {collector.id for collector in registry.all()}
    assert {"dns", "steam", "discord_invite", "bluesky", "mastodon", "company"} <= ids

    findings = asyncio.run(
        PhoneCollector().collect("+44 20 7946 0958", CollectorContext(Settings(), repository.db))
    )
    assert findings[0].data["e164"] == "+442079460958"
    assert findings[0].entities[0]["verified"] is False
