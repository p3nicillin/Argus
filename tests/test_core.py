from __future__ import annotations

import asyncio
import json
import zipfile
from pathlib import Path

import pytest

from argus_osint.bundles import InvestigationBundle
from argus_osint.collectors import (
    CollectorContext,
    CollectorRegistry,
    Finding,
    PhoneCollector,
    UsernameCorrelationCollector,
)
from argus_osint.config import Settings
from argus_osint.db import Database
from argus_osint.evidence import EvidenceManager, sha256_file
from argus_osint.operations import OperationManager
from argus_osint.plugins import PluginManager
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

    correlation = asyncio.run(
        UsernameCorrelationCollector().collect(
            "example_user", CollectorContext(Settings(), repository.db)
        )
    )[0]
    assert all(candidate["identity_match"] is False for candidate in correlation.data["candidates"])
    assert correlation.confidence < 0.5


def test_plugin_install_and_out_of_process_rpc(repository: Repository, tmp_path: Path) -> None:
    source = tmp_path / "plugin-source"
    source.mkdir()
    (source / "plugin.json").write_text(
        json.dumps(
            {
                "id": "echo",
                "name": "Echo",
                "version": "1.0.0",
                "description": "Test JSON-RPC plugin",
                "entrypoint": "main.py",
                "permissions": [],
            }
        ),
        encoding="utf-8",
    )
    (source / "main.py").write_text(
        "import json\nimport sys\nrequest=json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':request['params']}))\n",
        encoding="utf-8",
    )
    package = tmp_path / "echo.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.write(source / "plugin.json", "plugin.json")
        archive.write(source / "main.py", "main.py")

    manager = PluginManager(tmp_path / "plugins", repository.db)
    assert manager.install(package).plugin_id == "echo"
    assert asyncio.run(manager.invoke("echo", "collect", {"value": 42})) == {"value": 42}


def test_plugin_install_rejects_unsafe_archive_members(
    repository: Repository, tmp_path: Path
) -> None:
    package = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(
            "plugin.json",
            json.dumps(
                {
                    "id": "unsafe",
                    "name": "Unsafe",
                    "version": "1.0.0",
                    "description": "Unsafe ZIP path",
                    "entrypoint": "main.py",
                    "permissions": [],
                }
            ),
        )
        archive.writestr("nested\\main.py", "print('unsafe')\n")

    manager = PluginManager(tmp_path / "plugins", repository.db)
    with pytest.raises(ValueError, match="unsafe path"):
        manager.install(package)


class DemoCollector:
    id = "demo"
    name = "Demo collector"
    description = "Deterministic operation test"
    query_hint = "query"

    async def collect(self, query: str, context: CollectorContext) -> list[Finding]:
        return [
            Finding(
                f"Result for {query}",
                "https://example.org/public-record",
                {"latitude": 51.5072, "longitude": -0.1276, "city": "London"},
                0.8,
                [
                    {"kind": "username", "value": "alice", "verified": True},
                    {"kind": "email", "value": "alice@example.org", "verified": False},
                ],
            )
        ]


def test_persistent_operation_provenance_location_and_correlation(
    repository: Repository,
) -> None:
    case_id = repository.create_investigation("Operations")
    registry = CollectorRegistry()
    registry.register(DemoCollector())
    manager = OperationManager(repository, registry, CollectorContext(Settings(), repository.db))
    job_id = manager.create_job(case_id, "demo", "alice")
    findings = asyncio.run(manager.run_job(job_id))

    assert len(findings) == 1
    assert repository.rows("collection_jobs", case_id)[0]["status"] == "completed"
    assert repository.rows("source_records", case_id)[0]["content_hash"]
    assert repository.rows("locations", case_id)[0]["label"] == "London"
    suggestions = manager.correlation.pending(case_id)
    assert suggestions[0]["relationship_kind"] == "possible_identity_match"
    manager.correlation.review(suggestions[0]["id"], True)
    assert repository.rows("relationships", case_id)[0]["verified"] is False


def test_investigation_bundle_round_trip(repository: Repository, tmp_path: Path) -> None:
    case_id = repository.create_investigation("Portable case", "Bundle round trip")
    entity_id = repository.add_entity(case_id, "domain", "example.org", verified=True)
    repository.add_note(case_id, "Finding", "A portable note")
    repository.add_bookmark(case_id, "Source", "https://example.org/source", "Public record")
    repository.add_location(case_id, 51.5, -0.12, "London", entity_id=entity_id)
    repository.add_comment(case_id, "investigation", case_id, "Peer reviewed", "reviewer")
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"evidence bytes")
    evidence = EvidenceManager(repository, tmp_path / "managed")
    evidence.ingest(case_id, artifact)
    bundle = InvestigationBundle(repository, evidence)
    path = bundle.export(case_id, tmp_path / "portable.argus")

    summary = bundle.inspect(path)
    assert summary["counts"]["evidence"] == 1
    imported_id = bundle.import_bundle(path)
    assert repository.investigation(imported_id)["title"] == "Portable case (imported)"
    assert len(repository.rows("entities", imported_id)) == 1
    assert len(repository.rows("evidence", imported_id)) == 1
    assert len(repository.rows("comments", imported_id)) == 1
    assert evidence.verify(repository.rows("evidence", imported_id)[0]["id"])[0]


def test_bundle_inspection_rejects_unverified_case_payload(
    repository: Repository, tmp_path: Path
) -> None:
    path = tmp_path / "tampered.argus"
    case = {"bundle_version": 1, "investigation": {"title": "Tampered"}, "records": {}}
    manifest = {
        "format": "argus-investigation-bundle",
        "version": 1,
        "files": {},
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("case.json", json.dumps(case).encode("utf-8"))
        archive.writestr("manifest.json", json.dumps(manifest).encode("utf-8"))

    bundle = InvestigationBundle(repository, EvidenceManager(repository, tmp_path / "managed"))
    with pytest.raises(ValueError, match="missing required file entries"):
        bundle.inspect(path)


def test_entity_merge_preserves_aliases_links_and_locations(repository: Repository) -> None:
    case_id = repository.create_investigation("Entity merge")
    source = repository.add_entity(case_id, "username", "Alice")
    target = repository.add_entity(case_id, "person", "alice", display_name="Alice Example")
    domain = repository.add_entity(case_id, "domain", "example.org")
    repository.add_alias(case_id, source, "@Alice", "alice", "username")
    repository.add_relationship(case_id, source, domain, "uses")
    repository.add_location(case_id, 10, 20, "Observation", entity_id=source)
    repository.merge_entities(case_id, source, target)

    assert {row["id"] for row in repository.rows("entities", case_id)} == {target, domain}
    assert repository.rows("relationships", case_id)[0]["source_entity_id"] == target
    assert repository.rows("locations", case_id)[0]["entity_id"] == target
    assert any(alias["alias"] == "@Alice" for alias in repository.rows("entity_aliases", case_id))
