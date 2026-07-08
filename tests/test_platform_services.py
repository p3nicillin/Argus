from __future__ import annotations

from pathlib import Path

from argus_osint.app_services import ArgusServices, build_services
from argus_osint.db import Database
from argus_osint.repository import Repository
from argus_osint.universal import UniversalInputNormalizer, UniversalSearchService
from argus_osint.workspace import (
    DashboardService,
    EnrichmentService,
    GraphService,
    TimelineService,
)


def test_universal_input_normalizer_understands_security_and_social_seeds():
    normalizer = UniversalInputNormalizer()

    assert normalizer.normalize("CVE-2024-3094").kind == "cve"
    assert normalizer.normalize("PERSON@EXAMPLE.ORG").value == "person@example.org"
    assert normalizer.normalize("https://github.com/octocat").kind == "github"
    assert normalizer.normalize("https://github.com/octocat").value == "octocat"
    assert normalizer.normalize("@alice@mastodon.social").kind == "mastodon"
    assert normalizer.normalize("4600 Silver Hill Rd, Washington, DC 20233").kind == "address"
    assert normalizer.normalize("0x0000000000000000000000000000000000000000").kind == "crypto_wallet"


def test_universal_search_builds_free_source_collection_plans(tmp_path: Path):
    repository = Repository(Database(tmp_path / "universal.sqlite3"), "analyst")
    try:
        service = UniversalSearchService(repository)

        cve_plan = service.plan("CVE-2024-3094")
        assert [item["collector"] for item in cve_plan["plan"][:3]] == [
            "nvd_cve",
            "cisa_kev",
            "epss",
        ]

        github_plan = service.plan("https://github.com/octocat")
        collectors = {item["collector"] for item in github_plan["plan"]}
        assert {"github", "social_profiles"} <= collectors

        phone_plan = service.plan("+44 20 7946 0958")
        assert "phone" in {item["collector"] for item in phone_plan["plan"]}

        repository.create_investigation("Universal case")
        search_result = service.search("Universal", limit=10)
        assert search_result["local_result_count"] == 1
        assert search_result["local_results"][0]["object_type"] == "investigation"
    finally:
        repository.db.close()


def test_workspace_services_return_dashboard_graph_timeline_and_enrichment(tmp_path: Path):
    repository = Repository(Database(tmp_path / "workspace.sqlite3"), "analyst")
    try:
        case_id = repository.create_investigation("Workspace case", tags=["pinned"])
        domain_id = repository.add_entity(case_id, "domain", "example.org", verified=True)
        email_id = repository.add_entity(case_id, "email", "admin@example.org")
        repository.add_alias(case_id, email_id, "Admin", "admin")
        repository.add_relationship(
            case_id,
            domain_id,
            email_id,
            "has_contact",
            confidence=0.8,
            verified=True,
        )
        repository.add_timeline_event(
            case_id,
            "2026-07-08T10:00:00+00:00",
            "Disclosure contact found",
            "security.txt listed an address",
            kind="discovery",
            entity_id=email_id,
        )
        repository.add_intelligence(
            case_id,
            "security_txt",
            "example.org",
            "security.txt",
            {"contact": "admin@example.org"},
            "https://example.org/.well-known/security.txt",
            0.9,
        )
        repository.save_search("example", "example.org")
        repository.search("example", case_id)

        dashboard = DashboardService(repository).overview(case_id)
        assert dashboard["stats"]["entities"] == 2
        assert dashboard["pinned_investigations"][0]["id"] == case_id
        assert dashboard["saved_searches"][0]["name"] == "example"
        assert dashboard["search_history"][0]["query"] == "example"

        graph = GraphService(repository).relationship_graph(case_id)
        assert graph["groups"] == {"domain": 1, "email": 1}
        assert graph["edges"][0]["kind"] == "has_contact"

        timeline = TimelineService(repository).unified_timeline(case_id)
        assert {item["object_type"] for item in timeline} == {"timeline_event", "intelligence"}

        profiles = EnrichmentService(repository).entity_profiles(case_id)
        by_kind = {profile["entity"]["kind"]: profile for profile in profiles}
        assert by_kind["email"]["aliases"][0]["alias"] == "Admin"
        assert by_kind["domain"]["recommended_collection"]
    finally:
        repository.db.close()


def test_argus_services_composes_platform_services(tmp_path: Path):
    services = ArgusServices.build(db_path=tmp_path / "argus.sqlite3", actor="analyst")
    try:
        case_id = services.repository.create_investigation("Composed case")
        assert services.dashboard.overview(case_id)["stats"]["investigations"] == 1
        assert services.universal_search.plan("https://reddit.com/user/example")["supported"]
        assert services.security.build(case_id)["investigation"]["title"] == "Composed case"
    finally:
        services.close()

    services = build_services(db_path=tmp_path / "argus2.sqlite3", actor="analyst")
    try:
        assert services.collectors.get("github").id == "github"
    finally:
        services.close()
