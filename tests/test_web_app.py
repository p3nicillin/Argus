from __future__ import annotations

import json
from pathlib import Path

from argus_osint.app_services import ArgusServices
from argus_osint.web import ArgusWebApplication


def _json(app: ArgusWebApplication, path: str) -> dict:
    status, content_type, body = app.handle("GET", path)
    assert status == 200
    assert content_type.startswith("application/json")
    return json.loads(body)


def test_web_app_serves_static_shell_and_health(tmp_path: Path):
    services = ArgusServices.build(db_path=tmp_path / "argus.sqlite3", actor="analyst")
    try:
        app = ArgusWebApplication(services)
        status, content_type, body = app.handle("GET", "/")

        assert status == 200
        assert content_type == "text/html"
        assert b"Argus OSINT" in body

        health = _json(app, "/api/health")
        assert health["app"] == "Argus OSINT"
        assert health["database"].endswith("argus.sqlite3")
    finally:
        services.close()


def test_web_app_dashboard_search_and_case_resources(tmp_path: Path):
    services = ArgusServices.build(db_path=tmp_path / "argus.sqlite3", actor="analyst")
    try:
        case_id = services.repository.create_investigation("Web case", tags=["pinned"])
        first = services.repository.add_entity(case_id, "domain", "example.org", verified=True)
        second = services.repository.add_entity(case_id, "email", "admin@example.org")
        services.repository.add_relationship(case_id, first, second, "contact")
        services.repository.add_timeline_event(
            case_id,
            "2026-07-08T12:00:00+00:00",
            "Contact observed",
            "security contact found",
        )
        app = ArgusWebApplication(services)

        dashboard = _json(app, "/api/dashboard")
        assert dashboard["stats"]["investigations"] == 1
        assert dashboard["pinned_investigations"][0]["title"] == "Web case"

        search = _json(app, "/api/search?q=example.org")
        assert search["input"]["kind"] == "domain"
        assert search["local_result_count"] >= 1
        assert "dns" in {item["collector"] for item in search["plan"]}

        graph = _json(app, f"/api/investigations/{case_id}/graph")
        assert len(graph["nodes"]) == 2
        assert graph["edges"][0]["kind"] == "contact"

        timeline = app.handle("GET", f"/api/investigations/{case_id}/timeline")
        assert timeline[0] == 200
        assert json.loads(timeline[2])[0]["title"] == "Contact observed"
    finally:
        services.close()


def test_web_app_can_create_case_from_json(tmp_path: Path):
    services = ArgusServices.build(db_path=tmp_path / "argus.sqlite3", actor="analyst")
    try:
        app = ArgusWebApplication(services)
        status, _content_type, body = app.handle(
            "POST",
            "/api/investigations",
            json.dumps({"title": "Created from web", "tags": ["web"]}).encode("utf-8"),
        )

        assert status == 200
        payload = json.loads(body)
        assert payload["title"] == "Created from web"
        assert payload["tags"] == ["web"]
    finally:
        services.close()


def test_web_app_returns_client_errors_for_bad_api_inputs(tmp_path: Path):
    services = ArgusServices.build(db_path=tmp_path / "argus.sqlite3", actor="analyst")
    try:
        app = ArgusWebApplication(services)

        status, _content_type, body = app.handle("GET", "/api/search?q=example&limit=lots")
        assert status == 400
        assert json.loads(body)["error"] == "limit must be an integer"

        status, _content_type, body = app.handle("GET", "/api/investigations/not-a-number")
        assert status == 400
        assert json.loads(body)["error"] == "Investigation id must be an integer"

        status, _content_type, body = app.handle("GET", "/api/investigations/99999")
        assert status == 404
        assert json.loads(body)["error"] == "Investigation 99999 does not exist"

        status, _content_type, body = app.handle(
            "POST",
            "/api/jobs",
            json.dumps({"case_id": "nope", "collector": "dns", "query": "example.org"}).encode(
                "utf-8"
            ),
        )
        assert status == 400
        assert json.loads(body)["error"] == "case_id must be an integer"

        status, _content_type, body = app.handle(
            "POST",
            "/api/jobs",
            json.dumps({"case_id": 1, "collector": "dns"}).encode("utf-8"),
        )
        assert status == 400
        assert json.loads(body)["error"] == "query is required"
    finally:
        services.close()
