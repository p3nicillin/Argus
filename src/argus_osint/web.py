from __future__ import annotations

import argparse
import asyncio
import json
import mimetypes
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__
from .app_services import ArgusServices
from .config import SettingsStore

STATIC_ROOT = Path(__file__).with_name("web_static")


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ArgusWebApplication:
    """Local-only JSON API and static web shell for Argus."""

    def __init__(self, services: ArgusServices, static_root: Path = STATIC_ROOT) -> None:
        self.services = services
        self.static_root = static_root

    def handle(
        self,
        method: str,
        raw_path: str,
        body: bytes = b"",
    ) -> tuple[int, str, bytes]:
        parsed = urlparse(raw_path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if path.startswith("/api"):
                return self._json_response(self._api(method, path, query, body))
            if method != "GET":
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "Only GET is supported here")
            return self._static(path)
        except ApiError as exc:
            return self._json_response({"error": exc.message}, exc.status)
        except Exception as exc:
            return self._json_response({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _api(
        self,
        method: str,
        path: str,
        query: dict[str, list[str]],
        body: bytes,
    ) -> Any:
        parts = [part for part in path.split("/") if part]
        if parts == ["api", "health"] and method == "GET":
            return {
                "app": "Argus OSINT",
                "version": __version__,
                "workspace": str(self.services.settings.resolved_workspace()),
                "database": str(self.services.database.path),
            }
        if parts == ["api", "dashboard"] and method == "GET":
            case_id = self._optional_int(query, "case_id")
            return self.services.dashboard.overview(case_id)
        if parts == ["api", "search"] and method == "GET":
            term = self._query(query, "q")
            if not term:
                raise ApiError(HTTPStatus.BAD_REQUEST, "Search query is required")
            return self.services.universal_search.search(
                term,
                self._optional_int(query, "case_id"),
                self._optional_int(query, "limit") or 200,
            )
        if parts == ["api", "collectors"] and method == "GET":
            return [
                {
                    "id": collector.id,
                    "name": collector.name,
                    "description": collector.description,
                    "query_hint": collector.query_hint,
                }
                for collector in self.services.collectors.all()
            ]
        if parts == ["api", "investigations"]:
            if method == "GET":
                return self.services.repository.list_investigations(include_archived=True)
            if method == "POST":
                payload = self._payload(body)
                case_id = self.services.repository.create_investigation(
                    str(payload.get("title", "")).strip(),
                    str(payload.get("description", "")).strip(),
                    str(payload.get("investigator", "")).strip(),
                    self._list(payload.get("tags")),
                    self._dict(payload.get("metadata")),
                )
                return self.services.repository.investigation(case_id)
        if len(parts) >= 3 and parts[:2] == ["api", "investigations"]:
            case_id = self._case_id(parts[2])
            if len(parts) == 3 and method == "GET":
                return self.services.repository.investigation(case_id)
            if len(parts) == 4 and method == "GET":
                return self._case_resource(case_id, parts[3])
        if parts == ["api", "jobs"] and method == "POST":
            payload = self._payload(body)
            job_id = self.services.operations.create_job(
                int(payload["case_id"]),
                str(payload["collector"]),
                str(payload["query"]),
                self._dict(payload.get("options")),
            )
            if bool(payload.get("run")):
                self._run_job_background(job_id)
            return {"job_id": job_id, "status": "queued", "running": bool(payload.get("run"))}
        if (
            len(parts) == 4
            and parts[:2] == ["api", "jobs"]
            and parts[3] == "events"
            and method == "GET"
        ):
            return self.services.operations.events(int(parts[2]))
        raise ApiError(HTTPStatus.NOT_FOUND, f"No route for {method} {path}")

    def _case_resource(self, case_id: int, resource: str) -> Any:
        tables = {
            "notes": "notes",
            "entities": "entities",
            "relationships": "relationships",
            "evidence": "evidence",
            "bookmarks": "bookmarks",
            "intelligence": "intelligence",
            "sources": "source_records",
            "comments": "comments",
            "locations": "locations",
            "jobs": "collection_jobs",
        }
        if resource in tables:
            return self.services.repository.rows(tables[resource], case_id)
        if resource == "graph":
            return self.services.graph.relationship_graph(case_id)
        if resource == "timeline":
            return self.services.timeline.unified_timeline(case_id)
        if resource == "enrichment":
            return self.services.enrichment.entity_profiles(case_id)
        if resource == "security":
            return self.services.security.build(case_id)
        raise ApiError(HTTPStatus.NOT_FOUND, f"Unknown investigation resource: {resource}")

    def _static(self, path: str) -> tuple[int, str, bytes]:
        relative = "index.html" if path == "/" else unquote(path.lstrip("/"))
        target = (self.static_root / relative).resolve()
        root = self.static_root.resolve()
        if not target.is_file() or root not in target.parents:
            target = root / "index.html"
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        return HTTPStatus.OK, content_type, target.read_bytes()

    @staticmethod
    def _json_response(
        payload: Any,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> tuple[int, str, bytes]:
        return (
            int(status),
            "application/json; charset=utf-8",
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        )

    @staticmethod
    def _payload(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Request body must be valid JSON") from exc
        if not isinstance(value, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Request body must be a JSON object")
        return value

    @staticmethod
    def _query(query: dict[str, list[str]], name: str) -> str:
        return query.get(name, [""])[0].strip()

    @classmethod
    def _optional_int(cls, query: dict[str, list[str]], name: str) -> int | None:
        value = cls._query(query, name)
        return int(value) if value else None

    @staticmethod
    def _case_id(value: str) -> int:
        try:
            return int(value)
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Investigation id must be an integer") from exc

    @staticmethod
    def _list(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return []

    @staticmethod
    def _dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _run_job_background(self, job_id: int) -> None:
        def worker() -> None:
            asyncio.run(self.services.operations.run_job(job_id))

        threading.Thread(target=worker, daemon=True, name=f"argus-job-{job_id}").start()


class ArgusRequestHandler(BaseHTTPRequestHandler):
    application: ArgusWebApplication

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._headers("text/plain")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _handle(self) -> None:
        length = int(self.headers.get("content-length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        status, content_type, payload = self.application.handle(self.command, self.path, body)
        self.send_response(status)
        self._headers(content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")


def build_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    services: ArgusServices | None = None,
) -> ThreadingHTTPServer:
    settings = SettingsStore().load()
    services = services or ArgusServices.build(settings=settings)
    ArgusRequestHandler.application = ArgusWebApplication(services)
    server = ThreadingHTTPServer((host, port), ArgusRequestHandler)
    server.services = services  # type: ignore[attr-defined]
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local Argus web app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    server = build_server(args.host, args.port)
    url = f"http://{args.host}:{server.server_port}/"
    print(f"Argus web app running at {url}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        services = getattr(server, "services", None)
        if services:
            services.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
