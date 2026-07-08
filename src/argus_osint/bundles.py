from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .correlation import CorrelationEngine
from .evidence import EvidenceManager, sha256_file
from .repository import Repository, encode, now

BUNDLE_VERSION = 1
MAX_BUNDLE_BYTES = 5 * 1024 * 1024 * 1024


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class InvestigationBundle:
    """Integrity-checked portable case archive with safe ZIP extraction rules.

    The manifest detects corruption but is not an authenticity signature.
    """

    def __init__(self, repository: Repository, evidence: EvidenceManager) -> None:
        self.repository = repository
        self.evidence = evidence

    def export(self, case_id: int, destination: Path) -> Path:
        case = self.repository.investigation(case_id)
        tables = (
            "notes",
            "entities",
            "relationships",
            "evidence",
            "bookmarks",
            "timeline_events",
            "intelligence",
            "entity_aliases",
            "source_records",
            "comments",
            "locations",
            "correlation_suggestions",
            "collection_jobs",
        )
        payload = {
            "bundle_version": BUNDLE_VERSION,
            "exported_at": now(),
            "investigation": case,
            "records": {table: self.repository.rows(table, case_id) for table in tables},
        }
        case_data = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        manifest: dict[str, Any] = {
            "format": "argus-investigation-bundle",
            "version": BUNDLE_VERSION,
            "generated_at": now(),
            "files": {"case.json": {"sha256": _digest(case_data), "size": len(case_data)}},
        }
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".partial")
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as archive:
            archive.writestr("case.json", case_data)
            for record in payload["records"]["evidence"]:
                path = Path(record["stored_path"])
                if not path.is_file():
                    raise FileNotFoundError(f"Managed evidence is missing: {path}")
                archive_name = f"evidence/{record['id']}/{path.name}"
                size = path.stat().st_size
                if sha256_file(path) != record["sha256"]:
                    raise OSError(f"Evidence {record['id']} failed integrity verification")
                archive.write(path, archive_name)
                manifest["files"][archive_name] = {"sha256": record["sha256"], "size": size}
            manifest_data = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
            archive.writestr("manifest.json", manifest_data)
        temporary.replace(destination)
        return destination

    def inspect(self, source: Path) -> dict[str, Any]:
        with zipfile.ZipFile(source) as archive:
            self._validate_members(archive)
            manifest = json.loads(archive.read("manifest.json"))
            case = json.loads(archive.read("case.json"))
            self._verify(archive, manifest)
        return {
            "manifest": manifest,
            "investigation": case["investigation"],
            "counts": {key: len(value) for key, value in case["records"].items()},
        }

    def import_bundle(self, source: Path, title: str | None = None) -> int:
        with zipfile.ZipFile(source) as archive:
            self._validate_members(archive)
            manifest = json.loads(archive.read("manifest.json"))
            payload = json.loads(archive.read("case.json"))
            self._verify(archive, manifest)
            if payload.get("bundle_version") != BUNDLE_VERSION:
                raise ValueError(
                    f"Unsupported investigation bundle version: {payload.get('bundle_version')}"
                )
            original = payload["investigation"]
            case_id = self.repository.create_investigation(
                title or f"{original['title']} (imported)",
                original.get("description", ""),
                original.get("investigator", ""),
                original.get("tags", []),
                {
                    **original.get("metadata", {}),
                    "imported_at": now(),
                    "imported_from_case_id": original.get("id"),
                    "bundle_sha256": sha256_file(source),
                },
            )
            records = payload["records"]
            entity_map: dict[int, int] = {}
            intelligence_map: dict[int, int] = {}
            evidence_map: dict[int, int] = {}
            object_maps: dict[str, dict[int, int]] = {
                "investigation": {int(original["id"]): case_id},
                "entity": entity_map,
                "intelligence": intelligence_map,
                "evidence": evidence_map,
                "note": {},
                "bookmark": {},
                "relationship": {},
                "timeline": {},
            }
            for item in records.get("entities", []):
                entity_map[item["id"]] = self.repository.add_entity(
                    case_id,
                    item["kind"],
                    item["value"],
                    item.get("display_name", ""),
                    item.get("confidence", 0.5),
                    item.get("verified", False),
                    item.get("source_url", ""),
                    item.get("attributes", {}),
                    item.get("tags", []),
                )
            for item in records.get("notes", []):
                object_maps["note"][item["id"]] = self.repository.add_note(
                    case_id, item.get("title", ""), item["body"], item.get("tags", [])
                )
            for item in records.get("bookmarks", []):
                object_maps["bookmark"][item["id"]] = self.repository.add_bookmark(
                    case_id,
                    item["title"],
                    item["url"],
                    item.get("description", ""),
                    item.get("tags", []),
                )
            for item in records.get("intelligence", []):
                intelligence_map[item["id"]] = self.repository.add_intelligence(
                    case_id,
                    item["collector"],
                    item["query"],
                    item["title"],
                    item.get("data", {}),
                    item.get("source_url", ""),
                    item.get("confidence", 0.5),
                )
            for item in records.get("relationships", []):
                source_id = entity_map.get(item["source_entity_id"])
                target_id = entity_map.get(item["target_entity_id"])
                if source_id and target_id and source_id != target_id:
                    object_maps["relationship"][item["id"]] = self.repository.add_relationship(
                        case_id,
                        source_id,
                        target_id,
                        item["kind"],
                        item.get("confidence", 0.5),
                        item.get("verified", False),
                        item.get("source_url", ""),
                        item.get("attributes", {}),
                    )
            for item in records.get("timeline_events", []):
                object_maps["timeline"][item["id"]] = self.repository.add_timeline_event(
                    case_id,
                    item["occurred_at"],
                    item["title"],
                    item.get("description", ""),
                    item.get("kind", "event"),
                    item.get("source_url", ""),
                    entity_map.get(item.get("entity_id")),
                    item.get("attributes", {}),
                )
            with tempfile.TemporaryDirectory(prefix="argus-bundle-") as temporary:
                staging = Path(temporary)
                for item in records.get("evidence", []):
                    prefix = f"evidence/{item['id']}/"
                    candidates = [name for name in manifest["files"] if name.startswith(prefix)]
                    if len(candidates) != 1:
                        raise ValueError(f"Evidence {item['id']} has an invalid bundle entry")
                    destination = staging / Path(candidates[0]).name
                    with archive.open(candidates[0]) as bundled, destination.open("wb") as output:
                        shutil.copyfileobj(bundled, output, length=1024 * 1024)
                    evidence_map[item["id"]] = self.evidence.ingest(
                        case_id,
                        destination,
                        item.get("title", ""),
                        item.get("source_url", ""),
                        item.get("notes", ""),
                        item.get("confidence", 1.0),
                    )
            for item in records.get("entity_aliases", []):
                entity_id = entity_map.get(item["entity_id"])
                if entity_id:
                    self.repository.add_alias(
                        case_id,
                        entity_id,
                        item["alias"],
                        item["normalized"],
                        item.get("kind", "alias"),
                        item.get("source_url", ""),
                        item.get("confidence", 0.5),
                    )
            for item in records.get("locations", []):
                self.repository.add_location(
                    case_id,
                    item["latitude"],
                    item["longitude"],
                    item.get("label", ""),
                    entity_map.get(item.get("entity_id")),
                    intelligence_map.get(item.get("intelligence_id")),
                    item.get("source_url", ""),
                    item.get("confidence", 0.5),
                    item.get("attributes", {}),
                )
            for item in records.get("source_records", []):
                self.repository.db.execute(
                    "INSERT OR IGNORE INTO source_records(investigation_id,intelligence_id,url,title,publisher,published_at,retrieved_at,content_hash,snapshot_path,metadata) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        case_id,
                        intelligence_map.get(item.get("intelligence_id")),
                        item["url"],
                        item.get("title", ""),
                        item.get("publisher", ""),
                        item.get("published_at"),
                        item.get("retrieved_at", now()),
                        item["content_hash"],
                        item.get("snapshot_path", ""),
                        encode(item.get("metadata", {})),
                    ),
                )
            for item in records.get("comments", []):
                object_type = item["object_type"]
                mapped_id = object_maps.get(object_type, {}).get(item["object_id"])
                if mapped_id is not None:
                    self.repository.add_comment(
                        case_id,
                        object_type,
                        mapped_id,
                        item["body"],
                        item.get("author", ""),
                    )
            valid_statuses = {"pending", "running", "completed", "failed", "cancelled"}
            for item in records.get("collection_jobs", []):
                status = item.get("status", "completed")
                if status not in valid_statuses or status in {"pending", "running"}:
                    status = "completed"
                self.repository.db.execute(
                    "INSERT INTO collection_jobs(investigation_id,collector,query,status,progress,result_count,error,options,created_at,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        case_id,
                        item["collector"],
                        item["query"],
                        status,
                        item.get("progress", 1.0),
                        item.get("result_count", 0),
                        item.get("error", ""),
                        encode({**item.get("options", {}), "imported_history": True}),
                        item.get("created_at", now()),
                        item.get("started_at"),
                        item.get("finished_at"),
                    ),
                )
            CorrelationEngine(self.repository).generate(case_id)
        return case_id

    @staticmethod
    def _validate_members(archive: zipfile.ZipFile) -> None:
        total = 0
        names: set[str] = set()
        for member in archive.infolist():
            if InvestigationBundle._unsafe_archive_name(member.filename):
                raise ValueError(f"Unsafe path in bundle: {member.filename}")
            if member.filename in names:
                raise ValueError(f"Duplicate path in bundle: {member.filename}")
            names.add(member.filename)
            total += member.file_size
            if total > MAX_BUNDLE_BYTES:
                raise ValueError("Investigation bundle exceeds the 5 GiB safety limit")
            if member.compress_size and member.file_size / member.compress_size > 1000:
                raise ValueError(f"Suspicious compression ratio in {member.filename}")
        if not {"manifest.json", "case.json"} <= names:
            raise ValueError("Not an Argus investigation bundle")

    @staticmethod
    def _verify(archive: zipfile.ZipFile, manifest: dict[str, Any]) -> None:
        if manifest.get("format") != "argus-investigation-bundle":
            raise ValueError("Unrecognized bundle manifest")
        files = manifest.get("files")
        if not isinstance(files, dict) or "case.json" not in files:
            raise ValueError("Bundle manifest is missing required file entries")
        for name, expected in files.items():
            if not isinstance(name, str) or InvestigationBundle._unsafe_archive_name(name):
                raise ValueError(f"Unsafe path in bundle manifest: {name}")
            if not isinstance(expected, dict) or not {
                "sha256",
                "size",
            } <= expected.keys():
                raise ValueError(f"Invalid manifest entry for {name}")
            try:
                member = archive.getinfo(name)
            except KeyError as exc:
                raise ValueError(f"Bundle manifest references missing file: {name}") from exc
            if member.is_dir():
                raise ValueError(f"Bundle manifest references a directory: {name}")
            digest = hashlib.sha256()
            with archive.open(member) as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            if member.file_size != expected["size"] or digest.hexdigest() != expected["sha256"]:
                raise OSError(f"Bundle integrity verification failed for {name}")

    @staticmethod
    def _unsafe_archive_name(name: str) -> bool:
        path = PurePosixPath(name)
        return path.is_absolute() or ".." in path.parts or "\\" in name
