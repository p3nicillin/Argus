from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .repository import Repository, encode, now


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def extract_metadata(path: Path) -> dict[str, Any]:
    stat = path.stat()
    result: dict[str, Any] = {
        "filename": path.name,
        "extension": path.suffix.lower(),
        "size": stat.st_size,
        "created": datetime.fromtimestamp(stat.st_ctime, UTC).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
    }
    try:
        from PIL import ExifTags, Image

        with Image.open(path) as image:
            result["image"] = {
                "format": image.format,
                "mode": image.mode,
                "width": image.width,
                "height": image.height,
            }
            exif = image.getexif()
            if exif:
                result["exif"] = {
                    ExifTags.TAGS.get(key, str(key)): _json_safe(value)
                    for key, value in exif.items()
                }
    except (ImportError, OSError, ValueError):
        pass
    return result


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


class EvidenceManager:
    def __init__(self, repository: Repository, evidence_root: Path) -> None:
        self.repository = repository
        self.root = evidence_root
        self.root.mkdir(parents=True, exist_ok=True)

    def ingest(
        self,
        case_id: int,
        source: Path,
        title: str = "",
        source_url: str = "",
        notes: str = "",
        confidence: float = 1.0,
        move: bool = False,
    ) -> int:
        source = source.expanduser().resolve(strict=True)
        if not source.is_file():
            raise ValueError("Evidence source must be a file")
        digest = sha256_file(source)
        case_folder = self.root / f"case-{case_id}" / digest[:2]
        case_folder.mkdir(parents=True, exist_ok=True)
        destination = self._unique_destination(case_folder, digest, source.suffix.lower())
        if not destination.exists():
            temporary = destination.with_suffix(destination.suffix + ".partial")
            if move:
                shutil.move(str(source), temporary)
            else:
                shutil.copy2(source, temporary)
            if sha256_file(temporary) != digest:
                temporary.unlink(missing_ok=True)
                raise OSError("Evidence integrity check failed after copying")
            os.replace(temporary, destination)
        metadata = extract_metadata(destination)
        captured = (
            datetime.fromtimestamp(source.stat().st_mtime, UTC).isoformat()
            if source.exists()
            else now()
        )
        with self.repository.db.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO evidence(investigation_id,title,original_path,stored_path,source_url,mime_type,size,sha256,metadata,notes,confidence,captured_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    case_id,
                    title.strip() or source.name,
                    str(source),
                    str(destination),
                    source_url,
                    mimetypes.guess_type(source.name)[0] or "application/octet-stream",
                    destination.stat().st_size,
                    digest,
                    encode(metadata),
                    notes,
                    confidence,
                    captured,
                    now(),
                ),
            )
            item_id = int(cursor.lastrowid)
            self.repository._index(
                connection,
                "evidence",
                item_id,
                case_id,
                title or source.name,
                f"{notes} {source_url} {digest} {encode(metadata)}",
            )
            self.repository._audit(
                connection, "ingest", "evidence", item_id, case_id, {"sha256": digest}
            )
        return item_id

    @staticmethod
    def _unique_destination(folder: Path, digest: str, suffix: str) -> Path:
        return folder / f"{digest}{suffix}"

    def verify(self, evidence_id: int) -> tuple[bool, str]:
        row = self.repository.db.one("SELECT * FROM evidence WHERE id=?", (evidence_id,))
        if row is None:
            raise KeyError(f"Evidence {evidence_id} does not exist")
        path = Path(row["stored_path"])
        if not path.is_file():
            return False, "Managed evidence file is missing"
        actual = sha256_file(path)
        if actual != row["sha256"]:
            return False, f"SHA-256 mismatch: expected {row['sha256']}, got {actual}"
        return True, actual

    def export_manifest(self, case_id: int, destination: Path) -> None:
        evidence = self.repository.rows("evidence", case_id)
        manifest = {
            "investigation_id": case_id,
            "generated_at": now(),
            "algorithm": "SHA-256",
            "items": [
                {
                    key: item[key]
                    for key in (
                        "id",
                        "title",
                        "stored_path",
                        "source_url",
                        "size",
                        "sha256",
                        "captured_at",
                        "created_at",
                    )
                }
                for item in evidence
            ],
        }
        destination.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
