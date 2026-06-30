from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .db import Database
from .repository import encode, now

ALLOWED_PERMISSIONS = {"network", "read_files", "write_exports"}


@dataclass(frozen=True, slots=True)
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    description: str
    entrypoint: str
    permissions: tuple[str, ...]
    sha256: str = ""

    @classmethod
    def load(cls, directory: Path) -> PluginManifest:
        path = directory / "plugin.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid plugin manifest at {path}") from exc
        required = {"id", "name", "version", "description", "entrypoint"}
        missing = required - value.keys()
        if missing:
            raise ValueError(f"Plugin manifest is missing: {', '.join(sorted(missing))}")
        plugin_id = value["id"]
        if (
            not isinstance(plugin_id, str)
            or not plugin_id.replace("-", "").replace("_", "").isalnum()
        ):
            raise ValueError("Plugin id may contain only letters, numbers, hyphens and underscores")
        permissions = tuple(value.get("permissions", []))
        unknown = set(permissions) - ALLOWED_PERMISSIONS
        if unknown:
            raise ValueError(f"Unsupported plugin permissions: {', '.join(sorted(unknown))}")
        entrypoint = value["entrypoint"]
        if Path(entrypoint).is_absolute() or ".." in Path(entrypoint).parts:
            raise ValueError("Plugin entrypoint must stay inside its plugin folder")
        return cls(
            plugin_id,
            value["name"],
            value["version"],
            value["description"],
            entrypoint,
            permissions,
            value.get("sha256", ""),
        )


class PluginManager:
    """Discovers and runs JSON-line plugins out of process.

    The boundary prevents plugins from importing the application process. Permissions
    are explicit user-facing declarations; OS-level sandboxing remains platform dependent.
    """

    def __init__(self, root: Path, db: Database) -> None:
        self.root = root
        self.db = db
        self.root.mkdir(parents=True, exist_ok=True)

    def discover(self) -> list[PluginManifest]:
        manifests: list[PluginManifest] = []
        for directory in self.root.iterdir():
            if directory.is_dir() and (directory / "plugin.json").is_file():
                try:
                    manifest = PluginManifest.load(directory)
                except ValueError:
                    continue
                manifests.append(manifest)
                self.db.execute(
                    "INSERT INTO plugins(plugin_id,version,permissions,updated_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(plugin_id) DO UPDATE SET version=excluded.version,permissions=excluded.permissions,updated_at=excluded.updated_at",
                    (manifest.plugin_id, manifest.version, encode(manifest.permissions), now()),
                )
        return sorted(manifests, key=lambda item: item.name.lower())

    def is_enabled(self, plugin_id: str) -> bool:
        row = self.db.one("SELECT enabled FROM plugins WHERE plugin_id=?", (plugin_id,))
        return bool(row and row["enabled"])

    def set_enabled(self, plugin_id: str, enabled: bool) -> None:
        cursor = self.db.execute(
            "UPDATE plugins SET enabled=?,updated_at=? WHERE plugin_id=?",
            (int(enabled), now(), plugin_id),
        )
        if not cursor.rowcount:
            raise KeyError(f"Unknown plugin: {plugin_id}")

    def install(self, archive: Path) -> PluginManifest:
        if not zipfile.is_zipfile(archive):
            raise ValueError("Plugin package must be a ZIP archive")
        with tempfile.TemporaryDirectory(prefix="argus-plugin-") as temporary:
            staging = Path(temporary)
            with zipfile.ZipFile(archive) as package:
                for item in package.infolist():
                    destination = (staging / item.filename).resolve()
                    if (
                        staging.resolve() not in destination.parents
                        and destination != staging.resolve()
                    ):
                        raise ValueError("Plugin archive contains an unsafe path")
                package.extractall(staging)
            candidates = (
                [staging]
                if (staging / "plugin.json").exists()
                else [
                    path
                    for path in staging.iterdir()
                    if path.is_dir() and (path / "plugin.json").exists()
                ]
            )
            if len(candidates) != 1:
                raise ValueError("Plugin package must contain exactly one plugin.json")
            manifest = PluginManifest.load(candidates[0])
            entrypoint = candidates[0] / manifest.entrypoint
            if not entrypoint.is_file():
                raise ValueError("Plugin entrypoint does not exist")
            if manifest.sha256 and self._digest(entrypoint) != manifest.sha256.lower():
                raise ValueError("Plugin entrypoint checksum does not match its manifest")
            target = self.root / manifest.plugin_id
            backup = self.root / f".{manifest.plugin_id}.backup"
            if backup.exists():
                shutil.rmtree(backup)
            if target.exists():
                os.replace(target, backup)
            try:
                shutil.copytree(candidates[0], target)
            except Exception:
                if backup.exists():
                    os.replace(backup, target)
                raise
            if backup.exists():
                shutil.rmtree(backup)
        self.discover()
        return manifest

    def remove(self, plugin_id: str) -> None:
        manifest = self._manifest(plugin_id)
        path = self.root / manifest.plugin_id
        shutil.rmtree(path)
        self.db.execute("DELETE FROM plugins WHERE plugin_id=?", (plugin_id,))

    async def invoke(
        self, plugin_id: str, method: str, parameters: dict[str, Any], timeout: float = 60.0
    ) -> dict[str, Any]:
        manifest = self._manifest(plugin_id)
        if not self.is_enabled(plugin_id):
            raise RuntimeError(f"Plugin {plugin_id} is disabled")
        entrypoint = (self.root / plugin_id / manifest.entrypoint).resolve()
        root = (self.root / plugin_id).resolve()
        if root not in entrypoint.parents or not entrypoint.is_file():
            raise RuntimeError("Plugin entrypoint is invalid")
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            str(entrypoint),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(root),
            env={"PATH": os.environ.get("PATH", ""), "PYTHONUTF8": "1"},
        )
        request = (
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": parameters}).encode()
            + b"\n"
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(request), timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError(f"Plugin {plugin_id} timed out") from None
        if process.returncode != 0:
            raise RuntimeError(
                f"Plugin {plugin_id} failed: {stderr.decode(errors='replace')[:2000]}"
            )
        try:
            response = json.loads(stdout.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Plugin {plugin_id} returned an invalid response") from exc
        if response.get("error"):
            raise RuntimeError(f"Plugin {plugin_id}: {response['error']}")
        if response.get("id") != 1 or "result" not in response:
            raise RuntimeError(f"Plugin {plugin_id} returned an invalid JSON-RPC envelope")
        return response["result"]

    def _manifest(self, plugin_id: str) -> PluginManifest:
        path = self.root / plugin_id
        if not path.is_dir():
            raise KeyError(f"Unknown plugin: {plugin_id}")
        return PluginManifest.load(path)

    @staticmethod
    def _digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
