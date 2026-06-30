from __future__ import annotations

import contextlib
import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from platformdirs import user_config_path, user_data_path

APP_NAME = "ArgusOSINT"


@dataclass(slots=True)
class Settings:
    workspace: str = ""
    theme: str = "dark"
    font_size: int = 10
    request_timeout: float = 20.0
    max_redirects: int = 10
    user_agent: str = "ArgusOSINT/0.1 (+lawful public-source research)"
    proxy: str = ""
    verify_tls: bool = True
    cache_ttl_seconds: int = 3600
    investigator: str = ""

    def resolved_workspace(self) -> Path:
        if self.workspace:
            return Path(self.workspace).expanduser().resolve()
        return user_data_path(APP_NAME, ensure_exists=True)


class SettingsStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or user_config_path(APP_NAME, ensure_exists=True) / "settings.json"

    def load(self) -> Settings:
        if not self.path.exists():
            return Settings()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return Settings()
        allowed = {field.name for field in fields(Settings)}
        return Settings(**{key: value for key, value in raw.items() if key in allowed})

    def save(self, settings: Settings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
        os.replace(temporary, self.path)


class SecretStore:
    """Stores API secrets in the operating system credential vault."""

    service = "ArgusOSINT"

    @staticmethod
    def _keyring() -> Any:
        try:
            import keyring
        except ImportError as exc:
            raise RuntimeError("Install the 'keyring' package to store API credentials") from exc
        return keyring

    def get(self, name: str) -> str:
        return self._keyring().get_password(self.service, name) or ""

    def set(self, name: str, value: str) -> None:
        if value:
            self._keyring().set_password(self.service, name, value)
        else:
            self.delete(name)

    def delete(self, name: str) -> None:
        keyring = self._keyring()
        with contextlib.suppress(keyring.errors.PasswordDeleteError):
            keyring.delete_password(self.service, name)
