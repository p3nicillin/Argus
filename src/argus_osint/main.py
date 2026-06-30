from __future__ import annotations

import logging
import sys
from pathlib import Path

from platformdirs import user_log_path

from .config import APP_NAME, SettingsStore


def configure_logging() -> Path:
    log_directory = user_log_path(APP_NAME, ensure_exists=True)
    log_path = log_directory / "argus.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[logging.FileHandler(log_path, encoding="utf-8"), logging.StreamHandler()],
    )
    return log_path


def main() -> int:
    configure_logging()
    try:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QApplication, QMessageBox

        from .ui import MainWindow
    except ImportError as exc:
        print(
            "Argus OSINT requires PySide6. Install the project with: python -m pip install -e .",
            file=sys.stderr,
        )
        print(exc, file=sys.stderr)
        return 2
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    application = QApplication(sys.argv)
    application.setApplicationName("Argus OSINT")
    application.setOrganizationName("Argus")
    settings_store = SettingsStore()
    try:
        window = MainWindow(settings_store.load(), settings_store)
        window.show()
        return application.exec()
    except Exception as exc:
        logging.exception("Fatal application error")
        QMessageBox.critical(None, "Argus OSINT", f"The application could not start:\n\n{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
