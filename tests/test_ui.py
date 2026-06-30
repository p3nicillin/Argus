from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtWidgets import QApplication

from argus_osint.config import Settings, SettingsStore
from argus_osint.ui import MainWindow


def test_main_window_expanded_workspace(tmp_path: Path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    application = QApplication.instance() or QApplication([])
    settings = Settings(workspace=str(tmp_path))
    window = MainWindow(settings, SettingsStore(tmp_path / "settings.json"))
    case_id = window.repository.create_investigation("UI smoke")
    first = window.repository.add_entity(case_id, "person", "Alice")
    second = window.repository.add_entity(case_id, "domain", "example.org")
    window.repository.add_relationship(case_id, first, second, "uses")
    window.repository.add_location(case_id, 51.5, -0.12, "London", entity_id=first)
    window.select_case(case_id)
    window.show()
    application.processEvents()

    assert window.isVisible()
    assert window.case_tabs.count() >= 12
    assert window.entity_model.rowCount() == 2
    assert window.graph.scene().items()
    assert window.map_view.scene().items()

    window.close()
    application.processEvents()
