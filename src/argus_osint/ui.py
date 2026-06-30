from __future__ import annotations

import asyncio
import json
import math
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPointF,
    QRunnable,
    QSortFilterProxyModel,
    Qt,
    QThreadPool,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QKeySequence,
    QPainter,
    QPen,
    QShortcut,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGraphicsEllipseItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from .collectors import Collector, CollectorContext, CollectorRegistry, Finding
from .config import SecretStore, Settings, SettingsStore
from .db import Database
from .evidence import EvidenceManager
from .plugins import PluginManager
from .reports import ReportEngine
from .repository import Repository

DARK_STYLE = """
QWidget { background:#111820; color:#dce7ef; font-family:'Segoe UI'; }
QMainWindow, QDialog { background:#0e141b; }
QToolBar { background:#151f29; border:0; border-bottom:1px solid #273746; spacing:5px; padding:5px; }
QToolButton, QPushButton { background:#20303e; border:1px solid #31495b; border-radius:5px; padding:6px 12px; }
QToolButton:hover, QPushButton:hover { background:#29465a; border-color:#43a6d8; }
QPushButton:pressed { background:#17374a; }
QPushButton#primary { background:#1979a8; border-color:#36a5d4; color:white; font-weight:600; }
QLineEdit, QPlainTextEdit, QTextBrowser, QComboBox, QSpinBox { background:#0d141b; border:1px solid #304252; border-radius:5px; padding:6px; selection-background-color:#1d79a7; }
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus { border-color:#43a6d8; }
QTableView { background:#111a22; alternate-background-color:#15212b; gridline-color:#263746; border:1px solid #263746; }
QHeaderView::section { background:#1b2935; color:#a9c2d3; border:0; border-right:1px solid #304252; padding:7px; font-weight:600; }
QTableView::item:selected, QListWidget::item:selected { background:#1a668a; color:white; }
QTabWidget::pane { border:1px solid #273746; }
QTabBar::tab { background:#151f29; padding:8px 14px; border:1px solid #273746; }
QTabBar::tab:selected { background:#1e3444; border-bottom:2px solid #45a9d8; }
QDockWidget::title { background:#1b2935; padding:7px; font-weight:600; }
QStatusBar { background:#151f29; border-top:1px solid #273746; }
QProgressBar { border:1px solid #304252; border-radius:4px; text-align:center; background:#0d141b; }
QProgressBar::chunk { background:#2e9dcc; }
QFrame#card { background:#17232d; border:1px solid #2a3e4d; border-radius:8px; }
QLabel#metric { color:#55b9e4; font-size:24px; font-weight:700; }
QLabel#muted { color:#839aaa; }
"""

LIGHT_STYLE = """
QWidget { background:#f4f7fa; color:#17212b; font-family:'Segoe UI'; }
QMainWindow, QDialog { background:#edf2f6; }
QToolBar { background:white; border:0; border-bottom:1px solid #ced9e1; spacing:5px; padding:5px; }
QToolButton, QPushButton { background:#fff; border:1px solid #bdcbd5; border-radius:5px; padding:6px 12px; }
QToolButton:hover, QPushButton:hover { background:#e7f3f9; border-color:#248ebc; }
QPushButton#primary { background:#1979a8; border-color:#176f9a; color:white; font-weight:600; }
QLineEdit, QPlainTextEdit, QTextBrowser, QComboBox, QSpinBox { background:white; border:1px solid #b9c8d3; border-radius:5px; padding:6px; selection-background-color:#60afd1; }
QTableView { background:white; alternate-background-color:#f3f7fa; gridline-color:#d6e0e7; border:1px solid #c8d5df; }
QHeaderView::section { background:#e7eef3; color:#344b5b; border:0; border-right:1px solid #c8d5df; padding:7px; font-weight:600; }
QTableView::item:selected, QListWidget::item:selected { background:#318cb4; color:white; }
QTabWidget::pane { border:1px solid #c8d5df; }
QTabBar::tab { background:#e7eef3; padding:8px 14px; border:1px solid #c8d5df; }
QTabBar::tab:selected { background:white; border-bottom:2px solid #248ebc; }
QDockWidget::title { background:#e2eaf0; padding:7px; font-weight:600; }
QStatusBar { background:white; border-top:1px solid #ced9e1; }
QFrame#card { background:white; border:1px solid #ced9e1; border-radius:8px; }
QLabel#metric { color:#147ba8; font-size:24px; font-weight:700; }
QLabel#muted { color:#627988; }
"""


class TableModel(QAbstractTableModel):
    def __init__(self, columns: list[tuple[str, str]], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.columns = columns
        self.rows: list[dict[str, Any]] = []

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self.rows)):
            return None
        value = self.rows[index.row()].get(self.columns[index.column()][0], "")
        if role == Qt.ItemDataRole.DisplayRole:
            if isinstance(value, bool):
                return "Yes" if value else "No"
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False)
            return str(value)
        if role == Qt.ItemDataRole.UserRole:
            return self.rows[index.row()]
        if role == Qt.ItemDataRole.TextAlignmentRole and isinstance(value, (int, float)):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole:
            return (
                self.columns[section][1]
                if orientation == Qt.Orientation.Horizontal
                else section + 1
            )
        return None


class FilterProxy(QSortFilterProxyModel):
    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setFilterKeyColumn(-1)
        self.setDynamicSortFilter(True)


def configured_table(columns: list[tuple[str, str]]) -> tuple[QTableView, TableModel, FilterProxy]:
    model = TableModel(columns)
    proxy = FilterProxy()
    proxy.setSourceModel(model)
    table = QTableView()
    table.setModel(proxy)
    table.setSortingEnabled(True)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.horizontalHeader().setStretchLastSection(True)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    return table, model, proxy


class InvestigationDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, case: dict[str, Any] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Investigation")
        self.setMinimumWidth(520)
        form = QFormLayout(self)
        self.title = QLineEdit(case.get("title", "") if case else "")
        self.description = QPlainTextEdit(case.get("description", "") if case else "")
        self.description.setMaximumHeight(120)
        self.investigator = QLineEdit(case.get("investigator", "") if case else "")
        self.tags = QLineEdit(", ".join(case.get("tags", [])) if case else "")
        form.addRow("Title", self.title)
        form.addRow("Description", self.description)
        form.addRow("Investigator", self.investigator)
        form.addRow("Tags", self.tags)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _accept(self) -> None:
        if not self.title.text().strip():
            QMessageBox.warning(self, "Title required", "Enter an investigation title.")
            return
        self.accept()

    def value(self) -> dict[str, Any]:
        return {
            "title": self.title.text().strip(),
            "description": self.description.toPlainText().strip(),
            "investigator": self.investigator.text().strip(),
            "tags": [tag.strip() for tag in self.tags.text().split(",") if tag.strip()],
        }


class EntityDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add entity")
        form = QFormLayout(self)
        self.kind = QComboBox()
        self.kind.setEditable(True)
        self.kind.addItems(
            [
                "person",
                "username",
                "email",
                "phone",
                "domain",
                "ip",
                "url",
                "organization",
                "company",
                "steam_id",
                "discord_server",
                "file_hash",
            ]
        )
        self.value_edit = QLineEdit()
        self.name = QLineEdit()
        self.confidence = QSpinBox()
        self.confidence.setRange(0, 100)
        self.confidence.setValue(70)
        self.verified = QCheckBox("Verified public fact")
        self.source = QLineEdit()
        for label, widget in (
            ("Type", self.kind),
            ("Value", self.value_edit),
            ("Display name", self.name),
            ("Confidence %", self.confidence),
            ("Source URL", self.source),
        ):
            form.addRow(label, widget)
        form.addRow("", self.verified)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _accept(self) -> None:
        if not self.kind.currentText().strip() or not self.value_edit.text().strip():
            QMessageBox.warning(self, "Required fields", "Entity type and value are required.")
            return
        self.accept()

    def value(self) -> dict[str, Any]:
        return {
            "kind": self.kind.currentText(),
            "value": self.value_edit.text(),
            "display_name": self.name.text(),
            "confidence": self.confidence.value() / 100,
            "verified": self.verified.isChecked(),
            "source_url": self.source.text(),
        }


class NoteDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add note")
        self.setMinimumSize(520, 360)
        layout = QVBoxLayout(self)
        self.title = QLineEdit()
        self.title.setPlaceholderText("Note title")
        self.body = QPlainTextEdit()
        self.body.setPlaceholderText("Investigator notes…")
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("Comma-separated tags")
        layout.addWidget(self.title)
        layout.addWidget(self.body, 1)
        layout.addWidget(self.tags)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self) -> None:
        if not self.body.toPlainText().strip():
            QMessageBox.warning(self, "Note required", "Enter note content.")
            return
        self.accept()


class SettingsDialog(QDialog):
    secret_names = (
        ("GitHub token", "github_token"),
        ("Steam API key", "steam_api_key"),
        ("HIBP API key", "hibp_api_key"),
        ("VirusTotal API key", "virustotal_api_key"),
    )

    def __init__(
        self, settings: Settings, secrets: SecretStore, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.settings, self.secrets = settings, secrets
        self.setWindowTitle("Settings")
        self.setMinimumWidth(540)
        form = QFormLayout(self)
        self.theme = QComboBox()
        self.theme.addItems(["dark", "light"])
        self.theme.setCurrentText(settings.theme)
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 18)
        self.font_size.setValue(settings.font_size)
        self.timeout = QSpinBox()
        self.timeout.setRange(5, 120)
        self.timeout.setValue(int(settings.request_timeout))
        self.proxy = QLineEdit(settings.proxy)
        self.proxy.setPlaceholderText("Optional http://proxy:port")
        self.investigator = QLineEdit(settings.investigator)
        self.secret_edits: dict[str, QLineEdit] = {}
        form.addRow("Theme", self.theme)
        form.addRow("Font size", self.font_size)
        form.addRow("Request timeout", self.timeout)
        form.addRow("Proxy", self.proxy)
        form.addRow("Default investigator", self.investigator)
        for label, name in self.secret_names:
            edit = QLineEdit()
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            edit.setPlaceholderText("Stored" if secrets.get(name) else "Not configured")
            self.secret_edits[name] = edit
            form.addRow(label, edit)
        hint = QLabel(
            "Secrets are written to the operating system credential vault. Leave a secret blank to keep its current value."
        )
        hint.setWordWrap(True)
        hint.setObjectName("muted")
        form.addRow(hint)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def apply(self) -> None:
        self.settings.theme = self.theme.currentText()
        self.settings.font_size = self.font_size.value()
        self.settings.request_timeout = self.timeout.value()
        self.settings.proxy = self.proxy.text().strip()
        self.settings.investigator = self.investigator.text().strip()
        for name, edit in self.secret_edits.items():
            if edit.text():
                self.secrets.set(name, edit.text())


class WorkerSignals(QObject):
    completed = Signal(object)
    failed = Signal(str)


class AsyncWorker(QRunnable):
    def __init__(self, coroutine_factory: Callable[[], Any]) -> None:
        super().__init__()
        self.coroutine_factory = coroutine_factory
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            self.signals.completed.emit(asyncio.run(self.coroutine_factory()))
        except Exception as exc:
            self.signals.failed.emit(f"{exc}\n\n{traceback.format_exc()}")


class CollectorPanel(QWidget):
    findings_ready = Signal(str, str, object)

    def __init__(
        self, registry: CollectorRegistry, context: CollectorContext, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.registry, self.context = registry, context
        self.pool = QThreadPool.globalInstance()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        self.collectors = QListWidget()
        for collector in registry.all():
            item = QListWidgetItem(collector.name)
            item.setData(Qt.ItemDataRole.UserRole, collector.id)
            item.setToolTip(collector.description)
            self.collectors.addItem(item)
        self.collectors.currentItemChanged.connect(self._selection_changed)
        self.description = QLabel()
        self.description.setWordWrap(True)
        self.description.setObjectName("muted")
        self.query = QLineEdit()
        self.query.returnPressed.connect(self.run)
        self.run_button = QPushButton("Run collector")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.run)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.collectors, 1)
        layout.addWidget(self.description)
        layout.addWidget(self.query)
        layout.addWidget(self.run_button)
        layout.addWidget(self.progress)
        if self.collectors.count():
            self.collectors.setCurrentRow(0)

    def _selection_changed(self, current: QListWidgetItem | None) -> None:
        if not current:
            return
        collector = self.registry.get(current.data(Qt.ItemDataRole.UserRole))
        self.description.setText(collector.description)
        self.query.setPlaceholderText(collector.query_hint)

    def run(self) -> None:
        item = self.collectors.currentItem()
        query = self.query.text().strip()
        if not item or not query:
            return
        collector = self.registry.get(item.data(Qt.ItemDataRole.UserRole))
        self.progress.show()
        self.run_button.setEnabled(False)
        worker = AsyncWorker(lambda: collector.collect(query, self.context))
        worker.signals.completed.connect(
            lambda findings, c=collector, q=query: self._done(c, q, findings)
        )
        worker.signals.failed.connect(self._failed)
        self.pool.start(worker)

    def _done(self, collector: Collector, query: str, findings: list[Finding]) -> None:
        self.progress.hide()
        self.run_button.setEnabled(True)
        self.findings_ready.emit(collector.id, query, findings)

    def _failed(self, detail: str) -> None:
        self.progress.hide()
        self.run_button.setEnabled(True)
        QMessageBox.critical(self, "Collector failed", detail)


class RelationshipGraph(QGraphicsView):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setScene(QGraphicsScene(self))

    def render_data(
        self, entities: list[dict[str, Any]], relationships: list[dict[str, Any]]
    ) -> None:
        scene = self.scene()
        scene.clear()
        if not entities:
            scene.addText("No entities yet. Add entities or archive collector findings.")
            return
        radius = max(150.0, len(entities) * 18.0)
        center = QPointF(radius + 120, radius + 120)
        positions: dict[int, QPointF] = {}
        for index, entity in enumerate(entities):
            angle = 2 * math.pi * index / len(entities)
            positions[entity["id"]] = QPointF(
                center.x() + radius * math.cos(angle), center.y() + radius * math.sin(angle)
            )
        pen = QPen(QColor("#547589"), 1.5)
        for relationship in relationships:
            source, target = (
                positions.get(relationship["source_entity_id"]),
                positions.get(relationship["target_entity_id"]),
            )
            if source and target:
                line = QGraphicsLineItem(source.x(), source.y(), target.x(), target.y())
                line.setPen(pen)
                line.setToolTip(
                    f"{relationship['kind']} · confidence {relationship['confidence']:.0%}"
                )
                scene.addItem(line)
        colors = {
            "person": "#e2a65e",
            "domain": "#54a9d3",
            "ip": "#8e7cc3",
            "email": "#68b27f",
            "username": "#d66c8b",
        }
        for entity in entities:
            point = positions[entity["id"]]
            node = QGraphicsEllipseItem(point.x() - 25, point.y() - 25, 50, 50)
            node.setBrush(QColor(colors.get(entity["kind"], "#7892a3")))
            node.setPen(QPen(QColor("#dbe8ef"), 2 if entity["verified"] else 1))
            node.setToolTip(json.dumps(entity, indent=2, ensure_ascii=False))
            scene.addItem(node)
            text = QGraphicsSimpleTextItem(entity["display_name"] or entity["value"])
            text.setBrush(QColor("#dce7ef"))
            text.setPos(point.x() - text.boundingRect().width() / 2, point.y() + 30)
            scene.addItem(text)
        scene.setSceneRect(scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))
        self.fitInView(scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings, settings_store: SettingsStore) -> None:
        super().__init__()
        self.settings, self.settings_store = settings, settings_store
        self.secrets = SecretStore()
        self.workspace = settings.resolved_workspace()
        self._open_workspace(self.workspace)
        self.setWindowTitle("Argus OSINT")
        self.resize(1480, 900)
        self.setMinimumSize(1000, 650)
        self.setAcceptDrops(True)
        self.case_id: int | None = None
        self._build_ui()
        self._apply_theme()
        self.refresh_cases()

    def _open_workspace(self, workspace: Path) -> None:
        workspace.mkdir(parents=True, exist_ok=True)
        self.workspace = workspace
        self.db = Database(workspace / "argus.sqlite3")
        self.repository = Repository(self.db, self.settings.investigator)
        self.evidence = EvidenceManager(self.repository, workspace / "evidence")
        self.reports = ReportEngine(self.repository)
        self.plugins = PluginManager(workspace / "plugins", self.db)
        self.registry = CollectorRegistry()
        self.collector_context = CollectorContext(self.settings, self.db, self.secrets)

    def _build_ui(self) -> None:
        toolbar = QToolBar("Main", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        for text, shortcut, callback in (
            ("New case", "Ctrl+N", self.new_case),
            ("Add entity", "Ctrl+E", self.add_entity),
            ("Add note", "Ctrl+Shift+N", self.add_note),
            ("Add evidence", "Ctrl+I", self.add_evidence),
            ("Export report", "Ctrl+R", self.export_report),
        ):
            action = QAction(text, self)
            action.setShortcut(QKeySequence(shortcut))
            action.triggered.connect(callback)
            toolbar.addAction(action)
        toolbar.addSeparator()
        self.global_search = QLineEdit()
        self.global_search.setPlaceholderText("Search all investigations…  Ctrl+K")
        self.global_search.setMaximumWidth(430)
        self.global_search.returnPressed.connect(self.run_search)
        toolbar.addWidget(self.global_search)
        QShortcut(QKeySequence("Ctrl+K"), self, self.global_search.setFocus)
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.edit_settings)
        toolbar.addAction(settings_action)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.setCentralWidget(self.tabs)
        self.dashboard = QWidget()
        self.dashboard_layout = QVBoxLayout(self.dashboard)
        self.metric_layout = QHBoxLayout()
        self.dashboard_layout.addLayout(self.metric_layout)
        self.case_table, self.case_model, self.case_proxy = configured_table(
            [
                ("id", "ID"),
                ("title", "Investigation"),
                ("status", "Status"),
                ("investigator", "Investigator"),
                ("updated_at", "Updated"),
            ]
        )
        self.case_table.doubleClicked.connect(self._case_double_clicked)
        self.dashboard_layout.addWidget(self.case_table, 1)
        self.tabs.addTab(self.dashboard, "Investigations")
        self.case_tabs = QTabWidget()
        self.tabs.addTab(self.case_tabs, "Case workspace")
        self.entity_table, self.entity_model, self.entity_proxy = configured_table(
            [
                ("kind", "Type"),
                ("value", "Value"),
                ("display_name", "Name"),
                ("confidence", "Confidence"),
                ("verified", "Verified"),
                ("source_url", "Source"),
            ]
        )
        self.evidence_table, self.evidence_model, self.evidence_proxy = configured_table(
            [
                ("title", "Title"),
                ("mime_type", "Type"),
                ("size", "Bytes"),
                ("sha256", "SHA-256"),
                ("captured_at", "Captured"),
            ]
        )
        self.timeline_table, self.timeline_model, self.timeline_proxy = configured_table(
            [
                ("occurred_at", "Time"),
                ("kind", "Type"),
                ("title", "Event"),
                ("description", "Description"),
                ("source_url", "Source"),
            ]
        )
        self.notes_table, self.notes_model, self.notes_proxy = configured_table(
            [("title", "Title"), ("body", "Note"), ("tags", "Tags"), ("updated_at", "Updated")]
        )
        self.intel_table, self.intel_model, self.intel_proxy = configured_table(
            [
                ("collector", "Collector"),
                ("query", "Query"),
                ("title", "Finding"),
                ("confidence", "Confidence"),
                ("collected_at", "Collected"),
            ]
        )
        self.graph = RelationshipGraph()
        for widget, label in (
            (self.entity_table, "Entities"),
            (self.graph, "Relationships"),
            (self.evidence_table, "Evidence"),
            (self.timeline_table, "Timeline"),
            (self.notes_table, "Notes"),
            (self.intel_table, "Collected intelligence"),
        ):
            self.case_tabs.addTab(widget, label)
        self.search_table, self.search_model, self.search_proxy = configured_table(
            [
                ("object_type", "Type"),
                ("investigation_id", "Case"),
                ("title", "Title"),
                ("excerpt", "Match"),
            ]
        )
        self.tabs.addTab(self.search_table, "Search results")
        self.inspector = QTextBrowser()
        self.inspector.setOpenExternalLinks(True)
        dock = QDockWidget("Inspector", self)
        dock.setWidget(self.inspector)
        dock.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        for table in (
            self.case_table,
            self.entity_table,
            self.evidence_table,
            self.timeline_table,
            self.notes_table,
            self.intel_table,
            self.search_table,
        ):
            table.clicked.connect(lambda index, t=table: self._inspect(t, index))
        self.collector_panel = CollectorPanel(self.registry, self.collector_context)
        self.collector_panel.findings_ready.connect(self.archive_findings)
        collector_dock = QDockWidget("OSINT collectors", self)
        collector_dock.setWidget(self.collector_panel)
        collector_dock.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, collector_dock)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage(f"Workspace: {self.workspace}")
        menu = self.menuBar()
        file_menu = menu.addMenu("&File")
        file_menu.addAction("New investigation", self.new_case, QKeySequence("Ctrl+N"))
        file_menu.addAction("Open workspace…", self.choose_workspace)
        file_menu.addAction("Export report…", self.export_report)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)
        case_menu = menu.addMenu("&Investigation")
        case_menu.addAction("Edit", self.edit_case)
        case_menu.addAction("Duplicate", self.duplicate_case)
        case_menu.addAction("Archive / reopen", self.toggle_archive)
        case_menu.addAction("Merge into…", self.merge_case)
        view_menu = menu.addMenu("&View")
        view_menu.addAction(dock.toggleViewAction())
        view_menu.addAction(collector_dock.toggleViewAction())
        view_menu.addAction("Toggle theme", self.toggle_theme, QKeySequence("Ctrl+Shift+T"))

    def _apply_theme(self) -> None:
        QApplication.instance().setStyleSheet(
            DARK_STYLE if self.settings.theme == "dark" else LIGHT_STYLE
        )
        font = QApplication.instance().font()
        font.setPointSize(self.settings.font_size)
        QApplication.instance().setFont(font)

    def _metric(self, title: str, value: int) -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        metric = QLabel(str(value))
        metric.setObjectName("metric")
        label = QLabel(title)
        label.setObjectName("muted")
        layout.addWidget(metric)
        layout.addWidget(label)
        return card

    def refresh_cases(self) -> None:
        rows = self.repository.list_investigations()
        self.case_model.set_rows(rows)
        while self.metric_layout.count():
            item = self.metric_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for title, value in (
            ("Investigations", len(rows)),
            ("Active", sum(r["status"] == "active" for r in rows)),
            ("Entities", self.db.one("SELECT COUNT(*) n FROM entities")["n"]),
            ("Evidence", self.db.one("SELECT COUNT(*) n FROM evidence")["n"]),
        ):
            self.metric_layout.addWidget(self._metric(title, value))

    def select_case(self, case_id: int) -> None:
        self.case_id = case_id
        case = self.repository.investigation(case_id)
        self.tabs.setTabText(1, case["title"])
        self.tabs.setCurrentIndex(1)
        self.refresh_case()
        self.statusBar().showMessage(f"Investigation {case_id}: {case['title']}")

    def refresh_case(self) -> None:
        if self.case_id is None:
            return
        self.entity_model.set_rows(self.repository.rows("entities", self.case_id))
        self.evidence_model.set_rows(self.repository.rows("evidence", self.case_id))
        self.timeline_model.set_rows(self.repository.rows("timeline_events", self.case_id))
        self.notes_model.set_rows(self.repository.rows("notes", self.case_id))
        self.intel_model.set_rows(self.repository.rows("intelligence", self.case_id))
        self.graph.render_data(
            self.repository.rows("entities", self.case_id),
            self.repository.rows("relationships", self.case_id),
        )
        self.refresh_cases()

    def _selected_case_id(self) -> int | None:
        index = self.case_table.currentIndex()
        if index.isValid():
            return int(self.case_proxy.mapToSource(index).data(Qt.ItemDataRole.UserRole)["id"])
        return self.case_id

    def _case_double_clicked(self, index: QModelIndex) -> None:
        self.select_case(
            int(self.case_proxy.mapToSource(index).data(Qt.ItemDataRole.UserRole)["id"])
        )

    def new_case(self) -> None:
        dialog = InvestigationDialog(self)
        dialog.investigator.setText(self.settings.investigator)
        if dialog.exec():
            self.select_case(self.repository.create_investigation(**dialog.value()))

    def edit_case(self) -> None:
        case_id = self._selected_case_id()
        if case_id is None:
            return
        dialog = InvestigationDialog(self, self.repository.investigation(case_id))
        if dialog.exec():
            self.repository.update_investigation(case_id, **dialog.value())
            self.select_case(case_id)

    def toggle_archive(self) -> None:
        case_id = self._selected_case_id()
        if case_id is None:
            return
        if self.repository.investigation(case_id)["status"] == "archived":
            self.repository.reopen(case_id)
        else:
            self.repository.archive(case_id)
        self.refresh_cases()

    def duplicate_case(self) -> None:
        case_id = self._selected_case_id()
        if case_id is not None:
            self.select_case(self.repository.duplicate(case_id))

    def merge_case(self) -> None:
        source = self._selected_case_id()
        cases = [row for row in self.repository.list_investigations(False) if row["id"] != source]
        if source is None or not cases:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Merge investigation")
        layout = QFormLayout(dialog)
        combo = QComboBox()
        for case in cases:
            combo.addItem(case["title"], case["id"])
        layout.addRow("Merge into", combo)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if (
            dialog.exec()
            and QMessageBox.question(
                self,
                "Confirm merge",
                "Move all records into the selected investigation and archive the source?",
            )
            == QMessageBox.StandardButton.Yes
        ):
            target = int(combo.currentData())
            self.repository.merge(source, target)
            self.select_case(target)

    def add_entity(self) -> None:
        if self.case_id is None:
            QMessageBox.information(self, "Select investigation", "Open an investigation first.")
            return
        dialog = EntityDialog(self)
        if dialog.exec():
            self.repository.add_entity(self.case_id, **dialog.value())
            self.refresh_case()

    def add_note(self) -> None:
        if self.case_id is None:
            return
        dialog = NoteDialog(self)
        if dialog.exec():
            self.repository.add_note(
                self.case_id,
                dialog.title.text(),
                dialog.body.toPlainText(),
                [x.strip() for x in dialog.tags.text().split(",") if x.strip()],
            )
            self.refresh_case()

    def add_evidence(self) -> None:
        if self.case_id is None:
            return
        paths, _ = QFileDialog.getOpenFileNames(self, "Add evidence")
        for path in paths:
            try:
                self.evidence.ingest(self.case_id, Path(path))
            except Exception as exc:
                QMessageBox.critical(self, "Evidence import failed", str(exc))
        self.refresh_case()

    def dragEnterEvent(self, event: Any) -> None:
        if (
            self.case_id is not None
            and event.mimeData().hasUrls()
            and all(url.isLocalFile() for url in event.mimeData().urls())
        ):
            event.acceptProposedAction()

    def dropEvent(self, event: Any) -> None:
        for url in event.mimeData().urls():
            path = Path(url.toLocalFile())
            if path.is_file():
                self.evidence.ingest(self.case_id, path)
        self.refresh_case()
        event.acceptProposedAction()

    def archive_findings(self, collector_id: str, query: str, findings: list[Finding]) -> None:
        if self.case_id is None:
            QMessageBox.information(
                self, "Collector complete", "Open an investigation to archive findings."
            )
            return
        for finding in findings:
            self.repository.add_intelligence(
                self.case_id,
                collector_id,
                query,
                finding.title,
                finding.data,
                finding.source_url,
                finding.confidence,
            )
            for entity in finding.entities:
                self.repository.add_entity(
                    self.case_id,
                    source_url=finding.source_url,
                    confidence=finding.confidence,
                    **entity,
                )
        self.refresh_case()
        self.case_tabs.setCurrentWidget(self.intel_table)
        QMessageBox.information(
            self, "Collector complete", f"Archived {len(findings)} finding(s) and their entities."
        )

    def run_search(self) -> None:
        query = self.global_search.text().strip()
        if not query:
            return
        self.search_model.set_rows(self.repository.search(query))
        self.tabs.setCurrentWidget(self.search_table)

    def export_report(self) -> None:
        if self.case_id is None:
            return
        path, selected = QFileDialog.getSaveFileName(
            self,
            "Export report",
            f"investigation-{self.case_id}.pdf",
            "PDF (*.pdf);;HTML (*.html);;Word (*.docx);;Markdown (*.md);;JSON (*.json);;CSV (*.csv);;Text (*.txt)",
        )
        if not path:
            return
        try:
            self.reports.export(self.case_id, Path(path))
            self.statusBar().showMessage(f"Report exported to {path}", 8000)
        except Exception as exc:
            QMessageBox.critical(self, "Report export failed", str(exc))

    def _inspect(self, table: QTableView, index: QModelIndex) -> None:
        proxy = table.model()
        source = proxy.mapToSource(index)
        row = source.data(Qt.ItemDataRole.UserRole)
        if row:
            self.inspector.setHtml(
                "<pre style='white-space:pre-wrap'>"
                + json.dumps(row, indent=2, ensure_ascii=False)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                + "</pre>"
            )

    def edit_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self.secrets, self)
        if dialog.exec():
            dialog.apply()
            self.settings_store.save(self.settings)
            self.repository.actor = self.settings.investigator
            self._apply_theme()

    def toggle_theme(self) -> None:
        self.settings.theme = "light" if self.settings.theme == "dark" else "dark"
        self.settings_store.save(self.settings)
        self._apply_theme()

    def choose_workspace(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Open workspace", str(self.workspace))
        if not path or Path(path).resolve() == self.workspace:
            return
        self.db.close()
        self.settings.workspace = path
        self.settings_store.save(self.settings)
        self._open_workspace(Path(path))
        self.collector_panel.context = self.collector_context
        self.case_id = None
        self.refresh_cases()
        self.tabs.setCurrentIndex(0)

    def closeEvent(self, event: Any) -> None:
        self.settings_store.save(self.settings)
        self.db.close()
        event.accept()
