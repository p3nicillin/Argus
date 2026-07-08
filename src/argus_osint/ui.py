from __future__ import annotations

import asyncio
import contextlib
import json
import math
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QByteArray,
    QDateTime,
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
    QDateTimeEdit,
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
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QStatusBar,
    QStyle,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from .bundles import InvestigationBundle
from .campaigns import CampaignPlanner
from .collectors import Collector, CollectorContext, CollectorRegistry, Finding
from .config import SecretStore, Settings, SettingsStore
from .correlation import CorrelationEngine
from .db import Database
from .evidence import EvidenceManager
from .operations import OperationManager
from .plugins import PluginManager
from .reports import ReportEngine
from .repository import Repository
from .universal import UniversalSearchService
from .workspace import DashboardService, GraphService, TimelineService

DARK_STYLE = """
QWidget { background:#0E1117; color:#F0F6FC; font-family:'Segoe UI'; }
QMainWindow, QDialog { background:#0E1117; }
QToolBar { background:#161B22; border:0; border-bottom:1px solid #2D333B; spacing:7px; padding:8px; }
QToolButton, QPushButton { background:#1C2128; border:1px solid #2D333B; border-radius:10px; padding:7px 12px; color:#F0F6FC; }
QToolButton:hover, QPushButton:hover { background:#222A33; border-color:#4F8EF7; }
QPushButton:pressed { background:#182232; }
QPushButton#primary { background:#1F6FEB; border-color:#4F8EF7; color:white; font-weight:600; }
QPushButton#ghost { background:transparent; border:1px solid #2D333B; }
QLineEdit, QPlainTextEdit, QTextBrowser, QComboBox, QSpinBox { background:#0D1117; border:1px solid #2D333B; border-radius:10px; padding:8px; selection-background-color:#1F6FEB; color:#F0F6FC; }
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus { border-color:#4F8EF7; }
QTableView { background:#0D1117; alternate-background-color:#111820; gridline-color:#2D333B; border:1px solid #2D333B; border-radius:10px; selection-background-color:#1F6FEB; }
QHeaderView::section { background:#161B22; color:#8B949E; border:0; border-right:1px solid #2D333B; padding:8px; font-weight:600; }
QTableView::item:selected, QListWidget::item:selected { background:#1F6FEB; color:white; }
QTabWidget::pane { border:1px solid #2D333B; border-radius:10px; top:-1px; }
QTabBar::tab { background:#161B22; padding:9px 14px; border:1px solid #2D333B; border-top-left-radius:8px; border-top-right-radius:8px; margin-right:2px; color:#8B949E; }
QTabBar::tab:selected { background:#1C2128; color:#F0F6FC; border-bottom:2px solid #4F8EF7; }
QDockWidget::title { background:#161B22; padding:8px; font-weight:600; border:1px solid #2D333B; }
QStatusBar { background:#161B22; border-top:1px solid #2D333B; color:#8B949E; }
QProgressBar { border:1px solid #2D333B; border-radius:8px; text-align:center; background:#0D1117; }
QProgressBar::chunk { background:#4F8EF7; border-radius:8px; }
QFrame#card, QFrame#searchHero { background:#1C2128; border:1px solid #2D333B; border-radius:12px; }
QFrame#card:hover { border-color:#4F8EF7; }
QListWidget#sidebar { background:#0D1117; border:0; border-right:1px solid #2D333B; padding:8px; outline:0; }
QListWidget#sidebar::item { padding:10px 12px; margin:2px 0; border-radius:10px; color:#8B949E; }
QListWidget#sidebar::item:hover { background:#161B22; color:#F0F6FC; }
QListWidget#sidebar::item:selected { background:#1C2128; color:#F0F6FC; border-left:3px solid #4F8EF7; }
QLabel#pageTitle { font-size:24px; font-weight:700; color:#F0F6FC; }
QLabel#sectionTitle { font-size:14px; font-weight:700; color:#F0F6FC; }
QLabel#metric { color:#56CCF2; font-size:28px; font-weight:700; }
QLabel#muted { color:#8B949E; }
QLabel#pill { color:#56CCF2; background:#102033; border:1px solid #224A70; border-radius:8px; padding:3px 8px; }
"""

LIGHT_STYLE = """
QWidget { background:#F6F8FA; color:#1F2328; font-family:'Segoe UI'; }
QMainWindow, QDialog { background:#F6F8FA; }
QToolBar { background:white; border:0; border-bottom:1px solid #D0D7DE; spacing:7px; padding:8px; }
QToolButton, QPushButton { background:white; border:1px solid #D0D7DE; border-radius:10px; padding:7px 12px; }
QToolButton:hover, QPushButton:hover { background:#EEF5FF; border-color:#4F8EF7; }
QPushButton#primary { background:#0969DA; border-color:#4F8EF7; color:white; font-weight:600; }
QPushButton#ghost { background:transparent; border:1px solid #D0D7DE; }
QLineEdit, QPlainTextEdit, QTextBrowser, QComboBox, QSpinBox { background:white; border:1px solid #D0D7DE; border-radius:10px; padding:8px; selection-background-color:#4F8EF7; }
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus { border-color:#4F8EF7; }
QTableView { background:white; alternate-background-color:#F6F8FA; gridline-color:#D0D7DE; border:1px solid #D0D7DE; border-radius:10px; }
QHeaderView::section { background:#F6F8FA; color:#57606A; border:0; border-right:1px solid #D0D7DE; padding:8px; font-weight:600; }
QTableView::item:selected, QListWidget::item:selected { background:#0969DA; color:white; }
QTabWidget::pane { border:1px solid #D0D7DE; border-radius:10px; top:-1px; }
QTabBar::tab { background:#EAEEF2; padding:9px 14px; border:1px solid #D0D7DE; border-top-left-radius:8px; border-top-right-radius:8px; margin-right:2px; color:#57606A; }
QTabBar::tab:selected { background:white; color:#1F2328; border-bottom:2px solid #0969DA; }
QDockWidget::title { background:#F6F8FA; padding:8px; font-weight:600; border:1px solid #D0D7DE; }
QStatusBar { background:white; border-top:1px solid #D0D7DE; color:#57606A; }
QFrame#card, QFrame#searchHero { background:white; border:1px solid #D0D7DE; border-radius:12px; }
QListWidget#sidebar { background:white; border:0; border-right:1px solid #D0D7DE; padding:8px; outline:0; }
QListWidget#sidebar::item { padding:10px 12px; margin:2px 0; border-radius:10px; color:#57606A; }
QListWidget#sidebar::item:hover { background:#F6F8FA; color:#1F2328; }
QListWidget#sidebar::item:selected { background:#EEF5FF; color:#1F2328; border-left:3px solid #0969DA; }
QLabel#pageTitle { font-size:24px; font-weight:700; color:#1F2328; }
QLabel#sectionTitle { font-size:14px; font-weight:700; color:#1F2328; }
QLabel#metric { color:#0969DA; font-size:28px; font-weight:700; }
QLabel#muted { color:#57606A; }
QLabel#pill { color:#0969DA; background:#EEF5FF; border:1px solid #B6D7FF; border-radius:8px; padding:3px 8px; }
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
    table.setShowGrid(False)
    table.setWordWrap(False)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(34)
    table.horizontalHeader().setStretchLastSection(True)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    table.horizontalHeader().setMinimumSectionSize(110)
    table.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
    copy_action = QAction("Copy selected row", table)
    copy_action.triggered.connect(
        lambda: QApplication.clipboard().setText(
            json.dumps(
                proxy.mapToSource(table.currentIndex()).data(Qt.ItemDataRole.UserRole) or {},
                indent=2,
                ensure_ascii=False,
            )
        )
        if table.currentIndex().isValid()
        else None
    )
    table.addAction(copy_action)
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
    job_changed = Signal()

    def __init__(
        self,
        registry: CollectorRegistry,
        operations: OperationManager,
        case_provider: Callable[[], int | None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.registry, self.operations = registry, operations
        self.case_provider = case_provider
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
        self.batch_button = QPushButton("Batch…")
        self.batch_button.clicked.connect(self.run_batch)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.collectors, 1)
        layout.addWidget(self.description)
        layout.addWidget(self.query)
        actions = QHBoxLayout()
        actions.addWidget(self.run_button)
        actions.addWidget(self.batch_button)
        layout.addLayout(actions)
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
        case_id = self.case_provider()
        if case_id is None:
            QMessageBox.information(self, "Select investigation", "Open an investigation first.")
            return
        job_id = self.operations.create_job(case_id, collector.id, query)
        self.job_changed.emit()
        self.progress.show()
        self.run_button.setEnabled(False)
        worker = AsyncWorker(lambda: self.operations.run_job(job_id))
        worker.signals.completed.connect(
            lambda findings, c=collector, q=query: self._done(c, q, findings)
        )
        worker.signals.failed.connect(self._failed)
        self.pool.start(worker)

    def _done(self, collector: Collector, query: str, findings: list[Finding]) -> None:
        self.progress.hide()
        self.run_button.setEnabled(True)
        self.job_changed.emit()
        QMessageBox.information(
            self,
            "Collection complete",
            f"Archived {len(findings)} finding(s) with provenance and correlation analysis.",
        )

    def _failed(self, detail: str) -> None:
        self.progress.hide()
        self.run_button.setEnabled(True)
        self.job_changed.emit()
        QMessageBox.critical(self, "Collector failed", detail)

    def run_batch(self) -> None:
        item = self.collectors.currentItem()
        case_id = self.case_provider()
        if not item or case_id is None:
            QMessageBox.information(self, "Select investigation", "Open an investigation first.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Batch collection")
        dialog.resize(560, 420)
        layout = QVBoxLayout(dialog)
        hint = QLabel("Enter one query per line. Blank lines and duplicates are ignored.")
        queries = QPlainTextEdit()
        queries.setPlaceholderText(self.query.placeholderText())
        concurrency = QSpinBox()
        concurrency.setRange(1, 10)
        concurrency.setValue(3)
        form = QFormLayout()
        form.addRow("Concurrent jobs", concurrency)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(hint)
        layout.addWidget(queries, 1)
        layout.addLayout(form)
        layout.addWidget(buttons)
        if not dialog.exec():
            return
        values = list(dict.fromkeys(line.strip() for line in queries.toPlainText().splitlines()))
        values = [value for value in values if value]
        if not values:
            return
        collector_id = item.data(Qt.ItemDataRole.UserRole)
        self.progress.show()
        self.run_button.setEnabled(False)
        self.batch_button.setEnabled(False)
        worker = AsyncWorker(
            lambda: self.operations.run_batch(
                case_id,
                [(collector_id, value) for value in values],
                concurrency.value(),
            )
        )
        worker.signals.completed.connect(self._batch_done)
        worker.signals.failed.connect(self._failed)
        self.pool.start(worker)

    def _batch_done(self, results: list[dict[str, Any]]) -> None:
        self.progress.hide()
        self.run_button.setEnabled(True)
        self.batch_button.setEnabled(True)
        self.job_changed.emit()
        succeeded = sum(bool(item["ok"]) for item in results)
        QMessageBox.information(
            self,
            "Batch complete",
            f"{succeeded} of {len(results)} collection jobs completed successfully.",
        )

    def set_operations(self, operations: OperationManager) -> None:
        self.operations = operations


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


class GeoMapView(QGraphicsView):
    """Offline world-coordinate view; no third-party map tile tracking or API key."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setScene(QGraphicsScene(self))

    def render_locations(self, locations: list[dict[str, Any]]) -> None:
        scene = self.scene()
        scene.clear()
        width, height = 1080.0, 540.0
        scene.setSceneRect(0, 0, width, height)
        grid_pen = QPen(QColor("#344b5b"), 0.8)
        for longitude in range(-180, 181, 30):
            x = (longitude + 180) / 360 * width
            scene.addLine(x, 0, x, height, grid_pen)
        for latitude in range(-90, 91, 30):
            y = (90 - latitude) / 180 * height
            scene.addLine(0, y, width, y, grid_pen)
        scene.addText("180°W                 0°                 180°E").setPos(8, 5)
        if not locations:
            scene.addText("No geospatial observations in this investigation.").setPos(350, 250)
        for location in locations:
            x = (float(location["longitude"]) + 180) / 360 * width
            y = (90 - float(location["latitude"])) / 180 * height
            size = 8 + 10 * float(location["confidence"])
            node = scene.addEllipse(
                x - size / 2,
                y - size / 2,
                size,
                size,
                QPen(QColor("#d8f3ff"), 1.5),
                QColor("#e66f51"),
            )
            node.setToolTip(json.dumps(location, indent=2, ensure_ascii=False))
            label = scene.addSimpleText(
                location["label"] or f"{location['latitude']}, {location['longitude']}"
            )
            label.setBrush(QColor("#dce7ef"))
            label.setPos(x + 7, y - 7)
        self.fitInView(scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)


class RelationshipDialog(QDialog):
    def __init__(self, entities: list[dict[str, Any]], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add relationship")
        self.source = QComboBox()
        self.target = QComboBox()
        for entity in entities:
            label = f"{entity['kind']}: {entity['display_name'] or entity['value']}"
            self.source.addItem(label, entity["id"])
            self.target.addItem(label, entity["id"])
        if self.target.count() > 1:
            self.target.setCurrentIndex(1)
        self.kind = QComboBox()
        self.kind.setEditable(True)
        self.kind.addItems(
            [
                "associated_with",
                "owns",
                "uses",
                "member_of",
                "resolves_to",
                "mentions",
                "created_by",
            ]
        )
        self.confidence = QSpinBox()
        self.confidence.setRange(0, 100)
        self.confidence.setValue(60)
        self.verified = QCheckBox("Verified public fact")
        self.source_url = QLineEdit()
        form = QFormLayout(self)
        form.addRow("Source", self.source)
        form.addRow("Relationship", self.kind)
        form.addRow("Target", self.target)
        form.addRow("Confidence %", self.confidence)
        form.addRow("Source URL", self.source_url)
        form.addRow("", self.verified)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _accept(self) -> None:
        if self.source.currentData() == self.target.currentData():
            QMessageBox.warning(self, "Invalid relationship", "Choose two different entities.")
            return
        if not self.kind.currentText().strip():
            return
        self.accept()

    def value(self) -> dict[str, Any]:
        return {
            "source_id": int(self.source.currentData()),
            "target_id": int(self.target.currentData()),
            "kind": self.kind.currentText().strip(),
            "confidence": self.confidence.value() / 100,
            "verified": self.verified.isChecked(),
            "source_url": self.source_url.text().strip(),
        }


class TimelineDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add timeline event")
        self.occurred = QDateTimeEdit(QDateTime.currentDateTime())
        self.occurred.setCalendarPopup(True)
        self.occurred.setDisplayFormat("yyyy-MM-dd HH:mm:ss t")
        self.title = QLineEdit()
        self.description = QPlainTextEdit()
        self.description.setMaximumHeight(120)
        self.kind = QComboBox()
        self.kind.setEditable(True)
        self.kind.addItems(["event", "observation", "publication", "registration", "incident"])
        self.source_url = QLineEdit()
        form = QFormLayout(self)
        form.addRow("Occurred", self.occurred)
        form.addRow("Title", self.title)
        form.addRow("Description", self.description)
        form.addRow("Type", self.kind)
        form.addRow("Source URL", self.source_url)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _accept(self) -> None:
        if not self.title.text().strip():
            QMessageBox.warning(self, "Title required", "Enter an event title.")
            return
        self.accept()

    def value(self) -> dict[str, Any]:
        return {
            "occurred_at": self.occurred.dateTime().toUTC().toString(Qt.DateFormat.ISODate),
            "title": self.title.text().strip(),
            "description": self.description.toPlainText().strip(),
            "kind": self.kind.currentText().strip(),
            "source_url": self.source_url.text().strip(),
        }


class BookmarkDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add source bookmark")
        self.title = QLineEdit()
        self.url = QLineEdit()
        self.description = QPlainTextEdit()
        self.description.setMaximumHeight(100)
        self.tags = QLineEdit()
        form = QFormLayout(self)
        form.addRow("Title", self.title)
        form.addRow("URL", self.url)
        form.addRow("Description", self.description)
        form.addRow("Tags", self.tags)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _accept(self) -> None:
        if not self.title.text().strip() or not self.url.text().strip():
            QMessageBox.warning(self, "Required fields", "Title and URL are required.")
            return
        self.accept()


class CorrelationPanel(QWidget):
    changed = Signal()

    def __init__(
        self,
        engine: CorrelationEngine,
        case_provider: Callable[[], int | None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.engine = engine
        self.case_provider = case_provider
        layout = QVBoxLayout(self)
        actions = QHBoxLayout()
        generate = QPushButton("Generate suggestions")
        accept = QPushButton("Accept selected")
        reject = QPushButton("Reject selected")
        generate.clicked.connect(self.generate)
        accept.clicked.connect(lambda: self.review(True))
        reject.clicked.connect(lambda: self.review(False))
        actions.addWidget(generate)
        actions.addWidget(accept)
        actions.addWidget(reject)
        actions.addStretch(1)
        self.table, self.model, self.proxy = configured_table(
            [
                ("status", "Status"),
                ("source_value", "Source"),
                ("target_value", "Target"),
                ("relationship_kind", "Suggested link"),
                ("score", "Score"),
                ("reasons", "Reasons"),
            ]
        )
        layout.addLayout(actions)
        layout.addWidget(self.table, 1)

    def refresh(self) -> None:
        case_id = self.case_provider()
        self.model.set_rows(self.engine.pending(case_id) if case_id is not None else [])

    def generate(self) -> None:
        case_id = self.case_provider()
        if case_id is None:
            return
        self.model.set_rows(self.engine.generate(case_id))
        self.changed.emit()

    def review(self, accept: bool) -> None:
        index = self.table.currentIndex()
        if not index.isValid():
            return
        row = self.proxy.mapToSource(index).data(Qt.ItemDataRole.UserRole)
        self.engine.review(int(row["id"]), accept)
        self.refresh()
        self.changed.emit()


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
        self.operations = OperationManager(self.repository, self.registry, self.collector_context)
        self.correlation = self.operations.correlation
        self.bundle = InvestigationBundle(self.repository, self.evidence)
        self.campaign_planner = CampaignPlanner(self.registry)
        self.universal_search = UniversalSearchService(self.repository, self.campaign_planner)
        self.dashboard_service = DashboardService(self.repository)
        self.graph_service = GraphService(self.repository)
        self.timeline_service = TimelineService(self.repository)

    def _build_ui(self) -> None:
        toolbar = QToolBar("Main", self)
        toolbar.setObjectName("topToolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        for icon, text, shortcut, callback in (
            ("SP_FileDialogNewFolder", "New", "Ctrl+N", self.new_case),
            ("SP_FileIcon", "Entity", "Ctrl+E", self.add_entity),
            ("SP_DialogOpenButton", "Evidence", "Ctrl+I", self.add_evidence),
            ("SP_DialogSaveButton", "Report", "Ctrl+R", self.export_report),
        ):
            action = QAction(text, self)
            action.setIcon(self._standard_icon(icon))
            action.setShortcut(QKeySequence(shortcut))
            action.triggered.connect(callback)
            toolbar.addAction(action)
        toolbar.addSeparator()
        self.global_search = QLineEdit()
        self.global_search.setPlaceholderText(
            "Universal search: domain, email, CVE, handle, address, IP...  Ctrl+K"
        )
        self.global_search.setMinimumWidth(360)
        self.global_search.setMaximumWidth(620)
        self.global_search.returnPressed.connect(self.run_search)
        toolbar.addWidget(self.global_search)
        QShortcut(QKeySequence("Ctrl+K"), self, self.global_search.setFocus)
        save_search_action = QAction("Save", self)
        save_search_action.setIcon(self._standard_icon("SP_DialogSaveButton"))
        save_search_action.triggered.connect(self.save_current_search)
        toolbar.addAction(save_search_action)
        open_search_action = QAction("Recent", self)
        open_search_action.setIcon(self._standard_icon("SP_BrowserReload"))
        open_search_action.triggered.connect(self.open_saved_search)
        toolbar.addAction(open_search_action)
        toolbar.addSeparator()
        command_action = QAction("Command", self)
        command_action.setIcon(self._standard_icon("SP_FileDialogDetailedView"))
        command_action.setShortcut(QKeySequence("Ctrl+Shift+P"))
        command_action.triggered.connect(self.command_palette)
        toolbar.addAction(command_action)
        theme_action = QAction("Theme", self)
        theme_action.setIcon(self._standard_icon("SP_DesktopIcon"))
        theme_action.setShortcut(QKeySequence("Ctrl+Shift+T"))
        theme_action.triggered.connect(self.toggle_theme)
        toolbar.addAction(theme_action)
        settings_action = QAction("Settings", self)
        settings_action.setIcon(self._standard_icon("SP_FileDialogInfoView"))
        settings_action.triggered.connect(self.edit_settings)
        toolbar.addAction(settings_action)

        shell = QWidget()
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(235)
        self.sidebar.setIconSize(self._standard_icon("SP_FileIcon").actualSize(self.size()))
        self.sidebar.currentRowChanged.connect(self._sidebar_changed)
        shell_layout.addWidget(self.sidebar)
        self.pages = QStackedWidget()
        shell_layout.addWidget(self.pages, 1)
        self.setCentralWidget(shell)

        self.dashboard = self._build_dashboard_page()
        self.pages.addWidget(self.dashboard)
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
        self.dashboard_cases_card.layout().addWidget(self.case_table, 1)

        self.search_page = self._build_search_page()
        self.pages.addWidget(self.search_page)

        self.case_workspace = QWidget()
        case_layout = QVBoxLayout(self.case_workspace)
        case_layout.setContentsMargins(18, 18, 18, 18)
        self.case_header = QFrame()
        self.case_header.setObjectName("card")
        case_header_layout = QHBoxLayout(self.case_header)
        case_title_group = QVBoxLayout()
        self.case_title = QLabel("No investigation selected")
        self.case_title.setObjectName("pageTitle")
        self.case_meta = QLabel("Open or create a case to begin collection and analysis.")
        self.case_meta.setObjectName("muted")
        case_title_group.addWidget(self.case_title)
        case_title_group.addWidget(self.case_meta)
        case_header_layout.addLayout(case_title_group, 1)
        for label, callback in (
            ("Add entity", self.add_entity),
            ("Add note", self.add_note),
            ("Add evidence", self.add_evidence),
            ("Export", self.export_report),
        ):
            button = QPushButton(label)
            if label == "Add entity":
                button.setObjectName("primary")
            button.clicked.connect(callback)
            case_header_layout.addWidget(button)
        case_layout.addWidget(self.case_header)
        self.case_tabs = QTabWidget()
        self.case_tabs.setDocumentMode(True)
        case_layout.addWidget(self.case_tabs, 1)
        self.pages.addWidget(self.case_workspace)
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
        self.bookmark_table, self.bookmark_model, self.bookmark_proxy = configured_table(
            [
                ("title", "Title"),
                ("url", "URL"),
                ("description", "Description"),
                ("tags", "Tags"),
            ]
        )
        self.source_table, self.source_model, self.source_proxy = configured_table(
            [
                ("publisher", "Publisher"),
                ("title", "Title"),
                ("url", "URL"),
                ("content_hash", "Content SHA-256"),
                ("retrieved_at", "Retrieved"),
            ]
        )
        self.comment_table, self.comment_model, self.comment_proxy = configured_table(
            [
                ("object_type", "Target"),
                ("body", "Comment"),
                ("author", "Author"),
                ("created_at", "Created"),
            ]
        )
        self.job_table, self.job_model, self.job_proxy = configured_table(
            [
                ("id", "Job"),
                ("status", "Status"),
                ("collector", "Collector"),
                ("query", "Query"),
                ("progress", "Progress"),
                ("result_count", "Results"),
                ("error", "Error"),
                ("created_at", "Created"),
            ]
        )
        self.profile_table, self.profile_model, self.profile_proxy = configured_table(
            [
                ("kind", "Type"),
                ("value", "Profile / Handle"),
                ("display_name", "Name"),
                ("confidence", "Confidence"),
                ("verified", "Verified"),
                ("source_url", "Source"),
            ]
        )
        self.domain_table, self.domain_model, self.domain_proxy = configured_table(
            [
                ("kind", "Type"),
                ("value", "Infrastructure"),
                ("display_name", "Name"),
                ("confidence", "Confidence"),
                ("verified", "Verified"),
                ("source_url", "Source"),
            ]
        )
        jobs_widget = QWidget()
        jobs_layout = QVBoxLayout(jobs_widget)
        jobs_actions = QHBoxLayout()
        retry_job = QPushButton("Retry selected")
        cancel_job = QPushButton("Cancel selected")
        retry_job.clicked.connect(self.retry_job)
        cancel_job.clicked.connect(self.cancel_job)
        jobs_actions.addWidget(retry_job)
        jobs_actions.addWidget(cancel_job)
        jobs_actions.addStretch(1)
        jobs_layout.addLayout(jobs_actions)
        jobs_layout.addWidget(self.job_table, 1)
        self.graph = RelationshipGraph()
        self.map_view = GeoMapView()
        self.correlation_panel = CorrelationPanel(self.correlation, lambda: self.case_id)
        self.correlation_panel.changed.connect(self.refresh_case)
        for widget, label in (
            (self.entity_table, "Entities"),
            (self.graph, "Relationships"),
            (self.correlation_panel, "Correlation review"),
            (self.map_view, "Map"),
            (self.evidence_table, "Evidence"),
            (self.timeline_table, "Timeline"),
            (self.notes_table, "Notes"),
            (self.intel_table, "Collected intelligence"),
            (self.source_table, "Source provenance"),
            (self.bookmark_table, "Bookmarks"),
            (self.comment_table, "Comments"),
            (jobs_widget, "Collection jobs"),
            (self.profile_table, "Public profiles"),
            (self.domain_table, "Domains & infrastructure"),
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
        self.search_results_card.layout().addWidget(self.search_table, 1)
        self.search_plan_table, self.search_plan_model, self.search_plan_proxy = configured_table(
            [
                ("collector", "Collector"),
                ("query", "Query"),
                ("reason", "Why Argus recommends it"),
            ]
        )
        self.search_plan_card.layout().addWidget(self.search_plan_table, 1)
        self.history_table, self.history_model, self.history_proxy = configured_table(
            [
                ("query", "Query"),
                ("result_count", "Results"),
                ("created_at", "Searched"),
            ]
        )
        self.history_page = self._simple_table_page(
            "History",
            "Search history and recent analyst activity.",
            self.history_table,
        )
        self.pages.addWidget(self.history_page)
        self.plugins_page = self._build_plugins_page()
        self.pages.addWidget(self.plugins_page)
        self.settings_page = self._build_settings_page()
        self.pages.addWidget(self.settings_page)
        self.inspector = QTextBrowser()
        self.inspector.setOpenExternalLinks(True)
        self.inspector_dock = QDockWidget("Inspector", self)
        self.inspector_dock.setWidget(self.inspector)
        self.inspector_dock.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.inspector_dock)
        for table in (
            self.case_table,
            self.entity_table,
            self.profile_table,
            self.domain_table,
            self.evidence_table,
            self.timeline_table,
            self.notes_table,
            self.intel_table,
            self.source_table,
            self.bookmark_table,
            self.comment_table,
            self.job_table,
            self.search_table,
            self.search_plan_table,
            self.history_table,
        ):
            table.clicked.connect(lambda index, t=table: self._inspect(t, index))
        self.correlation_panel.table.clicked.connect(
            lambda index: self._inspect(self.correlation_panel.table, index)
        )
        self.collector_panel = CollectorPanel(self.registry, self.operations, lambda: self.case_id)
        self.collector_panel.job_changed.connect(self.refresh_case)
        self.collector_dock = QDockWidget("OSINT collectors", self)
        self.collector_dock.setWidget(self.collector_panel)
        self.collector_dock.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea
            | Qt.DockWidgetArea.RightDockWidgetArea
            | Qt.DockWidgetArea.BottomDockWidgetArea
        )
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.collector_dock)
        self.setStatusBar(QStatusBar())
        self.status_workspace = QLabel(f"Workspace: {self.workspace}")
        self.status_case = QLabel("No case selected")
        self.status_records = QLabel("")
        self.statusBar().addWidget(self.status_workspace, 1)
        self.statusBar().addPermanentWidget(self.status_case)
        self.statusBar().addPermanentWidget(self.status_records)
        menu = self.menuBar()
        file_menu = menu.addMenu("&File")
        file_menu.addAction("New investigation", self.new_case, QKeySequence("Ctrl+N"))
        file_menu.addAction("Open workspace…", self.choose_workspace)
        file_menu.addAction("Export report…", self.export_report)
        file_menu.addAction("Export investigation bundle…", self.export_bundle)
        file_menu.addAction("Import investigation bundle…", self.import_bundle)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)
        case_menu = menu.addMenu("&Investigation")
        case_menu.addAction("Edit", self.edit_case)
        case_menu.addAction("Duplicate", self.duplicate_case)
        case_menu.addAction("Archive / reopen", self.toggle_archive)
        case_menu.addAction("Merge into…", self.merge_case)
        case_menu.addSeparator()
        case_menu.addAction("Add relationship…", self.add_relationship)
        case_menu.addAction("Merge entities…", self.merge_entities)
        case_menu.addAction("Add timeline event…", self.add_timeline_event)
        case_menu.addAction("Add bookmark…", self.add_bookmark)
        case_menu.addAction("Add case comment…", self.add_comment)
        search_menu = menu.addMenu("&Search")
        search_menu.addAction("Save current search…", self.save_current_search)
        search_menu.addAction("Open saved search…", self.open_saved_search)
        view_menu = menu.addMenu("&View")
        view_menu.addAction(self.inspector_dock.toggleViewAction())
        view_menu.addAction(self.collector_dock.toggleViewAction())
        view_menu.addAction("Toggle theme", self.toggle_theme, QKeySequence("Ctrl+Shift+T"))
        view_menu.addAction("Restore default layout", self.restore_default_layout)
        self._add_navigation()
        self.sidebar.setCurrentRow(0)
        self._restore_window_layout()

    def _standard_icon(self, name: str) -> Any:
        pixmap = getattr(QStyle.StandardPixmap, name, QStyle.StandardPixmap.SP_FileIcon)
        return self.style().standardIcon(pixmap)

    def _card(self, title: str = "", subtitle: str = "") -> QFrame:
        card = QFrame()
        card.setObjectName("card")
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)
        if title:
            header = QLabel(title)
            header.setObjectName("sectionTitle")
            layout.addWidget(header)
        if subtitle:
            hint = QLabel(subtitle)
            hint.setObjectName("muted")
            hint.setWordWrap(True)
            layout.addWidget(hint)
        return card

    def _page_header(self, title: str, subtitle: str) -> QFrame:
        header = QFrame()
        header.setObjectName("card")
        layout = QVBoxLayout(header)
        layout.setContentsMargins(16, 14, 16, 14)
        heading = QLabel(title)
        heading.setObjectName("pageTitle")
        body = QLabel(subtitle)
        body.setObjectName("muted")
        body.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(body)
        return header

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)
        layout.addWidget(
            self._page_header(
                "Security Research Dashboard",
                "Recent investigations, system health, search history, and analyst shortcuts.",
            )
        )
        self.metric_layout = QGridLayout()
        self.metric_layout.setSpacing(12)
        layout.addLayout(self.metric_layout)
        grid = QGridLayout()
        grid.setSpacing(12)
        self.dashboard_cases_card = self._card("Investigations", "Open a case or review activity.")
        self.dashboard_pinned_table, self.dashboard_pinned_model, _ = configured_table(
            [("id", "ID"), ("title", "Pinned case"), ("status", "Status"), ("updated_at", "Updated")]
        )
        pinned_card = self._card("Pinned cases", "Cases tagged with pinned.")
        pinned_card.layout().addWidget(self.dashboard_pinned_table, 1)
        self.dashboard_history_table, self.dashboard_history_model, _ = configured_table(
            [("query", "Query"), ("result_count", "Results"), ("created_at", "Searched")]
        )
        history_card = self._card("Search history", "Recent searches across the workspace.")
        history_card.layout().addWidget(self.dashboard_history_table, 1)
        self.dashboard_saved_table, self.dashboard_saved_model, _ = configured_table(
            [("name", "Saved search"), ("query", "Query"), ("created_at", "Created")]
        )
        saved_card = self._card("Saved searches", "Reusable search templates.")
        saved_card.layout().addWidget(self.dashboard_saved_table, 1)
        self.dashboard_jobs_table, self.dashboard_jobs_model, _ = configured_table(
            [("status", "Status"), ("collector", "Collector"), ("query", "Query"), ("created_at", "Queued")]
        )
        jobs_card = self._card("System status", "Recent collection jobs and API activity.")
        jobs_card.layout().addWidget(self.dashboard_jobs_table, 1)
        grid.addWidget(self.dashboard_cases_card, 0, 0, 2, 2)
        grid.addWidget(pinned_card, 0, 2)
        grid.addWidget(history_card, 1, 2)
        grid.addWidget(saved_card, 2, 0)
        grid.addWidget(jobs_card, 2, 1, 1, 2)
        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 2)
        grid.setColumnStretch(2, 2)
        layout.addLayout(grid, 1)
        return page

    def _build_search_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)
        hero = QFrame()
        hero.setObjectName("searchHero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(16, 16, 16, 16)
        title = QLabel("Universal Search")
        title.setObjectName("pageTitle")
        self.search_summary = QLabel(
            "Search local case data and generate bounded free-source collection plans."
        )
        self.search_summary.setObjectName("muted")
        self.search_summary.setWordWrap(True)
        row = QHBoxLayout()
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Try CVE-2024-3094, example.org, @handle, email, phone, address...")
        self.search_entry.returnPressed.connect(self.run_search)
        search_button = QPushButton("Search")
        search_button.setObjectName("primary")
        search_button.clicked.connect(self.run_search)
        row.addWidget(self.search_entry, 1)
        row.addWidget(search_button)
        suggestions = QHBoxLayout()
        for label, query in (
            ("CVE", "CVE-2024-3094"),
            ("Domain", "example.org"),
            ("GitHub", "https://github.com/octocat"),
            ("Address", "4600 Silver Hill Rd, Washington, DC 20233"),
        ):
            button = QPushButton(label)
            button.setObjectName("ghost")
            button.clicked.connect(lambda _checked=False, value=query: self._set_search_template(value))
            suggestions.addWidget(button)
        suggestions.addStretch(1)
        self.search_kind = QLabel("Ready")
        self.search_kind.setObjectName("pill")
        suggestions.addWidget(self.search_kind)
        hero_layout.addWidget(title)
        hero_layout.addWidget(self.search_summary)
        hero_layout.addLayout(row)
        hero_layout.addLayout(suggestions)
        layout.addWidget(hero)
        result_grid = QGridLayout()
        result_grid.setSpacing(12)
        self.search_results_card = self._card("Local results", "Matches from indexed investigations.")
        self.search_plan_card = self._card("Recommended collection", "Explainable next steps.")
        result_grid.addWidget(self.search_results_card, 0, 0, 1, 2)
        result_grid.addWidget(self.search_plan_card, 0, 2)
        result_grid.setColumnStretch(0, 2)
        result_grid.setColumnStretch(1, 2)
        result_grid.setColumnStretch(2, 2)
        layout.addLayout(result_grid, 1)
        return page

    def _simple_table_page(self, title: str, subtitle: str, table: QTableView) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)
        layout.addWidget(self._page_header(title, subtitle))
        card = self._card(title)
        card.layout().addWidget(table, 1)
        layout.addWidget(card, 1)
        return page

    def _build_plugins_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)
        layout.addWidget(
            self._page_header(
                "Plugins",
                "Review installed plugin metadata and manage the local extension directory.",
            )
        )
        card = self._card("Installed plugins", "Plugins run out-of-process over JSON-RPC.")
        self.plugin_table, self.plugin_model, _ = configured_table(
            [("plugin_id", "Plugin"), ("version", "Version"), ("enabled", "Enabled"), ("updated_at", "Updated")]
        )
        card.layout().addWidget(self.plugin_table, 1)
        layout.addWidget(card, 1)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)
        layout.addWidget(
            self._page_header(
                "Settings",
                "Theme, workspace, investigator identity, proxy, timeout, and optional free-tier API keys.",
            )
        )
        card = self._card("Workspace controls")
        row = QHBoxLayout()
        for label, callback in (
            ("Open workspace", self.choose_workspace),
            ("Application settings", self.edit_settings),
            ("Toggle theme", self.toggle_theme),
            ("Restore layout", self.restore_default_layout),
        ):
            button = QPushButton(label)
            if label == "Application settings":
                button.setObjectName("primary")
            button.clicked.connect(callback)
            row.addWidget(button)
        row.addStretch(1)
        card.layout().addLayout(row)
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    def _add_navigation(self) -> None:
        self.nav_specs: list[tuple[str, str, str]] = [
            ("dashboard", "Dashboard", "SP_ComputerIcon"),
            ("search", "Search", "SP_FileDialogContentsView"),
            ("investigations", "Investigations", "SP_DirIcon"),
            ("profiles", "Public Profiles", "SP_FileIcon"),
            ("infrastructure", "Domains & Infrastructure", "SP_DriveNetIcon"),
            ("relationships", "Relationships", "SP_CommandLink"),
            ("maps", "Maps", "SP_DriveHDIcon"),
            ("timeline", "Timeline", "SP_BrowserReload"),
            ("notes", "Notes", "SP_FileDialogInfoView"),
            ("evidence", "Evidence", "SP_DialogOpenButton"),
            ("reports", "Reports", "SP_DialogSaveButton"),
            ("bookmarks", "Bookmarks", "SP_DialogYesButton"),
            ("history", "History", "SP_FileDialogDetailedView"),
            ("plugins", "Plugins", "SP_FileDialogListView"),
            ("settings", "Settings", "SP_FileDialogInfoView"),
        ]
        for key, label, icon in self.nav_specs:
            item = QListWidgetItem(self._standard_icon(icon), label)
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.sidebar.addItem(item)

    def _sidebar_changed(self, row: int) -> None:
        item = self.sidebar.item(row)
        if item is None:
            return
        key = item.data(Qt.ItemDataRole.UserRole)
        case_tabs = {
            "profiles": self.profile_table,
            "infrastructure": self.domain_table,
            "relationships": self.graph,
            "maps": self.map_view,
            "timeline": self.timeline_table,
            "notes": self.notes_table,
            "evidence": self.evidence_table,
            "reports": self.source_table,
            "bookmarks": self.bookmark_table,
        }
        if key == "dashboard":
            self.pages.setCurrentWidget(self.dashboard)
        elif key == "search":
            self.pages.setCurrentWidget(self.search_page)
            self.search_entry.setFocus()
        elif key == "investigations":
            self.pages.setCurrentWidget(self.dashboard)
            self.case_table.setFocus()
        elif key in case_tabs:
            self.pages.setCurrentWidget(self.case_workspace)
            self.case_tabs.setCurrentWidget(case_tabs[key])
            if self.case_id is None:
                self._notify("Open an investigation to use this workspace view.")
        elif key == "history":
            self.pages.setCurrentWidget(self.history_page)
        elif key == "plugins":
            self.pages.setCurrentWidget(self.plugins_page)
        elif key == "settings":
            self.pages.setCurrentWidget(self.settings_page)

    def _set_search_template(self, query: str) -> None:
        self.search_entry.setText(query)
        self.global_search.setText(query)
        self.run_search()

    def _layout_file(self) -> Path:
        return self.workspace / "ui-layout.json"

    def _restore_window_layout(self) -> None:
        path = self._layout_file()
        if not path.exists():
            return
        with contextlib.suppress(Exception):
            payload = json.loads(path.read_text(encoding="utf-8"))
            geometry = payload.get("geometry")
            state = payload.get("state")
            if geometry:
                self.restoreGeometry(QByteArray.fromBase64(QByteArray(geometry.encode("ascii"))))
            if state:
                self.restoreState(QByteArray.fromBase64(QByteArray(state.encode("ascii"))))

    def _save_window_layout(self) -> None:
        payload = {
            "geometry": bytes(self.saveGeometry().toBase64()).decode("ascii"),
            "state": bytes(self.saveState().toBase64()).decode("ascii"),
        }
        self._layout_file().write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _notify(self, message: str, timeout: int = 5000) -> None:
        self.statusBar().showMessage(message, timeout)

    def restore_default_layout(self) -> None:
        with contextlib.suppress(OSError):
            self._layout_file().unlink()
        self.resize(1480, 900)
        self.inspector_dock.show()
        self.collector_dock.show()
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.inspector_dock)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.collector_dock)
        self._notify("Default workspace layout restored.")

    def command_palette(self) -> None:
        commands: list[tuple[str, Callable[[], None]]] = [
            ("New investigation", self.new_case),
            ("Universal search", self.global_search.setFocus),
            ("Add entity", self.add_entity),
            ("Add note", self.add_note),
            ("Add evidence", self.add_evidence),
            ("Export report", self.export_report),
            ("Open saved search", self.open_saved_search),
            ("Toggle theme", self.toggle_theme),
            ("Settings", self.edit_settings),
        ]
        selected, accepted = QInputDialog.getItem(
            self,
            "Command palette",
            "Run command",
            [label for label, _callback in commands],
            0,
            False,
        )
        if accepted:
            for label, callback in commands:
                if label == selected:
                    callback()
                    break

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
        card.setMinimumHeight(92)
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
        overview = self.dashboard_service.overview()
        stats = overview["stats"]
        while self.metric_layout.count():
            item = self.metric_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for index, (title, value) in enumerate((
            ("Investigations", len(rows)),
            ("Active", sum(r["status"] == "active" for r in rows)),
            ("Entities", stats["entities"]),
            ("Evidence", stats["evidence"]),
            ("Collected records", stats["intelligence"]),
            ("Operations", stats["collection_jobs"]),
        )):
            self.metric_layout.addWidget(self._metric(title, value), index // 3, index % 3)
        self.dashboard_pinned_model.set_rows(overview["pinned_investigations"])
        self.dashboard_history_model.set_rows(overview["search_history"])
        self.dashboard_saved_model.set_rows(overview["saved_searches"])
        self.dashboard_jobs_model.set_rows(overview["recent_jobs"])
        self.history_model.set_rows(overview["search_history"])
        self.plugin_model.set_rows(self.repository.db.all("SELECT * FROM plugins ORDER BY plugin_id"))
        self.status_records.setText(
            f"{stats['entities']} entities · {stats['intelligence']} findings · {stats['collection_jobs']} jobs"
        )

    def select_case(self, case_id: int) -> None:
        self.case_id = case_id
        case = self.repository.investigation(case_id)
        self.case_title.setText(case["title"])
        self.case_meta.setText(
            f"{case['status']} · {case['investigator'] or 'No investigator'} · "
            f"updated {case['updated_at']}"
        )
        self.pages.setCurrentWidget(self.case_workspace)
        self.refresh_case()
        self.status_case.setText(f"Case {case_id}: {case['title']}")
        self._notify(f"Opened investigation {case_id}: {case['title']}")

    def refresh_case(self) -> None:
        if self.case_id is None:
            return
        entities = self.repository.rows("entities", self.case_id)
        self.entity_model.set_rows(entities)
        self.profile_model.set_rows([
            entity
            for entity in entities
            if entity["kind"] in {"person", "username", "email", "phone", "social_profile"}
        ])
        self.domain_model.set_rows([
            entity
            for entity in entities
            if entity["kind"] in {"domain", "ip", "url", "asn", "cve", "file_hash"}
        ])
        self.evidence_model.set_rows(self.repository.rows("evidence", self.case_id))
        self.timeline_model.set_rows(self.repository.rows("timeline_events", self.case_id))
        self.notes_model.set_rows(self.repository.rows("notes", self.case_id))
        self.intel_model.set_rows(self.repository.rows("intelligence", self.case_id))
        self.bookmark_model.set_rows(self.repository.rows("bookmarks", self.case_id))
        self.source_model.set_rows(self.repository.rows("source_records", self.case_id))
        self.comment_model.set_rows(self.repository.rows("comments", self.case_id))
        self.job_model.set_rows(self.repository.rows("collection_jobs", self.case_id))
        self.graph.render_data(entities, self.repository.rows("relationships", self.case_id))
        self.map_view.render_locations(self.repository.rows("locations", self.case_id))
        self.correlation_panel.refresh()
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

    def add_relationship(self) -> None:
        if self.case_id is None:
            return
        entities = self.repository.rows("entities", self.case_id)
        if len(entities) < 2:
            QMessageBox.information(
                self,
                "Entities required",
                "Add at least two entities before creating a relationship.",
            )
            return
        dialog = RelationshipDialog(entities, self)
        if dialog.exec():
            self.repository.add_relationship(self.case_id, **dialog.value())
            self.refresh_case()
            self.case_tabs.setCurrentWidget(self.graph)

    def merge_entities(self) -> None:
        if self.case_id is None:
            return
        entities = self.repository.rows("entities", self.case_id)
        if len(entities) < 2:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Merge duplicate entities")
        form = QFormLayout(dialog)
        source = QComboBox()
        target = QComboBox()
        for entity in entities:
            label = f"{entity['kind']}: {entity['display_name'] or entity['value']}"
            source.addItem(label, entity["id"])
            target.addItem(label, entity["id"])
        target.setCurrentIndex(1)
        form.addRow("Merge", source)
        form.addRow("Into", target)
        hint = QLabel(
            "The source entity is removed; aliases, links, locations and timeline references are retained."
        )
        hint.setWordWrap(True)
        hint.setObjectName("muted")
        form.addRow(hint)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if not dialog.exec():
            return
        if source.currentData() == target.currentData():
            QMessageBox.warning(self, "Invalid merge", "Choose two different entities.")
            return
        if (
            QMessageBox.question(
                self,
                "Confirm entity merge",
                "Merge the source entity into the target? This changes graph references.",
            )
            == QMessageBox.StandardButton.Yes
        ):
            self.repository.merge_entities(
                self.case_id, int(source.currentData()), int(target.currentData())
            )
            self.correlation.generate(self.case_id)
            self.refresh_case()

    def add_timeline_event(self) -> None:
        if self.case_id is None:
            return
        dialog = TimelineDialog(self)
        if dialog.exec():
            self.repository.add_timeline_event(self.case_id, **dialog.value())
            self.refresh_case()
            self.case_tabs.setCurrentWidget(self.timeline_table)

    def add_bookmark(self) -> None:
        if self.case_id is None:
            return
        dialog = BookmarkDialog(self)
        if dialog.exec():
            self.repository.add_bookmark(
                self.case_id,
                dialog.title.text(),
                dialog.url.text(),
                dialog.description.toPlainText(),
                [tag.strip() for tag in dialog.tags.text().split(",") if tag.strip()],
            )
            self.refresh_case()
            self.case_tabs.setCurrentWidget(self.bookmark_table)

    def add_comment(self) -> None:
        if self.case_id is None:
            return
        body, accepted = QInputDialog.getMultiLineText(self, "Add case comment", "Comment")
        if accepted and body.strip():
            self.repository.add_comment(
                self.case_id,
                "investigation",
                self.case_id,
                body,
                self.settings.investigator,
            )
            self.refresh_case()
            self.case_tabs.setCurrentWidget(self.comment_table)

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

    def _selected_job_id(self) -> int | None:
        index = self.job_table.currentIndex()
        if not index.isValid():
            return None
        row = self.job_proxy.mapToSource(index).data(Qt.ItemDataRole.UserRole)
        return int(row["id"])

    def cancel_job(self) -> None:
        job_id = self._selected_job_id()
        if job_id is not None:
            self.operations.cancel(job_id)
            self.refresh_case()

    def retry_job(self) -> None:
        job_id = self._selected_job_id()
        if job_id is None:
            return
        new_job_id = self.operations.retry(job_id)
        worker = AsyncWorker(lambda: self.operations.run_job(new_job_id))
        worker.signals.completed.connect(lambda _findings: self.refresh_case())
        worker.signals.failed.connect(
            lambda detail: (self.refresh_case(), QMessageBox.critical(self, "Retry failed", detail))
        )
        QThreadPool.globalInstance().start(worker)
        self.refresh_case()

    def run_search(self) -> None:
        query = self.global_search.text().strip()
        if not query and hasattr(self, "search_entry"):
            query = self.search_entry.text().strip()
        if not query:
            return
        self.global_search.setText(query)
        if hasattr(self, "search_entry"):
            self.search_entry.setText(query)
        result = self.universal_search.search(query)
        normalized = result["input"]
        self.search_model.set_rows(result["local_results"])
        self.search_plan_model.set_rows(result["plan"])
        self.search_kind.setText(normalized["kind"].replace("_", " ").title())
        warning = "; ".join(normalized["warnings"])
        plan_count = len(result["plan"])
        self.search_summary.setText(
            f"{result['local_result_count']} local matches · {plan_count} recommended collectors"
            + (f" · {warning}" if warning else "")
        )
        self.pages.setCurrentWidget(self.search_page)
        self._notify(f"Search complete: {query}")

    def save_current_search(self) -> None:
        query = self.global_search.text().strip()
        if not query and hasattr(self, "search_entry"):
            query = self.search_entry.text().strip()
        if not query:
            return
        name, accepted = QInputDialog.getText(self, "Save search", "Search name")
        if accepted and name.strip():
            self.repository.save_search(name, query)
            self.refresh_cases()
            self._notify(f"Saved search: {name}")

    def open_saved_search(self) -> None:
        searches = self.repository.saved_searches()
        if not searches:
            QMessageBox.information(self, "Saved searches", "No searches have been saved yet.")
            return
        labels = [item["name"] for item in searches]
        selected, accepted = QInputDialog.getItem(
            self, "Saved searches", "Search", labels, 0, False
        )
        if accepted:
            search = next(item for item in searches if item["name"] == selected)
            self.global_search.setText(search["query"])
            if hasattr(self, "search_entry"):
                self.search_entry.setText(search["query"])
            self.run_search()

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

    def export_bundle(self) -> None:
        if self.case_id is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export investigation bundle",
            f"investigation-{self.case_id}.argus",
            "Argus investigation bundle (*.argus)",
        )
        if not path:
            return
        try:
            self.bundle.export(self.case_id, Path(path))
            self.statusBar().showMessage(f"Investigation bundle exported to {path}", 8000)
        except Exception as exc:
            QMessageBox.critical(self, "Bundle export failed", str(exc))

    def import_bundle(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import investigation bundle", "", "Argus investigation bundle (*.argus)"
        )
        if not path:
            return
        try:
            summary = self.bundle.inspect(Path(path))
            case = summary["investigation"]
            counts = ", ".join(
                f"{value} {key.replace('_', ' ')}"
                for key, value in summary["counts"].items()
                if value
            )
            if (
                QMessageBox.question(
                    self,
                    "Import verified bundle",
                    f"Import '{case['title']}'?\n\nIntegrity checks passed.\n{counts}",
                )
                != QMessageBox.StandardButton.Yes
            ):
                return
            case_id = self.bundle.import_bundle(Path(path))
            self.select_case(case_id)
        except Exception as exc:
            QMessageBox.critical(self, "Bundle import failed", str(exc))

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
            self._notify("Settings updated.")

    def toggle_theme(self) -> None:
        self.settings.theme = "light" if self.settings.theme == "dark" else "dark"
        self.settings_store.save(self.settings)
        self._apply_theme()
        self._notify(f"{self.settings.theme.title()} theme enabled.")

    def choose_workspace(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Open workspace", str(self.workspace))
        if not path or Path(path).resolve() == self.workspace:
            return
        QThreadPool.globalInstance().waitForDone(5000)
        self._save_window_layout()
        self.db.close()
        self.settings.workspace = path
        self.settings_store.save(self.settings)
        self._open_workspace(Path(path))
        self.collector_panel.set_operations(self.operations)
        self.correlation_panel.engine = self.correlation
        self.case_id = None
        self.status_workspace.setText(f"Workspace: {self.workspace}")
        self.status_case.setText("No case selected")
        self.case_title.setText("No investigation selected")
        self.case_meta.setText("Open or create a case to begin collection and analysis.")
        self.refresh_cases()
        self.pages.setCurrentWidget(self.dashboard)
        self._restore_window_layout()

    def closeEvent(self, event: Any) -> None:
        self.settings_store.save(self.settings)
        self._save_window_layout()
        QThreadPool.globalInstance().waitForDone(5000)
        self.db.close()
        event.accept()
