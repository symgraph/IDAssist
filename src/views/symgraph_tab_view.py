#!/usr/bin/env python3
"""
SymGraph Tab View for IDAssist.

Shared Status / Fetch / Push UX for SymGraph operations.
"""

from typing import Any, Dict, List, Optional

from ..qt_compat import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QProgressBar,
    QRadioButton,
    QSlider,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QFont,
    Signal,
    Qt,
)

from ..services.models.symgraph_models import BinaryRevision, ConflictAction, ConflictEntry, PushScope


class SymGraphTabView(QWidget):
    """SymGraph tab with Status, Fetch, and Push subtabs."""

    DOCUMENT_TYPE_OPTIONS = (
        ("General", "general"),
        ("Malware Report", "malware_report"),
        ("Vulnerability Analysis", "vuln_analysis"),
        ("API Documentation", "api_doc"),
        ("Notes", "notes"),
    )

    query_requested = Signal()
    open_binary_requested = Signal()
    pull_preview_requested = Signal()
    apply_selected_requested = Signal(list)
    apply_all_new_requested = Signal()
    push_preview_requested = Signal()
    push_execute_requested = Signal()

    MERGE_POLICY_UPSERT = "upsert"
    MERGE_POLICY_PREFER_LOCAL = "prefer_local"
    MERGE_POLICY_REPLACE = "replace"

    def __init__(self):
        super().__init__()
        self._graph_preview = None
        self._graph_stats = None
        self._push_graph_data = None
        self._push_graph_stats = None
        self._push_preview_symbols: List[Dict[str, Any]] = []
        self._pull_preview_documents: List[Dict[str, Any]] = []
        self._push_preview_documents: List[Dict[str, Any]] = []
        self._open_binary_url: Optional[str] = None
        self._merge_policy = self.MERGE_POLICY_UPSERT
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        self._create_binary_info_section(layout)

        self.subtabs = QTabWidget()
        self.subtabs.addTab(self._create_status_tab(), "Status")
        self.subtabs.addTab(self._create_fetch_tab(), "Fetch")
        self.subtabs.addTab(self._create_push_tab(), "Push")
        layout.addWidget(self.subtabs)

        self.setLayout(layout)

    def _create_binary_info_section(self, parent_layout):
        info_frame = QFrame()
        info_frame.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(10, 10, 10, 10)

        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Binary:"))
        self.binary_name_label = QLabel("<no binary loaded>")
        self.binary_name_label.setStyleSheet("font-weight: bold;")
        name_layout.addWidget(self.binary_name_label)
        name_layout.addStretch()
        info_layout.addLayout(name_layout)

        hash_layout = QHBoxLayout()
        hash_layout.addWidget(QLabel("SHA256:"))
        self.sha256_label = QLabel("<none>")
        self.sha256_label.setStyleSheet("font-family: monospace; font-size: 11px;")
        hash_layout.addWidget(self.sha256_label)
        hash_layout.addStretch()
        info_layout.addLayout(hash_layout)

        summary_layout = QHBoxLayout()
        summary_layout.addWidget(QLabel("Local Summary:"))
        self.local_summary_label = QLabel("No binary loaded")
        self.local_summary_label.setStyleSheet("color: gray;")
        summary_layout.addWidget(self.local_summary_label)
        summary_layout.addStretch()
        info_layout.addLayout(summary_layout)

        parent_layout.addWidget(info_frame)

    def _create_status_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        server_group = QGroupBox("SymGraph Server")
        server_layout = QVBoxLayout()

        button_row = QHBoxLayout()
        self.query_button = QPushButton("Query SymGraph")
        self.query_button.clicked.connect(self.query_requested.emit)
        button_row.addWidget(self.query_button)
        self.open_binary_button = QPushButton("Open in SymGraph")
        self.open_binary_button.setEnabled(False)
        self.open_binary_button.clicked.connect(self.open_binary_requested.emit)
        button_row.addWidget(self.open_binary_button)
        button_row.addStretch()
        server_layout.addLayout(button_row)

        status_row = QHBoxLayout()
        status_row.addWidget(QLabel("Status:"))
        self.status_label = QLabel("Not checked")
        self.status_label.setStyleSheet("color: gray;")
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        server_layout.addLayout(status_row)

        self.stats_frame = QFrame()
        self.stats_frame.setFrameStyle(QFrame.Box | QFrame.Sunken)
        stats_layout = QGridLayout(self.stats_frame)
        self.symbols_stat = QLabel("Symbols: -")
        self.functions_stat = QLabel("Functions: -")
        self.nodes_stat = QLabel("Graph Nodes: -")
        self.edges_stat = QLabel("Graph Edges: -")
        self.updated_stat = QLabel("Last Updated: -")
        self.latest_revision_stat = QLabel("Latest Version: -")
        self.accessible_versions_stat = QLabel("Accessible Versions: -")
        stats_layout.addWidget(self.symbols_stat, 0, 0)
        stats_layout.addWidget(self.functions_stat, 0, 1)
        stats_layout.addWidget(self.nodes_stat, 1, 0)
        stats_layout.addWidget(self.edges_stat, 1, 1)
        stats_layout.addWidget(self.updated_stat, 2, 0)
        stats_layout.addWidget(self.latest_revision_stat, 2, 1)
        stats_layout.addWidget(self.accessible_versions_stat, 3, 0, 1, 2)
        self.stats_frame.setVisible(False)
        server_layout.addWidget(self.stats_frame)
        server_group.setLayout(server_layout)
        layout.addWidget(server_group)
        layout.addStretch()
        return page

    def _create_fetch_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        config_group = QGroupBox("Fetch Configuration")
        config_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Version:"))
        self.fetch_version_combo = QComboBox()
        self.fetch_version_combo.setMinimumWidth(180)
        row1.addWidget(self.fetch_version_combo)
        row1.addSpacing(12)
        row1.addWidget(QLabel("Name Filter:"))
        self.fetch_name_filter = QLineEdit()
        self.fetch_name_filter.setPlaceholderText("Substring match")
        row1.addWidget(self.fetch_name_filter)
        row1.addStretch()
        config_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Symbol Types:"))
        self.pull_functions_cb = QCheckBox("Functions")
        self.pull_functions_cb.setChecked(True)
        self.pull_variables_cb = QCheckBox("Variables")
        self.pull_variables_cb.setChecked(True)
        self.pull_types_cb = QCheckBox("Types")
        self.pull_types_cb.setChecked(True)
        self.pull_comments_cb = QCheckBox("Comments")
        self.pull_comments_cb.setChecked(True)
        row2.addWidget(self.pull_functions_cb)
        row2.addWidget(self.pull_variables_cb)
        row2.addWidget(self.pull_types_cb)
        row2.addWidget(self.pull_comments_cb)
        row2.addSpacing(16)
        self.pull_graph_cb = QCheckBox("Include Graph Data")
        self.pull_graph_cb.setChecked(True)
        row2.addWidget(self.pull_graph_cb)
        row2.addStretch()
        config_layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Min Confidence:"))
        self.confidence_slider = QSlider(Qt.Horizontal)
        self.confidence_slider.setMinimum(0)
        self.confidence_slider.setMaximum(100)
        self.confidence_slider.setValue(0)
        self.confidence_slider.setFixedWidth(140)
        self.confidence_slider.valueChanged.connect(self._on_confidence_changed)
        row3.addWidget(self.confidence_slider)
        self.confidence_value_label = QLabel("0.0")
        self.confidence_value_label.setFixedWidth(30)
        row3.addWidget(self.confidence_value_label)
        row3.addSpacing(16)
        row3.addWidget(QLabel("Graph Merge:"))
        merge_widget, _ = self._create_merge_policy_widget()
        row3.addWidget(merge_widget)
        row3.addStretch()
        config_layout.addLayout(row3)

        action_row = QHBoxLayout()
        self.pull_preview_button = QPushButton("Preview Fetch")
        self.pull_preview_button.clicked.connect(self.pull_preview_requested.emit)
        action_row.addWidget(self.pull_preview_button)
        self.fetch_reset_button = QPushButton("Reset")
        self.fetch_reset_button.clicked.connect(self.clear_conflicts)
        action_row.addWidget(self.fetch_reset_button)
        action_row.addStretch()
        config_layout.addLayout(action_row)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        self.fetch_summary_frame = QFrame()
        self.fetch_summary_frame.setFrameStyle(QFrame.Box | QFrame.Sunken)
        summary_layout = QHBoxLayout(self.fetch_summary_frame)
        self.summary_new_count = QLabel("New: 0")
        self.summary_conflict_count = QLabel("Conflicts: 0")
        self.summary_same_count = QLabel("Same: 0")
        self.summary_selected_count = QLabel("Selected: 0")
        self.summary_document_count = QLabel("Documents: 0")
        self.summary_graph_nodes_label = QLabel("Graph Nodes: 0")
        self.summary_graph_edges_label = QLabel("Graph Edges: 0")
        self.summary_graph_version_label = QLabel("Version: -")
        for label in (
            self.summary_new_count,
            self.summary_conflict_count,
            self.summary_same_count,
            self.summary_selected_count,
            self.summary_document_count,
            self.summary_graph_nodes_label,
            self.summary_graph_edges_label,
            self.summary_graph_version_label,
        ):
            summary_layout.addWidget(label)
        summary_layout.addStretch()
        layout.addWidget(self.fetch_summary_frame)

        self.conflict_table = QTableWidget()
        self.conflict_table.setColumnCount(6)
        self.conflict_table.setHorizontalHeaderLabels(
            ["Select", "Address", "Type/Storage", "Local Name", "Remote Name", "Action"]
        )
        self.conflict_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.conflict_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        header = self.conflict_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.conflict_table.setColumnWidth(0, 54)
        self.conflict_table.setColumnWidth(1, 110)
        self.conflict_table.setColumnWidth(2, 130)
        self.conflict_table.setColumnWidth(5, 90)
        self.conflict_table.setMinimumHeight(250)
        layout.addWidget(self.conflict_table)

        select_row = QHBoxLayout()
        self.select_all_button = QPushButton("Select All")
        self.select_all_button.clicked.connect(self.on_select_all)
        select_row.addWidget(self.select_all_button)
        self.deselect_all_button = QPushButton("Deselect All")
        self.deselect_all_button.clicked.connect(self.on_deselect_all)
        select_row.addWidget(self.deselect_all_button)
        self.select_new_button = QPushButton("Select New")
        self.select_new_button.clicked.connect(self.on_select_new)
        select_row.addWidget(self.select_new_button)
        self.select_conflicts_button = QPushButton("Select Conflicts")
        self.select_conflicts_button.clicked.connect(self.on_select_conflicts)
        select_row.addWidget(self.select_conflicts_button)
        self.invert_selection_button = QPushButton("Invert")
        self.invert_selection_button.clicked.connect(self.on_invert_selection)
        select_row.addWidget(self.invert_selection_button)
        select_row.addStretch()
        layout.addLayout(select_row)

        apply_row = QHBoxLayout()
        self.apply_all_new_button = QPushButton("Apply All New")
        self.apply_all_new_button.clicked.connect(self.apply_all_new_requested.emit)
        apply_row.addWidget(self.apply_all_new_button)
        self.apply_button = QPushButton("Apply Selected")
        self.apply_button.clicked.connect(self.on_apply_clicked)
        apply_row.addWidget(self.apply_button)
        apply_row.addStretch()
        layout.addLayout(apply_row)

        self.fetch_documents_table = QTableWidget()
        self.fetch_documents_table.setColumnCount(5)
        self.fetch_documents_table.setHorizontalHeaderLabels(
            ["Select", "Title", "Size", "Date", "Version"]
        )
        self.fetch_documents_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.fetch_documents_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        fetch_docs_header = self.fetch_documents_table.horizontalHeader()
        fetch_docs_header.setSectionResizeMode(0, QHeaderView.Fixed)
        fetch_docs_header.setSectionResizeMode(1, QHeaderView.Stretch)
        fetch_docs_header.setSectionResizeMode(2, QHeaderView.Fixed)
        fetch_docs_header.setSectionResizeMode(3, QHeaderView.Fixed)
        fetch_docs_header.setSectionResizeMode(4, QHeaderView.Fixed)
        self.fetch_documents_table.setColumnWidth(0, 54)
        self.fetch_documents_table.setColumnWidth(2, 90)
        self.fetch_documents_table.setColumnWidth(3, 140)
        self.fetch_documents_table.setColumnWidth(4, 80)
        self.fetch_documents_table.setMaximumHeight(150)
        layout.addWidget(QLabel("Documents"))
        layout.addWidget(self.fetch_documents_table)

        self.fetch_progress_bar = QProgressBar()
        self.fetch_progress_bar.setVisible(False)
        layout.addWidget(self.fetch_progress_bar)

        self.fetch_progress_label = QLabel("")
        self.fetch_progress_label.setStyleSheet("color: gray;")
        self.fetch_progress_label.setVisible(False)
        layout.addWidget(self.fetch_progress_label)

        self.pull_status_label = QLabel("")
        self.pull_status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.pull_status_label)
        return page

    def _create_push_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        config_group = QGroupBox("Push Configuration")
        config_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Scope:"))
        self.full_binary_radio = QRadioButton("Full Binary")
        self.current_function_radio = QRadioButton("Current Function")
        self.current_function_radio.setChecked(True)
        self.scope_group = QButtonGroup(self)
        self.scope_group.addButton(self.full_binary_radio, 1)
        self.scope_group.addButton(self.current_function_radio, 2)
        row1.addWidget(self.full_binary_radio)
        row1.addWidget(self.current_function_radio)
        row1.addSpacing(16)
        row1.addWidget(QLabel("Visibility:"))
        self.push_visibility_combo = QComboBox()
        self.push_visibility_combo.addItem("Public", "public")
        self.push_visibility_combo.addItem("Private", "private")
        row1.addWidget(self.push_visibility_combo)
        row1.addStretch()
        config_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Symbol Types:"))
        self.push_functions_cb = QCheckBox("Functions")
        self.push_functions_cb.setChecked(True)
        self.push_variables_cb = QCheckBox("Variables")
        self.push_variables_cb.setChecked(True)
        self.push_types_cb = QCheckBox("Types")
        self.push_types_cb.setChecked(True)
        self.push_comments_cb = QCheckBox("Comments")
        self.push_comments_cb.setChecked(False)
        for widget in (
            self.push_functions_cb,
            self.push_variables_cb,
            self.push_types_cb,
            self.push_comments_cb,
        ):
            row2.addWidget(widget)
        row2.addSpacing(16)
        self.push_graph_check = QCheckBox("Include Graph Data")
        self.push_graph_check.setChecked(True)
        row2.addWidget(self.push_graph_check)
        row2.addStretch()
        config_layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Name Filter:"))
        self.push_name_filter = QLineEdit()
        self.push_name_filter.setPlaceholderText("Substring match")
        row3.addWidget(self.push_name_filter)
        row3.addStretch()
        config_layout.addLayout(row3)

        action_row = QHBoxLayout()
        self.push_preview_button = QPushButton("Preview Push")
        self.push_preview_button.clicked.connect(self.push_preview_requested.emit)
        action_row.addWidget(self.push_preview_button)
        self.push_button = QPushButton("Push Selected")
        self.push_button.clicked.connect(self.push_execute_requested.emit)
        action_row.addWidget(self.push_button)
        action_row.addStretch()
        config_layout.addLayout(action_row)
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        self.push_summary_frame = QFrame()
        self.push_summary_frame.setFrameStyle(QFrame.Box | QFrame.Sunken)
        push_summary_layout = QHBoxLayout(self.push_summary_frame)
        self.push_matching_count = QLabel("Matching: 0")
        self.push_selected_count = QLabel("Selected: 0")
        self.push_documents_count = QLabel("Documents: 0")
        self.push_graph_nodes_label = QLabel("Graph Nodes: 0")
        self.push_graph_edges_label = QLabel("Graph Edges: 0")
        for label in (
            self.push_matching_count,
            self.push_selected_count,
            self.push_documents_count,
            self.push_graph_nodes_label,
            self.push_graph_edges_label,
        ):
            push_summary_layout.addWidget(label)
        push_summary_layout.addStretch()
        layout.addWidget(self.push_summary_frame)

        self.push_preview_table = QTableWidget()
        self.push_preview_table.setColumnCount(6)
        self.push_preview_table.setHorizontalHeaderLabels(
            ["Select", "Address", "Type", "Name", "Confidence", "Provenance"]
        )
        self.push_preview_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.push_preview_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        header = self.push_preview_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.push_preview_table.setColumnWidth(0, 54)
        self.push_preview_table.setColumnWidth(1, 110)
        self.push_preview_table.setColumnWidth(2, 100)
        self.push_preview_table.setColumnWidth(4, 90)
        self.push_preview_table.setColumnWidth(5, 100)
        self.push_preview_table.setMinimumHeight(250)
        layout.addWidget(self.push_preview_table)

        push_select_row = QHBoxLayout()
        self.push_select_all_button = QPushButton("Select All")
        self.push_select_all_button.clicked.connect(self.on_push_select_all)
        push_select_row.addWidget(self.push_select_all_button)
        self.push_deselect_all_button = QPushButton("Deselect All")
        self.push_deselect_all_button.clicked.connect(self.on_push_deselect_all)
        push_select_row.addWidget(self.push_deselect_all_button)
        self.push_invert_selection_button = QPushButton("Invert")
        self.push_invert_selection_button.clicked.connect(self.on_push_invert_selection)
        push_select_row.addWidget(self.push_invert_selection_button)
        push_select_row.addStretch()
        layout.addLayout(push_select_row)

        self.push_documents_table = QTableWidget()
        self.push_documents_table.setColumnCount(6)
        self.push_documents_table.setHorizontalHeaderLabels(
            ["Select", "Title", "Size", "Date", "Version", "Doc Type"]
        )
        self.push_documents_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.push_documents_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        push_docs_header = self.push_documents_table.horizontalHeader()
        push_docs_header.setSectionResizeMode(0, QHeaderView.Fixed)
        push_docs_header.setSectionResizeMode(1, QHeaderView.Stretch)
        push_docs_header.setSectionResizeMode(2, QHeaderView.Fixed)
        push_docs_header.setSectionResizeMode(3, QHeaderView.Fixed)
        push_docs_header.setSectionResizeMode(4, QHeaderView.Fixed)
        push_docs_header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.push_documents_table.setColumnWidth(0, 54)
        self.push_documents_table.setColumnWidth(2, 90)
        self.push_documents_table.setColumnWidth(3, 140)
        self.push_documents_table.setColumnWidth(4, 80)
        self.push_documents_table.setColumnWidth(5, 110)
        self.push_documents_table.setMaximumHeight(150)
        layout.addWidget(QLabel("Documents"))
        layout.addWidget(self.push_documents_table)

        self.push_progress_bar = QProgressBar()
        self.push_progress_bar.setVisible(False)
        layout.addWidget(self.push_progress_bar)

        self.push_progress_label = QLabel("")
        self.push_progress_label.setStyleSheet("color: gray;")
        self.push_progress_label.setVisible(False)
        layout.addWidget(self.push_progress_label)

        self.push_status_label = QLabel("Status: Ready")
        self.push_status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.push_status_label)
        return page

    def _create_merge_policy_widget(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        group = QButtonGroup(widget)

        for label, policy in (
            ("Upsert", self.MERGE_POLICY_UPSERT),
            ("Prefer Local", self.MERGE_POLICY_PREFER_LOCAL),
            ("Replace", self.MERGE_POLICY_REPLACE),
        ):
            button = QRadioButton(label)
            button.setProperty("merge_policy", policy)
            if policy == self._merge_policy:
                button.setChecked(True)
            button.toggled.connect(self._on_merge_policy_changed)
            group.addButton(button)
            layout.addWidget(button)

        return widget, group

    def _on_merge_policy_changed(self):
        button = self.sender()
        if not isinstance(button, QRadioButton) or not button.isChecked():
            return
        policy = button.property("merge_policy")
        if policy:
            self._merge_policy = policy

    def _on_confidence_changed(self, value: int):
        self.confidence_value_label.setText(f"{value / 100.0:.1f}")

    def _format_storage_info(self, symbol) -> str:
        if not symbol:
            return ""

        sym_type = getattr(symbol, "symbol_type", "function")
        metadata = getattr(symbol, "metadata", {}) or {}

        if sym_type != "variable":
            return sym_type

        storage_class = metadata.get("storage_class", "")
        scope = metadata.get("scope", "")
        if storage_class == "parameter":
            idx = metadata.get("parameter_index", "?")
            reg = metadata.get("register")
            return f"param[{idx}] ({reg})" if reg else f"param[{idx}]"
        if storage_class == "stack":
            offset = metadata.get("stack_offset", 0)
            sign = "+" if offset >= 0 else "-"
            return f"local [{sign}0x{abs(offset):x}]"
        if storage_class == "register":
            reg = metadata.get("register", "?")
            return f"local ({reg})"
        if scope == "local":
            return "local"
        return "global"

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        if size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        if size_bytes >= 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes} B"

    @staticmethod
    def _format_version(version: Optional[int]) -> str:
        return f"v{version}" if version else "New"

    def _set_checkbox_widget(self, table: QTableWidget, row: int, checked: bool):
        checkbox = QCheckBox()
        checkbox.setChecked(checked)
        checkbox.stateChanged.connect(self._update_selection_summaries)
        container = QWidget()
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(checkbox)
        table.setCellWidget(row, 0, container)

    def _iter_checked_rows(self, table: QTableWidget):
        for row in range(table.rowCount()):
            widget = table.cellWidget(row, 0)
            if not widget:
                continue
            checkbox = widget.findChild(QCheckBox)
            if checkbox and checkbox.isChecked():
                yield row

    def _set_all_rows(self, table: QTableWidget, checked: bool, action_filter: Optional[ConflictAction] = None):
        for row in range(table.rowCount()):
            item = table.item(row, 1)
            payload = item.data(Qt.UserRole + 1) if item else None
            if action_filter is not None and getattr(payload, "action", None) != action_filter:
                continue
            widget = table.cellWidget(row, 0)
            if not widget:
                continue
            checkbox = widget.findChild(QCheckBox)
            if checkbox:
                checkbox.setChecked(checked)
        self._update_selection_summaries()

    def _update_selection_summaries(self):
        selected_fetch_symbols = sum(1 for _ in self._iter_checked_rows(self.conflict_table))
        selected_fetch_documents = sum(1 for _ in self._iter_checked_rows(self.fetch_documents_table))
        self.summary_selected_count.setText(
            f"Selected: {selected_fetch_symbols} symbols / {selected_fetch_documents} docs"
        )
        selected_push_symbols = sum(1 for _ in self._iter_checked_rows(self.push_preview_table))
        selected_push_documents = sum(1 for _ in self._iter_checked_rows(self.push_documents_table))
        self.push_selected_count.setText(
            f"Selected: {selected_push_symbols} symbols / {selected_push_documents} docs"
        )

    def set_binary_info(self, name: str, sha256: str, local_metadata: Optional[Dict[str, Any]] = None):
        display_name = name or "<no binary loaded>"
        display_sha = sha256 or "<none>"
        self.binary_name_label.setText(display_name)
        self.sha256_label.setText(display_sha)

        if local_metadata:
            parts = []
            if local_metadata.get("functions") is not None:
                parts.append(f"{local_metadata['functions']:,} functions")
            if local_metadata.get("symbols") is not None:
                parts.append(f"{local_metadata['symbols']:,} symbols")
            if local_metadata.get("graph_nodes") is not None:
                parts.append(f"{local_metadata['graph_nodes']:,} graph nodes")
            if local_metadata.get("graph_edges") is not None:
                parts.append(f"{local_metadata['graph_edges']:,} graph edges")
            self.local_summary_label.setText(" | ".join(parts) if parts else "Binary metadata available")
        elif sha256:
            self.local_summary_label.setText("Binary metadata available")
        else:
            self.local_summary_label.setText("No binary loaded")

    def set_query_status(self, status: str, found: bool = False):
        self.status_label.setText(status)
        if found:
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
        elif "error" in status.lower() or "not found" in status.lower():
            self.status_label.setStyleSheet("color: red;")
        else:
            self.status_label.setStyleSheet("color: gray;")

    def set_stats(
        self,
        symbols: int,
        functions: int,
        nodes: int,
        last_updated: str,
        revisions: Optional[List[BinaryRevision]] = None,
        latest_revision: Optional[int] = None,
        selected_revision: Optional[int] = None,
    ):
        self.symbols_stat.setText(f"Symbols: {symbols:,}")
        self.functions_stat.setText(f"Functions: {functions:,}")
        self.nodes_stat.setText(f"Graph Nodes: {nodes:,}")
        self.edges_stat.setText("Graph Edges: -")
        self.updated_stat.setText(f"Last Updated: {last_updated or 'Unknown'}")
        self.latest_revision_stat.setText(
            f"Latest Version: v{latest_revision}" if latest_revision else "Latest Version: -"
        )
        self.accessible_versions_stat.setText(
            f"Accessible Versions: {len(revisions or [])}" if revisions is not None else "Accessible Versions: -"
        )
        self.stats_frame.setVisible(True)
        self.set_fetch_versions(revisions or [], selected_revision)

    def set_fetch_versions(self, revisions: List[BinaryRevision], selected_revision: Optional[int] = None):
        current = self.fetch_version_combo.currentData()
        self.fetch_version_combo.blockSignals(True)
        self.fetch_version_combo.clear()
        if not revisions:
            self.fetch_version_combo.addItem("Latest", None)
        else:
            for revision in revisions:
                self.fetch_version_combo.addItem(revision.display_label, revision.version)
            target = selected_revision if selected_revision is not None else revisions[0].version
            index = self.fetch_version_combo.findData(target)
            if index >= 0:
                self.fetch_version_combo.setCurrentIndex(index)
        self.fetch_version_combo.blockSignals(False)
        if current is not None and self.fetch_version_combo.findData(current) >= 0:
            self.fetch_version_combo.setCurrentIndex(self.fetch_version_combo.findData(current))

    def hide_stats(self):
        self.stats_frame.setVisible(False)
        self.latest_revision_stat.setText("Latest Version: -")
        self.accessible_versions_stat.setText("Accessible Versions: -")
        self.fetch_version_combo.clear()
        self.fetch_version_combo.addItem("Latest", None)

    def set_open_binary_url(self, url: Optional[str]):
        self._open_binary_url = url
        self.open_binary_button.setEnabled(bool(url))

    def get_open_binary_url(self) -> Optional[str]:
        return self._open_binary_url

    def set_push_status(self, status: str, success: bool = None):
        self.push_status_label.setText(f"Status: {status}")
        if success is True:
            self.push_status_label.setStyleSheet("color: green;")
        elif success is False:
            self.push_status_label.setStyleSheet("color: red;")
        else:
            self.push_status_label.setStyleSheet("color: gray;")

    def set_pull_status(self, status: str, success: bool = None):
        self.pull_status_label.setText(status)
        if success is True:
            self.pull_status_label.setStyleSheet("color: green;")
        elif success is False:
            self.pull_status_label.setStyleSheet("color: red;")
        else:
            self.pull_status_label.setStyleSheet("color: gray;")

    def set_graph_preview_data(self, graph_export, graph_stats=None):
        self._graph_preview = graph_export
        self._graph_stats = graph_stats or {}
        nodes = self._graph_stats.get("nodes", 0)
        edges = self._graph_stats.get("edges", 0)
        version = self.fetch_version_combo.currentData()
        self.summary_graph_nodes_label.setText(f"Graph Nodes: {nodes:,}")
        self.summary_graph_edges_label.setText(f"Graph Edges: {edges:,}")
        self.summary_graph_version_label.setText(
            f"Version: v{version}" if version is not None else "Version: Latest"
        )

    def clear_graph_preview_data(self):
        self.set_graph_preview_data(None, {})

    def populate_conflicts(self, conflicts: List[ConflictEntry]):
        self.conflict_table.setRowCount(0)

        new_count = sum(1 for c in conflicts if c.action == ConflictAction.NEW)
        conflict_count = sum(1 for c in conflicts if c.action == ConflictAction.CONFLICT)
        same_count = sum(1 for c in conflicts if c.action == ConflictAction.SAME)
        self.summary_new_count.setText(f"New: {new_count}")
        self.summary_conflict_count.setText(f"Conflicts: {conflict_count}")
        self.summary_same_count.setText(f"Same: {same_count}")

        actionable = sorted(
            [c for c in conflicts if c.action != ConflictAction.SAME],
            key=lambda item: (0 if item.action == ConflictAction.NEW else 1, item.address)
        )
        preselected_ids = {id(item) for item in actionable}

        sorted_conflicts = sorted(
            conflicts,
            key=lambda item: (
                0 if item.action == ConflictAction.NEW else 1 if item.action == ConflictAction.CONFLICT else 2,
                item.address,
            ),
        )

        for conflict in sorted_conflicts:
            conflict.selected = id(conflict) in preselected_ids if conflict.action != ConflictAction.SAME else False
            self._add_conflict_row(conflict)

        self.apply_all_new_button.setEnabled(new_count > 0 or self._graph_preview is not None)
        self.apply_button.setEnabled(bool(conflicts) or self._graph_preview is not None)
        self._update_selection_summaries()

    def populate_fetch_documents(self, documents: List[Dict[str, Any]]):
        self._pull_preview_documents = list(documents)
        self.fetch_documents_table.setRowCount(0)
        self.summary_document_count.setText(f"Documents: {len(documents)}")

        for document in documents:
            row = self.fetch_documents_table.rowCount()
            self.fetch_documents_table.insertRow(row)
            self._set_checkbox_widget(self.fetch_documents_table, row, True)

            title_item = QTableWidgetItem(document.get("title", "Untitled Document"))
            title_item.setData(Qt.UserRole + 1, document)
            title_item.setFlags(title_item.flags() & ~Qt.ItemIsEditable)
            self.fetch_documents_table.setItem(row, 1, title_item)

            size_item = QTableWidgetItem(self._format_size(int(document.get("size_bytes", 0) or 0)))
            size_item.setFlags(size_item.flags() & ~Qt.ItemIsEditable)
            self.fetch_documents_table.setItem(row, 2, size_item)

            date_item = QTableWidgetItem(document.get("updated_at") or document.get("created_at") or "-")
            date_item.setFlags(date_item.flags() & ~Qt.ItemIsEditable)
            self.fetch_documents_table.setItem(row, 3, date_item)

            version_item = QTableWidgetItem(self._format_version(document.get("version")))
            version_item.setFlags(version_item.flags() & ~Qt.ItemIsEditable)
            self.fetch_documents_table.setItem(row, 4, version_item)

        self._update_selection_summaries()

    def _add_conflict_row(self, conflict: ConflictEntry):
        row = self.conflict_table.rowCount()
        self.conflict_table.insertRow(row)
        self._set_checkbox_widget(self.conflict_table, row, conflict.selected)

        addr_item = QTableWidgetItem(f"0x{conflict.address:x}")
        addr_item.setData(Qt.UserRole, conflict.address)
        addr_item.setData(Qt.UserRole + 1, conflict)
        addr_item.setFlags(addr_item.flags() & ~Qt.ItemIsEditable)
        self.conflict_table.setItem(row, 1, addr_item)

        storage_item = QTableWidgetItem(self._format_storage_info(conflict.remote_symbol))
        storage_item.setFlags(storage_item.flags() & ~Qt.ItemIsEditable)
        self.conflict_table.setItem(row, 2, storage_item)

        local_item = QTableWidgetItem(conflict.local_name or "<none>")
        local_item.setFlags(local_item.flags() & ~Qt.ItemIsEditable)
        self.conflict_table.setItem(row, 3, local_item)

        remote_item = QTableWidgetItem(conflict.remote_name or "<none>")
        remote_item.setFlags(remote_item.flags() & ~Qt.ItemIsEditable)
        self.conflict_table.setItem(row, 4, remote_item)

        action_item = QTableWidgetItem(conflict.action.value.upper())
        action_item.setFlags(action_item.flags() & ~Qt.ItemIsEditable)
        if conflict.action == ConflictAction.CONFLICT:
            action_item.setForeground(Qt.red)
        elif conflict.action == ConflictAction.NEW:
            action_item.setForeground(Qt.darkGreen)
        else:
            action_item.setForeground(Qt.darkGray)
        self.conflict_table.setItem(row, 5, action_item)

    def get_pull_config(self) -> Dict[str, Any]:
        symbol_types = []
        if self.pull_functions_cb.isChecked():
            symbol_types.append("function")
        if self.pull_variables_cb.isChecked():
            symbol_types.append("variable")
        if self.pull_types_cb.isChecked():
            symbol_types.append("type")
        if self.pull_comments_cb.isChecked():
            symbol_types.append("comment")
        return {
            "symbol_types": symbol_types,
            "min_confidence": self.confidence_slider.value() / 100.0,
            "include_graph": self.pull_graph_cb.isChecked(),
            "version": self.fetch_version_combo.currentData(),
            "name_filter": self.fetch_name_filter.text().strip(),
        }

    def get_graph_merge_policy(self) -> str:
        return self._merge_policy

    def has_graph_preview(self) -> bool:
        return self._graph_preview is not None

    def get_graph_preview(self):
        return self._graph_preview

    def clear_conflicts(self):
        self.conflict_table.setRowCount(0)
        self.fetch_documents_table.setRowCount(0)
        self._graph_preview = None
        self._graph_stats = None
        self._pull_preview_documents = []
        self.summary_new_count.setText("New: 0")
        self.summary_conflict_count.setText("Conflicts: 0")
        self.summary_same_count.setText("Same: 0")
        self.summary_selected_count.setText("Selected: 0")
        self.summary_document_count.setText("Documents: 0")
        self.clear_graph_preview_data()
        self.set_pull_status("", None)
        self.fetch_progress_bar.setVisible(False)
        self.fetch_progress_label.setVisible(False)

    def get_all_new_conflicts(self) -> List[ConflictEntry]:
        results = []
        for row in range(self.conflict_table.rowCount()):
            item = self.conflict_table.item(row, 1)
            conflict = item.data(Qt.UserRole + 1) if item else None
            if conflict and conflict.action == ConflictAction.NEW:
                results.append(conflict)
        return results

    def get_selected_conflicts(self) -> List[ConflictEntry]:
        selected = []
        for row in self._iter_checked_rows(self.conflict_table):
            item = self.conflict_table.item(row, 1)
            conflict = item.data(Qt.UserRole + 1) if item else None
            if conflict:
                selected.append(conflict)
        return selected

    def get_selected_addresses(self) -> List[int]:
        return [conflict.address for conflict in self.get_selected_conflicts()]

    def get_selected_fetch_documents(self) -> List[Dict[str, Any]]:
        selected = []
        for row in self._iter_checked_rows(self.fetch_documents_table):
            item = self.fetch_documents_table.item(row, 1)
            document = item.data(Qt.UserRole + 1) if item else None
            if document:
                selected.append(document)
        return selected

    def show_applying_page(self, message: str = "Applying symbols..."):
        self.fetch_progress_bar.setValue(0)
        self.fetch_progress_bar.setVisible(True)
        self.fetch_progress_label.setText(message)
        self.fetch_progress_label.setVisible(True)

    def update_apply_progress(self, current: int, total: int, message: str = None):
        percentage = int((current / total) * 100) if total > 0 else 0
        self.fetch_progress_bar.setValue(percentage)
        self.fetch_progress_bar.setVisible(True)
        if message:
            self.fetch_progress_label.setText(message)
            self.fetch_progress_label.setVisible(True)

    def show_complete_page(self, applied: int, errors: int = 0):
        if errors > 0:
            self.set_pull_status(f"Applied {applied} symbols ({errors} errors)", success=True)
        else:
            self.set_pull_status(f"Applied {applied} symbols successfully", success=True)
        self.fetch_progress_bar.setVisible(False)
        self.fetch_progress_label.setVisible(False)

    def set_buttons_enabled(self, enabled: bool):
        for button in (
            self.query_button,
            self.open_binary_button,
            self.pull_preview_button,
            self.apply_button,
            self.apply_all_new_button,
            self.push_preview_button,
            self.push_button,
            self.select_all_button,
            self.deselect_all_button,
            self.select_new_button,
            self.select_conflicts_button,
            self.invert_selection_button,
            self.push_select_all_button,
            self.push_deselect_all_button,
            self.push_invert_selection_button,
        ):
            button.setEnabled(enabled if button is not self.open_binary_button else enabled and bool(self._open_binary_url))

    def set_apply_button_text(self, text: str):
        self.apply_button.setText(text)

    def set_pull_button_text(self, text: str):
        self.pull_preview_button.setText(text)

    def get_push_config(self) -> Dict[str, Any]:
        symbol_types = []
        if self.push_functions_cb.isChecked():
            symbol_types.append("function")
        if self.push_variables_cb.isChecked():
            symbol_types.append("variable")
        if self.push_types_cb.isChecked():
            symbol_types.append("type")
        if self.push_comments_cb.isChecked():
            symbol_types.append("comment")
        return {
            "scope": PushScope.FULL_BINARY.value if self.full_binary_radio.isChecked() else PushScope.CURRENT_FUNCTION.value,
            "symbol_types": symbol_types,
            "name_filter": self.push_name_filter.text().strip(),
            "push_graph": self.push_graph_check.isChecked(),
            "visibility": self.push_visibility_combo.currentData() or "public",
        }

    def clear_push_preview(self):
        self._push_preview_symbols = []
        self._push_preview_documents = []
        self._push_graph_data = None
        self._push_graph_stats = None
        self.push_preview_table.setRowCount(0)
        self.push_documents_table.setRowCount(0)
        self.push_matching_count.setText("Matching: 0")
        self.push_selected_count.setText("Selected: 0")
        self.push_documents_count.setText("Documents: 0")
        self.push_graph_nodes_label.setText("Graph Nodes: 0")
        self.push_graph_edges_label.setText("Graph Edges: 0")

    def set_push_preview(
        self,
        symbols: List[Dict[str, Any]],
        graph_data=None,
        graph_stats=None,
        documents: Optional[List[Dict[str, Any]]] = None,
    ):
        self.clear_push_preview()
        self._push_preview_symbols = list(symbols)
        self._push_preview_documents = list(documents or [])
        self._push_graph_data = graph_data
        self._push_graph_stats = graph_stats or {}
        selected_count = len(symbols)

        self.push_matching_count.setText(f"Matching: {len(symbols)}")
        self.push_documents_count.setText(f"Documents: {len(self._push_preview_documents)}")
        self.push_graph_nodes_label.setText(f"Graph Nodes: {self._push_graph_stats.get('nodes', 0):,}")
        self.push_graph_edges_label.setText(f"Graph Edges: {self._push_graph_stats.get('edges', 0):,}")

        for index, symbol in enumerate(symbols):
            row = self.push_preview_table.rowCount()
            self.push_preview_table.insertRow(row)
            self._set_checkbox_widget(self.push_preview_table, row, True)

            address = int(symbol.get("address", 0))
            name = symbol.get("name") or symbol.get("content") or "<unnamed>"
            symbol_type = symbol.get("symbol_type", "function")
            confidence = float(symbol.get("confidence", 0.0))
            provenance = symbol.get("provenance", "unknown")

            addr_item = QTableWidgetItem(f"0x{address:x}")
            addr_item.setData(Qt.UserRole + 1, symbol)
            addr_item.setFlags(addr_item.flags() & ~Qt.ItemIsEditable)
            self.push_preview_table.setItem(row, 1, addr_item)

            type_item = QTableWidgetItem(symbol_type)
            type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
            self.push_preview_table.setItem(row, 2, type_item)

            name_item = QTableWidgetItem(name)
            name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
            self.push_preview_table.setItem(row, 3, name_item)

            confidence_item = QTableWidgetItem(f"{confidence:.2f}")
            confidence_item.setFlags(confidence_item.flags() & ~Qt.ItemIsEditable)
            self.push_preview_table.setItem(row, 4, confidence_item)

            provenance_item = QTableWidgetItem(provenance)
            provenance_item.setFlags(provenance_item.flags() & ~Qt.ItemIsEditable)
            self.push_preview_table.setItem(row, 5, provenance_item)

        self.push_selected_count.setText(f"Selected: {selected_count}")

        for document in self._push_preview_documents:
            row = self.push_documents_table.rowCount()
            self.push_documents_table.insertRow(row)
            self._set_checkbox_widget(self.push_documents_table, row, True)

            title_item = QTableWidgetItem(document.get("title", "Untitled Document"))
            title_item.setData(Qt.UserRole + 1, document)
            title_item.setFlags(title_item.flags() & ~Qt.ItemIsEditable)
            self.push_documents_table.setItem(row, 1, title_item)

            size_item = QTableWidgetItem(self._format_size(int(document.get("size_bytes", 0) or 0)))
            size_item.setFlags(size_item.flags() & ~Qt.ItemIsEditable)
            self.push_documents_table.setItem(row, 2, size_item)

            date_item = QTableWidgetItem(document.get("updated_at") or document.get("created_at") or "-")
            date_item.setFlags(date_item.flags() & ~Qt.ItemIsEditable)
            self.push_documents_table.setItem(row, 3, date_item)

            version_item = QTableWidgetItem(self._format_version(document.get("version")))
            version_item.setFlags(version_item.flags() & ~Qt.ItemIsEditable)
            self.push_documents_table.setItem(row, 4, version_item)

            type_combo = QComboBox()
            for label, value in self.DOCUMENT_TYPE_OPTIONS:
                type_combo.addItem(label, value)
            current_type = document.get("doc_type") or "notes"
            if current_type == "protocol_spec":
                current_type = "api_doc"
            combo_index = type_combo.findData(current_type)
            type_combo.setCurrentIndex(combo_index if combo_index >= 0 else 0)
            self.push_documents_table.setCellWidget(row, 5, type_combo)

        self._update_selection_summaries()

    def get_selected_push_symbols(self) -> List[Dict[str, Any]]:
        selected = []
        for row in self._iter_checked_rows(self.push_preview_table):
            item = self.push_preview_table.item(row, 1)
            symbol = item.data(Qt.UserRole + 1) if item else None
            if symbol:
                selected.append(symbol)
        return selected

    def get_selected_push_documents(self) -> List[Dict[str, Any]]:
        selected = []
        for row in self._iter_checked_rows(self.push_documents_table):
            item = self.push_documents_table.item(row, 1)
            document = dict(item.data(Qt.UserRole + 1)) if item else None
            if not document:
                continue
            widget = self.push_documents_table.cellWidget(row, 5)
            if isinstance(widget, QComboBox):
                document["doc_type"] = widget.currentData() or widget.currentText()
            selected.append(document)
        return selected

    def get_push_graph_data(self):
        return self._push_graph_data

    def show_push_progress(self, message: str = "Preparing push..."):
        self.push_progress_bar.setValue(0)
        self.push_progress_bar.setVisible(True)
        self.push_progress_label.setText(message)
        self.push_progress_label.setVisible(True)

    def update_push_progress(self, current: int, total: int, message: str = None):
        percentage = int((current / total) * 100) if total > 0 else 0
        self.push_progress_bar.setValue(percentage)
        self.push_progress_bar.setVisible(True)
        if message:
            self.push_progress_label.setText(message)
            self.push_progress_label.setVisible(True)

    def hide_push_progress(self):
        self.push_progress_bar.setVisible(False)
        self.push_progress_label.setVisible(False)

    def on_apply_clicked(self):
        selected = self.get_selected_addresses()
        selected_documents = self.get_selected_fetch_documents()
        if selected or selected_documents or self._graph_preview:
            self.apply_selected_requested.emit(selected)
        else:
            self.set_pull_status("No items selected", success=False)

    def on_select_all(self):
        self._set_all_rows(self.conflict_table, True)

    def on_deselect_all(self):
        self._set_all_rows(self.conflict_table, False)

    def on_select_new(self):
        self._set_all_rows(self.conflict_table, False)
        self._set_all_rows(self.conflict_table, True, ConflictAction.NEW)

    def on_select_conflicts(self):
        self._set_all_rows(self.conflict_table, False)
        self._set_all_rows(self.conflict_table, True, ConflictAction.CONFLICT)

    def on_invert_selection(self):
        for row in range(self.conflict_table.rowCount()):
            widget = self.conflict_table.cellWidget(row, 0)
            checkbox = widget.findChild(QCheckBox) if widget else None
            if checkbox:
                checkbox.setChecked(not checkbox.isChecked())
        self._update_selection_summaries()

    def on_push_select_all(self):
        self._set_all_rows(self.push_preview_table, True)
        self._set_all_rows(self.push_documents_table, True)

    def on_push_deselect_all(self):
        self._set_all_rows(self.push_preview_table, False)
        self._set_all_rows(self.push_documents_table, False)

    def on_push_invert_selection(self):
        for row in range(self.push_preview_table.rowCount()):
            widget = self.push_preview_table.cellWidget(row, 0)
            checkbox = widget.findChild(QCheckBox) if widget else None
            if checkbox:
                checkbox.setChecked(not checkbox.isChecked())
        for row in range(self.push_documents_table.rowCount()):
            widget = self.push_documents_table.cellWidget(row, 0)
            checkbox = widget.findChild(QCheckBox) if widget else None
            if checkbox:
                checkbox.setChecked(not checkbox.isChecked())
        self._update_selection_summaries()
