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
    QToolButton,
    QVBoxLayout,
    QWidget,
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
    upload_binary_requested = Signal()
    auto_refresh_changed = Signal(bool)
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
        self._all_conflicts: List[ConflictEntry] = []
        self._conflict_selection_state: Dict[Any, bool] = {}
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
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self._create_overview_section(layout)

        self.workflow_tabs = QTabWidget()
        self.workflow_tabs.addTab(self._create_fetch_tab(), "Import From SymGraph")
        self.workflow_tabs.addTab(self._create_push_tab(), "Publish To SymGraph")
        layout.addWidget(self.workflow_tabs, 1)

        self.setLayout(layout)

    def _create_overview_section(self, parent_layout):
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(8)

        local_frame = QFrame()
        local_frame.setFrameStyle(QFrame.Box | QFrame.Sunken)
        local_layout = QVBoxLayout(local_frame)
        local_layout.setContentsMargins(10, 10, 10, 10)
        local_layout.setSpacing(8)

        local_header = QHBoxLayout()
        local_header.addWidget(QLabel("Local Status"))
        local_header.addStretch()
        local_layout.addLayout(local_header)

        identity_grid = QGridLayout()
        identity_grid.setHorizontalSpacing(10)
        identity_grid.setVerticalSpacing(4)
        identity_grid.addWidget(QLabel("Binary"), 0, 0)
        self.binary_name_label = QLabel("<no binary loaded>")
        self.binary_name_label.setStyleSheet("font-weight: 600;")
        identity_grid.addWidget(self.binary_name_label, 0, 1)
        identity_grid.addWidget(QLabel("SHA256"), 1, 0)
        self.sha256_label = QLabel("<none>")
        self.sha256_label.setStyleSheet("font-family: monospace; font-size: 11px;")
        identity_grid.addWidget(self.sha256_label, 1, 1)
        local_layout.addLayout(identity_grid)

        self.local_summary_label = QLabel("No binary loaded")
        self.local_summary_label.setProperty("role", "muted")
        self.local_summary_label.setStyleSheet("color: palette(mid);")
        local_layout.addWidget(self.local_summary_label)

        remote_frame = QFrame()
        remote_frame.setFrameStyle(QFrame.Box | QFrame.Sunken)
        remote_layout = QVBoxLayout(remote_frame)
        remote_layout.setContentsMargins(10, 10, 10, 10)
        remote_layout.setSpacing(8)

        remote_header = QHBoxLayout()
        remote_header.addWidget(QLabel("Remote Status"))
        self.status_badge = QLabel("Not checked")
        self.status_badge.setStyleSheet("padding: 2px 8px; background: palette(midlight); color: palette(text);")
        remote_header.addWidget(self.status_badge)
        remote_header.addStretch()
        self.auto_refresh_checkbox = QCheckBox("Auto-refresh")
        self.auto_refresh_checkbox.setChecked(False)
        self.auto_refresh_checkbox.toggled.connect(self.auto_refresh_changed.emit)
        remote_header.addWidget(self.auto_refresh_checkbox)
        self.query_button = QPushButton("Refresh")
        self.query_button.clicked.connect(self.query_requested.emit)
        remote_header.addWidget(self.query_button)
        self.upload_binary_button = QPushButton("Upload Binary")
        self.upload_binary_button.clicked.connect(self.upload_binary_requested.emit)
        remote_header.addWidget(self.upload_binary_button)
        self.open_binary_button = QPushButton("Open in SymGraph")
        self.open_binary_button.setEnabled(False)
        self.open_binary_button.clicked.connect(self.open_binary_requested.emit)
        remote_header.addWidget(self.open_binary_button)
        remote_layout.addLayout(remote_header)

        self.status_label = QLabel("Use Refresh to check whether this binary already exists in SymGraph.")
        self.status_label.setWordWrap(True)
        remote_layout.addWidget(self.status_label)
        self.storage_status_label = QLabel("Stored Binary: Unknown")
        self.storage_status_label.setStyleSheet("color: palette(mid);")

        self.stats_frame = QFrame()
        stats_layout = QGridLayout(self.stats_frame)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setHorizontalSpacing(18)
        stats_layout.setVerticalSpacing(4)
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
        stats_layout.addWidget(self.accessible_versions_stat, 3, 0)
        stats_layout.addWidget(self.storage_status_label, 3, 1)
        self.stats_frame.setVisible(False)
        remote_layout.addWidget(self.stats_frame)

        container_layout.addWidget(local_frame)
        container_layout.addWidget(remote_frame)
        parent_layout.addWidget(container)

    def _create_fetch_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        config_group = QGroupBox("Import Configuration")
        config_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Source Revision:"))
        self.fetch_version_combo = QComboBox()
        self.fetch_version_combo.setMinimumWidth(180)
        row1.addWidget(self.fetch_version_combo)
        row1.addStretch()
        config_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Include:"))
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

        advanced_row = QHBoxLayout()
        self.fetch_advanced_toggle = self._create_disclosure_button("Advanced Filters")
        advanced_row.addWidget(self.fetch_advanced_toggle)
        advanced_row.addStretch()
        config_layout.addLayout(advanced_row)

        self.fetch_advanced_panel = QWidget()
        fetch_advanced_layout = QGridLayout(self.fetch_advanced_panel)
        fetch_advanced_layout.setContentsMargins(0, 0, 0, 0)
        fetch_advanced_layout.setHorizontalSpacing(12)
        fetch_advanced_layout.setVerticalSpacing(6)
        fetch_advanced_layout.addWidget(QLabel("Name Filter:"), 0, 0)
        self.fetch_name_filter = QLineEdit()
        self.fetch_name_filter.setPlaceholderText("Substring match")
        fetch_advanced_layout.addWidget(self.fetch_name_filter, 0, 1)
        fetch_advanced_layout.addWidget(QLabel("Min Confidence:"), 1, 0)
        self.confidence_slider = QSlider(Qt.Horizontal)
        self.confidence_slider.setMinimum(0)
        self.confidence_slider.setMaximum(100)
        self.confidence_slider.setValue(0)
        self.confidence_slider.setFixedWidth(140)
        self.confidence_slider.valueChanged.connect(self._on_confidence_changed)
        fetch_advanced_layout.addWidget(self.confidence_slider, 1, 1)
        self.confidence_value_label = QLabel("0.0")
        self.confidence_value_label.setFixedWidth(30)
        fetch_advanced_layout.addWidget(self.confidence_value_label, 1, 2)
        fetch_advanced_layout.addWidget(QLabel("Graph Merge:"), 2, 0)
        merge_widget, _ = self._create_merge_policy_widget()
        fetch_advanced_layout.addWidget(merge_widget, 2, 1, 1, 2)
        self.fetch_advanced_panel.setVisible(False)
        self.fetch_advanced_toggle.toggled.connect(self.fetch_advanced_panel.setVisible)
        config_layout.addWidget(self.fetch_advanced_panel)

        action_row = QHBoxLayout()
        self.pull_preview_button = QPushButton("Preview Import")
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
        self.summary_selected_count = QLabel("Selected: 0 symbols / 0 docs")
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

        preview_tabs = QTabWidget()

        changes_page = QWidget()
        changes_layout = QVBoxLayout(changes_page)
        changes_layout.setContentsMargins(0, 0, 0, 0)
        changes_layout.setSpacing(8)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Show:"))
        self.filter_new_cb = QCheckBox("New")
        self.filter_new_cb.setChecked(True)
        self.filter_conflicts_cb = QCheckBox("Conflicts")
        self.filter_conflicts_cb.setChecked(True)
        self.filter_same_cb = QCheckBox("Unchanged")
        self.filter_same_cb.setChecked(False)
        for widget in (self.filter_new_cb, self.filter_conflicts_cb, self.filter_same_cb):
            widget.toggled.connect(self._refresh_conflict_table)
            filter_row.addWidget(widget)
        filter_row.addStretch()
        changes_layout.addLayout(filter_row)

        self.conflict_table = QTableWidget()
        self.conflict_table.setColumnCount(6)
        self.conflict_table.setHorizontalHeaderLabels(
            ["Select", "Address", "Type/Storage", "Local Name", "Remote Name", "Status"]
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
        self.conflict_table.setAlternatingRowColors(True)
        changes_layout.addWidget(self.conflict_table)

        footer_row = QHBoxLayout()
        select_row = QHBoxLayout()
        select_row.setContentsMargins(0, 0, 0, 0)
        select_row.setSpacing(6)
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
        footer_row.addLayout(select_row)
        footer_row.addStretch()

        apply_row = QHBoxLayout()
        apply_row.setContentsMargins(0, 0, 0, 0)
        apply_row.setSpacing(6)
        self.apply_all_new_button = QPushButton("Apply Recommended")
        self.apply_all_new_button.clicked.connect(self.apply_all_new_requested.emit)
        apply_row.addWidget(self.apply_all_new_button)
        self.apply_button = QPushButton("Apply Selected")
        self.apply_button.clicked.connect(self.on_apply_clicked)
        apply_row.addWidget(self.apply_button)
        footer_row.addLayout(apply_row)
        changes_layout.addLayout(footer_row)
        preview_tabs.addTab(changes_page, "Changes")

        documents_page = QWidget()
        documents_layout = QVBoxLayout(documents_page)
        documents_layout.setContentsMargins(0, 0, 0, 0)
        documents_layout.setSpacing(8)
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
        self.fetch_documents_table.setAlternatingRowColors(True)
        documents_layout.addWidget(self.fetch_documents_table)
        preview_tabs.addTab(documents_page, "Documents")

        graph_page = QWidget()
        graph_layout = QVBoxLayout(graph_page)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_layout.setSpacing(8)
        self.fetch_graph_summary_label = QLabel("No graph data loaded.")
        self.fetch_graph_summary_label.setWordWrap(True)
        graph_layout.addWidget(self.fetch_graph_summary_label)
        graph_layout.addStretch()
        preview_tabs.addTab(graph_page, "Graph")

        layout.addWidget(preview_tabs, 1)

        self.fetch_progress_bar = QProgressBar()
        self.fetch_progress_bar.setVisible(False)
        layout.addWidget(self.fetch_progress_bar)

        self.fetch_progress_label = QLabel("")
        self.fetch_progress_label.setStyleSheet("color: gray;")
        self.fetch_progress_label.setVisible(False)
        layout.addWidget(self.fetch_progress_label)

        self.pull_status_label = QLabel("")
        self.pull_status_label.setWordWrap(True)
        self.pull_status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.pull_status_label)
        return page

    def _create_push_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        config_group = QGroupBox("Publish Configuration")
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
        row2.addWidget(QLabel("Include:"))
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

        advanced_row = QHBoxLayout()
        self.push_advanced_toggle = self._create_disclosure_button("Advanced Filters")
        advanced_row.addWidget(self.push_advanced_toggle)
        advanced_row.addStretch()
        config_layout.addLayout(advanced_row)

        self.push_advanced_panel = QWidget()
        push_advanced_layout = QGridLayout(self.push_advanced_panel)
        push_advanced_layout.setContentsMargins(0, 0, 0, 0)
        push_advanced_layout.setHorizontalSpacing(12)
        push_advanced_layout.addWidget(QLabel("Name Filter:"), 0, 0)
        self.push_name_filter = QLineEdit()
        self.push_name_filter.setPlaceholderText("Substring match")
        push_advanced_layout.addWidget(self.push_name_filter, 0, 1)
        self.push_advanced_panel.setVisible(False)
        self.push_advanced_toggle.toggled.connect(self.push_advanced_panel.setVisible)
        config_layout.addWidget(self.push_advanced_panel)

        action_row = QHBoxLayout()
        self.push_preview_button = QPushButton("Preview Publish")
        self.push_preview_button.clicked.connect(self.push_preview_requested.emit)
        action_row.addWidget(self.push_preview_button)
        self.push_reset_button = QPushButton("Reset")
        self.push_reset_button.clicked.connect(self.clear_push_preview)
        action_row.addWidget(self.push_reset_button)
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

        push_preview_tabs = QTabWidget()

        push_symbols_page = QWidget()
        push_symbols_layout = QVBoxLayout(push_symbols_page)
        push_symbols_layout.setContentsMargins(0, 0, 0, 0)
        push_symbols_layout.setSpacing(8)
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
        self.push_preview_table.setAlternatingRowColors(True)
        push_symbols_layout.addWidget(self.push_preview_table)

        push_footer_row = QHBoxLayout()
        push_select_row = QHBoxLayout()
        push_select_row.setContentsMargins(0, 0, 0, 0)
        push_select_row.setSpacing(6)
        self.push_select_all_button = QPushButton("Select All")
        self.push_select_all_button.clicked.connect(self.on_push_select_all)
        push_select_row.addWidget(self.push_select_all_button)
        self.push_deselect_all_button = QPushButton("Deselect All")
        self.push_deselect_all_button.clicked.connect(self.on_push_deselect_all)
        push_select_row.addWidget(self.push_deselect_all_button)
        self.push_invert_selection_button = QPushButton("Invert")
        self.push_invert_selection_button.clicked.connect(self.on_push_invert_selection)
        push_select_row.addWidget(self.push_invert_selection_button)
        push_footer_row.addLayout(push_select_row)
        push_footer_row.addStretch()
        push_action_row = QHBoxLayout()
        push_action_row.setContentsMargins(0, 0, 0, 0)
        push_action_row.setSpacing(6)
        self.push_button = QPushButton("Publish Selected")
        self.push_button.clicked.connect(self.push_execute_requested.emit)
        push_action_row.addWidget(self.push_button)
        push_footer_row.addLayout(push_action_row)
        push_symbols_layout.addLayout(push_footer_row)
        push_preview_tabs.addTab(push_symbols_page, "Symbols")

        push_documents_page = QWidget()
        push_documents_layout = QVBoxLayout(push_documents_page)
        push_documents_layout.setContentsMargins(0, 0, 0, 0)
        push_documents_layout.setSpacing(8)
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
        self.push_documents_table.setAlternatingRowColors(True)
        push_documents_layout.addWidget(self.push_documents_table)
        push_preview_tabs.addTab(push_documents_page, "Documents")

        push_graph_page = QWidget()
        push_graph_layout = QVBoxLayout(push_graph_page)
        push_graph_layout.setContentsMargins(0, 0, 0, 0)
        push_graph_layout.setSpacing(8)
        self.push_graph_summary_label = QLabel("No graph data included in this publish preview.")
        self.push_graph_summary_label.setWordWrap(True)
        push_graph_layout.addWidget(self.push_graph_summary_label)
        push_graph_layout.addStretch()
        push_preview_tabs.addTab(push_graph_page, "Graph")

        layout.addWidget(push_preview_tabs, 1)

        self.push_progress_bar = QProgressBar()
        self.push_progress_bar.setVisible(False)
        layout.addWidget(self.push_progress_bar)

        self.push_progress_label = QLabel("")
        self.push_progress_label.setStyleSheet("color: gray;")
        self.push_progress_label.setVisible(False)
        layout.addWidget(self.push_progress_label)

        self.push_status_label = QLabel("Status: Ready")
        self.push_status_label.setWordWrap(True)
        self.push_status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.push_status_label)
        return page

    def _create_disclosure_button(self, label: str) -> QToolButton:
        button = QToolButton()
        button.setText(label)
        button.setCheckable(True)
        button.setChecked(False)
        button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        button.setArrowType(Qt.RightArrow)
        button.toggled.connect(
            lambda checked, target=button: target.setArrowType(Qt.DownArrow if checked else Qt.RightArrow)
        )
        return button

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

    @staticmethod
    def _coerce_address(value: Any) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return 0
            try:
                return int(stripped, 0)
            except ValueError:
                return 0
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def _set_checkbox_widget(self, table: QTableWidget, row: int, checked: bool, on_change=None):
        checkbox = QCheckBox()
        checkbox.setChecked(checked)
        checkbox.stateChanged.connect(self._update_selection_summaries)
        if on_change is not None:
            checkbox.stateChanged.connect(on_change)
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

    @staticmethod
    def _conflict_key(conflict: ConflictEntry):
        remote_name = conflict.remote_name or ""
        local_name = conflict.local_name or ""
        return (conflict.address, conflict.action.value, remote_name, local_name)

    def _on_conflict_checkbox_changed(self, key, state: int):
        self._conflict_selection_state[key] = state == Qt.Checked

    def _filtered_conflicts(self) -> List[ConflictEntry]:
        allowed_actions = set()
        if self.filter_new_cb.isChecked():
            allowed_actions.add(ConflictAction.NEW)
        if self.filter_conflicts_cb.isChecked():
            allowed_actions.add(ConflictAction.CONFLICT)
        if self.filter_same_cb.isChecked():
            allowed_actions.add(ConflictAction.SAME)
        return [conflict for conflict in self._all_conflicts if conflict.action in allowed_actions]

    def _refresh_conflict_table(self):
        if not hasattr(self, "conflict_table"):
            return
        self.conflict_table.setRowCount(0)
        for conflict in self._filtered_conflicts():
            self._add_conflict_row(conflict)
        self.apply_button.setEnabled(
            bool(self._all_conflicts) or self._graph_preview is not None or bool(self._pull_preview_documents)
        )
        self._update_selection_summaries()

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
            self.status_label.setStyleSheet("color: green;")
            self.status_badge.setText("Found")
            self.status_badge.setStyleSheet(
                "padding: 2px 8px; background: #1f6f3d; color: white; font-weight: 600;"
            )
        elif "error" in status.lower() or "not found" in status.lower():
            self.status_label.setStyleSheet("color: red;")
            if "not found" in status.lower():
                self.status_badge.setText("Not Found")
                self.status_badge.setStyleSheet(
                    "padding: 2px 8px; background: #8b2e2e; color: white; font-weight: 600;"
                )
            else:
                self.status_badge.setText("Error")
                self.status_badge.setStyleSheet(
                    "padding: 2px 8px; background: #8b2e2e; color: white; font-weight: 600;"
                )
        else:
            self.status_label.setStyleSheet("color: gray;")
            self.status_badge.setText("Checking" if "check" in status.lower() else "Unknown")
            self.status_badge.setStyleSheet(
                "padding: 2px 8px; background: palette(midlight); color: palette(text);"
            )

    def reset_query_status(self):
        self.status_badge.setText("Not checked")
        self.status_badge.setStyleSheet(
            "padding: 2px 8px; background: palette(midlight); color: palette(text);"
        )
        self.status_label.setText("Use Refresh to check whether this binary already exists in SymGraph.")
        self.status_label.setStyleSheet("color: gray;")

    def set_stats(
        self,
        symbols: int,
        functions: int,
        nodes: int,
        edges: int,
        last_updated: str,
        revisions: Optional[List[BinaryRevision]] = None,
        latest_revision: Optional[int] = None,
        selected_revision: Optional[int] = None,
    ):
        self.symbols_stat.setText(f"Symbols: {symbols:,}")
        self.functions_stat.setText(f"Functions: {functions:,}")
        self.nodes_stat.setText(f"Graph Nodes: {nodes:,}")
        self.edges_stat.setText(f"Graph Edges: {edges:,}")
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

    def set_storage_status(self, stored: Optional[bool]):
        if stored is True:
            self.storage_status_label.setText("Stored Binary: Stored")
            self.storage_status_label.setStyleSheet("color: green;")
        elif stored is False:
            self.storage_status_label.setText("Stored Binary: Missing")
            self.storage_status_label.setStyleSheet("color: red;")
        else:
            self.storage_status_label.setText("Stored Binary: Unknown")
            self.storage_status_label.setStyleSheet("color: palette(mid);")

    def get_open_binary_url(self) -> Optional[str]:
        return self._open_binary_url

    def set_auto_refresh_enabled(self, enabled: bool):
        self.auto_refresh_checkbox.blockSignals(True)
        self.auto_refresh_checkbox.setChecked(enabled)
        self.auto_refresh_checkbox.blockSignals(False)

    def is_auto_refresh_enabled(self) -> bool:
        return self.auto_refresh_checkbox.isChecked()

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
        if graph_export:
            communities = self._graph_stats.get("communities", 0)
            self.fetch_graph_summary_label.setText(
                f"Graph preview ready from {self.summary_graph_version_label.text().replace('Version: ', '')}: "
                f"{nodes:,} nodes, {edges:,} edges"
                + (f", {communities:,} communities" if communities else "")
                + f". Merge policy: {self._merge_policy.replace('_', ' ')}."
            )
        else:
            self.fetch_graph_summary_label.setText("No graph data loaded.")

    def clear_graph_preview_data(self):
        self.set_graph_preview_data(None, {})

    def populate_conflicts(self, conflicts: List[ConflictEntry]):
        self._all_conflicts = sorted(
            conflicts,
            key=lambda item: (
                0 if item.action == ConflictAction.NEW else 1 if item.action == ConflictAction.CONFLICT else 2,
                item.address,
            ),
        )
        self._conflict_selection_state = {}

        new_count = sum(1 for c in conflicts if c.action == ConflictAction.NEW)
        conflict_count = sum(1 for c in conflicts if c.action == ConflictAction.CONFLICT)
        same_count = sum(1 for c in conflicts if c.action == ConflictAction.SAME)
        self.summary_new_count.setText(f"New: {new_count}")
        self.summary_conflict_count.setText(f"Conflicts: {conflict_count}")
        self.summary_same_count.setText(f"Same: {same_count}")

        for conflict in self._all_conflicts:
            conflict.selected = conflict.action != ConflictAction.SAME
            self._conflict_selection_state[self._conflict_key(conflict)] = conflict.selected

        self.apply_all_new_button.setEnabled(new_count > 0 or self._graph_preview is not None)
        self._refresh_conflict_table()

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
        key = self._conflict_key(conflict)
        checked = self._conflict_selection_state.get(key, conflict.action != ConflictAction.SAME)
        self._set_checkbox_widget(
            self.conflict_table,
            row,
            checked,
            on_change=lambda state, conflict_key=key: self._on_conflict_checkbox_changed(conflict_key, state),
        )

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
        self._all_conflicts = []
        self._conflict_selection_state = {}
        self._graph_preview = None
        self._graph_stats = None
        self._pull_preview_documents = []
        self.summary_new_count.setText("New: 0")
        self.summary_conflict_count.setText("Conflicts: 0")
        self.summary_same_count.setText("Same: 0")
        self.summary_selected_count.setText("Selected: 0 symbols / 0 docs")
        self.summary_document_count.setText("Documents: 0")
        self.clear_graph_preview_data()
        self.set_pull_status("", None)
        self.fetch_progress_bar.setVisible(False)
        self.fetch_progress_label.setVisible(False)

    def get_all_new_conflicts(self) -> List[ConflictEntry]:
        return [conflict for conflict in self._all_conflicts if conflict.action == ConflictAction.NEW]

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
            self.upload_binary_button,
            self.open_binary_button,
            self.pull_preview_button,
            self.fetch_reset_button,
            self.apply_button,
            self.apply_all_new_button,
            self.push_preview_button,
            self.push_reset_button,
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
        self.push_graph_summary_label.setText("No graph data included in this publish preview.")
        self.set_push_status("Ready", success=None)

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
        if graph_data:
            self.push_graph_summary_label.setText(
                f"Publish preview includes {self._push_graph_stats.get('nodes', 0):,} graph nodes and "
                f"{self._push_graph_stats.get('edges', 0):,} graph edges."
            )
        else:
            self.push_graph_summary_label.setText("No graph data included in this publish preview.")

        for index, symbol in enumerate(symbols):
            row = self.push_preview_table.rowCount()
            self.push_preview_table.insertRow(row)
            self._set_checkbox_widget(self.push_preview_table, row, True)

            address = self._coerce_address(symbol.get("address", 0))
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
