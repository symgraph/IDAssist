#!/usr/bin/env python3
"""
SymGraph Tab View for IDAssist.

This view provides the UI for querying, pushing, and pulling
symbols and graph data from SymGraph.
"""

from ..qt_compat import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QLabel, QGroupBox, QRadioButton,
    QCheckBox, QButtonGroup, QSplitter, QFrame, QSlider,
    QStackedWidget, QProgressBar, QTabWidget, QComboBox,
    Signal, Qt, QFont
)

from ..services.models.symgraph_models import ConflictAction, ConflictEntry, PushScope


class SymGraphTabView(QWidget):
    """View for SymGraph tab with query, push, and pull sections."""

    # Signals for controller communication
    query_requested = Signal()
    push_requested = Signal(str, bool, bool, str)  # scope, push_symbols, push_graph, visibility
    pull_preview_requested = Signal()
    apply_selected_requested = Signal(list)  # list of selected addresses
    apply_all_new_requested = Signal()  # Apply all NEW items automatically
    select_all_requested = Signal()
    deselect_all_requested = Signal()
    invert_selection_requested = Signal()

    # Wizard page indices
    PAGE_INITIAL = 0
    PAGE_SUMMARY = 1
    PAGE_DETAILS = 2
    PAGE_APPLYING = 3
    PAGE_COMPLETE = 4

    MERGE_POLICY_UPSERT = "upsert"
    MERGE_POLICY_PREFER_LOCAL = "prefer_local"
    MERGE_POLICY_REPLACE = "replace"

    def __init__(self):
        super().__init__()
        self._graph_preview = None
        self._graph_stats = None
        self._merge_policy = self.MERGE_POLICY_UPSERT
        self.setup_ui()

    def setup_ui(self):
        """Set up the main UI layout."""
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Binary info header
        self.create_binary_info_section(layout)

        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Vertical)

        # Top panel - Query and Push sections
        top_panel = QWidget()
        top_layout = QVBoxLayout(top_panel)
        top_layout.setContentsMargins(0, 0, 0, 0)
        self.create_query_section(top_layout)
        self.create_push_section(top_layout)
        splitter.addWidget(top_panel)

        # Bottom panel - Pull section with conflict table
        bottom_panel = self.create_pull_section()
        splitter.addWidget(bottom_panel)

        # Set initial sizes (40% for query/push, 60% for pull)
        splitter.setSizes([400, 600])

        layout.addWidget(splitter)
        self.setLayout(layout)

    def create_binary_info_section(self, parent_layout):
        """Create the binary info header section."""
        info_frame = QFrame()
        info_frame.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(10, 10, 10, 10)

        # Binary name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Binary:"))
        self.binary_name_label = QLabel("<no binary loaded>")
        self.binary_name_label.setStyleSheet("font-weight: bold;")
        name_layout.addWidget(self.binary_name_label)
        name_layout.addStretch()
        info_layout.addLayout(name_layout)

        # SHA256 hash
        hash_layout = QHBoxLayout()
        hash_layout.addWidget(QLabel("SHA256:"))
        self.sha256_label = QLabel("<none>")
        self.sha256_label.setStyleSheet("font-family: monospace; font-size: 11px;")
        hash_layout.addWidget(self.sha256_label)
        hash_layout.addStretch()
        info_layout.addLayout(hash_layout)

        parent_layout.addWidget(info_frame)

    def create_query_section(self, parent_layout):
        """Create the query section for checking SymGraph status."""
        group = QGroupBox("Query Status")
        layout = QVBoxLayout()

        # Query button row
        button_row = QHBoxLayout()
        self.query_button = QPushButton("Check SymGraph")
        self.query_button.clicked.connect(self.query_requested.emit)
        button_row.addWidget(self.query_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        # Status label
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.status_label = QLabel("Not checked")
        self.status_label.setStyleSheet("color: gray;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        layout.addLayout(status_layout)

        # Stats frame (initially hidden)
        self.stats_frame = QFrame()
        self.stats_frame.setFrameStyle(QFrame.Box | QFrame.Sunken)
        stats_layout = QHBoxLayout(self.stats_frame)

        # Left column
        left_col = QVBoxLayout()
        self.symbols_stat = QLabel("Symbols: -")
        self.functions_stat = QLabel("Functions: -")
        left_col.addWidget(self.symbols_stat)
        left_col.addWidget(self.functions_stat)
        stats_layout.addLayout(left_col)

        # Right column
        right_col = QVBoxLayout()
        self.nodes_stat = QLabel("Graph Nodes: -")
        self.updated_stat = QLabel("Last Updated: -")
        right_col.addWidget(self.nodes_stat)
        right_col.addWidget(self.updated_stat)
        stats_layout.addLayout(right_col)

        self.stats_frame.setVisible(False)
        layout.addWidget(self.stats_frame)

        group.setLayout(layout)
        parent_layout.addWidget(group)

    def create_push_section(self, parent_layout):
        """Create the push section for uploading to SymGraph."""
        group = QGroupBox("Push to SymGraph")
        layout = QVBoxLayout()

        # Scope selection
        scope_layout = QHBoxLayout()
        scope_layout.addWidget(QLabel("Scope:"))

        self.scope_group = QButtonGroup(self)
        self.full_binary_radio = QRadioButton("Full Binary")
        self.current_function_radio = QRadioButton("Current Function")
        self.current_function_radio.setChecked(True)

        self.scope_group.addButton(self.full_binary_radio, 1)
        self.scope_group.addButton(self.current_function_radio, 2)

        scope_layout.addWidget(self.full_binary_radio)
        scope_layout.addWidget(self.current_function_radio)
        scope_layout.addStretch()
        layout.addLayout(scope_layout)

        # Data to push checkboxes
        data_layout = QHBoxLayout()
        data_layout.addWidget(QLabel("Data to Push:"))

        self.push_symbols_check = QCheckBox("Symbols (function names, variables, types)")
        self.push_symbols_check.setChecked(True)
        data_layout.addWidget(self.push_symbols_check)

        self.push_graph_check = QCheckBox("Graph (nodes, edges, summaries)")
        self.push_graph_check.setChecked(True)
        data_layout.addWidget(self.push_graph_check)

        data_layout.addStretch()
        layout.addLayout(data_layout)

        visibility_layout = QHBoxLayout()
        visibility_layout.addWidget(QLabel("Visibility:"))

        self.push_visibility_combo = QComboBox()
        self.push_visibility_combo.addItem("Public", "public")
        self.push_visibility_combo.addItem("Private", "private")
        self.push_visibility_combo.setCurrentIndex(0)
        self.push_visibility_combo.setToolTip(
            "Public pushes are available to everyone with access to the binary. "
            "Private pushes may be restricted by your SymGraph tier."
        )
        visibility_layout.addWidget(self.push_visibility_combo)
        visibility_layout.addStretch()
        layout.addLayout(visibility_layout)

        # Push button and status
        push_row = QHBoxLayout()
        self.push_button = QPushButton("Push to SymGraph")
        self.push_button.clicked.connect(self.on_push_clicked)
        push_row.addWidget(self.push_button)

        self.push_status_label = QLabel("Status: Ready")
        self.push_status_label.setStyleSheet("color: gray;")
        push_row.addWidget(self.push_status_label)
        push_row.addStretch()
        layout.addLayout(push_row)

        group.setLayout(layout)
        parent_layout.addWidget(group)

    def create_pull_section(self):
        """Create the pull section with wizard-based merge flow."""
        group = QGroupBox("Pull from SymGraph")
        layout = QVBoxLayout()

        # === Configuration Panel (always visible) ===
        config_layout = QVBoxLayout()

        # Symbol type checkboxes
        type_label = QLabel("Symbol Types:")
        config_layout.addWidget(type_label)

        type_row = QHBoxLayout()
        self.pull_functions_cb = QCheckBox("Functions")
        self.pull_functions_cb.setChecked(True)
        type_row.addWidget(self.pull_functions_cb)

        self.pull_variables_cb = QCheckBox("Variables")
        self.pull_variables_cb.setChecked(True)
        type_row.addWidget(self.pull_variables_cb)

        self.pull_types_cb = QCheckBox("Types")
        self.pull_types_cb.setChecked(True)
        type_row.addWidget(self.pull_types_cb)

        self.pull_comments_cb = QCheckBox("Comments")
        self.pull_comments_cb.setChecked(True)
        type_row.addWidget(self.pull_comments_cb)

        type_row.addStretch()
        config_layout.addLayout(type_row)

        # Options row: Graph checkbox and confidence slider
        options_row = QHBoxLayout()

        self.pull_graph_cb = QCheckBox("Include Graph Data")
        self.pull_graph_cb.setChecked(True)
        self.pull_graph_cb.setToolTip("Download graph nodes and edges for semantic analysis")
        options_row.addWidget(self.pull_graph_cb)

        options_row.addSpacing(20)

        # Confidence slider
        conf_label = QLabel("Min Confidence:")
        options_row.addWidget(conf_label)

        self.confidence_slider = QSlider(Qt.Horizontal)
        self.confidence_slider.setMinimum(0)
        self.confidence_slider.setMaximum(100)
        self.confidence_slider.setValue(0)
        self.confidence_slider.setFixedWidth(100)
        self.confidence_slider.setToolTip("Only show symbols with confidence >= this threshold")
        self.confidence_slider.valueChanged.connect(self._on_confidence_changed)
        options_row.addWidget(self.confidence_slider)

        self.confidence_value_label = QLabel("0.0")
        self.confidence_value_label.setFixedWidth(30)
        options_row.addWidget(self.confidence_value_label)

        options_row.addStretch()
        config_layout.addLayout(options_row)

        layout.addLayout(config_layout)

        # === Wizard Stacked Widget ===
        self.wizard_stack = QStackedWidget()

        # Page 0: Initial (Fetch Preview button)
        self.wizard_stack.addWidget(self._create_initial_page())

        # Page 1: Summary (counts in cards)
        self.wizard_stack.addWidget(self._create_summary_page())

        # Page 2: Details (conflict table)
        self.wizard_stack.addWidget(self._create_details_page())

        # Page 3: Applying (progress bar)
        self.wizard_stack.addWidget(self._create_applying_page())

        # Page 4: Complete (success message)
        self.wizard_stack.addWidget(self._create_complete_page())

        layout.addWidget(self.wizard_stack)

        # Status label (always visible at bottom)
        self.pull_status_label = QLabel("")
        layout.addWidget(self.pull_status_label)

        group.setLayout(layout)
        return group

    def _create_initial_page(self):
        """Create the initial page with Fetch Preview button."""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        button_row = QHBoxLayout()
        self.pull_preview_button = QPushButton("Fetch Preview")
        self.pull_preview_button.clicked.connect(self.pull_preview_requested.emit)
        button_row.addWidget(self.pull_preview_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        layout.addStretch()
        page.setLayout(layout)
        return page

    def _create_merge_policy_widget(self):
        """Create merge policy selection widget."""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        label = QLabel("Graph Merge Policy:")
        label.setStyleSheet("font-weight: bold;")
        layout.addWidget(label)

        group = QButtonGroup()
        upsert_btn = QRadioButton("Upsert (merge and overwrite)")
        prefer_btn = QRadioButton("Prefer Local (skip existing)")
        replace_btn = QRadioButton("Replace (clear graph tables)")

        upsert_btn.setProperty("merge_policy", self.MERGE_POLICY_UPSERT)
        prefer_btn.setProperty("merge_policy", self.MERGE_POLICY_PREFER_LOCAL)
        replace_btn.setProperty("merge_policy", self.MERGE_POLICY_REPLACE)

        group.addButton(upsert_btn)
        group.addButton(prefer_btn)
        group.addButton(replace_btn)

        layout.addWidget(upsert_btn)
        layout.addWidget(prefer_btn)
        layout.addWidget(replace_btn)

        upsert_btn.setChecked(True)
        group.buttonClicked.connect(lambda _: self._on_merge_policy_changed(group))

        widget.setLayout(layout)
        return widget, group

    def _create_summary_page(self):
        """Create the summary page showing counts in card-style boxes."""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 10, 0, 0)

        # Summary cards row
        cards_row = QHBoxLayout()

        # NEW card (green)
        new_card = QFrame()
        new_card.setFrameStyle(QFrame.Box | QFrame.Raised)
        new_card.setStyleSheet("QFrame { background-color: #e8f5e9; border: 1px solid #81c784; border-radius: 4px; }")
        new_layout = QVBoxLayout()
        new_layout.setContentsMargins(10, 10, 10, 10)
        new_title = QLabel("NEW")
        new_title.setStyleSheet("color: #2e7d32; font-weight: bold;")
        new_title.setAlignment(Qt.AlignCenter)
        self.summary_new_count = QLabel("0")
        self.summary_new_count.setFont(QFont("", 24, QFont.Bold))
        self.summary_new_count.setStyleSheet("color: #2e7d32;")
        self.summary_new_count.setAlignment(Qt.AlignCenter)
        new_subtitle = QLabel("(safe)")
        new_subtitle.setStyleSheet("color: #66bb6a;")
        new_subtitle.setAlignment(Qt.AlignCenter)
        new_layout.addWidget(new_title)
        new_layout.addWidget(self.summary_new_count)
        new_layout.addWidget(new_subtitle)
        new_card.setLayout(new_layout)
        cards_row.addWidget(new_card)

        # CONFLICTS card (orange)
        conflict_card = QFrame()
        conflict_card.setFrameStyle(QFrame.Box | QFrame.Raised)
        conflict_card.setStyleSheet("QFrame { background-color: #fff3e0; border: 1px solid #ffb74d; border-radius: 4px; }")
        conflict_layout = QVBoxLayout()
        conflict_layout.setContentsMargins(10, 10, 10, 10)
        conflict_title = QLabel("CONFLICTS")
        conflict_title.setStyleSheet("color: #e65100; font-weight: bold;")
        conflict_title.setAlignment(Qt.AlignCenter)
        self.summary_conflict_count = QLabel("0")
        self.summary_conflict_count.setFont(QFont("", 24, QFont.Bold))
        self.summary_conflict_count.setStyleSheet("color: #e65100;")
        self.summary_conflict_count.setAlignment(Qt.AlignCenter)
        conflict_subtitle = QLabel("(review)")
        conflict_subtitle.setStyleSheet("color: #ffa726;")
        conflict_subtitle.setAlignment(Qt.AlignCenter)
        conflict_layout.addWidget(conflict_title)
        conflict_layout.addWidget(self.summary_conflict_count)
        conflict_layout.addWidget(conflict_subtitle)
        conflict_card.setLayout(conflict_layout)
        cards_row.addWidget(conflict_card)

        # SAME card (gray)
        same_card = QFrame()
        same_card.setFrameStyle(QFrame.Box | QFrame.Raised)
        same_card.setStyleSheet("QFrame { background-color: #f5f5f5; border: 1px solid #bdbdbd; border-radius: 4px; }")
        same_layout = QVBoxLayout()
        same_layout.setContentsMargins(10, 10, 10, 10)
        same_title = QLabel("UNCHANGED")
        same_title.setStyleSheet("color: #616161; font-weight: bold;")
        same_title.setAlignment(Qt.AlignCenter)
        self.summary_same_count = QLabel("0")
        self.summary_same_count.setFont(QFont("", 24, QFont.Bold))
        self.summary_same_count.setStyleSheet("color: #616161;")
        self.summary_same_count.setAlignment(Qt.AlignCenter)
        same_subtitle = QLabel("(skip)")
        same_subtitle.setStyleSheet("color: #9e9e9e;")
        same_subtitle.setAlignment(Qt.AlignCenter)
        same_layout.addWidget(same_title)
        same_layout.addWidget(self.summary_same_count)
        same_layout.addWidget(same_subtitle)
        same_card.setLayout(same_layout)
        cards_row.addWidget(same_card)

        layout.addLayout(cards_row)

        # Graph info box
        self.summary_graph_box = QGroupBox("Graph Data")
        graph_layout = QVBoxLayout()

        self.summary_graph_label = QLabel("No graph data selected")
        self.summary_graph_label.setStyleSheet("color: #666; font-style: italic;")
        self.summary_graph_label.setAlignment(Qt.AlignCenter)
        graph_layout.addWidget(self.summary_graph_label)

        stats_row = QHBoxLayout()
        self.summary_graph_nodes_label = QLabel("Nodes: 0")
        self.summary_graph_edges_label = QLabel("Edges: 0")
        self.summary_graph_communities_label = QLabel("Communities: 0")
        stats_row.addWidget(self.summary_graph_nodes_label)
        stats_row.addWidget(self.summary_graph_edges_label)
        stats_row.addWidget(self.summary_graph_communities_label)
        stats_row.addStretch()
        graph_layout.addLayout(stats_row)

        merge_widget, merge_group = self._create_merge_policy_widget()
        self.summary_merge_group = merge_group
        graph_layout.addWidget(merge_widget)

        self.summary_graph_box.setLayout(graph_layout)
        layout.addWidget(self.summary_graph_box)

        layout.addSpacing(10)

        # Action buttons
        button_row = QHBoxLayout()

        self.apply_all_new_button = QPushButton("Apply All New")
        self.apply_all_new_button.setStyleSheet("QPushButton { background-color: #4caf50; color: white; font-weight: bold; padding: 8px 16px; }")
        self.apply_all_new_button.clicked.connect(self._on_apply_all_new_clicked)
        button_row.addWidget(self.apply_all_new_button)

        self.review_conflicts_button = QPushButton("Review Conflicts")
        self.review_conflicts_button.clicked.connect(lambda: self.wizard_stack.setCurrentIndex(self.PAGE_DETAILS))
        button_row.addWidget(self.review_conflicts_button)

        self.show_all_button = QPushButton("Show All Details")
        self.show_all_button.clicked.connect(lambda: self.wizard_stack.setCurrentIndex(self.PAGE_DETAILS))
        button_row.addWidget(self.show_all_button)

        button_row.addStretch()

        self.summary_back_button = QPushButton("Back")
        self.summary_back_button.clicked.connect(self._reset_wizard)
        button_row.addWidget(self.summary_back_button)

        layout.addLayout(button_row)

        layout.addStretch()
        page.setLayout(layout)
        return page

    def _create_details_page(self):
        """Create the details page with symbol and graph tabs."""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        self.details_tabs = QTabWidget()

        # Symbols tab
        symbols_tab = QWidget()
        symbols_layout = QVBoxLayout()

        self.conflict_table = QTableWidget()
        self.conflict_table.setColumnCount(6)
        self.conflict_table.setHorizontalHeaderLabels([
            "Select", "Address", "Type/Storage", "Local Name", "Remote Name", "Action"
        ])
        self.conflict_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.conflict_table.setSelectionMode(QAbstractItemView.ExtendedSelection)

        header = self.conflict_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Fixed)

        self.conflict_table.setColumnWidth(0, 50)
        self.conflict_table.setColumnWidth(1, 100)
        self.conflict_table.setColumnWidth(2, 120)
        self.conflict_table.setColumnWidth(5, 80)

        symbols_layout.addWidget(self.conflict_table)

        selection_row = QHBoxLayout()
        self.select_all_button = QPushButton("Select All")
        self.select_all_button.clicked.connect(self.on_select_all)
        selection_row.addWidget(self.select_all_button)

        self.deselect_all_button = QPushButton("Deselect All")
        self.deselect_all_button.clicked.connect(self.on_deselect_all)
        selection_row.addWidget(self.deselect_all_button)

        self.invert_selection_button = QPushButton("Invert Selection")
        self.invert_selection_button.clicked.connect(self.on_invert_selection)
        selection_row.addWidget(self.invert_selection_button)

        selection_row.addStretch()
        symbols_layout.addLayout(selection_row)
        symbols_tab.setLayout(symbols_layout)

        # Graph tab
        graph_tab = QWidget()
        graph_layout = QVBoxLayout()

        self.details_graph_label = QLabel("No graph data available")
        self.details_graph_label.setStyleSheet("color: #666; font-style: italic;")
        graph_layout.addWidget(self.details_graph_label)

        stats_row = QHBoxLayout()
        self.details_graph_nodes_label = QLabel("Nodes: 0")
        self.details_graph_edges_label = QLabel("Edges: 0")
        self.details_graph_communities_label = QLabel("Communities: 0")
        stats_row.addWidget(self.details_graph_nodes_label)
        stats_row.addWidget(self.details_graph_edges_label)
        stats_row.addWidget(self.details_graph_communities_label)
        stats_row.addStretch()
        graph_layout.addLayout(stats_row)

        self.details_graph_policy_label = QLabel("Selected policy: Upsert")
        self.details_graph_policy_label.setStyleSheet("color: #444;")
        graph_layout.addWidget(self.details_graph_policy_label)

        merge_widget, merge_group = self._create_merge_policy_widget()
        self.details_merge_group = merge_group
        graph_layout.addWidget(merge_widget)
        graph_layout.addStretch()
        graph_tab.setLayout(graph_layout)

        self.details_tabs.addTab(symbols_tab, "Symbols")
        self.details_tabs.addTab(graph_tab, "Graph")

        layout.addWidget(self.details_tabs)

        # Action buttons
        action_row = QHBoxLayout()
        self.apply_button = QPushButton("Apply Selected")
        self.apply_button.clicked.connect(self.on_apply_clicked)
        action_row.addWidget(self.apply_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self._reset_wizard)
        action_row.addWidget(self.cancel_button)

        action_row.addStretch()

        self.back_to_summary_button = QPushButton("Back to Summary")
        self.back_to_summary_button.clicked.connect(lambda: self.wizard_stack.setCurrentIndex(self.PAGE_SUMMARY))
        action_row.addWidget(self.back_to_summary_button)

        layout.addLayout(action_row)

        page.setLayout(layout)
        return page

    def _on_merge_policy_changed(self, group: QButtonGroup):
        button = group.checkedButton()
        if not button:
            return
        policy = button.property("merge_policy")
        if not policy:
            return
        self._merge_policy = policy
        self._sync_merge_policy_groups()
        self._update_merge_policy_labels()

    def _sync_merge_policy_groups(self):
        for group in (getattr(self, "summary_merge_group", None), getattr(self, "details_merge_group", None)):
            if not group:
                continue
            blocked = group.blockSignals(True)
            for btn in group.buttons():
                if btn.property("merge_policy") == self._merge_policy:
                    btn.setChecked(True)
            group.blockSignals(blocked)

    def _update_merge_policy_labels(self):
        label_map = {
            self.MERGE_POLICY_UPSERT: "Upsert",
            self.MERGE_POLICY_PREFER_LOCAL: "Prefer Local",
            self.MERGE_POLICY_REPLACE: "Replace",
        }
        label = label_map.get(self._merge_policy, "Upsert")
        if hasattr(self, "details_graph_policy_label"):
            self.details_graph_policy_label.setText(f"Selected policy: {label}")

    def get_graph_merge_policy(self) -> str:
        return self._merge_policy

    def _create_applying_page(self):
        """Create the applying page with progress bar."""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 20, 0, 0)

        layout.addStretch()

        self.apply_progress_bar = QProgressBar()
        self.apply_progress_bar.setMinimum(0)
        self.apply_progress_bar.setMaximum(100)
        layout.addWidget(self.apply_progress_bar)

        self.apply_progress_label = QLabel("Applying symbols...")
        self.apply_progress_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.apply_progress_label)

        layout.addStretch()

        cancel_row = QHBoxLayout()
        cancel_row.addStretch()
        self.apply_cancel_button = QPushButton("Cancel")
        self.apply_cancel_button.clicked.connect(self._reset_wizard)
        cancel_row.addWidget(self.apply_cancel_button)
        cancel_row.addStretch()
        layout.addLayout(cancel_row)

        page.setLayout(layout)
        return page

    def _create_complete_page(self):
        """Create the complete page with success message."""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 20, 0, 0)

        layout.addStretch()

        self.complete_icon = QLabel("Done!")
        self.complete_icon.setFont(QFont("", 18, QFont.Bold))
        self.complete_icon.setStyleSheet("color: #4caf50;")
        self.complete_icon.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.complete_icon)

        self.complete_message = QLabel("")
        self.complete_message.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.complete_message)

        layout.addStretch()

        done_row = QHBoxLayout()
        done_row.addStretch()
        self.done_button = QPushButton("Done")
        self.done_button.clicked.connect(self._reset_wizard)
        done_row.addWidget(self.done_button)
        done_row.addStretch()
        layout.addLayout(done_row)

        page.setLayout(layout)
        return page

    def _reset_wizard(self):
        """Reset wizard to initial state."""
        self.wizard_stack.setCurrentIndex(self.PAGE_INITIAL)
        self.conflict_table.setRowCount(0)
        self.pull_status_label.setText("")
        self._merge_policy = self.MERGE_POLICY_UPSERT
        self._sync_merge_policy_groups()
        self._update_merge_policy_labels()
        self.clear_graph_preview_data()
        if hasattr(self, "details_tabs"):
            self.details_tabs.setCurrentIndex(0)

    def _on_apply_all_new_clicked(self):
        """Handle Apply All New button click."""
        self.apply_all_new_requested.emit()

    # === Public methods for controller ===

    def set_binary_info(self, name: str, sha256: str):
        """Set the binary information display."""
        self.binary_name_label.setText(name or "<no binary loaded>")
        self.sha256_label.setText(sha256 or "<none>")

    def set_query_status(self, status: str, found: bool = False):
        """Set the query status display."""
        self.status_label.setText(status)
        if found:
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
        elif "error" in status.lower() or "not found" in status.lower():
            self.status_label.setStyleSheet("color: red;")
        else:
            self.status_label.setStyleSheet("color: gray;")

    def set_stats(self, symbols: int, functions: int, nodes: int, last_updated: str):
        """Set the statistics display."""
        self.symbols_stat.setText(f"Symbols: {symbols:,}")
        self.functions_stat.setText(f"Functions: {functions:,}")
        self.nodes_stat.setText(f"Graph Nodes: {nodes:,}")
        self.updated_stat.setText(f"Last Updated: {last_updated or 'Unknown'}")
        self.stats_frame.setVisible(True)

    def hide_stats(self):
        """Hide the statistics display."""
        self.stats_frame.setVisible(False)

    def set_push_status(self, status: str, success: bool = None):
        """Set the push status display."""
        self.push_status_label.setText(f"Status: {status}")
        if success is True:
            self.push_status_label.setStyleSheet("color: green;")
        elif success is False:
            self.push_status_label.setStyleSheet("color: red;")
        else:
            self.push_status_label.setStyleSheet("color: gray;")

    def set_pull_status(self, status: str, success: bool = None):
        """Set the pull status display."""
        self.pull_status_label.setText(status)
        if success is True:
            self.pull_status_label.setStyleSheet("color: green;")
        elif success is False:
            self.pull_status_label.setStyleSheet("color: red;")
        else:
            self.pull_status_label.setStyleSheet("color: gray;")

    def set_graph_preview_data(self, graph_export, graph_stats=None):
        self._graph_preview = graph_export
        self._graph_stats = graph_stats

        if graph_stats:
            nodes = graph_stats.get("nodes", 0)
            edges = graph_stats.get("edges", 0)
            communities = graph_stats.get("communities", 0)
            self.summary_graph_label.setText("Graph data available for merge")
            self.summary_graph_nodes_label.setText(f"Nodes: {nodes:,}")
            self.summary_graph_edges_label.setText(f"Edges: {edges:,}")
            self.summary_graph_communities_label.setText(f"Communities: {communities:,}")
            self.details_graph_label.setText("Graph data available for merge")
            self.details_graph_nodes_label.setText(f"Nodes: {nodes:,}")
            self.details_graph_edges_label.setText(f"Edges: {edges:,}")
            self.details_graph_communities_label.setText(f"Communities: {communities:,}")
        else:
            self.summary_graph_label.setText("No graph data selected")
            self.summary_graph_nodes_label.setText("Nodes: 0")
            self.summary_graph_edges_label.setText("Edges: 0")
            self.summary_graph_communities_label.setText("Communities: 0")
            self.details_graph_label.setText("No graph data available")
            self.details_graph_nodes_label.setText("Nodes: 0")
            self.details_graph_edges_label.setText("Edges: 0")
            self.details_graph_communities_label.setText("Communities: 0")
        self._update_merge_policy_labels()

    def clear_graph_preview_data(self):
        self.set_graph_preview_data(None, None)

    def populate_conflicts(self, conflicts: list):
        """Populate the conflict resolution table and show summary."""
        self.conflict_table.setRowCount(0)

        # Calculate summary counts
        new_count = sum(1 for c in conflicts if c.action == ConflictAction.NEW)
        conflict_count = sum(1 for c in conflicts if c.action == ConflictAction.CONFLICT)
        same_count = sum(1 for c in conflicts if c.action == ConflictAction.SAME)

        # Update summary page
        self.summary_new_count.setText(str(new_count))
        self.summary_conflict_count.setText(str(conflict_count))
        self.summary_same_count.setText(str(same_count))

        # Enable/disable buttons based on counts
        self.apply_all_new_button.setEnabled(new_count > 0 or self._graph_preview is not None)
        self.review_conflicts_button.setEnabled(conflict_count > 0)

        # Sort conflicts: CONFLICT first, then by address
        sorted_conflicts = sorted(
            conflicts,
            key=lambda x: (x.action != ConflictAction.CONFLICT, x.address)
        )

        for conflict in sorted_conflicts:
            self.add_conflict_row(conflict)

        # Show summary page
        self.wizard_stack.setCurrentIndex(self.PAGE_SUMMARY)

    def _format_storage_info(self, symbol) -> str:
        """Format symbol type and storage location for display."""
        if not symbol:
            return ""

        sym_type = getattr(symbol, 'symbol_type', 'function')
        metadata = getattr(symbol, 'metadata', {}) or {}

        if sym_type != 'variable':
            return "func"

        storage_class = metadata.get('storage_class', '')
        scope = metadata.get('scope', '')

        if storage_class == 'parameter':
            idx = metadata.get('parameter_index', '?')
            reg = metadata.get('register')
            if reg:
                return f"param[{idx}] ({reg})"
            return f"param[{idx}]"
        elif storage_class == 'stack':
            offset = metadata.get('stack_offset', 0)
            sign = '+' if offset >= 0 else ''
            return f"local [{sign}0x{abs(offset):x}]"
        elif storage_class == 'register':
            reg = metadata.get('register', '?')
            return f"local ({reg})"
        elif scope == 'local':
            return "local"
        else:
            return "global"

    def add_conflict_row(self, conflict: ConflictEntry):
        """Add a single conflict entry to the table."""
        row = self.conflict_table.rowCount()
        self.conflict_table.insertRow(row)

        # Checkbox for selection
        checkbox = QCheckBox()
        checkbox.setChecked(conflict.selected)
        checkbox_widget = QWidget()
        checkbox_layout = QHBoxLayout(checkbox_widget)
        checkbox_layout.addWidget(checkbox)
        checkbox_layout.setAlignment(Qt.AlignCenter)
        checkbox_layout.setContentsMargins(0, 0, 0, 0)
        self.conflict_table.setCellWidget(row, 0, checkbox_widget)

        # Address
        addr_item = QTableWidgetItem(f"0x{conflict.address:x}")
        addr_item.setFlags(addr_item.flags() & ~Qt.ItemIsEditable)
        addr_item.setData(Qt.UserRole, conflict.address)
        self.conflict_table.setItem(row, 1, addr_item)

        # Type/Storage info
        storage_text = self._format_storage_info(conflict.remote_symbol)
        storage_item = QTableWidgetItem(storage_text)
        storage_item.setFlags(storage_item.flags() & ~Qt.ItemIsEditable)
        self.conflict_table.setItem(row, 2, storage_item)

        # Local Name
        local_item = QTableWidgetItem(conflict.local_name or "<none>")
        local_item.setFlags(local_item.flags() & ~Qt.ItemIsEditable)
        if conflict.local_name is None:
            local_item.setForeground(Qt.gray)
        self.conflict_table.setItem(row, 3, local_item)

        # Remote Name
        remote_item = QTableWidgetItem(conflict.remote_name or "<none>")
        remote_item.setFlags(remote_item.flags() & ~Qt.ItemIsEditable)
        if conflict.remote_name is None:
            remote_item.setForeground(Qt.gray)
        self.conflict_table.setItem(row, 4, remote_item)

        # Action type
        action_item = QTableWidgetItem(conflict.action.value.upper())
        action_item.setFlags(action_item.flags() & ~Qt.ItemIsEditable)

        # Color-code by action type
        if conflict.action == ConflictAction.CONFLICT:
            action_item.setForeground(Qt.red)
        elif conflict.action == ConflictAction.NEW:
            action_item.setForeground(Qt.darkGreen)
        elif conflict.action == ConflictAction.SAME:
            action_item.setForeground(Qt.darkGray)

        self.conflict_table.setItem(row, 5, action_item)

        # Store conflict reference for later retrieval
        addr_item.setData(Qt.UserRole + 1, conflict)

    def get_selected_addresses(self) -> list:
        """Get list of addresses for selected conflict entries."""
        selected = []
        for row in range(self.conflict_table.rowCount()):
            checkbox_widget = self.conflict_table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    addr_item = self.conflict_table.item(row, 1)
                    if addr_item:
                        address = addr_item.data(Qt.UserRole)
                        selected.append(address)
        return selected

    def get_selected_conflicts(self) -> list:
        """Get list of ConflictEntry objects for selected rows."""
        selected = []
        for row in range(self.conflict_table.rowCount()):
            checkbox_widget = self.conflict_table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    addr_item = self.conflict_table.item(row, 1)
                    if addr_item:
                        conflict = addr_item.data(Qt.UserRole + 1)
                        if conflict:
                            selected.append(conflict)
        return selected

    def _on_confidence_changed(self, value: int):
        """Update the confidence label when slider moves."""
        confidence = value / 100.0
        self.confidence_value_label.setText(f"{confidence:.1f}")

    def get_pull_config(self) -> dict:
        """Get the current pull configuration settings.

        Returns:
            dict with keys:
                - symbol_types: list of enabled symbol types ('function', 'variable', 'type', 'comment')
                - min_confidence: float 0.0-1.0
                - include_graph: bool
        """
        types = []
        if self.pull_functions_cb.isChecked():
            types.append('function')
        if self.pull_variables_cb.isChecked():
            types.append('variable')
        if self.pull_types_cb.isChecked():
            types.append('type')
        if self.pull_comments_cb.isChecked():
            types.append('comment')

        return {
            'symbol_types': types,
            'min_confidence': self.confidence_slider.value() / 100.0,
            'include_graph': self.pull_graph_cb.isChecked()
        }

    def has_graph_preview(self) -> bool:
        return self._graph_preview is not None

    def get_graph_preview(self):
        return self._graph_preview

    def clear_conflicts(self):
        """Clear the conflict resolution table and reset wizard."""
        self._reset_wizard()

    def get_all_new_conflicts(self) -> list:
        """Get all conflict entries with NEW action type."""
        new_conflicts = []
        for row in range(self.conflict_table.rowCount()):
            addr_item = self.conflict_table.item(row, 1)
            if addr_item:
                conflict = addr_item.data(Qt.UserRole + 1)
                if conflict and conflict.action == ConflictAction.NEW:
                    new_conflicts.append(conflict)
        return new_conflicts

    def show_applying_page(self, message: str = "Applying symbols..."):
        """Switch to the applying page and show progress."""
        self.apply_progress_bar.setValue(0)
        self.apply_progress_label.setText(message)
        self.wizard_stack.setCurrentIndex(self.PAGE_APPLYING)

    def update_apply_progress(self, current: int, total: int, message: str = None):
        """Update the apply progress bar."""
        if total > 0:
            percentage = int((current / total) * 100)
            self.apply_progress_bar.setValue(percentage)
        if message:
            self.apply_progress_label.setText(message)

    def show_complete_page(self, applied: int, errors: int = 0):
        """Switch to the complete page with results."""
        if errors > 0:
            self.complete_message.setText(f"Applied {applied} symbols ({errors} errors)")
            self.complete_icon.setStyleSheet("color: #ff9800;")  # Orange for partial success
        else:
            self.complete_message.setText(f"Applied {applied} symbols successfully")
            self.complete_icon.setStyleSheet("color: #4caf50;")  # Green for success
        self.wizard_stack.setCurrentIndex(self.PAGE_COMPLETE)

    def set_buttons_enabled(self, enabled: bool):
        """Enable or disable all action buttons."""
        self.query_button.setEnabled(enabled)
        self.push_button.setEnabled(enabled)
        self.pull_preview_button.setEnabled(enabled)
        self.apply_button.setEnabled(enabled)

    def set_apply_button_text(self, text: str):
        """Update the apply button text (e.g., to show 'Stop' during operation)."""
        self.apply_button.setText(text)

    def set_pull_button_text(self, text: str):
        """Update the pull button text (e.g., to show 'Stop' during operation)."""
        self.pull_preview_button.setText(text)

    # === Private slot handlers ===

    def on_push_clicked(self):
        """Handle push button click."""
        scope = PushScope.FULL_BINARY.value if self.full_binary_radio.isChecked() else PushScope.CURRENT_FUNCTION.value
        push_symbols = self.push_symbols_check.isChecked()
        push_graph = self.push_graph_check.isChecked()
        visibility = self.push_visibility_combo.currentData() or "public"

        if not push_symbols and not push_graph:
            self.set_push_status("Select at least one data type", success=False)
            return

        self.push_requested.emit(scope, push_symbols, push_graph, visibility)

    def on_apply_clicked(self):
        """Handle apply selected button click."""
        selected = self.get_selected_addresses()
        if selected or self._graph_preview:
            self.apply_selected_requested.emit(selected)
        else:
            self.set_pull_status("No items selected", success=False)

    def on_select_all(self):
        """Select all items in the conflict table."""
        for row in range(self.conflict_table.rowCount()):
            checkbox_widget = self.conflict_table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox:
                    checkbox.setChecked(True)

    def on_deselect_all(self):
        """Deselect all items in the conflict table."""
        for row in range(self.conflict_table.rowCount()):
            checkbox_widget = self.conflict_table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox:
                    checkbox.setChecked(False)

    def on_invert_selection(self):
        """Invert the selection in the conflict table."""
        for row in range(self.conflict_table.rowCount()):
            checkbox_widget = self.conflict_table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox:
                    checkbox.setChecked(not checkbox.isChecked())
