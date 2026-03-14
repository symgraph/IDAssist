#!/usr/bin/env python3

from ..qt_compat import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                         QTableWidget, QTableWidgetItem, QComboBox, QTextEdit,
                         QLineEdit, QCheckBox, QHeaderView, QAbstractItemView,
                         QGroupBox, QScrollArea, QFileDialog, Signal, Qt)
from ..services.service_registry import get_service_registry


class SettingsTabView(QWidget):
    # Signals for controller communication
    llm_provider_add_requested = Signal()
    llm_provider_edit_requested = Signal(int)  # row index
    llm_provider_duplicate_requested = Signal(int)  # row index
    llm_provider_delete_requested = Signal(int)  # row index
    llm_provider_test_requested = Signal(int)  # row index
    llm_active_provider_changed = Signal(str)  # provider name
    reasoning_effort_changed = Signal(str)  # reasoning effort level

    mcp_provider_add_requested = Signal()
    mcp_provider_edit_requested = Signal(int)  # row index
    mcp_provider_duplicate_requested = Signal(int)  # row index
    mcp_provider_delete_requested = Signal(int)  # row index
    mcp_provider_test_requested = Signal(int)  # row index

    system_prompt_changed = Signal(str)
    database_path_changed = Signal(str, str)  # path_type, path_value

    # SymGraph signals
    symgraph_api_url_changed = Signal(str)
    symgraph_api_key_changed = Signal(str)
    symgraph_test_requested = Signal()

    # Cancel signals for test buttons
    llm_test_cancel_requested = Signal()
    mcp_test_cancel_requested = Signal()
    symgraph_test_cancel_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        # Create scroll area for the settings content
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout()
        scroll_layout.setContentsMargins(5, 5, 5, 5)
        scroll_layout.setSpacing(10)

        # Create all sections
        self.create_llm_provider_section(scroll_layout)
        self.create_mcp_provider_section(scroll_layout)
        registry = get_service_registry()
        settings = registry.get_settings_service()
        if settings.is_symgraph_enabled():
            self.create_symgraph_section(scroll_layout)
        self.create_system_prompt_section(scroll_layout)
        self.create_database_paths_section(scroll_layout)

        # Add stretch to push everything to the top
        scroll_layout.addStretch()

        scroll_widget.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll_area)
        self.setLayout(main_layout)

    def create_llm_provider_section(self, parent_layout):
        group_box = QGroupBox("LLM Providers")
        layout = QVBoxLayout()

        # LLM Providers table
        self.llm_table = QTableWidget()
        self.llm_table.setColumnCount(7)
        self.llm_table.setHorizontalHeaderLabels([
            "Name", "Model", "Type", "URL", "Max Tokens", "Key", "Disable TLS"
        ])

        # Configure table
        self.llm_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        header = self.llm_table.horizontalHeader()
        for i in range(7):
            header.setSectionResizeMode(i, QHeaderView.Interactive)

        # Set initial column widths
        self.llm_table.setColumnWidth(0, 120)  # Name
        self.llm_table.setColumnWidth(1, 120)  # Model
        self.llm_table.setColumnWidth(2, 100)  # Type
        self.llm_table.setColumnWidth(3, 200)  # URL
        self.llm_table.setColumnWidth(4, 80)   # Max Tokens
        self.llm_table.setColumnWidth(5, 120)  # Key
        self.llm_table.setColumnWidth(6, 80)   # Disable TLS

        layout.addWidget(self.llm_table)

        # LLM Provider buttons
        llm_buttons_layout = QHBoxLayout()
        self.llm_add_button = QPushButton("Add")
        self.llm_edit_button = QPushButton("Edit")
        self.llm_duplicate_button = QPushButton("Duplicate")
        self.llm_delete_button = QPushButton("Delete")
        self.llm_test_button = QPushButton("Test")

        self.llm_add_button.clicked.connect(self.llm_provider_add_requested.emit)
        self.llm_edit_button.clicked.connect(self.on_llm_edit_clicked)
        self.llm_duplicate_button.clicked.connect(self.on_llm_duplicate_clicked)
        self.llm_delete_button.clicked.connect(self.on_llm_delete_clicked)
        self.llm_test_button.clicked.connect(self.on_llm_test_clicked)

        llm_buttons_layout.addWidget(self.llm_add_button)
        llm_buttons_layout.addWidget(self.llm_edit_button)
        llm_buttons_layout.addWidget(self.llm_duplicate_button)
        llm_buttons_layout.addWidget(self.llm_delete_button)
        llm_buttons_layout.addWidget(self.llm_test_button)

        # Status label for test results
        self.llm_test_status = QLabel()
        self.llm_test_status.setFixedWidth(20)
        llm_buttons_layout.addWidget(self.llm_test_status)

        llm_buttons_layout.addStretch()

        layout.addLayout(llm_buttons_layout)

        # Active Provider section
        active_layout = QHBoxLayout()
        active_layout.addWidget(QLabel("Active Provider:"))

        self.active_provider_combo = QComboBox()
        self.active_provider_combo.currentTextChanged.connect(self.llm_active_provider_changed.emit)
        active_layout.addWidget(self.active_provider_combo)

        # Reasoning Effort dropdown
        active_layout.addWidget(QLabel("Reasoning Effort:"))
        self.reasoning_effort_combo = QComboBox()
        self.reasoning_effort_combo.addItem("None", "none")
        self.reasoning_effort_combo.addItem("Low", "low")
        self.reasoning_effort_combo.addItem("Medium", "medium")
        self.reasoning_effort_combo.addItem("High", "high")
        self.reasoning_effort_combo.setToolTip(
            "Extended thinking for complex queries\n"
            "None: Standard response (default)\n"
            "Low: ~2K thinking tokens\n"
            "Medium: ~10K thinking tokens\n"
            "High: ~25K thinking tokens\n\n"
            "Higher levels increase cost and latency"
        )
        self.reasoning_effort_combo.currentTextChanged.connect(self._on_reasoning_effort_changed)
        active_layout.addWidget(self.reasoning_effort_combo)

        active_layout.addStretch()
        layout.addLayout(active_layout)

        group_box.setLayout(layout)
        parent_layout.addWidget(group_box)

    def create_mcp_provider_section(self, parent_layout):
        group_box = QGroupBox("MCP Providers")
        layout = QVBoxLayout()

        # MCP Providers table
        self.mcp_table = QTableWidget()
        self.mcp_table.setColumnCount(4)
        self.mcp_table.setHorizontalHeaderLabels([
            "Name", "URL", "Enabled", "Transport"
        ])

        # Configure table
        self.mcp_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        header = self.mcp_table.horizontalHeader()
        for i in range(4):
            header.setSectionResizeMode(i, QHeaderView.Interactive)

        # Set initial column widths
        self.mcp_table.setColumnWidth(0, 120)  # Name
        self.mcp_table.setColumnWidth(1, 200)  # URL
        self.mcp_table.setColumnWidth(2, 80)   # Enabled
        self.mcp_table.setColumnWidth(3, 100)  # Transport

        layout.addWidget(self.mcp_table)

        # MCP Provider buttons
        mcp_buttons_layout = QHBoxLayout()
        self.mcp_add_button = QPushButton("Add")
        self.mcp_edit_button = QPushButton("Edit")
        self.mcp_duplicate_button = QPushButton("Duplicate")
        self.mcp_delete_button = QPushButton("Delete")
        self.mcp_test_button = QPushButton("Test")

        self.mcp_add_button.clicked.connect(self.mcp_provider_add_requested.emit)
        self.mcp_edit_button.clicked.connect(self.on_mcp_edit_clicked)
        self.mcp_duplicate_button.clicked.connect(self.on_mcp_duplicate_clicked)
        self.mcp_delete_button.clicked.connect(self.on_mcp_delete_clicked)
        self.mcp_test_button.clicked.connect(self.on_mcp_test_clicked)

        mcp_buttons_layout.addWidget(self.mcp_add_button)
        mcp_buttons_layout.addWidget(self.mcp_edit_button)
        mcp_buttons_layout.addWidget(self.mcp_duplicate_button)
        mcp_buttons_layout.addWidget(self.mcp_delete_button)
        mcp_buttons_layout.addWidget(self.mcp_test_button)

        # Status label for test results
        self.mcp_test_status = QLabel()
        self.mcp_test_status.setFixedWidth(20)
        mcp_buttons_layout.addWidget(self.mcp_test_status)

        mcp_buttons_layout.addStretch()

        layout.addLayout(mcp_buttons_layout)

        group_box.setLayout(layout)
        parent_layout.addWidget(group_box)

    def create_symgraph_section(self, parent_layout):
        """Create the SymGraph settings section"""
        group_box = QGroupBox("SymGraph")
        layout = QVBoxLayout()

        # API URL
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("API URL:"))
        self.symgraph_url_field = QLineEdit()
        self.symgraph_url_field.setPlaceholderText("https://api.SymGraph")
        self.symgraph_url_field.setToolTip("SymGraph API URL (for self-hosted instances)")
        self.symgraph_url_field.editingFinished.connect(
            lambda: self.symgraph_api_url_changed.emit(self.symgraph_url_field.text())
        )
        url_layout.addWidget(self.symgraph_url_field, 1)
        layout.addLayout(url_layout)

        # API Key
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("API Key:"))
        self.symgraph_key_field = QLineEdit()
        self.symgraph_key_field.setPlaceholderText("sg_xxxxx")
        self.symgraph_key_field.setEchoMode(QLineEdit.Password)
        self.symgraph_key_field.setToolTip("Your SymGraph API key (required for push/pull operations)")
        self.symgraph_key_field.editingFinished.connect(
            lambda: self.symgraph_api_key_changed.emit(self.symgraph_key_field.text())
        )
        key_layout.addWidget(self.symgraph_key_field, 1)

        # Show/hide key button
        self.symgraph_key_toggle = QPushButton("Show")
        self.symgraph_key_toggle.setMaximumWidth(60)
        self.symgraph_key_toggle.clicked.connect(self._toggle_symgraph_key_visibility)
        key_layout.addWidget(self.symgraph_key_toggle)

        # Test button
        self.symgraph_test_button = QPushButton("Test")
        self.symgraph_test_button.setMaximumWidth(60)
        self.symgraph_test_button.clicked.connect(self.symgraph_test_requested.emit)
        key_layout.addWidget(self.symgraph_test_button)

        # Status label for test results
        self.symgraph_test_status = QLabel()
        self.symgraph_test_status.setFixedWidth(20)
        key_layout.addWidget(self.symgraph_test_status)

        layout.addLayout(key_layout)

        # Info label
        info_label = QLabel(
            "SymGraph provides cloud-based symbol and graph data sharing. "
            "Query operations are free; push/pull require an API key."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(info_label)

        group_box.setLayout(layout)
        parent_layout.addWidget(group_box)

    def _toggle_symgraph_key_visibility(self):
        """Toggle visibility of the SymGraph API key field"""
        if self.symgraph_key_field.echoMode() == QLineEdit.Password:
            self.symgraph_key_field.setEchoMode(QLineEdit.Normal)
            self.symgraph_key_toggle.setText("Hide")
        else:
            self.symgraph_key_field.setEchoMode(QLineEdit.Password)
            self.symgraph_key_toggle.setText("Show")

    def set_symgraph_api_url(self, url: str):
        """Set the SymGraph API URL field"""
        self.symgraph_url_field.setText(url)

    def set_symgraph_api_key(self, key: str):
        """Set the SymGraph API key field"""
        self.symgraph_key_field.setText(key)

    def _set_test_status(self, label: QLabel, status: str, tooltip: str = ""):
        """Set a test status indicator label"""
        if status == 'success':
            label.setText("OK")
            label.setStyleSheet("color: green;")
        elif status == 'failure':
            label.setText("X")
            label.setStyleSheet("color: red;")
        elif status == 'testing':
            label.setText("...")
            label.setStyleSheet("color: gray;")
        else:  # clear
            label.setText("")
            label.setStyleSheet("")

        if tooltip:
            label.setToolTip(tooltip)
        else:
            label.setToolTip("")

    def set_llm_test_status(self, status: str, tooltip: str = ""):
        """Set the LLM Provider test status indicator"""
        self._set_test_status(self.llm_test_status, status, tooltip)

    def set_llm_test_enabled(self, enabled: bool):
        """Toggle the LLM test button between Test and Cancel modes"""
        if not enabled:
            # Testing in progress - show Cancel
            self.llm_test_button.setText("Cancel")
            self.llm_test_button.setEnabled(True)
            try:
                self.llm_test_button.clicked.disconnect()
            except RuntimeError:
                pass
            self.llm_test_button.clicked.connect(self.llm_test_cancel_requested.emit)
        else:
            # Test done - restore Test
            self.llm_test_button.setText("Test")
            self.llm_test_button.setEnabled(True)
            try:
                self.llm_test_button.clicked.disconnect()
            except RuntimeError:
                pass
            self.llm_test_button.clicked.connect(self.on_llm_test_clicked)

    def set_mcp_test_status(self, status: str, tooltip: str = ""):
        """Set the MCP Server test status indicator"""
        self._set_test_status(self.mcp_test_status, status, tooltip)

    def set_mcp_test_enabled(self, enabled: bool):
        """Toggle the MCP test button between Test and Cancel modes"""
        if not enabled:
            self.mcp_test_button.setText("Cancel")
            self.mcp_test_button.setEnabled(True)
            try:
                self.mcp_test_button.clicked.disconnect()
            except RuntimeError:
                pass
            self.mcp_test_button.clicked.connect(self.mcp_test_cancel_requested.emit)
        else:
            self.mcp_test_button.setText("Test")
            self.mcp_test_button.setEnabled(True)
            try:
                self.mcp_test_button.clicked.disconnect()
            except RuntimeError:
                pass
            self.mcp_test_button.clicked.connect(self.on_mcp_test_clicked)

    def set_symgraph_test_status(self, status: str, tooltip: str = ""):
        """Set the SymGraph test status indicator"""
        self._set_test_status(self.symgraph_test_status, status, tooltip)

    def set_symgraph_test_enabled(self, enabled: bool):
        """Toggle the SymGraph test button between Test and Cancel modes"""
        if not enabled:
            self.symgraph_test_button.setText("Cancel")
            self.symgraph_test_button.setEnabled(True)
            try:
                self.symgraph_test_button.clicked.disconnect()
            except RuntimeError:
                pass
            self.symgraph_test_button.clicked.connect(self.symgraph_test_cancel_requested.emit)
        else:
            self.symgraph_test_button.setText("Test")
            self.symgraph_test_button.setEnabled(True)
            try:
                self.symgraph_test_button.clicked.disconnect()
            except RuntimeError:
                pass
            self.symgraph_test_button.clicked.connect(self.symgraph_test_requested.emit)

    def create_system_prompt_section(self, parent_layout):
        group_box = QGroupBox("System Prompt")
        layout = QVBoxLayout()

        self.system_prompt_text = QTextEdit()
        self.system_prompt_text.setPlainText("You are an AI assistant specialized in binary analysis and reverse engineering...")
        self.system_prompt_text.setMaximumHeight(120)
        self.system_prompt_text.textChanged.connect(self.on_system_prompt_changed)

        layout.addWidget(self.system_prompt_text)

        group_box.setLayout(layout)
        parent_layout.addWidget(group_box)

    def create_database_paths_section(self, parent_layout):
        group_box = QGroupBox("Database Paths")
        layout = QVBoxLayout()

        # Analysis DB path
        analysis_layout = QHBoxLayout()
        analysis_layout.addWidget(QLabel("Analysis DB:"))
        self.analysis_db_path = QLineEdit("/path/to/analysis.db")
        self.analysis_db_button = QPushButton("Browse...")
        self.analysis_db_button.clicked.connect(lambda: self.browse_database_path("analysis_db"))

        analysis_layout.addWidget(self.analysis_db_path)
        analysis_layout.addWidget(self.analysis_db_button)
        layout.addLayout(analysis_layout)

        # RLHF DB path
        rlhf_layout = QHBoxLayout()
        rlhf_layout.addWidget(QLabel("RLHF DB:"))
        self.rlhf_db_path = QLineEdit("/path/to/rlhf.db")
        self.rlhf_db_button = QPushButton("Browse...")
        self.rlhf_db_button.clicked.connect(lambda: self.browse_database_path("rlhf_db"))

        rlhf_layout.addWidget(self.rlhf_db_path)
        rlhf_layout.addWidget(self.rlhf_db_button)
        layout.addLayout(rlhf_layout)

        # RAG Index path
        rag_layout = QHBoxLayout()
        rag_layout.addWidget(QLabel("RAG Index:"))
        self.rag_index_path = QLineEdit("/path/to/rag_index")
        self.rag_index_button = QPushButton("Browse...")
        self.rag_index_button.clicked.connect(lambda: self.browse_database_path("rag_index"))

        rag_layout.addWidget(self.rag_index_path)
        rag_layout.addWidget(self.rag_index_button)
        layout.addLayout(rag_layout)

        group_box.setLayout(layout)
        parent_layout.addWidget(group_box)

    def add_llm_provider(self, name, model, provider_type, url, max_tokens, key, disable_tls=False):
        """Add an LLM provider to the table"""
        row_count = self.llm_table.rowCount()
        self.llm_table.insertRow(row_count)

        self.llm_table.setItem(row_count, 0, QTableWidgetItem(name))
        self.llm_table.setItem(row_count, 1, QTableWidgetItem(model))
        self.llm_table.setItem(row_count, 2, QTableWidgetItem(provider_type))
        self.llm_table.setItem(row_count, 3, QTableWidgetItem(url))
        self.llm_table.setItem(row_count, 4, QTableWidgetItem(str(max_tokens)))

        if key and len(key) > 0:
            masked_key = "*" * min(len(key), 20)
        else:
            masked_key = ""
        self.llm_table.setItem(row_count, 5, QTableWidgetItem(masked_key))

        tls_checkbox = QCheckBox()
        tls_checkbox.setChecked(disable_tls)
        self.llm_table.setCellWidget(row_count, 6, tls_checkbox)

        # Update active provider combo
        self.active_provider_combo.addItem(name)

    def add_mcp_provider(self, name, url, enabled=True, transport="streamablehttp"):
        """Add an MCP provider to the table"""
        row_count = self.mcp_table.rowCount()
        self.mcp_table.insertRow(row_count)

        self.mcp_table.setItem(row_count, 0, QTableWidgetItem(name))
        self.mcp_table.setItem(row_count, 1, QTableWidgetItem(url))

        enabled_checkbox = QCheckBox()
        enabled_checkbox.setChecked(enabled)
        self.mcp_table.setCellWidget(row_count, 2, enabled_checkbox)

        self.mcp_table.setItem(row_count, 3, QTableWidgetItem(transport))

    def on_llm_edit_clicked(self):
        current_row = self.llm_table.currentRow()
        if current_row >= 0:
            self.llm_provider_edit_requested.emit(current_row)

    def on_llm_duplicate_clicked(self):
        current_row = self.llm_table.currentRow()
        if current_row >= 0:
            self.llm_provider_duplicate_requested.emit(current_row)

    def on_llm_delete_clicked(self):
        current_row = self.llm_table.currentRow()
        if current_row >= 0:
            self.llm_provider_delete_requested.emit(current_row)

    def on_llm_test_clicked(self):
        current_row = self.llm_table.currentRow()
        if current_row >= 0:
            self.llm_provider_test_requested.emit(current_row)

    def on_mcp_edit_clicked(self):
        current_row = self.mcp_table.currentRow()
        if current_row >= 0:
            self.mcp_provider_edit_requested.emit(current_row)

    def on_mcp_duplicate_clicked(self):
        current_row = self.mcp_table.currentRow()
        if current_row >= 0:
            self.mcp_provider_duplicate_requested.emit(current_row)

    def on_mcp_delete_clicked(self):
        current_row = self.mcp_table.currentRow()
        if current_row >= 0:
            self.mcp_provider_delete_requested.emit(current_row)

    def on_mcp_test_clicked(self):
        current_row = self.mcp_table.currentRow()
        if current_row >= 0:
            self.mcp_provider_test_requested.emit(current_row)

    def on_system_prompt_changed(self):
        self.system_prompt_changed.emit(self.system_prompt_text.toPlainText())

    def browse_database_path(self, path_type):
        """Open file dialog to browse for database path"""
        if path_type == "rag_index":
            path = QFileDialog.getExistingDirectory(self, "Select RAG Index Directory")
        else:
            path, _ = QFileDialog.getOpenFileName(self, f"Select {path_type.replace('_', ' ').title()}", "", "Database files (*.db);;All files (*)")

        if path:
            if path_type == "analysis_db":
                self.analysis_db_path.setText(path)
            elif path_type == "rlhf_db":
                self.rlhf_db_path.setText(path)
            elif path_type == "rag_index":
                self.rag_index_path.setText(path)

            self.database_path_changed.emit(path_type, path)

    def _on_reasoning_effort_changed(self, text):
        """Handle reasoning effort combo change"""
        current_data = self.reasoning_effort_combo.currentData()
        if current_data:
            self.reasoning_effort_changed.emit(current_data)

    def set_reasoning_effort(self, reasoning_effort: str):
        """Set the reasoning effort combo to the specified value"""
        index = self.reasoning_effort_combo.findData(reasoning_effort)
        if index >= 0:
            self.reasoning_effort_combo.currentTextChanged.disconnect(self._on_reasoning_effort_changed)
            self.reasoning_effort_combo.setCurrentIndex(index)
            self.reasoning_effort_combo.currentTextChanged.connect(self._on_reasoning_effort_changed)
