#!/usr/bin/env python3

"""
Manual Analysis Panel for Semantic Graph tab.

Provides organized UI for triggering various analysis operations:
- Primary Operations: ReIndex (full pipeline), Semantic Analysis
- Individual Operations: Security, Network Flow, Community Detection, Refresh Names
"""

from ...qt_compat import (
    Signal, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QLabel,
    QProgressBar, QFrame, QCheckBox
)


class ManualAnalysisPanel(QWidget):
    """Panel for manual analysis operations."""

    # Signals
    reindex_requested = Signal()
    semantic_analysis_requested = Signal()
    security_analysis_requested = Signal()
    network_flow_requested = Signal()
    community_detection_requested = Signal()
    refresh_names_requested = Signal()

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)

        # Header
        header = QLabel("Manual Analysis Operations")
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header)

        # Primary Operations Section
        primary_group = QGroupBox("Primary Operations")
        primary_layout = QVBoxLayout(primary_group)
        primary_layout.setSpacing(10)

        # ReIndex Binary
        reindex_row = self._create_button_row(
            "ReIndex Binary",
            "Full Pipeline: Extract structure, then run Security, Network Flow, and Community Detection analyses.",
            "reindex"
        )
        self.reindex_button = reindex_row.findChild(QPushButton)
        self.reindex_button.clicked.connect(self.reindex_requested.emit)
        primary_layout.addWidget(reindex_row)

        # Semantic Analysis
        semantic_row = self._create_button_row(
            "Semantic Analysis",
            "Use LLM to generate summaries for unsummarized functions. Requires configured LLM provider.",
            "semantic"
        )
        self.semantic_button = semantic_row.findChild(QPushButton)
        self.semantic_button.clicked.connect(self.semantic_analysis_requested.emit)
        primary_layout.addWidget(semantic_row)

        # RAG/MCP/Force options for Semantic Analysis
        options_row = QHBoxLayout()
        options_row.setContentsMargins(self.BUTTON_WIDTH + 10, 0, 0, 0)

        self.rag_checkbox = QCheckBox("Enable RAG")
        self.rag_checkbox.setToolTip("Include RAG (Retrieval-Augmented Generation) context in prompts")
        options_row.addWidget(self.rag_checkbox)

        self.mcp_checkbox = QCheckBox("Enable MCP")
        self.mcp_checkbox.setToolTip("Include MCP (Model Context Protocol) context in prompts")
        options_row.addWidget(self.mcp_checkbox)

        self.force_checkbox = QCheckBox("Force")
        self.force_checkbox.setToolTip("Force re-analyze all functions, not just stale/unsummarized ones")
        options_row.addWidget(self.force_checkbox)

        options_row.addStretch()
        primary_layout.addLayout(options_row)

        layout.addWidget(primary_group)

        # Individual Operations Section
        individual_group = QGroupBox("Individual Analysis Operations")
        individual_layout = QVBoxLayout(individual_group)
        individual_layout.setSpacing(10)

        # Security Analysis
        security_row = self._create_button_row(
            "Security Analysis",
            "Find taint paths from sources to sinks, create TAINT_FLOWS_TO and VULNERABLE_VIA edges.",
            "security"
        )
        self.security_button = security_row.findChild(QPushButton)
        self.security_button.clicked.connect(self.security_analysis_requested.emit)
        individual_layout.addWidget(security_row)

        # Network Flow Analysis
        network_row = self._create_button_row(
            "Network Flow Analysis",
            "Trace send/recv APIs (send, recv, WSASend, SSL_write, etc.), create NETWORK_SEND/RECV edges.",
            "network"
        )
        self.network_button = network_row.findChild(QPushButton)
        self.network_button.clicked.connect(self.network_flow_requested.emit)
        individual_layout.addWidget(network_row)

        # Community Detection
        community_row = self._create_button_row(
            "Community Detection",
            "Group related functions into communities using Label Propagation algorithm.",
            "community"
        )
        self.community_button = community_row.findChild(QPushButton)
        self.community_button.clicked.connect(self.community_detection_requested.emit)
        individual_layout.addWidget(community_row)

        # Refresh Names
        refresh_row = self._create_button_row(
            "Refresh Names",
            "Sync function names in the graph to match current IDA names.",
            "refresh"
        )
        self.refresh_button = refresh_row.findChild(QPushButton)
        self.refresh_button.clicked.connect(self.refresh_names_requested.emit)
        individual_layout.addWidget(refresh_row)

        layout.addWidget(individual_group)

        # Progress Section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.status_label = QLabel("Status: Idle")
        progress_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        progress_layout.addWidget(self.progress_bar)

        layout.addWidget(progress_group)

        # Add stretch to push everything to the top
        layout.addStretch()

    BUTTON_WIDTH = 168

    def _create_button_row(self, button_text: str, description: str, name: str) -> QFrame:
        """Create a button row with description."""
        frame = QFrame()
        frame.setObjectName(f"{name}_row")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)

        # Button with fixed width for consistency
        button = QPushButton(button_text)
        button.setObjectName(f"{name}_button")
        button.setFixedWidth(self.BUTTON_WIDTH)
        button.setToolTip(description)
        layout.addWidget(button)

        # Description
        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(desc_label, 1)

        return frame

    def set_status(self, message: str):
        """Update the status label."""
        self.status_label.setText(f"Status: {message}")

    def set_progress(self, current: int, total: int, message: str = ""):
        """Update the progress bar."""
        if total > 0:
            percent = int((current / total) * 100)
            self.progress_bar.setValue(percent)
            if message:
                self.progress_bar.setFormat(f"{percent}% - {message}")
            else:
                self.progress_bar.setFormat(f"{percent}%")
        else:
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("0%")

    def reset_progress(self):
        """Reset the progress bar."""
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0%")

    def set_reindex_running(self, running: bool):
        """Update ReIndex button state."""
        self.reindex_button.setText("Stop" if running else "ReIndex Binary")

    def set_semantic_running(self, running: bool):
        """Update Semantic Analysis button state."""
        self.semantic_button.setText("Stop" if running else "Semantic Analysis")

    def set_security_running(self, running: bool):
        """Update Security Analysis button state."""
        self.security_button.setText("Stop" if running else "Security Analysis")

    def set_network_running(self, running: bool):
        """Update Network Flow button state."""
        self.network_button.setText("Stop" if running else "Network Flow Analysis")

    def set_community_running(self, running: bool):
        """Update Community Detection button state."""
        self.community_button.setText("Stop" if running else "Community Detection")

    def is_rag_enabled(self) -> bool:
        """Return whether RAG is enabled for semantic analysis."""
        return self.rag_checkbox.isChecked()

    def is_mcp_enabled(self) -> bool:
        """Return whether MCP is enabled for semantic analysis."""
        return self.mcp_checkbox.isChecked()

    def is_force_enabled(self) -> bool:
        """Return whether force re-analysis is enabled for semantic analysis."""
        return self.force_checkbox.isChecked()
