#!/usr/bin/env python3

from ..qt_compat import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                         QPushButton, QTextBrowser, QTextEdit, QLineEdit, QSizePolicy, QCheckBox,
                         QApplication, QGroupBox, QGridLayout, QSplitter, QFrame,
                         Signal, Qt, QKeySequence, QFontDatabase, exec_dialog)

from .streaming_markdown_browser import StreamingMarkdownBrowser
from ..services.streaming.streaming_renderer import MARKDOWN_CSS, render_markdown_to_html


class MarkdownCopyBrowser(QTextBrowser):
    """
    QTextBrowser subclass that copies the backing markdown source.

    When the user presses Ctrl+C or uses the context menu to copy, this widget
    copies the original markdown text rather than the rendered HTML.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._markdown_source = ""

    def set_markdown_source(self, markdown_text: str):
        """Store the markdown source for copy operations"""
        self._markdown_source = markdown_text

    def _copy_markdown(self):
        """Copy the markdown source to clipboard"""
        if self._markdown_source:
            QApplication.clipboard().setText(self._markdown_source)

    def keyPressEvent(self, event):
        """Intercept Ctrl+C to copy markdown"""
        if event.matches(QKeySequence.Copy):
            self._copy_markdown()
        else:
            super().keyPressEvent(event)

    def contextMenuEvent(self, event):
        """Override context menu to replace Copy action with markdown copy"""
        from ..qt_compat import QMenu, QAction

        menu = self.createStandardContextMenu()

        # Find and replace the Copy action
        for action in menu.actions():
            if action.text().replace('&', '') == 'Copy':
                # Disconnect original and connect our markdown copy
                action.triggered.disconnect()
                action.triggered.connect(self._copy_markdown)
                break

        exec_dialog(menu, event.globalPos())
        menu.deleteLater()


class ExplainTabView(QWidget):
    # Signals for controller communication
    explain_function_requested = Signal()
    explain_line_requested = Signal()
    stop_function_requested = Signal()
    stop_line_requested = Signal()
    clear_requested = Signal()
    edit_mode_changed = Signal(bool)
    rag_enabled_changed = Signal(bool)
    mcp_enabled_changed = Signal(bool)
    # RLHF feedback signals
    rlhf_feedback_requested = Signal(bool)  # True for upvote, False for downvote
    # Line explanation panel signals
    line_explanation_closed = Signal()  # Emitted when user clicks close button

    def __init__(self):
        super().__init__()
        self.is_edit_mode = False
        self.function_query_running = False
        self.line_query_running = False
        self.markdown_content = "No explanation available. Click 'Explain Function' or 'Explain Line' to generate content."
        self.line_markdown_content = ""  # Separate content for line explanation
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Top row - Current Offset and Edit/Save button
        self.create_top_row(layout)

        # Create splitter for function and line explanation panels
        self.main_splitter = QSplitter(Qt.Vertical)

        # Main text widget - HTML browser/Markdown editor (function explanation)
        self.create_main_text_widget()

        # Line explanation panel (initially hidden)
        self.create_line_explanation_panel()

        # Security analysis panel (created before adding to splitter)
        self.create_security_panel()

        # Add widgets to splitter
        self.main_splitter.addWidget(self.explain_browser)
        self.main_splitter.addWidget(self.explain_editor)
        self.main_splitter.addWidget(self.line_explanation_group)
        self.main_splitter.addWidget(self.security_group)

        # Set initial splitter sizes (function panel takes most space)
        self.main_splitter.setSizes([400, 0, 0, 160])
        self.main_splitter.setStretchFactor(0, 3)  # Function browser
        self.main_splitter.setStretchFactor(1, 3)  # Function editor (same stretch as browser)
        self.main_splitter.setStretchFactor(2, 1)  # Line explanation
        self.main_splitter.setStretchFactor(3, 0)  # Security panel

        layout.addWidget(self.main_splitter)

        # Bottom row - Action buttons
        self.create_bottom_row(layout)

        self.setLayout(layout)

    def create_top_row(self, parent_layout):
        top_row = QHBoxLayout()

        # Size-constrained and left-justified labels
        offset_label = QLabel("Current Offset:")
        offset_label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        offset_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        self.current_offset_label = QLabel("0x0")
        self.current_offset_label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.current_offset_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # RAG and MCP checkboxes
        self.rag_checkbox = QCheckBox("RAG")
        self.rag_checkbox.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.rag_checkbox.setChecked(False)  # Default disabled
        self.rag_checkbox.toggled.connect(self.rag_enabled_changed.emit)

        self.mcp_checkbox = QCheckBox("MCP")
        self.mcp_checkbox.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.mcp_checkbox.setChecked(False)  # Default disabled
        self.mcp_checkbox.toggled.connect(self.mcp_enabled_changed.emit)

        # Size-constrained Edit button
        self.edit_save_button = QPushButton("Edit")
        self.edit_save_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.edit_save_button.clicked.connect(self.toggle_edit_mode)

        top_row.addWidget(offset_label)
        top_row.addWidget(self.current_offset_label)
        top_row.addStretch()  # Push checkboxes and button to the right
        top_row.addWidget(self.rag_checkbox)
        top_row.addWidget(self.mcp_checkbox)
        top_row.addWidget(self.edit_save_button)

        parent_layout.addLayout(top_row)

    def create_main_text_widget(self):
        # HTML browser for read-only mode (uses StreamingMarkdownBrowser for responsive streaming)
        self.explain_browser = StreamingMarkdownBrowser()
        self.explain_browser.set_markdown_source(self.markdown_content)
        self.explain_browser.setHtml(self.markdown_to_html(self.markdown_content))
        self.explain_browser.anchorClicked.connect(self._on_anchor_clicked)
        # Prevent default navigation for custom protocols
        self.explain_browser.setOpenLinks(False)

        # Text editor for edit mode
        self.explain_editor = QTextEdit()
        self.explain_editor.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.explain_editor.setPlainText(self.markdown_content)
        self.explain_editor.hide()  # Hidden by default

        # ESC key discards edits and returns to view mode
        from ..qt_compat import QShortcut
        esc_shortcut = QShortcut(QKeySequence(Qt.Key_Escape), self.explain_editor)
        esc_shortcut.setContext(Qt.WidgetShortcut)
        esc_shortcut.activated.connect(self.cancel_edit_mode)

    def create_line_explanation_panel(self):
        """Create the line explanation panel (collapsible, dismissable)"""
        self.line_explanation_group = QGroupBox("Line Explanation")
        self.line_explanation_group.setVisible(False)  # Initially hidden

        line_layout = QVBoxLayout()
        line_layout.setContentsMargins(5, 5, 5, 5)
        line_layout.setSpacing(3)

        # Header row with close button
        header_row = QHBoxLayout()
        header_row.addStretch()
        self.line_close_button = QPushButton("\u00d7")  # x symbol
        self.line_close_button.setFixedSize(20, 20)
        self.line_close_button.setToolTip("Close line explanation panel")
        self.line_close_button.clicked.connect(self._on_line_close_clicked)
        header_row.addWidget(self.line_close_button)
        line_layout.addLayout(header_row)

        # Line explanation browser
        self.line_explanation_browser = MarkdownCopyBrowser()
        self.line_explanation_browser.setOpenLinks(False)
        self.line_explanation_browser.anchorClicked.connect(self._on_anchor_clicked)
        line_layout.addWidget(self.line_explanation_browser)

        self.line_explanation_group.setLayout(line_layout)

    def create_bottom_row(self, parent_layout):
        bottom_row = QHBoxLayout()

        self.explain_function_button = QPushButton("Explain Function")
        self.explain_line_button = QPushButton("Explain Line")
        self.clear_button = QPushButton("Clear")

        # Connect button signals
        self.explain_function_button.clicked.connect(self._on_explain_function_clicked)
        self.explain_line_button.clicked.connect(self._on_explain_line_clicked)
        self.clear_button.clicked.connect(self.clear_requested.emit)

        bottom_row.addWidget(self.explain_function_button)
        bottom_row.addWidget(self.explain_line_button)
        bottom_row.addWidget(self.clear_button)

        parent_layout.addLayout(bottom_row)

    def create_security_panel(self):
        """Create the security analysis panel (lives inside the main splitter)."""
        self.security_group = QGroupBox("Security Analysis")
        self.security_group.setVisible(False)

        grid = QGridLayout()
        grid.setContentsMargins(8, 6, 8, 6)
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(2)

        self.risk_label = QLabel("Risk: —")
        self.activity_label = QLabel("Activity: —")
        self.flags_label = QLabel("Flags: None")
        self.flags_label.setWordWrap(True)
        self.network_label = QLabel("Network APIs")
        self.file_label = QLabel("File I/O APIs")

        self.network_text = QTextEdit()
        self.network_text.setReadOnly(True)
        self.network_text.setMinimumHeight(36)
        self.network_text.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.network_text.setLineWrapMode(QTextEdit.NoWrap)

        self.file_text = QTextEdit()
        self.file_text.setReadOnly(True)
        self.file_text.setMinimumHeight(36)
        self.file_text.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.file_text.setLineWrapMode(QTextEdit.NoWrap)

        grid.addWidget(self.risk_label, 0, 0)
        grid.addWidget(self.activity_label, 0, 1)
        grid.addWidget(self.flags_label, 1, 0, 1, 2)
        grid.addWidget(self.network_label, 2, 0)
        grid.addWidget(self.file_label, 2, 1)
        grid.addWidget(self.network_text, 3, 0)
        grid.addWidget(self.file_text, 3, 1)

        # Let the API text areas absorb extra vertical space from the splitter
        for r in range(0, 3):
            grid.setRowStretch(r, 0)
        grid.setRowStretch(3, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        self.security_group.setLayout(grid)

    def toggle_edit_mode(self):
        # Prevent edit mode changes during query execution
        if self.function_query_running or self.line_query_running:
            return

        self.is_edit_mode = not self.is_edit_mode

        # Save security and line-explanation panel sizes before the swap
        old_sizes = self.main_splitter.sizes()
        security_size = old_sizes[3] if len(old_sizes) >= 4 else 0
        line_size = old_sizes[2] if len(old_sizes) >= 3 else 0
        if self.is_edit_mode:
            self.explain_browser.hide()
            self.explain_editor.show()
            self.edit_save_button.setText("Save")
            self.explain_editor.setPlainText(self.markdown_content)
        else:
            self.explain_editor.hide()
            self.explain_browser.show()
            self.edit_save_button.setText("Edit")
            self.markdown_content = self.explain_editor.toPlainText()
            self.explain_browser.setHtml(self.markdown_to_html(self.markdown_content))
            self.explain_browser.set_markdown_source(self.markdown_content)

        # Restore panel sizes — give all remaining space to the active text widget
        from ..qt_compat import QTimer
        is_edit = self.is_edit_mode
        def _restore_sizes():
            total = sum(self.main_splitter.sizes())
            active_size = total - line_size - security_size
            if is_edit:
                self.main_splitter.setSizes([0, active_size, line_size, security_size])
            else:
                self.main_splitter.setSizes([active_size, 0, line_size, security_size])
        QTimer.singleShot(0, _restore_sizes)

        self.edit_mode_changed.emit(self.is_edit_mode)

    def cancel_edit_mode(self):
        """Discard edits and return to view mode without saving"""
        if not self.is_edit_mode:
            return
        self.is_edit_mode = False
        old_sizes = self.main_splitter.sizes()
        security_size = old_sizes[3] if len(old_sizes) >= 4 else 0
        line_size = old_sizes[2] if len(old_sizes) >= 3 else 0
        self.explain_editor.hide()
        self.explain_browser.show()
        self.edit_save_button.setText("Edit")
        from ..qt_compat import QTimer
        def _restore_sizes():
            total = sum(self.main_splitter.sizes())
            active_size = total - line_size - security_size
            self.main_splitter.setSizes([active_size, 0, line_size, security_size])
        QTimer.singleShot(0, _restore_sizes)

    def set_current_offset(self, offset_hex):
        """Update the displayed current offset"""
        self.current_offset_label.setText(offset_hex)

    def set_explanation_content(self, markdown_text):
        """Set the explanation content (in Markdown format)"""
        self.markdown_content = markdown_text
        if not self.is_edit_mode:
            # Check if user is near the bottom before updating
            should_auto_scroll = self._should_auto_scroll_to_bottom()
            scrollbar = self.explain_browser.verticalScrollBar()
            old_value = scrollbar.value() if scrollbar else 0

            # Store markdown source for copy operations
            self.explain_browser.set_markdown_source(markdown_text)

            self.explain_browser.setHtml(self.markdown_to_html(markdown_text))

            # Defer scroll restoration until after Qt processes the layout change
            from ..qt_compat import QTimer
            if should_auto_scroll:
                # Auto-scroll to bottom if user was following the explanation
                QTimer.singleShot(0, self._scroll_to_bottom)
            else:
                # Preserve position if user scrolled away
                def restore_scroll():
                    if scrollbar:
                        scrollbar.setValue(old_value)
                QTimer.singleShot(0, restore_scroll)
        else:
            self.explain_editor.setPlainText(markdown_text)

    def update_security_info(self, risk_level, activity_profile, security_flags, network_apis, file_io_apis):
        """Update the security analysis panel."""
        self.risk_label.setText(f"Risk: {risk_level or '—'}")
        self.activity_label.setText(f"Activity: {activity_profile or '—'}")

        flags_text = ", ".join(security_flags) if security_flags else "None"
        self.flags_label.setText(f"Flags: {flags_text}")

        self.network_text.setPlainText("\n".join(network_apis) if network_apis else "(none detected)")
        self.file_text.setPlainText("\n".join(file_io_apis) if file_io_apis else "(none detected)")

        has_data = bool(risk_level or activity_profile or security_flags or network_apis or file_io_apis)
        self.security_group.setVisible(has_data)

    def clear_security_info(self):
        """Clear and hide the security analysis panel."""
        self.risk_label.setText("Risk: —")
        self.activity_label.setText("Activity: —")
        self.flags_label.setText("Flags: None")
        self.network_text.clear()
        self.file_text.clear()
        self.security_group.setVisible(False)

    def is_rag_enabled(self):
        """Get the current state of the RAG checkbox"""
        return self.rag_checkbox.isChecked()

    def is_mcp_enabled(self):
        """Get the current state of the MCP checkbox"""
        return self.mcp_checkbox.isChecked()

    def set_rag_enabled(self, enabled):
        """Set the RAG checkbox state"""
        self.rag_checkbox.setChecked(enabled)

    def set_mcp_enabled(self, enabled):
        """Set the MCP checkbox state"""
        self.mcp_checkbox.setChecked(enabled)

    def get_explanation_content(self):
        """Get the current explanation content"""
        if self.is_edit_mode:
            return self.explain_editor.toPlainText()
        return self.markdown_content

    def clear_content(self):
        """Clear the explanation content"""
        default_content = "No explanation available. Click 'Explain Function' or 'Explain Line' to generate content."
        self.set_explanation_content(default_content)

    # Line explanation panel methods

    def set_line_explanation_content(self, markdown_text: str):
        """Set the line explanation content and show the panel"""
        self.line_markdown_content = markdown_text
        self.line_explanation_browser.set_markdown_source(markdown_text)
        self.line_explanation_browser.setHtml(self.markdown_to_html(markdown_text))
        self.line_explanation_group.setVisible(True)

        # Adjust splitter to show line panel if hidden
        sizes = self.main_splitter.sizes()
        if len(sizes) >= 4 and sizes[2] < 50:
            # Give line panel reasonable space while preserving security panel size
            security_size = sizes[3]
            available = sum(sizes) - security_size
            new_sizes = [int(available * 0.6), 0, int(available * 0.4), security_size]
            if self.is_edit_mode:
                new_sizes[0] = 0
                new_sizes[1] = int(available * 0.6)
            self.main_splitter.setSizes(new_sizes)

    def clear_line_explanation(self):
        """Clear and hide the line explanation panel"""
        self.line_markdown_content = ""
        self.line_explanation_browser.set_markdown_source("")
        self.line_explanation_browser.setHtml("")
        self.line_explanation_group.setVisible(False)

    def get_line_explanation_content(self) -> str:
        """Get the current line explanation content"""
        return self.line_markdown_content

    def _on_line_close_clicked(self):
        """Handle close button click on line explanation panel"""
        self.clear_line_explanation()
        self.line_explanation_closed.emit()

    def _should_auto_scroll_to_bottom(self):
        """Check if we should auto-scroll to bottom (user is following the explanation)"""
        if not hasattr(self, 'explain_browser'):
            return True

        scrollbar = self.explain_browser.verticalScrollBar()
        if not scrollbar:
            return True

        # Check if user is near the bottom (within 50 pixels)
        current_pos = scrollbar.value()
        max_pos = scrollbar.maximum()

        # If there's no content to scroll, always auto-scroll
        if max_pos <= 0:
            return True

        # User is considered "following" if they're within 50px of bottom
        return (max_pos - current_pos) <= 50

    def _scroll_to_bottom(self):
        """Scroll the text browser to the bottom"""
        if hasattr(self, 'explain_browser'):
            scrollbar = self.explain_browser.verticalScrollBar()
            if scrollbar:
                scrollbar.setValue(scrollbar.maximum())

    def markdown_to_html(self, markdown_text):
        """Convert Markdown text to HTML for display"""
        try:
            html = render_markdown_to_html(markdown_text, include_css=False)
            feedback_html = self._get_feedback_html()

            return f"""
            {MARKDOWN_CSS}
            <div>
                {html}
                {feedback_html}
            </div>
            """
        except:
            return f"<pre>{markdown_text}</pre>"

    def _get_feedback_html(self):
        """Generate HTML for RLHF feedback thumbs up/down links"""
        return """
        <div style='text-align: center; margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd;'>
            <a href='rlhf://upvote' style='text-decoration: none; color: #4CAF50; margin-right: 15px; font-size: 16px;'>&#x2714;&#xFE0F;</a>
            <a href='rlhf://downvote' style='text-decoration: none; color: #F44336; font-size: 16px;'>&#x274C;</a>
        </div>
        """

    def _on_anchor_clicked(self, url):
        """Handle clicks on HTML anchors (specifically RLHF feedback links)"""
        url_str = url.toString()
        if url_str == "rlhf://upvote":
            self.rlhf_feedback_requested.emit(True)
        elif url_str == "rlhf://downvote":
            self.rlhf_feedback_requested.emit(False)

    def _on_explain_function_clicked(self):
        """Handle explain function button click - toggles between explain and stop"""
        if self.function_query_running:
            self.stop_function_requested.emit()
        else:
            self.explain_function_requested.emit()

    def _on_explain_line_clicked(self):
        """Handle explain line button click - toggles between explain and stop"""
        if self.line_query_running:
            self.stop_line_requested.emit()
        else:
            self.explain_line_requested.emit()

    def set_function_query_running(self, running: bool):
        """Update function query running state and button text"""
        self.function_query_running = running
        if running:
            self.explain_function_button.setText("Stop")
            self.explain_function_button.setStyleSheet("background-color: #ff6b6b; color: white;")
            # Disable edit button during query to prevent conflicts
            self.edit_save_button.setEnabled(False)
            self.edit_save_button.setToolTip("Edit mode disabled during query execution")
        else:
            self.explain_function_button.setText("Explain Function")
            self.explain_function_button.setStyleSheet("")
            # Re-enable edit button if no other query is running
            if not self.line_query_running:
                self.edit_save_button.setEnabled(True)
                self.edit_save_button.setToolTip("Toggle edit mode")

    def set_line_query_running(self, running: bool):
        """Update line query running state and button text"""
        self.line_query_running = running
        if running:
            self.explain_line_button.setText("Stop")
            self.explain_line_button.setStyleSheet("background-color: #ff6b6b; color: white;")
            # Disable edit button during query to prevent conflicts
            self.edit_save_button.setEnabled(False)
            self.edit_save_button.setToolTip("Edit mode disabled during query execution")
        else:
            self.explain_line_button.setText("Explain Line")
            self.explain_line_button.setStyleSheet("")
            # Re-enable edit button if no other query is running
            if not self.function_query_running:
                self.edit_save_button.setEnabled(True)
                self.edit_save_button.setToolTip("Toggle edit mode")
