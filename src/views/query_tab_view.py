#!/usr/bin/env python3

from ..qt_compat import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                         QTextBrowser, QTextEdit, QLineEdit, QTableWidget, QTableWidgetItem,
                         QSplitter, QPlainTextEdit, QHeaderView, QAbstractItemView, QSizePolicy, QCheckBox,
                         QApplication, Signal, Qt, QDateTime, QKeySequence, QFontDatabase, exec_dialog,
                         apply_stop_button_style, clear_stop_button_style)

from .streaming_markdown_browser import StreamingMarkdownBrowser
from ..services.streaming.render_update import RenderUpdate
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


class QueryTabView(QWidget):
    CHAT_TYPE_OPTIONS = [
        ("Chat", "chat"),
        ("General", "general"),
        ("Malware Report", "malware_report"),
        ("Vulnerability Analysis", "vuln_analysis"),
        ("API Documentation", "api_doc"),
        ("Notes", "notes"),
    ]

    # Signals for controller communication
    submit_query_requested = Signal(str)  # query text
    stop_query_requested = Signal()
    new_chat_requested = Signal()
    delete_chats_requested = Signal(list)  # list of chat IDs
    chat_selected = Signal(int)  # chat ID
    chat_name_changed = Signal(int, str)  # chat ID, new name
    chat_type_changed = Signal(int, str)  # chat ID, new type
    edit_mode_changed = Signal(bool)
    rag_enabled_changed = Signal(bool)
    mcp_enabled_changed = Signal(bool)
    agentic_enabled_changed = Signal(bool)
    # RLHF feedback signals
    rlhf_feedback_requested = Signal(bool)  # True for upvote, False for downvote

    def __init__(self):
        super().__init__()
        self.is_edit_mode = False
        self.markdown_content = "No chat selected. Click 'New' to start a conversation."
        self.chat_counter = 0
        self.current_chat_id = None
        self.query_running = False
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Top row - Current Offset and Edit/Save button
        self.create_top_row(layout)

        # Create splitter for resizable sections
        self.splitter = QSplitter(Qt.Vertical)

        # Main text widget - HTML browser/Markdown editor
        self.create_main_text_widget()

        # History table
        self.create_history_table()

        # Input text widget
        self.create_input_widget()

        # Add widgets to splitter
        self.splitter.addWidget(self.query_browser)
        self.splitter.addWidget(self.query_editor)
        self.splitter.addWidget(self.history_table)
        self.splitter.addWidget(self.input_widget)

        # Set initial splitter sizes (give more space to main text and input)
        self.splitter.setSizes([400, 400, 80, 100])

        layout.addWidget(self.splitter)

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

        # Agentic mode checkbox (ReAct autonomous agent)
        self.agentic_checkbox = QCheckBox("ReAct Agent")
        self.agentic_checkbox.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.agentic_checkbox.setChecked(False)  # Default disabled
        self.agentic_checkbox.setToolTip("Enable ReAct autonomous agent for complex investigations")
        self.agentic_checkbox.toggled.connect(self.agentic_enabled_changed.emit)

        # Size-constrained Edit button
        self.edit_save_button = QPushButton("Edit")
        self.edit_save_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.edit_save_button.clicked.connect(self.toggle_edit_mode)

        top_row.addWidget(offset_label)
        top_row.addWidget(self.current_offset_label)
        top_row.addStretch()  # Push checkboxes and button to the right
        top_row.addWidget(self.rag_checkbox)
        top_row.addWidget(self.mcp_checkbox)
        top_row.addWidget(self.agentic_checkbox)
        top_row.addWidget(self.edit_save_button)

        parent_layout.addLayout(top_row)

    def create_main_text_widget(self):
        # HTML browser for read-only mode (uses StreamingMarkdownBrowser for responsive streaming)
        self.query_browser = StreamingMarkdownBrowser()
        self.query_browser.set_markdown_source(self.markdown_content)
        self.query_browser.setHtml(self.markdown_to_html(self.markdown_content))
        self.query_browser.anchorClicked.connect(self._on_anchor_clicked)
        # Prevent default navigation for custom protocols
        self.query_browser.setOpenLinks(False)

        # Track user scroll actions to detect when they scroll away from bottom
        self._auto_scroll_enabled = True
        self._programmatic_scroll = False  # Flag to ignore our own scroll commands
        self.query_browser.verticalScrollBar().valueChanged.connect(self._on_scroll_changed)

        # Text editor for edit mode
        self.query_editor = QTextEdit()
        self.query_editor.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.query_editor.setPlainText(self.markdown_content)
        self.query_editor.hide()  # Hidden by default

        # ESC key discards edits and returns to view mode
        from ..qt_compat import QShortcut
        esc_shortcut = QShortcut(QKeySequence(Qt.Key_Escape), self.query_editor)
        esc_shortcut.setContext(Qt.WidgetShortcut)
        esc_shortcut.activated.connect(self.cancel_edit_mode)

    def create_history_table(self):
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(3)
        self.history_table.setHorizontalHeaderLabels(["Description", "Timestamp", "Type"])

        # Configure table behavior
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.ExtendedSelection)  # Allow multi-select
        self.history_table.itemSelectionChanged.connect(self.on_history_selection_changed)
        self.history_table.itemDoubleClicked.connect(self.on_history_item_double_clicked)
        self.history_table.itemChanged.connect(self.on_history_item_changed)

        # Enable sorting and set default sort order (timestamp descending - newest first)
        self.history_table.setSortingEnabled(True)
        self.history_table.sortByColumn(1, Qt.DescendingOrder)  # Sort by timestamp column, descending

        # Make table columns resizable
        header = self.history_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)

        # Set default height to show 3 rows
        row_height = self.history_table.verticalHeader().defaultSectionSize()
        header_height = self.history_table.horizontalHeader().height()
        self.history_table.setMinimumHeight(header_height + (row_height * 3))  # +10 for margins
        self._update_history_table_layout()

    def create_input_widget(self):
        self.input_widget = QPlainTextEdit()
        self.input_widget.setPlaceholderText("Enter your query here...\nUse #func, #addr, #line, #range(start, end) for context macros.\n(Press Enter to submit, Ctrl+Enter for new line)")
        # self.input_widget.setMaximumHeight(100)  # Limit initial height

        # Handle key events for Enter and Ctrl+Enter
        self.input_widget.keyPressEvent = self.input_key_press_event

    def create_bottom_row(self, parent_layout):
        bottom_row = QHBoxLayout()

        self.submit_button = QPushButton("Submit")
        self.new_button = QPushButton("New")
        self.delete_button = QPushButton("Delete")

        # Connect button signals
        self.submit_button.clicked.connect(self.on_submit_clicked)
        self.new_button.clicked.connect(self.new_chat_requested.emit)
        self.delete_button.clicked.connect(self.on_delete_clicked)

        bottom_row.addWidget(self.submit_button)
        bottom_row.addWidget(self.new_button)
        bottom_row.addWidget(self.delete_button)

        parent_layout.addLayout(bottom_row)

    def input_key_press_event(self, event):
        """Handle Enter and Ctrl+Enter in input widget"""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            if event.modifiers() == Qt.ControlModifier:
                # Ctrl+Enter: Insert newline
                self.input_widget.insertPlainText("\n")
            else:
                # Enter: Submit query (or stop if running)
                self.on_submit_clicked()
        else:
            # Default behavior for other keys
            QPlainTextEdit.keyPressEvent(self.input_widget, event)

    def toggle_edit_mode(self):
        # Prevent edit mode changes during query execution
        if self.query_running:
            return

        self.is_edit_mode = not self.is_edit_mode

        # Save history and input panel sizes before the swap
        old_sizes = self.splitter.sizes()
        history_size = old_sizes[2] if len(old_sizes) >= 3 else 80
        input_size = old_sizes[3] if len(old_sizes) >= 4 else 100

        if self.is_edit_mode:
            self.query_browser.hide()
            self.query_editor.show()
            self.edit_save_button.setText("Save")
            # Don't set content here - let the controller prepare proper editable content
            # via set_chat_content() after receiving edit_mode_changed signal
        else:
            self.query_editor.hide()
            self.query_browser.show()
            self.edit_save_button.setText("Edit")
            # Store edited content for the controller to save
            self.markdown_content = self.query_editor.toPlainText()
            self.query_browser.setHtml(self.markdown_to_html(self.markdown_content))
            self.query_browser.set_markdown_source(self.markdown_content)

        # Restore: give all remaining space to the active text widget
        total = sum(self.splitter.sizes())
        active_size = total - history_size - input_size
        if self.is_edit_mode:
            self.splitter.setSizes([0, active_size, history_size, input_size])
        else:
            self.splitter.setSizes([active_size, 0, history_size, input_size])

        self.edit_mode_changed.emit(self.is_edit_mode)

    def cancel_edit_mode(self):
        """Discard edits and return to view mode without saving"""
        if not self.is_edit_mode:
            return
        self.is_edit_mode = False
        old_sizes = self.splitter.sizes()
        history_size = old_sizes[2] if len(old_sizes) >= 3 else 80
        input_size = old_sizes[3] if len(old_sizes) >= 4 else 100
        self.query_editor.hide()
        self.query_browser.show()
        self.edit_save_button.setText("Edit")
        total = sum(self.splitter.sizes())
        active_size = total - history_size - input_size
        self.splitter.setSizes([active_size, 0, history_size, input_size])

    def on_submit_clicked(self):
        """Handle submit button click - toggles between submit and stop"""
        if self.query_running:
            self.stop_query_requested.emit()
        else:
            query_text = self.input_widget.toPlainText().strip()
            if query_text:
                self.submit_query_requested.emit(query_text)
                self.input_widget.clear()  # Clear input after submit

    def on_delete_clicked(self):
        selected_rows = sorted({item.row() for item in self.history_table.selectedItems()})

        if selected_rows:
            self.delete_chats_requested.emit(selected_rows)

    def on_history_selection_changed(self):
        selected_rows = {item.row() for item in self.history_table.selectedItems()}
        if len(selected_rows) == 1:
            row = next(iter(selected_rows))
            chat_id = self.history_table.item(row, 0).data(Qt.UserRole)  # Store chat ID in user data
            if chat_id is not None:
                self.current_chat_id = chat_id
                self.chat_selected.emit(chat_id)

    def on_history_item_double_clicked(self, item):
        if item.column() == 0:  # Description column
            # Enable editing for the description
            self.history_table.editItem(item)

    def on_history_item_changed(self, item):
        """Handle when a history table item is edited"""
        if item.column() == 0:  # Description column
            # Get the chat ID and new name
            chat_id = item.data(Qt.UserRole)
            new_name = item.text().strip()

            if chat_id is not None and new_name:
                # Emit signal to notify controller of the name change
                self.chat_name_changed.emit(chat_id, new_name)

    def add_chat_to_history(self, chat_id, description, timestamp=None, chat_type="chat"):
        """Add a new chat entry to the history table"""
        if timestamp is None:
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")

        # Temporarily disable sorting and item change signals while adding the item
        was_sorting_enabled = self.history_table.isSortingEnabled()
        self.history_table.setSortingEnabled(False)

        # Temporarily disconnect itemChanged signal to prevent false triggers during loading
        self.history_table.itemChanged.disconnect()

        row_count = self.history_table.rowCount()
        self.history_table.insertRow(row_count)

        desc_item = QTableWidgetItem(description)
        desc_item.setData(Qt.UserRole, chat_id)  # Store chat ID
        timestamp_item = QTableWidgetItem(timestamp)
        timestamp_item.setFlags(timestamp_item.flags() & ~Qt.ItemIsEditable)  # Make timestamp read-only

        self.history_table.setItem(row_count, 0, desc_item)
        self.history_table.setItem(row_count, 1, timestamp_item)
        self.set_chat_type_cell(row_count, chat_id, chat_type)

        # Reconnect the itemChanged signal
        self.history_table.itemChanged.connect(self.on_history_item_changed)

        # Re-enable sorting if it was enabled before
        if was_sorting_enabled:
            self.history_table.setSortingEnabled(True)
            # Trigger a sort to ensure proper order (newest first)
            self.history_table.sortByColumn(1, Qt.DescendingOrder)

        # Find and select the new chat (it may have moved due to sorting)
        self._select_chat_by_id(chat_id)
        self.current_chat_id = chat_id
        self._update_history_table_layout()

    def _select_chat_by_id(self, chat_id):
        """Find and select a chat by its ID in the history table"""
        for row in range(self.history_table.rowCount()):
            item = self.history_table.item(row, 0)  # Description column
            if item and item.data(Qt.UserRole) == chat_id:
                self.history_table.selectRow(row)
                return
        # If not found, select the first row as fallback
        if self.history_table.rowCount() > 0:
            self.history_table.selectRow(0)

    def remove_selected_chats(self):
        """Remove selected chats from history table"""
        selected_rows = sorted({item.row() for item in self.history_table.selectedItems()})

        # Remove rows in reverse order to maintain indices
        for row in sorted(selected_rows, reverse=True):
            self.history_table.removeRow(row)
        self._update_history_table_layout()

        # Clear current chat if it was deleted
        if not self.history_table.rowCount():
            self.current_chat_id = None
            self.set_chat_content("No chat selected. Click 'New' to start a conversation.")

    def set_current_offset(self, offset_hex):
        """Update the displayed current offset"""
        self.current_offset_label.setText(offset_hex)

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

    def is_agentic_enabled(self):
        """Get the current state of the Agentic checkbox"""
        return self.agentic_checkbox.isChecked()

    def set_agentic_enabled(self, enabled):
        """Set the Agentic checkbox state"""
        self.agentic_checkbox.setChecked(enabled)

    def set_query_running(self, running: bool):
        """Update query running state and button text"""
        self.query_running = running
        if running:
            self.submit_button.setText("Stop")
            apply_stop_button_style(self.submit_button)
            # Disable edit button during query to prevent conflicts
            self.edit_save_button.setEnabled(False)
            self.edit_save_button.setToolTip("Edit mode disabled during query execution")
        else:
            self.submit_button.setText("Submit")
            clear_stop_button_style(self.submit_button)
            # Re-enable edit button
            self.edit_save_button.setEnabled(True)
            self.edit_save_button.setToolTip("Toggle edit mode")

    def set_chat_content(self, markdown_text):
        """Set the chat content (in Markdown format)"""
        self.markdown_content = markdown_text

        if not self.is_edit_mode:
            # Save scroll position before updating
            scrollbar = self.query_browser.verticalScrollBar()
            old_value = scrollbar.value() if scrollbar else 0
            should_auto_scroll = self._auto_scroll_enabled

            # Set flag to ignore scroll events during the entire update cycle
            # This stays True until after the deferred scroll completes
            self._programmatic_scroll = True

            # Store markdown source for copy operations
            self.query_browser.set_markdown_source(markdown_text)

            html_content = self.markdown_to_html(markdown_text)
            self.query_browser.setHtml(html_content)

            # Defer scroll restoration until after Qt processes the layout change
            # This ensures scrollbar.maximum() reflects the new content size
            from ..qt_compat import QTimer
            if should_auto_scroll:
                # User wants to follow new content - scroll to bottom
                def scroll_to_bottom():
                    try:
                        scrollbar.setValue(scrollbar.maximum())
                    except RuntimeError:
                        pass  # C++ object deleted
                    self._programmatic_scroll = False
                QTimer.singleShot(0, scroll_to_bottom)
            else:
                # User is reading elsewhere - preserve absolute position
                def restore_scroll():
                    try:
                        if scrollbar:
                            scrollbar.setValue(old_value)
                    except RuntimeError:
                        pass  # C++ object deleted
                    self._programmatic_scroll = False
                QTimer.singleShot(0, restore_scroll)
        else:
            self.query_editor.setPlainText(markdown_text)

    def get_chat_content(self):
        """Get the current chat content"""
        if self.is_edit_mode:
            return self.query_editor.toPlainText()
        return self.markdown_content

    def create_chat_type_combo(self, chat_id: int, chat_type: str):
        from ..qt_compat import QComboBox

        combo = QComboBox()
        for label, value in self.CHAT_TYPE_OPTIONS:
            combo.addItem(label, value)
        combo_index = combo.findData(chat_type)
        combo.setCurrentIndex(combo_index if combo_index >= 0 else 0)
        combo.currentIndexChanged.connect(
            lambda _index, widget=combo, cid=chat_id: self.chat_type_changed.emit(
                cid, widget.currentData() or "chat"
            )
        )
        return combo

    def set_chat_type_cell(self, row: int, chat_id: int, chat_type: str):
        self.history_table.setCellWidget(row, 2, self.create_chat_type_combo(chat_id, chat_type))
        self._update_history_table_layout()

    def _update_history_table_layout(self):
        if not hasattr(self, "history_table"):
            return

        self.history_table.resizeColumnToContents(1)
        self.history_table.resizeColumnToContents(2)
        self.history_table.setColumnWidth(1, max(150, self.history_table.columnWidth(1)))
        self.history_table.setColumnWidth(2, max(160, self.history_table.columnWidth(2)))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_history_table_layout()

    def get_next_chat_name(self):
        """Generate next chat name (Chat 1, Chat 2, etc.)"""
        self.chat_counter += 1
        return f"Chat {self.chat_counter}"

    def _on_scroll_changed(self, value):
        """
        Handle scroll position changes to detect user-initiated scrolling.

        When streaming content, we want to:
        - Auto-scroll to bottom if user hasn't manually scrolled away
        - Stop auto-scrolling if user scrolls up to read earlier content
        - Resume auto-scrolling if user scrolls back to bottom
        """
        # Ignore scroll changes we initiated programmatically
        if self._programmatic_scroll:
            return

        scrollbar = self.query_browser.verticalScrollBar()
        if not scrollbar:
            return

        max_pos = scrollbar.maximum()

        # No content to scroll - stay in auto-scroll mode
        if max_pos <= 0:
            return

        # Check if user is near bottom (within 50px)
        at_bottom = (max_pos - value) <= 50

        # Update auto-scroll state based on where user scrolled
        # If they scrolled to bottom, enable auto-scroll
        # If they scrolled away from bottom, disable auto-scroll
        self._auto_scroll_enabled = at_bottom

    def enable_auto_scroll(self):
        """Enable auto-scrolling (call when starting a new query)"""
        self._auto_scroll_enabled = True

    def is_auto_scroll_enabled(self):
        """Check if auto-scroll is currently enabled"""
        return getattr(self, '_auto_scroll_enabled', True)

    def _scroll_to_bottom(self):
        """Scroll the text browser to the bottom (programmatically)"""
        if hasattr(self, 'query_browser'):
            scrollbar = self.query_browser.verticalScrollBar()
            if scrollbar:
                # Set flag to ignore this scroll in our handler
                self._programmatic_scroll = True
                scrollbar.setValue(scrollbar.maximum())
                self._programmatic_scroll = False

    def begin_streaming(self, chat_history_html: str) -> None:
        """Begin streaming session by setting static chat history."""
        if not self.is_edit_mode:
            self.query_browser.setHtml(chat_history_html)
            self.query_browser._committed_html = chat_history_html
            self.query_browser._pending_start = self.query_browser.document().characterCount()
            self._auto_scroll_enabled = True

    def apply_streaming_update(self, update: RenderUpdate) -> None:
        """Apply incremental streaming update during active stream."""
        if not self.is_edit_mode:
            self.query_browser.apply_render_update(update)

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
