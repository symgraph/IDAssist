#!/usr/bin/env python3

from ..qt_compat import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                         QLineEdit, QTableWidget, QTableWidgetItem, QListWidget,
                         QListWidgetItem, QCheckBox, QHeaderView, QAbstractItemView,
                         QSplitter, QSizePolicy, Signal, Qt, QColor,
                         apply_stop_button_style, clear_stop_button_style)


class ActionsTabView(QWidget):
    # Signals for controller communication
    analyse_function_requested = Signal()
    apply_actions_requested = Signal(list)  # list of selected action data
    clear_actions_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Top row - Current Offset (consistent with other tabs)
        self.create_top_row(layout)

        # Create splitter for proposed actions table and available actions list
        self.splitter = QSplitter(Qt.Vertical)

        # Proposed actions table
        self.create_proposed_actions_table()

        # Available actions list
        self.create_available_actions_list()

        # Add widgets to splitter
        self.splitter.addWidget(self.proposed_actions_table)
        self.splitter.addWidget(self.available_actions_list)

        # Set initial splitter sizes (more space for proposed actions)
        self.splitter.setSizes([300, 150])

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

        top_row.addWidget(offset_label)
        top_row.addWidget(self.current_offset_label)
        top_row.addStretch()  # Fill remaining space

        parent_layout.addLayout(top_row)

    def create_proposed_actions_table(self):
        self.proposed_actions_table = QTableWidget()
        self.proposed_actions_table.setColumnCount(5)
        self.proposed_actions_table.setHorizontalHeaderLabels([
            "Select", "Action", "Description", "Status", "Confidence"
        ])

        # Configure table behavior
        self.proposed_actions_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.proposed_actions_table.setSelectionMode(QAbstractItemView.ExtendedSelection)

        # Make all columns resizable
        header = self.proposed_actions_table.horizontalHeader()
        for i in range(5):
            header.setSectionResizeMode(i, QHeaderView.Interactive)

        # Set initial column widths
        self.proposed_actions_table.setColumnWidth(0, 60)   # Select checkbox
        self.proposed_actions_table.setColumnWidth(1, 120)  # Action
        self.proposed_actions_table.setColumnWidth(2, 200)  # Description
        self.proposed_actions_table.setColumnWidth(3, 80)   # Status
        self.proposed_actions_table.setColumnWidth(4, 100)  # Confidence

        # Connect double-click for editing
        self.proposed_actions_table.itemDoubleClicked.connect(self.on_proposed_action_double_clicked)

    def create_available_actions_list(self):
        self.available_actions_list = QListWidget()

        # Actions will be populated by the controller
        # Set a reasonable minimum height
        self.available_actions_list.setMinimumHeight(80)

    def create_bottom_row(self, parent_layout):
        bottom_row = QHBoxLayout()

        self.analyse_function_button = QPushButton("Analyse Function")
        self.apply_actions_button = QPushButton("Apply Actions")
        self.clear_button = QPushButton("Clear")

        # Connect button signals
        self.analyse_function_button.clicked.connect(self.analyse_function_requested.emit)
        self.apply_actions_button.clicked.connect(self.on_apply_actions_clicked)
        self.clear_button.clicked.connect(self.clear_actions_requested.emit)

        bottom_row.addWidget(self.analyse_function_button)
        bottom_row.addWidget(self.apply_actions_button)
        bottom_row.addWidget(self.clear_button)

        parent_layout.addLayout(bottom_row)

    def add_available_action(self, action_name, description):
        """Add an action to the available actions list with checkbox"""
        item = QListWidgetItem()
        checkbox = QCheckBox(f"{action_name} - {description}")
        item.setSizeHint(checkbox.sizeHint())
        self.available_actions_list.addItem(item)
        self.available_actions_list.setItemWidget(item, checkbox)

    def add_proposed_action(self, action, description, status="Pending", confidence="", selected=False):
        """Add a proposed action to the table"""
        row_count = self.proposed_actions_table.rowCount()
        self.proposed_actions_table.insertRow(row_count)

        # Select checkbox (centered)
        checkbox_widget = QWidget()
        checkbox_layout = QHBoxLayout(checkbox_widget)
        select_checkbox = QCheckBox()
        select_checkbox.setChecked(selected)
        checkbox_layout.addWidget(select_checkbox)
        checkbox_layout.setAlignment(Qt.AlignCenter)
        checkbox_layout.setContentsMargins(0, 0, 0, 0)
        self.proposed_actions_table.setCellWidget(row_count, 0, checkbox_widget)

        # Action (editable)
        action_item = QTableWidgetItem(action)
        self.proposed_actions_table.setItem(row_count, 1, action_item)

        # Description (editable)
        desc_item = QTableWidgetItem(description)
        self.proposed_actions_table.setItem(row_count, 2, desc_item)

        # Status (editable)
        status_item = QTableWidgetItem(status)
        self.proposed_actions_table.setItem(row_count, 3, status_item)

        # Confidence (editable)
        confidence_item = QTableWidgetItem(confidence)
        self.proposed_actions_table.setItem(row_count, 4, confidence_item)

        # Auto-resize Action and Description columns to fit contents
        self.proposed_actions_table.resizeColumnToContents(1)  # Action column
        self.proposed_actions_table.resizeColumnToContents(2)  # Description column

    def get_selected_available_actions(self):
        """Get list of selected available actions"""
        selected_actions = []
        for i in range(self.available_actions_list.count()):
            item = self.available_actions_list.item(i)
            checkbox = self.available_actions_list.itemWidget(item)
            if checkbox and checkbox.isChecked():
                selected_actions.append(checkbox.text())
        return selected_actions

    def get_selected_proposed_actions(self):
        """Get list of selected proposed actions with their data"""
        selected_actions = []
        for row in range(self.proposed_actions_table.rowCount()):
            checkbox_widget = self.proposed_actions_table.cellWidget(row, 0)
            if checkbox_widget:
                # Find the checkbox within the widget
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    desc_item = self.proposed_actions_table.item(row, 2)
                    action_data = {
                        'action': self.proposed_actions_table.item(row, 1).text() if self.proposed_actions_table.item(row, 1) else "",
                        'description': desc_item.text() if desc_item else "",
                        'status': self.proposed_actions_table.item(row, 3).text() if self.proposed_actions_table.item(row, 3) else "",
                        'confidence': self.proposed_actions_table.item(row, 4).text() if self.proposed_actions_table.item(row, 4) else "",
                        'view_level': desc_item.data(Qt.UserRole) if desc_item else None,
                    }
                    selected_actions.append(action_data)
        return selected_actions

    def clear_proposed_actions(self):
        """Clear all proposed actions from the table"""
        self.proposed_actions_table.setRowCount(0)

    def set_current_offset(self, offset_hex):
        """Update the displayed current offset"""
        self.current_offset_label.setText(offset_hex)

    def on_proposed_action_double_clicked(self, item):
        """Handle double-click on proposed action items for editing"""
        if item.column() in [1, 2, 3, 4]:  # Action, Description, Status, Confidence columns
            # Enable editing for the item
            self.proposed_actions_table.editItem(item)

    def on_apply_actions_clicked(self):
        """Handle Apply Actions button click"""
        selected_actions = self.get_selected_proposed_actions()
        if selected_actions:
            self.apply_actions_requested.emit(selected_actions)

    def populate_sample_data(self):
        """Add some sample proposed actions for testing"""
        self.add_proposed_action(
            "rename_function",
            "Rename function to 'calculate_hash'",
            "Ready",
            "0.85"
        )
        self.add_proposed_action(
            "add_comment",
            "Add comment explaining hash algorithm",
            "Pending",
            "0.72"
        )
        self.add_proposed_action(
            "create_struct",
            "Define structure for data layout",
            "Ready",
            "0.91"
        )

    def update_action_status(self, action_data, status_info):
        """Update the status of a specific action in the table"""
        try:
            # Find the matching row based on description
            target_description = action_data.get('description', '')

            for row in range(self.proposed_actions_table.rowCount()):
                desc_item = self.proposed_actions_table.item(row, 2)  # Description column
                if desc_item and desc_item.text() == target_description:
                    # Update the status column (column 3)
                    status_item = self.proposed_actions_table.item(row, 3)
                    if status_item:
                        if status_info.get('applying', False):
                            status_item.setText("Applying...")
                            # Change row color to indicate in progress
                            status_item.setBackground(QColor(255, 255, 224))  # Light yellow
                        elif status_info.get('success', False):
                            status_item.setText("Applied")
                            # Change row color to indicate success
                            status_item.setBackground(QColor(144, 238, 144))  # Light green
                        else:
                            error_msg = status_info.get('error', 'Unknown error')
                            status_item.setText(f"Error: {error_msg}")
                            # Change row color to indicate error
                            status_item.setBackground(QColor(255, 182, 193))  # Light red
                    break

        except Exception as e:
            print(f"Error updating action status: {e}")

    def set_busy_state(self, busy: bool, message: str = ""):
        """Update UI for busy/analysis state"""
        if busy:
            if "Applying" in message:
                # When applying actions, disable analyze button but keep apply button enabled
                self.analyse_function_button.setEnabled(False)
                self.clear_button.setEnabled(False)
            else:
                # When analyzing, show stop button
                self.analyse_function_button.setText("Stop")
                apply_stop_button_style(self.analyse_function_button)
                self.apply_actions_button.setEnabled(False)
                self.clear_button.setEnabled(False)
        else:
            self.analyse_function_button.setText("Analyse Function")
            clear_stop_button_style(self.analyse_function_button)
            self.analyse_function_button.setEnabled(True)
            self.apply_actions_button.setEnabled(True)
            self.clear_button.setEnabled(True)

            # Force UI update
            self.analyse_function_button.update()
            self.apply_actions_button.update()
            self.clear_button.update()
