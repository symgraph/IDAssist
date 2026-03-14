#!/usr/bin/env python3

from ..qt_compat import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                         QTableWidget, QTableWidgetItem, QHeaderView,
                         QAbstractItemView, QLabel, QLineEdit, QComboBox,
                         QTextEdit, QSplitter, QGroupBox, Signal, Qt)


class RagTabView(QWidget):
    # Signals for controller communication
    add_documents_requested = Signal()
    refresh_requested = Signal()
    delete_documents_requested = Signal(list)  # list of selected document IDs/names
    search_requested = Signal(str, str)  # query, search_type
    clear_index_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Vertical)

        # Top panel - Document management
        top_panel = self.create_document_panel()
        splitter.addWidget(top_panel)

        # Bottom panel - Search functionality
        bottom_panel = self.create_search_panel()
        splitter.addWidget(bottom_panel)

        # Set initial sizes (70% for documents, 30% for search)
        splitter.setSizes([700, 300])

        layout.addWidget(splitter)
        self.setLayout(layout)

    def create_document_panel(self):
        """Create the document management panel"""
        panel = QGroupBox("Document Management")
        layout = QVBoxLayout()

        # Top row - Add Documents button and stats
        self.create_top_row(layout)

        # RAG documents table
        self.create_documents_table(layout)

        # Bottom row - Refresh and Delete buttons
        self.create_bottom_row(layout)

        panel.setLayout(layout)
        return panel

    def create_search_panel(self):
        """Create the search panel"""
        panel = QGroupBox("Search Documents")
        layout = QVBoxLayout()

        # Search controls
        search_controls = QHBoxLayout()

        # Search input
        search_controls.addWidget(QLabel("Query:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search query...")
        self.search_input.returnPressed.connect(self.on_search_clicked)
        search_controls.addWidget(self.search_input)

        # Search type combo
        search_controls.addWidget(QLabel("Type:"))
        self.search_type_combo = QComboBox()
        self.search_type_combo.addItems(["Hybrid", "Text", "Vector"])
        search_controls.addWidget(self.search_type_combo)

        # Search button
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.on_search_clicked)
        search_controls.addWidget(self.search_button)

        layout.addLayout(search_controls)

        # Search results
        self.search_results = QTextEdit()
        self.search_results.setReadOnly(True)
        self.search_results.setPlaceholderText("Search results will appear here...")
        layout.addWidget(self.search_results)

        panel.setLayout(layout)
        return panel

    def create_top_row(self, parent_layout):
        top_row = QHBoxLayout()

        self.add_documents_button = QPushButton("Add Documents")
        self.add_documents_button.clicked.connect(self.add_documents_requested.emit)
        top_row.addWidget(self.add_documents_button)

        # Stats label
        self.stats_label = QLabel("Documents: 0 | Chunks: 0 | Embeddings: 0")
        self.stats_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        top_row.addWidget(self.stats_label)

        parent_layout.addLayout(top_row)

    def create_documents_table(self, parent_layout):
        self.documents_table = QTableWidget()
        self.documents_table.setColumnCount(3)
        self.documents_table.setHorizontalHeaderLabels(["Name", "Size", "Chunks"])

        # Configure table behavior
        self.documents_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.documents_table.setSelectionMode(QAbstractItemView.ExtendedSelection)  # Allow multi-select

        # Make all columns resizable
        header = self.documents_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # Name column
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Size column
        header.setSectionResizeMode(2, QHeaderView.Interactive)  # Chunks column
        header.setStretchLastSection(True)  # Stretch last column to fill

        # Set initial column widths
        self.documents_table.setColumnWidth(0, 200)  # Name column - wider for filenames
        self.documents_table.setColumnWidth(1, 80)   # Size column - compact for file sizes
        self.documents_table.setColumnWidth(2, 80)   # Chunks column - compact for numbers

        parent_layout.addWidget(self.documents_table)

    def create_bottom_row(self, parent_layout):
        bottom_row = QHBoxLayout()

        self.refresh_button = QPushButton("Refresh")
        self.delete_button = QPushButton("Delete")
        self.clear_index_button = QPushButton("Clear Index")

        # Connect button signals
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.delete_button.clicked.connect(self.on_delete_clicked)
        self.clear_index_button.clicked.connect(self.clear_index_requested.emit)

        bottom_row.addWidget(self.refresh_button)
        bottom_row.addWidget(self.delete_button)
        bottom_row.addStretch()  # Push clear button to the right
        bottom_row.addWidget(self.clear_index_button)

        parent_layout.addLayout(bottom_row)

    def add_document(self, name, size, chunks):
        """Add a document to the RAG documents table"""
        row_count = self.documents_table.rowCount()
        self.documents_table.insertRow(row_count)

        # Name (read-only)
        name_item = QTableWidgetItem(name)
        name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)  # Make read-only
        self.documents_table.setItem(row_count, 0, name_item)

        # Size (read-only)
        size_item = QTableWidgetItem(size)
        size_item.setFlags(size_item.flags() & ~Qt.ItemIsEditable)  # Make read-only
        self.documents_table.setItem(row_count, 1, size_item)

        # Chunks (read-only)
        chunks_item = QTableWidgetItem(str(chunks))
        chunks_item.setFlags(chunks_item.flags() & ~Qt.ItemIsEditable)  # Make read-only
        self.documents_table.setItem(row_count, 2, chunks_item)

    def get_selected_documents(self):
        """Get list of selected document names"""
        selected_documents = []
        for item in self.documents_table.selectedItems():
            if item.column() == 0:  # Only get one item per row (Name column)
                selected_documents.append(item.text())
        return selected_documents

    def remove_selected_documents(self):
        """Remove selected documents from the table"""
        selected_rows = []
        for item in self.documents_table.selectedItems():
            if item.column() == 0:  # Only get one item per row
                selected_rows.append(item.row())

        # Remove rows in reverse order to maintain indices
        for row in sorted(selected_rows, reverse=True):
            self.documents_table.removeRow(row)

    def clear_documents(self):
        """Clear all documents from the table"""
        self.documents_table.setRowCount(0)

    def refresh_documents(self, documents_data):
        """Refresh the documents table with new data"""
        self.clear_documents()
        for doc_data in documents_data:
            self.add_document(doc_data['name'], doc_data['size'], doc_data['chunks'])

    def on_delete_clicked(self):
        """Handle Delete button click"""
        selected_documents = self.get_selected_documents()
        if selected_documents:
            self.delete_documents_requested.emit(selected_documents)

    def on_search_clicked(self):
        """Handle Search button click"""
        query = self.search_input.text().strip()
        if query:
            search_type = self.search_type_combo.currentText().lower()
            self.search_requested.emit(query, search_type)

    def update_stats(self, documents: int, chunks: int, embeddings: int):
        """Update the stats label"""
        self.stats_label.setText(f"Documents: {documents} | Chunks: {chunks} | Embeddings: {embeddings}")

    def set_search_results(self, results_text: str):
        """Set the search results content"""
        self.search_results.setHtml(results_text)

    def clear_search_results(self):
        """Clear the search results"""
        self.search_results.clear()
        self.search_input.clear()

    def populate_sample_data(self):
        """Add some sample RAG documents for testing"""
        self.add_document("malware_analysis.pdf", "2.5 MB", 45)
        self.add_document("reverse_engineering_guide.md", "1.2 MB", 28)
        self.add_document("assembly_reference.txt", "856 KB", 19)
        self.add_document("crypto_algorithms.pdf", "3.1 MB", 62)
