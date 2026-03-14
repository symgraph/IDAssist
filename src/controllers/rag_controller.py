#!/usr/bin/env python3

import os
from typing import List, Optional
from ..qt_compat import QFileDialog, QMessageBox, QThread, Signal, exec_dialog

from src.services.rag_service import rag_service
from src.services.models.rag_models import IngestRequest, SearchRequest, SearchType

from src.ida_compat import log


class DocumentIngestionThread(QThread):
    """Thread for handling document ingestion in background"""
    ingestion_complete = Signal(bool, str)  # success, message
    progress_update = Signal(str)  # status message

    def __init__(self, file_paths: List[str], generate_embeddings: bool = True):
        super().__init__()
        self.file_paths = file_paths
        self.generate_embeddings = generate_embeddings

    def run(self):
        """Execute document ingestion in background thread"""
        try:
            self.progress_update.emit(f"Ingesting {len(self.file_paths)} documents...")

            request = IngestRequest(
                file_paths=self.file_paths,
                generate_embeddings=self.generate_embeddings,
                chunk_size=500,
                max_snippet_length=500
            )

            success = rag_service.ingest_documents(request)

            if success:
                self.ingestion_complete.emit(True, f"Successfully ingested {len(self.file_paths)} documents")
            else:
                self.ingestion_complete.emit(False, "Failed to ingest some documents")

        except Exception as e:
            self.ingestion_complete.emit(False, f"Error during ingestion: {str(e)}")


class RAGController:
    """Controller for the RAG tab functionality"""

    def __init__(self, view):
        self.view = view
        self.ingestion_thread = None

        # Connect view signals
        self._connect_signals()

        # Load initial data
        self.refresh_documents()
        self.update_stats()

    def _connect_signals(self):
        """Connect view signals to controller methods"""
        self.view.add_documents_requested.connect(self.add_documents)
        self.view.refresh_requested.connect(self.refresh_documents)
        self.view.delete_documents_requested.connect(self.delete_documents)
        self.view.search_requested.connect(self.search_documents)
        self.view.clear_index_requested.connect(self.clear_index)

    def add_documents(self):
        """Handle add documents request"""
        log.log_info("Add documents requested")

        # Open file dialog
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        file_dialog.setNameFilters([
            "Text Files (*.txt *.md *.rst)",
            "PDF Files (*.pdf)",
            "All Files (*.*)"
        ])
        file_dialog.setWindowTitle("Select Documents to Add to RAG Index")

        if exec_dialog(file_dialog):
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                self._ingest_documents(selected_files)

    def _ingest_documents(self, file_paths: List[str]):
        """Ingest documents in background thread"""
        log.log_info(f"Starting ingestion of {len(file_paths)} documents")

        # Show processing message
        self._show_info_message("Processing", f"Ingesting {len(file_paths)} documents. This may take a while...")

        # Create and start ingestion thread
        self.ingestion_thread = DocumentIngestionThread(file_paths, generate_embeddings=True)
        self.ingestion_thread.ingestion_complete.connect(self._on_ingestion_complete)
        self.ingestion_thread.progress_update.connect(self._on_progress_update)
        self.ingestion_thread.start()

    def _on_progress_update(self, message: str):
        """Handle progress updates from ingestion thread"""
        log.log_info(f"Ingestion progress: {message}")
        # Could update a progress bar here if we add one to the UI

    def _on_ingestion_complete(self, success: bool, message: str):
        """Handle completion of document ingestion"""
        log.log_info(f"Ingestion complete: {success} - {message}")

        # Clean up thread
        if self.ingestion_thread:
            self.ingestion_thread.deleteLater()
            self.ingestion_thread = None

        # Show result message
        if success:
            self._show_info_message("Success", message)
            # Refresh the documents list and stats
            self.refresh_documents()
            self.update_stats()
        else:
            self._show_error_message("Ingestion Failed", message)

    def refresh_documents(self):
        """Handle refresh documents request"""
        log.log_info("Refresh documents requested")

        try:
            # Get documents from RAG service
            documents = rag_service.list_documents()

            # Convert to format expected by view
            documents_data = []
            for doc in documents:
                # Format file size
                size_mb = doc.file_size / (1024 * 1024)
                if size_mb >= 1.0:
                    size_str = f"{size_mb:.1f} MB"
                else:
                    size_kb = doc.file_size / 1024
                    size_str = f"{size_kb:.1f} KB"

                documents_data.append({
                    'name': doc.filename,
                    'size': size_str,
                    'chunks': doc.chunk_count
                })

            # Update view
            self.view.refresh_documents(documents_data)
            log.log_info(f"Refreshed {len(documents)} documents")

        except Exception as e:
            error_msg = f"Failed to refresh documents: {str(e)}"
            log.log_error(error_msg)
            self._show_error_message("Refresh Failed", error_msg)

    def delete_documents(self, document_names: List[str]):
        """Handle delete documents request"""
        log.log_info(f"Delete documents requested: {document_names}")

        if not document_names:
            return

        # Confirm deletion
        reply = QMessageBox.question(
            self.view,
            "Confirm Deletion",
            f"Are you sure you want to delete {len(document_names)} document(s) from the RAG index?\n\n"
            f"Documents: {', '.join(document_names)}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self._delete_documents(document_names)

    def _delete_documents(self, document_names: List[str]):
        """Delete documents from RAG service"""
        try:
            # Delete documents
            results = rag_service.delete_documents(document_names)

            # Check results
            successful_deletes = [name for name, success in results.items() if success]
            failed_deletes = [name for name, success in results.items() if not success]

            # Show results
            if successful_deletes:
                if failed_deletes:
                    message = f"Successfully deleted {len(successful_deletes)} documents.\n"
                    message += f"Failed to delete {len(failed_deletes)} documents: {', '.join(failed_deletes)}"
                    self._show_warning_message("Partial Success", message)
                else:
                    self._show_info_message("Success", f"Successfully deleted {len(successful_deletes)} documents")

                # Remove from view
                self.view.remove_selected_documents()

                # Refresh to ensure consistency
                self.refresh_documents()
                self.update_stats()
            else:
                self._show_error_message("Deletion Failed", f"Failed to delete documents: {', '.join(failed_deletes)}")

        except Exception as e:
            error_msg = f"Error deleting documents: {str(e)}"
            log.log_error(error_msg)
            self._show_error_message("Deletion Error", error_msg)

    def get_rag_stats(self):
        """Get RAG service statistics"""
        try:
            return rag_service.get_stats()
        except Exception as e:
            log.log_error(f"Failed to get RAG stats: {e}")
            return None

    def clear_index(self):
        """Clear the entire RAG index"""
        log.log_info("Clear RAG index requested")

        # Confirm clearing
        reply = QMessageBox.question(
            self.view,
            "Confirm Clear Index",
            "Are you sure you want to clear the entire RAG index?\n\n"
            "This will delete all indexed documents and cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                success = rag_service.clear_index()
                if success:
                    self._show_info_message("Success", "RAG index cleared successfully")
                    self.refresh_documents()
                    self.update_stats()
                else:
                    self._show_error_message("Clear Failed", "Failed to clear RAG index")
            except Exception as e:
                error_msg = f"Error clearing RAG index: {str(e)}"
                log.log_error(error_msg)
                self._show_error_message("Clear Error", error_msg)

    def search_documents(self, query: str, search_type_str: str):
        """Search documents using RAG service"""
        log.log_info(f"Search requested: '{query}' (type: {search_type_str})")

        try:
            # Convert string to SearchType enum
            search_type_map = {
                'hybrid': SearchType.HYBRID,
                'text': SearchType.TEXT,
                'vector': SearchType.VECTOR
            }
            search_type = search_type_map.get(search_type_str.lower(), SearchType.HYBRID)

            # Use different thresholds for different search types
            if search_type == SearchType.VECTOR:
                threshold = 0.2  # 20% for TF-IDF vector search (lower due to cosine similarity)
            else:
                threshold = 0.5  # 50% for text and hybrid search

            request = SearchRequest(
                query=query,
                search_type=search_type,
                max_results=5,  # Top 5 results
                similarity_threshold=threshold,
                include_metadata=True
            )

            results = rag_service.search(request)
            log.log_info(f"Search for '{query}' returned {len(results)} results")

            # Format results for display
            if results:
                results_html = self._format_search_results(results, query)
                self.view.set_search_results(results_html)
            else:
                self.view.set_search_results("<p><i>No results found.</i></p>")

            return results

        except Exception as e:
            error_msg = f"Search failed: {str(e)}"
            log.log_error(error_msg)
            self.view.set_search_results(f"<p><b>Error:</b> {error_msg}</p>")
            return []

    def _format_search_results(self, results, query: str) -> str:
        """Format search results as HTML"""
        html = f"<h3>Search Results for '{query}' ({len(results)} found)</h3>"

        for i, result in enumerate(results, 1):
            # Ensure score is in 0-1 range and convert to percentage
            score_normalized = max(0, min(1, result.score))
            score_percent = int(score_normalized * 100)

            html += f"""
            <div style='border: 1px solid #ccc; margin: 10px 0; padding: 10px; border-radius: 5px;'>
                <h4 style='margin: 0 0 5px 0; color: #2c5282;'>{i}. {result.filename}</h4>
                <p style='margin: 0 0 5px 0; font-size: 12px; color: #666;'>
                    Score: {score_percent}% | Type: {result.search_type.value} | Chunk: {result.chunk_id}
                </p>
                <p style='margin: 0; font-size: 13px;'>{result.snippet}</p>
            </div>
            """

        return html

    def update_stats(self):
        """Update the stats display"""
        try:
            stats = rag_service.get_stats()
            if stats:
                self.view.update_stats(
                    documents=stats.indexed_documents,
                    chunks=stats.total_chunks,
                    embeddings=stats.cached_embeddings
                )
        except Exception as e:
            log.log_error(f"Failed to update stats: {e}")

    # Utility methods for showing messages

    def _show_info_message(self, title: str, message: str):
        """Show info message box"""
        QMessageBox.information(self.view, title, message)

    def _show_warning_message(self, title: str, message: str):
        """Show warning message box"""
        QMessageBox.warning(self.view, title, message)

    def _show_error_message(self, title: str, message: str):
        """Show error message box"""
        QMessageBox.critical(self.view, title, message)
