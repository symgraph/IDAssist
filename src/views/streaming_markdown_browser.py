#!/usr/bin/env python3

from ..qt_compat import (QTextBrowser, QAbstractScrollArea, QApplication,
                         QTextCursor, QKeySequence, exec_dialog)

from ..services.streaming.render_update import RenderUpdate, UpdateType
from ..services.streaming.streaming_renderer import MARKDOWN_CSS

_BOTTOM_THRESHOLD = 50


class ScrollPositionTracker:
    """Track scroll position to preserve user's reading position.

    Looks up the scrollbar on every call instead of caching it, because
    setHtml() can destroy and recreate internal Qt widgets (including the
    scrollbar), leaving a cached reference as a dangling C++ pointer.
    """

    def __init__(self, scroll_area: QAbstractScrollArea):
        self._scroll_area = scroll_area

    def _bar(self):
        return self._scroll_area.verticalScrollBar()

    def is_at_bottom(self) -> bool:
        bar = self._bar()
        return (bar.maximum() - bar.value() <= _BOTTOM_THRESHOLD)

    def scroll_to_bottom(self) -> None:
        bar = self._bar()
        bar.setValue(bar.maximum())

    def get_scroll_value(self) -> int:
        return self._bar().value()

    def set_scroll_value(self, value: int) -> None:
        self._bar().setValue(value)


class StreamingMarkdownBrowser(QTextBrowser):
    """
    QTextBrowser with hybrid cursor-based rendering for reduced flicker.

    Features:
    - Copies markdown source on Ctrl+C (not rendered HTML)
    - Uses QTextCursor.insertHtml() when content is appended
    - Falls back to setHtml() when content changes earlier
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._markdown_source = ""
        self._scroll_tracker = ScrollPositionTracker(self)

        # Track previously rendered HTML for incremental updates
        self._last_rendered_html = ""
        self._committed_html = MARKDOWN_CSS  # Track committed HTML separately for RenderUpdate
        self._pending_start = 0  # Track character position where pending content starts

        # Initialize with CSS so content is styled from the start
        self.setHtml(MARKDOWN_CSS)

    # --- Markdown Copy Functionality (from MarkdownCopyBrowser) ---

    def set_markdown_source(self, markdown_text: str):
        """Store the markdown source for copy operations"""
        self._markdown_source = markdown_text

    def get_markdown_source(self) -> str:
        """Get the markdown source"""
        return self._markdown_source

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
        menu = self.createStandardContextMenu()
        for action in menu.actions():
            if action.text().replace('&', '') == 'Copy':
                action.triggered.disconnect()
                action.triggered.connect(self._copy_markdown)
                break
        exec_dialog(menu, event.globalPos())
        menu.deleteLater()

    # --- Streaming Functionality ---

    def set_streaming_content(self, markdown_text: str, html_content: str) -> None:
        """
        Update content with hybrid rendering for reduced flicker.

        Args:
            markdown_text: The markdown source (for copy operations)
            html_content: The pre-rendered HTML content
        """
        self.set_markdown_source(markdown_text)

        was_at_bottom = self._scroll_tracker.is_at_bottom()
        saved_scroll = self._scroll_tracker.get_scroll_value()

        # Check if we can do incremental append
        if (self._last_rendered_html and
            html_content.startswith(self._last_rendered_html)):
            # Incremental update - just append the delta
            delta_html = html_content[len(self._last_rendered_html):]
            if delta_html:
                cursor = self.textCursor()
                cursor.movePosition(QTextCursor.End)
                cursor.insertHtml(delta_html)
                self._force_layout()
        else:
            # Full replace needed
            self.setHtml(html_content)
            self._force_layout()

        self._last_rendered_html = html_content

        # Restore scroll position
        if was_at_bottom:
            self._scroll_tracker.scroll_to_bottom()
        else:
            self._scroll_tracker.set_scroll_value(saved_scroll)

    def apply_render_update(self, update: RenderUpdate) -> None:
        """Apply RenderUpdate using cursor-based operations for minimal reflow."""
        was_at_bottom = self._scroll_tracker.is_at_bottom()
        saved_scroll = self._scroll_tracker.get_scroll_value()

        if update.update_type == UpdateType.FULL_REPLACE:
            self.setHtml(update.full_html or "")
            self._committed_html = update.full_html or ""
            self._pending_start = self.document().characterCount()
        else:
            # Incremental update
            if update.committed_html:
                # New committed content - rebuild committed portion with setHtml
                self._committed_html += update.committed_html
                self.setHtml(self._committed_html)
                self._force_layout()
                self._pending_start = self.document().characterCount()

                # Append pending via cursor (avoids second setHtml)
                if update.pending_html:
                    cursor = self.textCursor()
                    cursor.movePosition(QTextCursor.End)
                    cursor.insertHtml(update.pending_html)
                    self._force_layout()
            else:
                # Only pending changed - pure cursor update (no flicker)
                cursor = self.textCursor()

                # Delete existing pending content
                if self._pending_start < self.document().characterCount():
                    cursor.setPosition(self._pending_start)
                    cursor.movePosition(QTextCursor.End,
                                       QTextCursor.KeepAnchor)
                    cursor.removeSelectedText()

                # Insert new pending content
                if update.pending_html:
                    cursor.movePosition(QTextCursor.End)
                    cursor.insertHtml(update.pending_html)

                self._force_layout()

        if was_at_bottom:
            self._scroll_tracker.scroll_to_bottom()
        else:
            self._scroll_tracker.set_scroll_value(saved_scroll)

    def reset_streaming(self) -> None:
        """Reset streaming state for new content"""
        self._last_rendered_html = ""
        self._committed_html = MARKDOWN_CSS
        self._pending_start = 0
        # Initialize document with CSS so streaming content is styled
        self.setHtml(MARKDOWN_CSS)

    def _force_layout(self) -> None:
        """Force Qt to complete document layout for accurate scrollbar"""
        doc = self.document()
        last_block = doc.lastBlock()
        if last_block.isValid():
            doc.documentLayout().blockBoundingRect(last_block)
