#!/usr/bin/env python3

"""
ReAct Agent Thread

QThread wrapper for ReAct orchestrator to run analysis
in background with Qt signal/slot communication.
"""

import asyncio
from typing import List, Dict, Any, Optional
from ..qt_compat import QThread, Signal

from src.services.react.react_orchestrator import ReActOrchestrator
from src.services.models.react_models import ReActResult, ReActConfig

from src.ida_compat import log


class ReActOrchestratorThread(QThread):
    """
    QThread wrapper for ReAct orchestrator.

    Runs the ReAct analysis loop in a background thread
    and emits Qt signals for progress updates.
    """

    # Signals for UI communication
    planning_complete = Signal(str)          # Todo list formatted
    iteration_started = Signal(int, str)     # Iteration number, current todo
    iteration_complete = Signal(int, str)    # Iteration number, summary
    todos_updated = Signal(str)              # Formatted todo list
    finding_discovered = Signal(str)         # New finding text
    progress_update = Signal(str, int)       # Status message, iteration
    content_chunk = Signal(str)              # Content update for display
    analysis_complete = Signal(object)       # ReActResult
    analysis_error = Signal(str)             # Error message

    def __init__(self,
                 objective: str,
                 initial_context: str,
                 llm_provider,
                 mcp_orchestrator,
                 mcp_tools: List[Dict[str, Any]],
                 config: ReActConfig = None,
                 parent=None):
        """
        Initialize the ReAct orchestrator thread.

        Args:
            objective: The user's question/goal
            initial_context: Initial binary context string
            llm_provider: LLM provider instance
            mcp_orchestrator: MCPToolOrchestrator instance
            mcp_tools: List of MCP tools in OpenAI format
            config: Optional ReActConfig
            parent: Optional parent QObject
        """
        super().__init__(parent)
        self.objective = objective
        self.initial_context = initial_context
        self.llm_provider = llm_provider
        self.mcp_orchestrator = mcp_orchestrator
        self.mcp_tools = mcp_tools
        self.config = config or ReActConfig()
        self.cancelled = False
        self._orchestrator: Optional[ReActOrchestrator] = None

        log.log_info("ReActOrchestratorThread initialized")

    def cancel(self):
        """Cancel the running analysis"""
        self.cancelled = True
        if self._orchestrator:
            self._orchestrator.cancel()
        log.log_info("ReActOrchestratorThread cancellation requested")

    def run(self):
        """Execute ReAct analysis in background thread"""
        try:
            log.log_info("ReActOrchestratorThread starting")

            # Create event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                result = loop.run_until_complete(self._run_analysis())

                if not self.cancelled:
                    self.analysis_complete.emit(result)

            finally:
                loop.close()

        except Exception as e:
            log.log_error(f"ReActOrchestratorThread error: {e}")
            import traceback
            log.log_error(traceback.format_exc())
            if not self.cancelled:
                self.analysis_error.emit(str(e))

    async def _run_analysis(self) -> ReActResult:
        """Run the ReAct analysis asynchronously"""
        # Create orchestrator
        self._orchestrator = ReActOrchestrator(
            llm_provider=self.llm_provider,
            mcp_orchestrator=self.mcp_orchestrator,
            mcp_tools=self.mcp_tools,
            config=self.config
        )

        # Set up callbacks to emit signals
        self._orchestrator.on_progress = self._on_progress
        self._orchestrator.on_todos_updated = self._on_todos_updated
        self._orchestrator.on_finding = self._on_finding
        self._orchestrator.on_iteration_start = self._on_iteration_start
        self._orchestrator.on_iteration_complete = self._on_iteration_complete
        self._orchestrator.on_content = self._on_content

        # Run analysis
        result = await self._orchestrator.analyze(
            self.objective,
            self.initial_context
        )

        return result

    def _on_progress(self, message: str, iteration: int):
        """Callback for progress updates"""
        if not self.cancelled:
            self.progress_update.emit(message, iteration)

    def _on_todos_updated(self, todos_formatted: str):
        """Callback for todo list updates"""
        if not self.cancelled:
            self.todos_updated.emit(todos_formatted)

    def _on_finding(self, finding: str):
        """Callback for new finding discovered"""
        if not self.cancelled:
            self.finding_discovered.emit(finding)

    def _on_iteration_start(self, iteration: int, todo_task: str):
        """Callback for iteration start"""
        if not self.cancelled:
            self.iteration_started.emit(iteration, todo_task)

    def _on_iteration_complete(self, iteration: int, summary: str):
        """Callback for iteration completion"""
        if not self.cancelled:
            self.iteration_complete.emit(iteration, summary)

    def _on_content(self, content: str):
        """Callback for content updates"""
        if not self.cancelled:
            self.content_chunk.emit(content)
