#!/usr/bin/env python3

"""
ReAct Orchestrator

Main orchestration logic for the ReAct autonomous agent.
Coordinates planning, investigation iterations, reflection, and synthesis.
"""

import asyncio
import time
from typing import List, Dict, Any, Optional, Callable

from .todo_list_manager import TodoListManager
from .findings_cache import FindingsCache
from .react_prompts import ReActPrompts
from ..models.react_models import ReActResult, ReActStatus, ReActConfig
from ..models.llm_models import ToolCall, ToolResult, ChatMessage, ChatRequest, MessageRole
from ..models.context_models import ContextWindowConfig
from ..context_window_manager import ContextWindowManager
from ..llm_providers.base_provider import NetworkError
from ..models.transcript_models import ToolChoiceMode

from src.ida_compat import log


class ReActOrchestrator:
    """
    Orchestrates ReAct autonomous agent execution.

    Uses MCP tool calling infrastructure for tool execution,
    coordinates the plan-investigate-reflect-synthesize loop.
    """

    def __init__(self,
                 llm_provider,
                 mcp_orchestrator,
                 mcp_tools: List[Dict[str, Any]],
                 config: ReActConfig = None):
        """
        Initialize the ReAct orchestrator.

        Args:
            llm_provider: LLM provider instance for chat completions
            mcp_orchestrator: MCPToolOrchestrator for tool execution
            mcp_tools: List of MCP tools in OpenAI format
            config: ReActConfig for behavior customization
        """
        self.llm_provider = llm_provider
        self.mcp_orchestrator = mcp_orchestrator
        self.mcp_tools = mcp_tools
        self.config = config or ReActConfig()

        # State management
        self.todo_manager = TodoListManager()
        self.findings = FindingsCache()
        self.cancelled = False
        self.iteration_count = 0
        self.tool_call_count = 0
        self.tool_fail_counts: Dict[str, int] = {}  # tool_name -> consecutive failure count
        self.start_time = 0.0

        # Conversation history (maintained across iterations for context continuity)
        self.conversation_history: List[ChatMessage] = []

        # Context window management - prevents context overflow in long investigations
        context_config = ContextWindowConfig(
            context_limit_tokens=self.config.context_window_tokens,
            threshold_percent=self.config.context_threshold_percent,
            max_tool_result_tokens=self.config.max_tool_result_tokens,
            min_recent_tool_pairs=self.config.min_recent_tool_pairs
        )
        self.context_manager = ContextWindowManager(llm_provider, context_config)

        # Callbacks for progress updates
        self.on_progress: Optional[Callable[[str, int], None]] = None
        self.on_todos_updated: Optional[Callable[[str], None]] = None
        self.on_finding: Optional[Callable[[str], None]] = None
        self.on_iteration_start: Optional[Callable[[int, str], None]] = None
        self.on_iteration_complete: Optional[Callable[[int, str], None]] = None
        self.on_content: Optional[Callable[[str], None]] = None
        self.on_tool_event: Optional[Callable[[dict], None]] = None

        log.log_info("ReActOrchestrator initialized")

    def cancel(self):
        """Cancel the orchestrator execution"""
        self.cancelled = True
        log.log_info("ReActOrchestrator cancellation requested")

    def _cleanup_orphaned_tool_calls(self):
        """
        Clean up any orphaned tool calls in conversation history.

        This is called during error/cancellation handling to ensure the
        conversation history is in a valid state for potential continuation
        or for review by the user.

        Delegates to ContextWindowManager for consistent handling of both
        tool_calls field and native_content blocks.
        """
        if not self.conversation_history:
            return

        # Use the context manager's validation which handles both
        # tool_calls field AND native_content for tool_use/tool_result blocks
        cleaned_history = self.context_manager._validate_and_fix_tool_pairs(
            self.conversation_history
        )

        if len(cleaned_history) != len(self.conversation_history):
            log.log_info(
                f"Cleaned up orphaned tool calls: removed "
                f"{len(self.conversation_history) - len(cleaned_history)} messages"
            )

        self.conversation_history = cleaned_history

    async def analyze(self, objective: str, initial_context: str = "") -> ReActResult:
        """
        Run ReAct analysis for the given objective.

        Args:
            objective: User's question/goal
            initial_context: Optional initial binary context

        Returns:
            ReActResult with findings and final answer
        """
        self.start_time = time.time()
        self.iteration_count = 0
        self.tool_call_count = 0
        self.tool_fail_counts.clear()
        self.cancelled = False
        self.findings.clear()
        self.todo_manager.clear()

        # Initialize conversation history with system prompt
        self.conversation_history.clear()
        self.conversation_history.append(
            ChatMessage(role=MessageRole.SYSTEM, content=ReActPrompts.get_system_prompt())
        )

        log.log_info(f"ReActOrchestrator: Starting analysis for: {objective[:50]}...")

        try:
            # Phase 1: Planning
            if self.on_progress:
                self.on_progress("Planning investigation...", 0)

            await self._run_planning(objective, initial_context)

            if self.cancelled:
                return ReActResult.cancelled()

            # Phase 2: Investigation Loop
            while not self.cancelled:
                self.iteration_count += 1

                # Check termination conditions
                if self.iteration_count > self.config.max_iterations:
                    log.log_info(f"ReAct: Max iterations ({self.config.max_iterations}) reached")
                    break

                if self.todo_manager.all_complete():
                    log.log_info("ReAct: All todos complete")
                    break

                # Mark next todo as in progress
                current_todo = self.todo_manager.mark_current_in_progress()
                if not current_todo:
                    log.log_info("ReAct: No more pending todos")
                    break

                if self.on_todos_updated:
                    self.on_todos_updated(self.todo_manager.format_for_prompt())

                if self.on_iteration_start:
                    self.on_iteration_start(self.iteration_count, current_todo.task)

                # Run investigation iteration
                iteration_result = await self._run_investigation_iteration(
                    objective, self.iteration_count
                )

                if self.cancelled:
                    return ReActResult.cancelled()

                # Mark current todo complete
                self.todo_manager.mark_current_complete(iteration_result)

                if self.on_iteration_complete:
                    self.on_iteration_complete(self.iteration_count, iteration_result[:200] if iteration_result else "")

                # Run self-reflection (unless disabled or max iterations approaching)
                if self.config.reflection_enabled and self.iteration_count < self.config.max_iterations:
                    should_synthesize = await self._run_reflection(objective)

                    if should_synthesize:
                        log.log_info("ReAct: Self-reflection indicates ready to synthesize")
                        break

            # Phase 3: Synthesis
            if self.on_progress:
                self.on_progress("Synthesizing final answer...", self.iteration_count)

            final_answer = await self._run_synthesis(objective)

            # Build result
            duration = time.time() - self.start_time
            status = ReActStatus.SUCCESS
            if self.iteration_count > self.config.max_iterations:
                status = ReActStatus.MAX_ITERATIONS

            log.log_info(f"ReAct: Analysis complete. Status={status.value}, "
                        f"iterations={self.iteration_count}, tool_calls={self.tool_call_count}")

            return ReActResult(
                status=status,
                answer=final_answer,
                findings=self.findings.findings.copy(),
                iteration_count=self.iteration_count,
                tool_call_count=self.tool_call_count,
                duration_seconds=duration,
                iteration_summaries=self.findings.iteration_summaries.copy()
            )

        except asyncio.CancelledError:
            log.log_info("ReAct: Analysis cancelled via asyncio")
            # Clean up any orphaned tool calls before returning
            self._cleanup_orphaned_tool_calls()
            return ReActResult.cancelled()
        except Exception as e:
            log.log_error(f"ReAct orchestrator error: {e}")
            import traceback
            log.log_error(traceback.format_exc())
            # Clean up any orphaned tool calls before returning
            self._cleanup_orphaned_tool_calls()
            return ReActResult.error(str(e))

    async def _run_planning(self, objective: str, initial_context: str):
        """Run planning phase to generate todo list"""
        log.log_info("ReAct: Starting planning phase")

        prompt = ReActPrompts.get_planning_prompt(objective, initial_context)

        # Planning is rendered as transcript task snapshots, not assistant streaming.
        plan_response = await self._call_llm_no_tools(prompt, emit_content=False)

        # Parse response into todos
        self.todo_manager.initialize_from_llm_response(plan_response)

        log.log_info(f"ReAct: Created {len(self.todo_manager.todos)} investigation steps")

        if self.on_todos_updated:
            self.on_todos_updated(self.todo_manager.format_for_prompt())

    async def _run_investigation_iteration(self, objective: str, iteration: int) -> str:
        """
        Run a single investigation iteration with multi-turn tool calling.

        Continues calling the LLM and executing tools until the LLM provides
        a final response (finish_reason = "stop") instead of more tool calls.
        """
        log.log_info(f"ReAct: Starting iteration {iteration}")

        remaining = self.config.max_iterations - iteration
        prompt = ReActPrompts.get_investigation_prompt(
            objective,
            self.todo_manager.format_for_prompt(),
            self.findings.format_for_prompt(),
            iteration,
            remaining
        )

        if self.on_progress:
            self.on_progress(f"Investigating... (iteration {iteration})", iteration)

        # Multi-turn tool calling loop - continue until LLM says "stop"
        max_tool_rounds = 10  # Prevent infinite loops
        tool_round = 0
        final_response = ""

        # First call with the investigation prompt
        response_text, tool_calls = await self._call_llm_with_tools(prompt, emit_content=False)
        final_response = response_text

        # Tool calling loop
        while tool_calls and tool_round < max_tool_rounds:
            # Check for cancellation BEFORE executing tools
            if self.cancelled:
                log.log_info("ReAct: Cancellation detected before tool execution")
                # Remove the last assistant message that has tool calls without results
                # to prevent orphaned tool calls in conversation history
                if (self.conversation_history and
                    self.conversation_history[-1].role == MessageRole.ASSISTANT and
                    self.conversation_history[-1].tool_calls):
                    orphaned_msg = self.conversation_history.pop()
                    log.log_debug(f"Removed orphaned assistant message with {len(orphaned_msg.tool_calls)} tool calls")
                break

            tool_round += 1
            log.log_info(f"ReAct: Tool round {tool_round} with {len(tool_calls)} tool calls")

            # Execute tools
            tool_results = await self._execute_tools(tool_calls, iteration)

            # Check for cancellation AFTER tool execution but BEFORE adding results
            if self.cancelled:
                log.log_info("ReAct: Cancellation detected after tool execution")
                # Remove the assistant message with tool calls since we won't add results
                if (self.conversation_history and
                    self.conversation_history[-1].role == MessageRole.ASSISTANT and
                    self.conversation_history[-1].tool_calls):
                    orphaned_msg = self.conversation_history.pop()
                    log.log_debug(f"Removed orphaned assistant message with {len(orphaned_msg.tool_calls)} tool calls")
                break

            # Validate tool results match tool calls before adding to history
            # Build a map of result IDs for validation
            result_id_map = {r.tool_call_id: r for r in tool_results}

            # Add tool results to conversation history (with truncation for large results)
            for tc in tool_calls:
                # Find matching result by tool_call_id (not by position)
                result = result_id_map.get(tc.id)
                if result is None:
                    log.log_warn(f"No result found for tool call {tc.id} ({tc.name}), creating error result")
                    content = f"Error: No result returned for tool call"
                else:
                    content = result.content if not result.error else f"Error: {result.error}"

                # Track per-tool failure counts and add escalating hints
                if result and result.error:
                    self.tool_fail_counts[tc.name] = self.tool_fail_counts.get(tc.name, 0) + 1
                    fail_count = self.tool_fail_counts[tc.name]
                    if fail_count >= 3:
                        content += (f"\n\nWARNING: '{tc.name}' has failed {fail_count} consecutive times. "
                                    f"This tool is not working for your current use case. "
                                    f"Do NOT call it again — use a different approach or skip this step.")
                    elif fail_count >= 2:
                        content += (f"\n\nNote: '{tc.name}' has now failed {fail_count} times in a row. "
                                    f"Consider using a different tool or approach.")
                elif result and not result.error:
                    self.tool_fail_counts[tc.name] = 0

                # Truncate oversized tool results to prevent context overflow
                content = self.context_manager.truncate_tool_result(content)

                tool_message = ChatMessage(
                    role=MessageRole.TOOL,
                    content=content,
                    tool_call_id=tc.id,
                    name=tc.name
                )
                self.conversation_history.append(tool_message)

            # Store findings from tool results
            for tc in tool_calls:
                # Track tool used
                self.todo_manager.add_tool_used(tc.name)

                result = result_id_map.get(tc.id)
                if result and not result.error:
                    self.findings.extract_from_tool_output(tc.name, result.content, iteration)
                    if self.on_finding:
                        preview = result.content[:100] + "..." if len(result.content) > 100 else result.content
                        self.on_finding(f"Found via {tc.name}: {preview}")

            # Continue the conversation - LLM can now make more tool calls or provide final response
            # No explicit prompt needed - LLM sees tool results in history and continues
            response_text, tool_calls = await self._call_llm_with_tools("", emit_content=False)
            final_response = response_text

        if tool_round >= max_tool_rounds:
            log.log_warn(f"ReAct: Reached max tool rounds ({max_tool_rounds}) in iteration {iteration}")

        # Store iteration summary
        self.findings.add_iteration_summary(final_response)

        return final_response

    async def _run_reflection(self, objective: str) -> bool:
        """
        Run self-reflection with adaptive planning.

        Reviews progress, updates todo list based on findings,
        and decides whether to continue or synthesize.

        Returns:
            True if ready to synthesize, False to continue investigating
        """
        log.log_info("ReAct: Running self-reflection with adaptive planning")

        # Skip reflection if we don't have enough findings
        if self.findings.get_findings_count() < self.config.min_findings_for_ready:
            log.log_debug(f"ReAct: Not enough findings for reflection ({self.findings.get_findings_count()} < {self.config.min_findings_for_ready})")
            return False

        prompt = ReActPrompts.get_reflection_prompt(
            objective,
            self.todo_manager.format_for_prompt(),
            self.findings.format_for_prompt()
        )

        # Reflection updates the task list and notices, not the assistant stream.
        response = await self._call_llm_no_tools(prompt, emit_content=False)

        # Parse reflection response
        new_tasks, tasks_to_remove, is_ready = self._parse_reflection_response(response)

        # Update todo list if changes suggested
        if new_tasks or tasks_to_remove:
            changes_made = self.todo_manager.update_from_reflection(new_tasks, tasks_to_remove)

            if changes_made:
                log.log_info(f"ReAct: Plan updated - added {len(new_tasks)} tasks, removed {len(tasks_to_remove)} tasks")

                # Grant extra iterations for newly added tasks (2 per task)
                if new_tasks:
                    extra_iterations = len(new_tasks) * 2
                    self.config.max_iterations += extra_iterations
                    log.log_info(f"ReAct: Extended max_iterations by {extra_iterations} for {len(new_tasks)} new task(s)")

                # Emit updated todo list
                if self.on_todos_updated:
                    self.on_todos_updated(self.todo_manager.format_for_prompt())

        if is_ready:
            log.log_info("ReAct: Self-reflection says READY to synthesize")
            return True
        else:
            log.log_info("ReAct: Self-reflection says CONTINUE investigating")
            return False

    def _parse_reflection_response(self, response: str) -> tuple[list[str], list[str], bool]:
        """
        Parse reflection response to extract todo updates and decision.

        Returns:
            (new_tasks, tasks_to_remove, is_ready)
        """
        import re

        new_tasks = []
        tasks_to_remove = []
        is_ready = False

        # Check decision (case-insensitive)
        response_upper = response.upper()
        if "DECISION:" in response_upper:
            decision_part = response_upper.split("DECISION:")[1].split("\n")[0]
            if "READY" in decision_part:
                is_ready = True

        # Extract all ADD entries directly - match "- ADD: [task]" patterns
        # This correctly handles multiple ADD lines without losing the first task
        add_pattern = r'[-*]\s*ADD:\s*(.+?)(?:\n|$)'
        add_matches = re.findall(add_pattern, response, re.IGNORECASE)
        new_tasks = [
            task.strip() for task in add_matches
            if task.strip() and len(task.strip()) > 5 and task.strip().lower() != 'none'
        ]

        # Extract all REMOVE entries directly - match "- REMOVE: [task]" patterns
        remove_pattern = r'[-*]\s*REMOVE:\s*(.+?)(?:\n|$)'
        remove_matches = re.findall(remove_pattern, response, re.IGNORECASE)
        tasks_to_remove = [
            task.strip() for task in remove_matches
            if task.strip() and len(task.strip()) > 5 and task.strip().lower() != 'none'
        ]

        log.log_debug(f"ReAct: Parsed reflection - new_tasks={len(new_tasks)}, remove={len(tasks_to_remove)}, ready={is_ready}")

        return new_tasks, tasks_to_remove, is_ready

    async def _run_synthesis(self, objective: str) -> str:
        """Run final synthesis to generate comprehensive answer"""
        log.log_info("ReAct: Running synthesis")

        prompt = ReActPrompts.get_synthesis_prompt(
            objective,
            self.todo_manager.format_for_prompt(),
            self.findings.format_detailed()
        )

        # Stream the synthesis (content streams during this call)
        final_answer = await self._call_llm_no_tools(prompt, emit_content=True)

        return final_answer

    async def _call_llm_no_tools(self, prompt: str, emit_content: bool = True) -> str:
        """
        Call LLM without tools (for planning, reflection, synthesis).

        Args:
            prompt: The prompt to send to the LLM
            emit_content: If True, emit content chunks via on_content callback (default: True)
                         Set to False for internal operations like reflection
        """
        # Add user prompt to conversation history
        user_message = ChatMessage(role=MessageRole.USER, content=prompt)
        self.conversation_history.append(user_message)

        # Detect if conversation history contains tool messages from previous iterations
        # Some providers (e.g., Bedrock via LiteLLM) require tools parameter when tool messages exist
        has_tool_messages = any(
            msg.role == MessageRole.TOOL or (hasattr(msg, 'tool_calls') and msg.tool_calls)
            for msg in self.conversation_history
        )

        # Check and manage context window before LLM call
        # This also validates tool pairs and removes orphans
        # Pass tools to context manager if history contains tool messages
        managed_history = await self.context_manager.check_and_manage(
            self.conversation_history,
            tools=self.mcp_tools if has_tool_messages else None
        )

        # Always update our reference if the managed history differs
        # (could be from compression OR from orphan removal)
        if managed_history is not self.conversation_history:
            if len(managed_history) != len(self.conversation_history):
                log.log_info(
                    f"ReAct: Context managed from {len(self.conversation_history)} "
                    f"to {len(managed_history)} messages"
                )
            self.conversation_history = managed_history

        # Use managed conversation history for context continuity
        # Pass tools if history contains tool messages (required by some providers like Bedrock)
        request = ChatRequest(
            messages=managed_history,
            model=self.llm_provider.model if hasattr(self.llm_provider, 'model') else '',
            max_tokens=getattr(self.llm_provider, 'max_tokens', 4096),
            temperature=0.7,
            stream=True,
            tools=self.mcp_tools if has_tool_messages else None
        )

        # Retry loop for transient network errors
        last_error = None
        for attempt in range(self.config.max_retries + 1):
            try:
                # Stream the response and accumulate chunks
                accumulated = ""
                native_content = None

                async for chunk in self.llm_provider.chat_completion_stream(request):
                    if chunk.content:
                        accumulated += chunk.content
                        # Emit content chunks for UI updates (unless suppressed)
                        if emit_content and self.on_content:
                            self.on_content(chunk.content)

                    # Capture native_content from final chunk (e.g., Anthropic thinking blocks)
                    if hasattr(chunk, 'native_content') and chunk.native_content:
                        native_content = chunk.native_content

                # Add assistant response to conversation history for context continuity
                assistant_message = ChatMessage(
                    role=MessageRole.ASSISTANT,
                    content=accumulated,
                    native_content=native_content
                )
                self.conversation_history.append(assistant_message)

                return accumulated

            except NetworkError as e:
                last_error = e
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (2 ** attempt)
                    log.log_warn(
                        f"ReAct: Network error (attempt {attempt + 1}/{self.config.max_retries + 1}), "
                        f"retrying in {delay}s: {e}"
                    )
                    if emit_content and self.on_content:
                        self.on_content(f"\n\n*Network timeout, retrying in {delay:.0f}s...*\n\n")
                    await asyncio.sleep(delay)
                else:
                    log.log_error(f"ReAct: Network error after {self.config.max_retries + 1} attempts: {e}")
                    raise

            except Exception as e:
                log.log_error(f"ReAct: LLM call failed: {e}")
                raise

        # Should not reach here, but just in case
        raise last_error

    async def _call_llm_with_tools(self, prompt: str = "", emit_content: bool = True) -> tuple:
        """
        Call LLM with tools enabled.

        Args:
            prompt: Optional user prompt. If empty, continues conversation with tool results.

        Returns:
            tuple: (text_response, tool_calls)
        """
        # Add user prompt to conversation history only if provided
        if prompt:
            user_message = ChatMessage(role=MessageRole.USER, content=prompt)
            self.conversation_history.append(user_message)

        # Check and manage context window before LLM call
        # This prevents context overflow by summarizing older messages when needed
        # Also validates tool pairs and removes orphans
        managed_history = await self.context_manager.check_and_manage(
            self.conversation_history,
            tools=self.mcp_tools
        )

        # Always update our reference if the managed history differs
        # (could be from compression OR from orphan removal)
        if managed_history is not self.conversation_history:
            if len(managed_history) != len(self.conversation_history):
                log.log_info(
                    f"ReAct: Context managed from {len(self.conversation_history)} "
                    f"to {len(managed_history)} messages"
                )
            self.conversation_history = managed_history

        # Use managed conversation history for context continuity
        request = ChatRequest(
            messages=managed_history,
            model=self.llm_provider.model if hasattr(self.llm_provider, 'model') else '',
            max_tokens=getattr(self.llm_provider, 'max_tokens', 4096),
            temperature=0.7,
            stream=True,
            tools=self.mcp_tools if self.mcp_tools else None,
            tool_choice=ToolChoiceMode.REQUIRED_INITIAL.to_openai_tool_choice(managed_history),
        )

        # Retry loop for transient network errors
        last_error = None
        for attempt in range(self.config.max_retries + 1):
            try:
                # Stream the response and accumulate chunks
                accumulated = ""
                final_tool_calls = []
                native_content = None

                async for chunk in self.llm_provider.chat_completion_stream(request):
                    if chunk.content:
                        accumulated += chunk.content
                        if emit_content and self.on_content:
                            self.on_content(chunk.content)

                    # Tool calls come in the final chunk
                    if hasattr(chunk, 'tool_calls') and chunk.tool_calls:
                        final_tool_calls = chunk.tool_calls

                    # Capture native_content from final chunk (e.g., Anthropic thinking blocks)
                    if hasattr(chunk, 'native_content') and chunk.native_content:
                        native_content = chunk.native_content

                # Add assistant response to conversation history (with tool calls if any)
                assistant_message = ChatMessage(
                    role=MessageRole.ASSISTANT,
                    content=accumulated,
                    tool_calls=final_tool_calls if final_tool_calls else None,
                    native_content=native_content
                )
                self.conversation_history.append(assistant_message)

                return accumulated, final_tool_calls

            except NetworkError as e:
                last_error = e
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (2 ** attempt)
                    log.log_warn(
                        f"ReAct: Network error (attempt {attempt + 1}/{self.config.max_retries + 1}), "
                        f"retrying in {delay}s: {e}"
                    )
                    if emit_content and self.on_content:
                        self.on_content(f"\n\n*Network timeout, retrying in {delay:.0f}s...*\n\n")
                    await asyncio.sleep(delay)
                else:
                    log.log_error(f"ReAct: Network error after {self.config.max_retries + 1} attempts: {e}")
                    # Don't raise - return a message to the LLM about the timeout
                    error_msg = (
                        f"The LLM request timed out after {self.config.max_retries + 1} attempts. "
                        "Please try a simpler query or try again later."
                    )
                    if emit_content and self.on_content:
                        self.on_content(f"\n\n*{error_msg}*\n\n")
                    raise

            except Exception as e:
                log.log_error(f"ReAct: LLM call with tools failed: {e}")
                raise

        # Should not reach here, but just in case
        raise last_error

    async def _execute_tools(self, tool_calls: List[ToolCall], iteration: int) -> List[ToolResult]:
        """Execute tool calls via MCP orchestrator"""
        self.tool_call_count += len(tool_calls)

        log.log_info(f"ReAct: Executing {len(tool_calls)} tool calls in iteration {iteration}")

        if self.on_tool_event:
            for tool_call in tool_calls:
                self.on_tool_event({
                    "phase": "requested",
                    "tool_call_id": tool_call.id,
                    "tool_name": tool_call.name,
                    "arguments": tool_call.arguments,
                })
                self.on_tool_event({
                    "phase": "started",
                    "tool_call_id": tool_call.id,
                    "tool_name": tool_call.name,
                    "arguments": tool_call.arguments,
                })

        try:
            results = await self.mcp_orchestrator.execute_tool_calls(tool_calls)
            if self.on_tool_event:
                result_map = {result.tool_call_id: result for result in results}
                for tool_call in tool_calls:
                    result = result_map.get(tool_call.id)
                    if result and not result.error:
                        self.on_tool_event({
                            "phase": "completed",
                            "tool_call_id": tool_call.id,
                            "tool_name": tool_call.name,
                            "content": result.content,
                        })
                    else:
                        self.on_tool_event({
                            "phase": "failed",
                            "tool_call_id": tool_call.id,
                            "tool_name": tool_call.name,
                            "error": result.error if result else "No result returned",
                        })
            return results
        except Exception as e:
            log.log_error(f"ReAct: Tool execution failed: {e}")
            if self.on_tool_event:
                for tool_call in tool_calls:
                    self.on_tool_event({
                        "phase": "failed",
                        "tool_call_id": tool_call.id,
                        "tool_name": tool_call.name,
                        "error": str(e),
                    })
            # Return error results for all tool calls
            return [
                ToolResult(
                    tool_call_id=tc.id,
                    content="",
                    error=str(e)
                )
                for tc in tool_calls
            ]
