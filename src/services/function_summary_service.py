#!/usr/bin/env python3
"""
FunctionSummaryService - Shared service for generating function summaries.

This service provides a unified interface for generating function explanation prompts
and LLM queries, ensuring both the Explain tab and Semantic Analysis use identical
prompt formats and feature support (RAG, MCP).
"""

from typing import Optional, Dict, Any, List
from src.ida_compat import log
from src.services.binary_context_service import BinaryContextService, ViewLevel
from src.services.rag_service import rag_service
from src.services.models.rag_models import SearchRequest, SearchType


class FunctionSummaryService:
    """
    Service for generating function summaries using LLM.

    Provides consistent prompt generation for function analysis across
    the Explain tab and Semantic Analysis features, ensuring feature parity
    for RAG and MCP support.
    """

    def __init__(self, settings_service=None, rag_enabled: bool = False,
                 mcp_enabled: bool = False):
        """
        Initialize the FunctionSummaryService.

        Args:
            settings_service: Optional settings service for configuration
            rag_enabled: Whether RAG context should be included
            mcp_enabled: Whether MCP context should be included
        """
        self.settings_service = settings_service
        self.rag_enabled = rag_enabled
        self.mcp_enabled = mcp_enabled
        self._context_service = BinaryContextService()

    def set_rag_enabled(self, enabled: bool) -> None:
        """Enable or disable RAG context injection."""
        self.rag_enabled = enabled

    def set_mcp_enabled(self, enabled: bool) -> None:
        """Enable or disable MCP context injection."""
        self.mcp_enabled = enabled

    def format_function_prompt(self, func_address: int,
                                view_level: Optional[ViewLevel] = None) -> Optional[str]:
        """
        Generate the standard function explanation prompt.

        Args:
            func_address: The function start address
            view_level: Optional view level (defaults to PSEUDO_C)

        Returns:
            The formatted prompt string, or None if the function cannot be found
        """
        if not self._context_service:
            log.log_warn("No context service available for prompt generation")
            return None

        # Build context for the target function explicitly. The semantic-analysis
        # worker runs off the UI thread, so screen-EA-based lookups are unreliable.
        context = self._context_service.get_context_for_address(func_address)

        if context.get("error"):
            log.log_warn(f"Context error: {context['error']}")
            return None

        if not context.get("function_context"):
            log.log_warn(f"No function found at address 0x{func_address:x}")
            return None

        # Default to PSEUDO_C (Hex-Rays decompiler output)
        if view_level is None:
            view_level = ViewLevel.PSEUDO_C

        code_data = self._context_service.get_code_at_level(func_address, view_level)

        # Try fallback to ASM if decompiler fails
        if code_data.get("error"):
            if view_level != ViewLevel.ASM:
                code_data = self._context_service.get_code_at_level(func_address, ViewLevel.ASM)

        if code_data.get("error"):
            log.log_warn(f"Failed to get code: {code_data.get('error')}")
            return None

        # Format the explanation prompt
        return self._format_explanation(context, code_data, include_llm_prompt=True)

    def generate_query_with_context(self, prompt: str,
                                     rag_enabled: Optional[bool] = None,
                                     mcp_enabled: Optional[bool] = None,
                                     code_content: Optional[str] = None) -> str:
        """
        Add RAG/MCP context to prompt if enabled.

        Args:
            prompt: The base prompt
            rag_enabled: Override RAG setting (uses instance setting if None)
            mcp_enabled: Override MCP setting (uses instance setting if None)
            code_content: Optional code content for RAG search

        Returns:
            The prompt with added context
        """
        # Use instance settings if not overridden
        if rag_enabled is None:
            rag_enabled = self.rag_enabled
        if mcp_enabled is None:
            mcp_enabled = self.mcp_enabled

        result = prompt

        # Add RAG context if enabled
        if rag_enabled and code_content:
            rag_context = self._get_rag_context(code_content)
            if rag_context:
                result += rag_context
            else:
                result += "\n\n**RAG Context**: No relevant documentation found for this code context."
        elif rag_enabled:
            result += "\n\n**RAG Context**: Unable to search documentation (no code content available)."

        # Add MCP context if enabled
        if mcp_enabled:
            result += "\n\n**MCP Context**: Please leverage Model Context Protocol tools and resources for enhanced analysis."

        return result

    def generate_full_query(self, func_address: int,
                            view_level: Optional[ViewLevel] = None,
                            rag_enabled: Optional[bool] = None,
                            mcp_enabled: Optional[bool] = None) -> Optional[str]:
        """
        Generate a complete LLM query for a function, including RAG/MCP context.

        Args:
            func_address: The function start address
            view_level: Optional view level (defaults to PSEUDO_C)
            rag_enabled: Override RAG setting (uses instance setting if None)
            mcp_enabled: Override MCP setting (uses instance setting if None)

        Returns:
            The complete query string, or None if the function cannot be found
        """
        prompt = self.format_function_prompt(func_address, view_level)
        if not prompt:
            return None

        # Extract code content for RAG search
        code_content = self._extract_code_content(func_address, view_level)

        return self.generate_query_with_context(
            prompt,
            rag_enabled=rag_enabled,
            mcp_enabled=mcp_enabled,
            code_content=code_content
        )

    def _format_explanation(self, context: dict, code_data: dict,
                            include_llm_prompt: bool = True) -> str:
        """
        Format function explanation as markdown.
        """
        func_ctx = context["function_context"]
        binary_info = context["binary_info"]

        if include_llm_prompt:
            explanation = """# Function Explanation

Describe the functionality of the decompiled code below. Provide a summary paragraph section followed by an analysis section that details the functionality of the code. The analysis section should be Markdown formatted. Try to identify the function name from the functionality present, or from string constants or log messages if they are present. But only fallback to strings or log messages that are clearly function names for this function. Include any other relavant details such as possible data structures and security issues,

"""
        else:
            explanation = "# Function Explanation\n\n"

        explanation += f"""## Function: {func_ctx['name']}
**Prototype**: `{func_ctx.get('prototype', 'unknown')}`
**Address**: {func_ctx['start']} - {func_ctx['end']}
**Size**: {func_ctx['size']} bytes
**Basic Blocks**: {func_ctx['basic_blocks']}
**Call Sites**: {func_ctx['call_sites']}

## Binary Context
**File**: {binary_info.get('filename', 'Unknown')}
**Architecture**: {binary_info.get('architecture', 'Unknown')}
**Platform**: {binary_info.get('platform', 'Unknown')}

## Code ({code_data['view_level']})
```
"""

        # Add code lines
        for line in code_data.get("lines", []):
            if isinstance(line, dict) and "content" in line:
                marker = ">>> " if line.get("is_current", False) else "    "
                address = line.get('address', '')
                content = line['content']

                # Only add colon if there's an address, otherwise just show content
                if address and address != "":
                    explanation += f"{marker}{address}: {content}\n"
                else:
                    explanation += f"{marker}{content}\n"

        explanation += "```\n\n"

        # Add callers/callees if available
        if func_ctx.get("callers"):
            explanation += f"**Callers**: {', '.join(func_ctx['callers'])}\n"
        if func_ctx.get("callees"):
            explanation += f"**Callees**: {', '.join(func_ctx['callees'])}\n"

        if not include_llm_prompt:
            explanation += """\n*This is a static analysis. Enable LLM integration for AI-powered explanations.*"""

        return explanation

    def _get_rag_context(self, code_content: str) -> str:
        """
        Get RAG context based on code content.
        """
        try:
            log.log_info("RAG enabled - performing hybrid search for additional context")

            # Create search request using the code content
            request = SearchRequest(
                query=code_content,
                search_type=SearchType.HYBRID,
                max_results=3,  # Limit to top 3 for prompt context
                similarity_threshold=0.3,  # Lower threshold for broader context
                include_metadata=True
            )

            # Perform RAG search
            results = rag_service.search(request)

            if not results:
                log.log_info("No RAG results found for code context")
                return ""

            log.log_info(f"Found {len(results)} RAG context results")

            # Format results for LLM context
            rag_context = "\n## Additional Reference Context\n"
            rag_context += "The following related documentation may provide helpful context:\n\n"

            for i, result in enumerate(results, 1):
                score_percent = int(result.score * 100)
                rag_context += f"### Reference {i} (Relevance: {score_percent}%)\n"
                rag_context += f"**Source:** {result.filename}, Chunk {result.chunk_id}\n"
                rag_context += f"**Content:** {result.snippet}\n\n"

            rag_context += "---\n"
            rag_context += "Please use this reference context to enhance your analysis, but focus primarily on the specific code provided.\n\n"

            return rag_context

        except Exception as e:
            log.log_error(f"Error getting RAG context: {e}")
            return ""

    def _extract_code_content(self, func_address: int,
                               view_level: Optional[ViewLevel] = None) -> Optional[str]:
        """
        Extract code content string from a function for RAG search.
        """
        if not self._context_service:
            return None

        # Default to PSEUDO_C (Hex-Rays)
        if view_level is None:
            view_level = ViewLevel.PSEUDO_C

        code_data = self._context_service.get_code_at_level(func_address, view_level)

        # Try fallback to ASM if decompiler fails
        if code_data.get("error"):
            if view_level != ViewLevel.ASM:
                code_data = self._context_service.get_code_at_level(func_address, ViewLevel.ASM)

        if code_data.get("error"):
            return None

        # Extract content from line dictionaries
        code_lines = code_data.get('lines', [])
        code_content_lines = []
        for line in code_lines:
            if isinstance(line, dict) and 'content' in line:
                code_content_lines.append(line['content'])
            elif isinstance(line, str):
                code_content_lines.append(line)

        if code_content_lines:
            return '\n'.join(code_content_lines)

        return None
