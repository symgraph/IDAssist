#!/usr/bin/env python3

"""
IDAssist Internal Tools

IDA-specific tool definitions and handlers used by the Actions tab
and tool orchestrator. All tools that call IDA APIs use execute_on_main_thread().
"""

from typing import Any, Dict, List

from src.ida_compat import log, execute_on_main_thread

try:
    from mcp.types import TextContent
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

# IDA imports
try:
    import idaapi
    import idautils
    import ida_funcs
    import ida_hexrays
    import ida_kernwin
    import ida_name
    import ida_bytes
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


# Callback registry for document chat creation
_document_chat_handler = None
DOCUMENT_CHAT_TOOL_NAME = "ga_add_document"


def set_document_chat_handler(handler):
    """Register a callback for creating document chats.

    Args:
        handler: Callable(title: str, content: str) -> int (chat_id)
    """
    global _document_chat_handler
    _document_chat_handler = handler


INTERNAL_TOOL_DEFINITIONS = [
    {
        "name": "decompile_function",
        "description": "Get Hex-Rays decompiled pseudo-C output for a function",
        "schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function address (hex string, e.g. '0x401000')"}
            },
            "required": ["address"]
        }
    },
    {
        "name": "get_disassembly",
        "description": "Get disassembly listing for a function",
        "schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function address (hex string)"}
            },
            "required": ["address"]
        }
    },
    {
        "name": "get_xrefs",
        "description": "Get cross-references to/from an address",
        "schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to find xrefs for (hex string)"},
                "direction": {"type": "string", "enum": ["to", "from", "both"], "description": "Direction of cross-references", "default": "both"}
            },
            "required": ["address"]
        }
    },
    {
        "name": "navigate_to",
        "description": "Move IDA cursor to a specific address",
        "schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to navigate to (hex string)"}
            },
            "required": ["address"]
        }
    },
    {
        "name": "rename_function",
        "description": "Rename a function in IDA",
        "schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function address (hex string)"},
                "new_name": {"type": "string", "description": "New name for the function"}
            },
            "required": ["address", "new_name"]
        }
    },
    {
        "name": "rename_variable",
        "description": "Rename a local variable in a decompiled function",
        "schema": {
            "type": "object",
            "properties": {
                "function_address": {"type": "string", "description": "Function address (hex string)"},
                "old_name": {"type": "string", "description": "Current variable name"},
                "new_name": {"type": "string", "description": "New variable name"}
            },
            "required": ["function_address", "old_name", "new_name"]
        }
    },
    {
        "name": "get_function_list",
        "description": "List all functions in the binary",
        "schema": {
            "type": "object",
            "properties": {
                "filter": {"type": "string", "description": "Optional name filter (substring match)"},
                "limit": {"type": "integer", "description": "Maximum number of functions to return", "default": 100}
            }
        }
    },
    {
        "name": "get_strings",
        "description": "Get string references from the binary",
        "schema": {
            "type": "object",
            "properties": {
                "min_length": {"type": "integer", "description": "Minimum string length", "default": 4},
                "limit": {"type": "integer", "description": "Maximum number of strings to return", "default": 100}
            }
        }
    },
    {
        "name": DOCUMENT_CHAT_TOOL_NAME,
        "description": "Create a new chat document with custom markdown content. Use this to produce standalone analysis reports, summaries, or findings separate from the current conversation.",
        "schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Title for the new chat document"},
                "content": {"type": "string", "description": "Markdown content for the document"}
            },
            "required": ["title", "content"]
        }
    },
]


def get_internal_tools_for_llm(exclude_names=None):
    """Return internal tool definitions in OpenAI tool-calling format.

    Args:
        exclude_names: set of tool names to skip (e.g. tools already
                       provided by an external MCP server).
    """
    exclude = exclude_names or set()
    tools = []
    for defn in INTERNAL_TOOL_DEFINITIONS:
        if defn["name"] in exclude:
            continue
        tools.append({
            "type": "function",
            "function": {
                "name": defn["name"],
                "description": defn["description"],
                "parameters": defn["schema"],
            }
        })
    return tools


def execute_internal_tool(name: str, arguments: Dict[str, Any]) -> str:
    """Execute an internal tool by name and return the result as a string."""
    handlers = {
        "decompile_function": _decompile_function,
        "get_disassembly": _get_disassembly,
        "get_xrefs": _get_xrefs,
        "navigate_to": _navigate_to,
        "rename_function": _rename_function,
        "rename_variable": _rename_variable,
        "get_function_list": _get_function_list,
        "get_strings": _get_strings,
        DOCUMENT_CHAT_TOOL_NAME: _ga_add_document,
    }
    handler = handlers.get(name)
    if not handler:
        return f"Unknown internal tool: {name}"
    try:
        result_parts = handler(arguments)
        # result_parts is List[TextContent] — extract text
        return "\n".join(part.text if hasattr(part, 'text') else str(part) for part in result_parts)
    except Exception as e:
        return f"Error executing {name}: {e}"


def _parse_address(addr_str: str) -> int:
    """Parse hex address string to integer."""
    addr_str = addr_str.strip()
    if addr_str.startswith("0x") or addr_str.startswith("0X"):
        return int(addr_str, 16)
    return int(addr_str, 16)


def _decompile_function(args: Dict) -> List['TextContent']:
    """Decompile a function using Hex-Rays."""
    ea = _parse_address(args["address"])
    result_holder = [None, None]  # [result, error]

    def _do():
        try:
            func = ida_funcs.get_func(ea)
            if not func:
                result_holder[0] = [TextContent(type="text", text=f"No function found at {hex(ea)}")]
                return

            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if not cfunc:
                    result_holder[0] = [TextContent(type="text", text=f"Decompilation failed for {hex(ea)}")]
                    return

                func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
                result = f"// Function: {func_name} at {hex(func.start_ea)}\n{str(cfunc)}"
                result_holder[0] = [TextContent(type="text", text=result)]
            except Exception as e:
                result_holder[0] = [TextContent(type="text", text=f"Decompilation error: {str(e)}")]
        except Exception as e:
            result_holder[1] = str(e)

    execute_on_main_thread(_do)
    if result_holder[1]:
        return [TextContent(type="text", text=f"Error: {result_holder[1]}")]
    return result_holder[0]


def _get_disassembly(args: Dict) -> List['TextContent']:
    """Get disassembly listing for a function."""
    ea = _parse_address(args["address"])
    result_holder = [None, None]  # [result, error]

    def _do():
        try:
            func = ida_funcs.get_func(ea)
            if not func:
                result_holder[0] = [TextContent(type="text", text=f"No function found at {hex(ea)}")]
                return

            func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
            lines = [f"; Function: {func_name} at {hex(func.start_ea)}"]

            for item_ea in idautils.FuncItems(func.start_ea):
                disasm = idc.generate_disasm_line(item_ea, 0)
                lines.append(f"  0x{item_ea:08x}  {disasm}")

            result_holder[0] = [TextContent(type="text", text="\n".join(lines))]
        except Exception as e:
            result_holder[1] = str(e)

    execute_on_main_thread(_do)
    if result_holder[1]:
        return [TextContent(type="text", text=f"Error: {result_holder[1]}")]
    return result_holder[0]


def _get_xrefs(args: Dict) -> List['TextContent']:
    """Get cross-references to/from an address."""
    ea = _parse_address(args["address"])
    direction = args.get("direction", "both")
    result_holder = [None, None]  # [result, error]

    def _do():
        try:
            results = []

            if direction in ("to", "both"):
                results.append("=== References TO ===")
                for ref in idautils.CodeRefsTo(ea, 0):
                    func = ida_funcs.get_func(ref)
                    func_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                    results.append(f"  Code: 0x{ref:x} ({func_name})")
                for ref in idautils.DataRefsTo(ea):
                    results.append(f"  Data: 0x{ref:x}")

            if direction in ("from", "both"):
                results.append("=== References FROM ===")
                for ref in idautils.CodeRefsFrom(ea, 0):
                    func = ida_funcs.get_func(ref)
                    func_name = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                    results.append(f"  Code: 0x{ref:x} ({func_name})")
                for ref in idautils.DataRefsFrom(ea):
                    results.append(f"  Data: 0x{ref:x}")

            if not results or all(r.startswith("===") for r in results):
                results.append("No cross-references found")

            result_holder[0] = [TextContent(type="text", text="\n".join(results))]
        except Exception as e:
            result_holder[1] = str(e)

    execute_on_main_thread(_do)
    if result_holder[1]:
        return [TextContent(type="text", text=f"Error: {result_holder[1]}")]
    return result_holder[0]


def _navigate_to(args: Dict) -> List['TextContent']:
    """Navigate IDA cursor to an address."""
    ea = _parse_address(args["address"])

    result_holder = [False]

    def _do():
        result_holder[0] = ida_kernwin.jumpto(ea)

    execute_on_main_thread(_do)

    if result_holder[0]:
        return [TextContent(type="text", text=f"Navigated to {hex(ea)}")]
    else:
        return [TextContent(type="text", text=f"Failed to navigate to {hex(ea)}")]


def _rename_function(args: Dict) -> List['TextContent']:
    """Rename a function."""
    ea = _parse_address(args["address"])
    new_name = args["new_name"]
    result_holder = [False, "", ""]  # [success, old_name, error]

    def _do():
        try:
            func = ida_funcs.get_func(ea)
            if not func:
                result_holder[2] = f"No function found at {hex(ea)}"
                return

            result_holder[1] = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
            result_holder[0] = ida_name.set_name(func.start_ea, new_name, ida_name.SN_CHECK)
        except Exception as e:
            result_holder[2] = str(e)

    execute_on_main_thread(_do)

    if result_holder[2]:
        return [TextContent(type="text", text=f"Error: {result_holder[2]}")]
    if result_holder[0]:
        # Record LLM rename for provenance tracking (best-effort)
        try:
            from .analysis_db_service import AnalysisDBService
            from src.ida_compat import get_binary_hash
            bh_holder = [None]
            def _get_hash():
                bh_holder[0] = get_binary_hash()
            execute_on_main_thread(_get_hash)
            if bh_holder[0]:
                AnalysisDBService().record_llm_rename(bh_holder[0], ea, 'function', new_name)
        except Exception:
            pass
        return [TextContent(type="text", text=f"Renamed '{result_holder[1]}' to '{new_name}'")]
    else:
        return [TextContent(type="text", text=f"Failed to rename function to '{new_name}'")]


def _rename_variable(args: Dict) -> List['TextContent']:
    """Rename a local variable in a function."""
    func_ea = _parse_address(args["function_address"])
    old_name = args["old_name"]
    new_name = args["new_name"]

    result_holder = [False, ""]

    def _do():
        try:
            # rename_lvar(ea_t, oldname, newname) -> bool
            result_holder[0] = ida_hexrays.rename_lvar(func_ea, old_name, new_name)
            if not result_holder[0]:
                result_holder[1] = f"rename_lvar failed (variable '{old_name}' may not exist)"
        except Exception as e:
            result_holder[1] = str(e)

    execute_on_main_thread(_do)

    if result_holder[0]:
        return [TextContent(type="text", text=f"Renamed variable '{old_name}' to '{new_name}'")]
    else:
        return [TextContent(type="text", text=f"Failed: {result_holder[1]}")]


def _get_function_list(args: Dict) -> List['TextContent']:
    """List functions in the binary."""
    name_filter = args.get("filter", "").lower()
    limit = args.get("limit", 100)
    result_holder = [None, None]  # [result, error]

    def _do():
        try:
            functions = []
            for func_ea in idautils.Functions():
                name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
                if name_filter and name_filter not in name.lower():
                    continue

                func = ida_funcs.get_func(func_ea)
                size = (func.end_ea - func.start_ea) if func else 0
                functions.append(f"  0x{func_ea:08x}  {name}  (size: {size})")

                if len(functions) >= limit:
                    break

            header = f"Functions ({len(functions)} shown):\n"
            result_holder[0] = [TextContent(type="text", text=header + "\n".join(functions))]
        except Exception as e:
            result_holder[1] = str(e)

    execute_on_main_thread(_do)
    if result_holder[1]:
        return [TextContent(type="text", text=f"Error: {result_holder[1]}")]
    return result_holder[0]


def _get_strings(args: Dict) -> List['TextContent']:
    """Get strings from the binary."""
    min_length = args.get("min_length", 4)
    limit = args.get("limit", 100)
    result_holder = [None, None]  # [result, error]

    def _do():
        try:
            strings = []
            for s in idautils.Strings():
                value = str(s)
                if len(value) >= min_length:
                    strings.append(f"  0x{s.ea:08x}  ({s.length:4d})  {value}")
                    if len(strings) >= limit:
                        break

            header = f"Strings ({len(strings)} shown):\n"
            result_holder[0] = [TextContent(type="text", text=header + "\n".join(strings))]
        except Exception as e:
            result_holder[1] = str(e)

    execute_on_main_thread(_do)
    if result_holder[1]:
        return [TextContent(type="text", text=f"Error: {result_holder[1]}")]
    return result_holder[0]


def _ga_add_document(args: Dict) -> List['TextContent']:
    """Create a new chat document with custom markdown content."""
    if _document_chat_handler is None:
        return [TextContent(type="text", text="Error: document chat handler not registered")]
    title = args.get("title", "Untitled Document")
    content = args.get("content", "")
    try:
        chat_id = _document_chat_handler(title, content)
        return [TextContent(type="text", text=f"Document '{title}' created as Chat {chat_id}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error creating document: {e}")]
