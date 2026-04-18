#!/usr/bin/env python3

"""
Binary Context Service for IDAssist

Full rewrite of BinAssist's BinaryContextService for IDA Pro 9.x.
Translates all Binary Ninja API calls to IDA Pro equivalents.
"""

from typing import Optional, Dict, Any, List
from enum import Enum
import hashlib
import os

from src.ida_compat import log, get_binary_hash as _get_binary_hash_from_file, execute_on_main_thread

# IDA imports - these are only available inside IDA
try:
    import idaapi
    import idautils
    import ida_funcs
    import ida_bytes
    import ida_hexrays
    import ida_kernwin
    import ida_ida
    import ida_nalt
    import ida_name
    import ida_segment
    import ida_typeinf
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class ViewLevel(Enum):
    """IDA abstraction levels (simplified from BinAssist)"""
    ASM = "assembly"
    PSEUDO_C = "pseudo_c"


# Module-level tracked view level (updated by UI hooks when IDA code views gain focus)
_tracked_view_level = None

def set_tracked_view_level(level):
    """Called by UI hooks when a code view (disassembly or pseudocode) gains focus."""
    global _tracked_view_level
    _tracked_view_level = level


class BinaryContextService:
    """Service for extracting context-aware information from IDA Pro"""

    def __init__(self):
        """Initialize - IDA doesn't need a BinaryView object"""
        self._current_offset = 0
        self._cached_binary_hash = None

    def set_current_offset(self, offset: int) -> None:
        """Set the current offset/address"""
        self._current_offset = offset

    def set_binary_hash(self, binary_hash: str) -> None:
        """Set the cached binary hash."""
        self._cached_binary_hash = binary_hash
        log.log_debug(f"Cached binary hash: {binary_hash}")

    def get_binary_hash(self) -> Optional[str]:
        """Get the cached binary hash."""
        return self._cached_binary_hash

    def _build_context_snapshot(self, address: int) -> Dict[str, Any]:
        """Build a context snapshot for a specific address on IDA's main thread."""
        self._current_offset = address
        return {
            "offset": self._current_offset,
            "offset_hex": f"0x{self._current_offset:x}",
            "current_view_level": self.get_current_view_level().value,
            "binary_info": self._get_binary_info(),
            "function_context": self._get_function_context(self._current_offset),
            "view_capabilities": self._get_view_capabilities(),
        }

    def get_current_context(self) -> Dict[str, Any]:
        """Get complete context snapshot for current state"""
        if not _IN_IDA:
            return {"error": "Not running inside IDA Pro"}

        context_holder = [{"error": "Failed to read current IDA context"}]

        def _do():
            try:
                current_ea = ida_kernwin.get_screen_ea()
                context_holder[0] = self._build_context_snapshot(current_ea)
            except Exception as e:
                context_holder[0] = {"error": f"Failed to get current context: {e}"}

        execute_on_main_thread(_do)
        return context_holder[0]

    def get_context_for_address(self, address: int) -> Dict[str, Any]:
        """Get complete context snapshot for an explicit address."""
        if not _IN_IDA:
            return {"error": "Not running inside IDA Pro"}
        if address is None:
            return {"error": "No address provided"}

        context_holder = [{"error": f"Failed to read IDA context at 0x{address:x}"}]

        def _do():
            try:
                context_holder[0] = self._build_context_snapshot(address)
            except Exception as e:
                context_holder[0] = {"error": f"Failed to get context for 0x{address:x}: {e}"}

        execute_on_main_thread(_do)
        return context_holder[0]

    def _get_binary_info(self) -> Dict[str, Any]:
        """Extract basic binary metadata from IDA"""
        if not _IN_IDA:
            return {}

        try:
            filename = ida_nalt.get_root_filename() or 'Unknown'
            filepath = ida_nalt.get_input_file_path() or 'Unknown'
            arch = ida_ida.inf_get_procname() or 'Unknown'
            entry_point = idc.get_inf_attr(idc.INF_START_EA)
            is_64bit = ida_ida.inf_is_64bit()
            is_be = ida_ida.inf_is_be()

            # Count functions
            total_functions = 0
            for _ in idautils.Functions():
                total_functions += 1

            # Get file type
            filetype = ida_ida.inf_get_filetype()
            filetype_map = {
                0: "Unknown",
                1: "EXE (old)",
                2: "COM (old)",
                3: "BIN",
                11: "ELF",
                12: "W32RUN",
                13: "LE",
                14: "LX",
                15: "NLM",
                16: "COFF",
                17: "PE",
                18: "OMF",
                20: "MACHO",
            }
            file_type_str = filetype_map.get(filetype, f"type_{filetype}")

            return {
                "filename": filename,
                "filepath": filepath,
                "architecture": arch,
                "platform": file_type_str,
                "entry_point": entry_point,
                "entry_point_hex": f"0x{entry_point:x}" if entry_point else None,
                "address_size": 8 if is_64bit else 4,
                "endianness": "big" if is_be else "little",
                "file_type": file_type_str,
                "total_functions": total_functions,
                "segments": self._get_segments_info()
            }
        except Exception as e:
            return {"error": f"Failed to get binary info: {str(e)}"}

    def get_binary_metadata_for_rlhf(self) -> Dict[str, Any]:
        """Extract binary metadata for RLHF feedback storage."""
        if not _IN_IDA:
            return {"filename": "Unknown", "size": 0, "sha256": "unknown"}

        try:
            filename = ida_nalt.get_root_filename() or "Unknown"
            filepath = ida_nalt.get_input_file_path() or ""

            size = 0
            sha256_hash = "unknown"

            if filepath and os.path.exists(filepath):
                size = os.path.getsize(filepath)
                with open(filepath, 'rb') as f:
                    sha256_hash = hashlib.sha256(f.read()).hexdigest()

            return {
                "filename": filename,
                "size": size,
                "sha256": sha256_hash
            }

        except Exception as e:
            log.log_error(f"Failed to get binary metadata for RLHF: {e}")
            return {"filename": "Unknown", "size": 0, "sha256": "unknown"}

    def _get_segments_info(self) -> List[Dict[str, Any]]:
        """Get segment information from IDA"""
        try:
            segments = []
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg:
                    segments.append({
                        "start": f"0x{seg.start_ea:x}",
                        "end": f"0x{seg.end_ea:x}",
                        "length": seg.end_ea - seg.start_ea,
                        "readable": bool(seg.perm & ida_segment.SFL_LOADER),
                        "writable": bool(seg.perm & 2),
                        "executable": bool(seg.perm & 1),
                    })
            return segments
        except Exception:
            return []

    def _get_function_context(self, address: int) -> Optional[Dict[str, Any]]:
        """Get context for function containing the given address"""
        if not _IN_IDA:
            return None

        func = ida_funcs.get_func(address)
        if not func:
            return None

        func_name = ida_funcs.get_func_name(func.start_ea)
        func_start = func.start_ea
        func_end = func.end_ea
        func_size = func_end - func_start

        # Count basic blocks
        bb_count = 0
        for _ in idautils.FuncItems(func_start):
            pass
        try:
            from ida_gdl import FlowChart
            fc = FlowChart(func)
            bb_count = fc.size
        except Exception:
            bb_count = 0

        # Get callers and callees
        callers = []
        callees = []
        try:
            for ref in idautils.CodeRefsTo(func_start, 0):
                caller_func = ida_funcs.get_func(ref)
                if caller_func:
                    callers.append(f"0x{caller_func.start_ea:x}")
            callers = list(set(callers))

            for item_ea in idautils.FuncItems(func_start):
                for ref in idautils.CodeRefsFrom(item_ea, 0):
                    ref_func = ida_funcs.get_func(ref)
                    if ref_func and ref_func.start_ea != func_start:
                        callees.append(f"0x{ref_func.start_ea:x}")
            callees = list(set(callees))
        except Exception:
            pass

        # Get function prototype
        prototype = self._get_function_prototype(func_start)

        return {
            "name": func_name,
            "start": f"0x{func_start:x}",
            "end": f"0x{func_end:x}",
            "size": func_size,
            "basic_blocks": bb_count,
            "call_sites": len(callees),
            "callers": callers,
            "callees": callees,
            "symbol": func_name,
            "analysis_skipped": False,
            "can_return": str(bool(func.flags & ida_funcs.FUNC_NORET) == False),
            "prototype": prototype,
        }

    def _get_function_prototype(self, func_ea: int) -> str:
        """Get function prototype/signature from IDA"""
        try:
            tinfo = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tinfo, func_ea):
                prototype = str(tinfo)
                func_name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
                return f"{prototype}"

            # Fallback: try idc.get_type
            type_str = idc.get_type(func_ea)
            if type_str:
                return type_str

            # Ultimate fallback
            func_name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
            return f"unknown {func_name}(...)"

        except Exception:
            func_name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
            return f"unknown {func_name}(...)"

    def _get_view_capabilities(self) -> Dict[str, bool]:
        """Determine what view levels are available"""
        has_decompiler = False
        try:
            if _IN_IDA and ida_hexrays.init_hexrays_plugin():
                has_decompiler = True
        except Exception:
            pass

        return {
            "assembly": True,
            "pseudo_c": has_decompiler,
            "data_view": True,
        }

    def get_current_view_level(self) -> ViewLevel:
        """Detect the current view level from IDA UI"""
        try:
            widget = ida_kernwin.get_current_widget()
            if widget:
                wtype = ida_kernwin.get_widget_type(widget)
                if wtype == ida_kernwin.BWN_PSEUDOCODE:
                    return ViewLevel.PSEUDO_C
                elif wtype == ida_kernwin.BWN_DISASM:
                    return ViewLevel.ASM
        except Exception:
            pass
        # Fall back to last tracked code view (set by UI hooks)
        if _tracked_view_level is not None:
            return _tracked_view_level
        return ViewLevel.ASM

    def get_code_at_level(self, address: int, view_level: ViewLevel, context_lines: int = 5) -> Dict[str, Any]:
        """Get code at specified abstraction level"""
        if not _IN_IDA:
            return {"error": "Not running inside IDA Pro"}

        result = {
            "address": f"0x{address:x}",
            "view_level": view_level.value,
            "lines": [],
            "error": None
        }

        try:
            if view_level == ViewLevel.ASM:
                result["lines"] = self._get_assembly_code(address, context_lines)
            elif view_level == ViewLevel.PSEUDO_C:
                result["lines"] = self._get_pseudo_code(address, context_lines)
            else:
                result["error"] = f"Unsupported view level: {view_level.value}"
        except Exception as e:
            result["error"] = f"Failed to get code: {str(e)}"

        return result

    def _get_assembly_code(self, address: int, context_lines: int) -> List[Dict[str, Any]]:
        """Get assembly code for function at address"""
        try:
            func = ida_funcs.get_func(address)
            if not func:
                return [{"error": "No function found at address"}]

            asm_text = self._asm_to_text(func.start_ea)
            if not asm_text:
                return [{"error": "Failed to get assembly text"}]

            lines = []
            for line_num, line in enumerate(asm_text.split('\n')):
                line = line.strip()
                if not line:
                    continue

                addr_match = None
                if line.startswith('0x'):
                    parts = line.split('  ', 1)
                    if len(parts) == 2:
                        try:
                            addr_match = int(parts[0], 16)
                            content = parts[1]
                        except ValueError:
                            content = line
                    else:
                        content = line
                else:
                    content = line

                lines.append({
                    "address": f"0x{addr_match:x}" if addr_match else "",
                    "content": content,
                    "is_current": addr_match == address if addr_match else False,
                    "line_number": line_num + 1
                })

            return lines

        except Exception as e:
            return [{"error": f"Failed to get assembly: {str(e)}"}]

    def _asm_to_text(self, func_start: int) -> str:
        """Convert assembly instructions to text using IDA API.

        All IDA API calls are marshalled to the main thread so this
        method is safe to call from background threads.
        """
        result = [None]

        def _do():
            func = ida_funcs.get_func(func_start)
            if not func:
                return

            func_name = ida_funcs.get_func_name(func_start) or f"sub_{func_start:x}"
            prototype = self._get_function_prototype(func_start)

            asm_instructions = ""
            for item_ea in idautils.FuncItems(func_start):
                disasm = idc.generate_disasm_line(item_ea, 0)
                if disasm:
                    asm_instructions += f"\n0x{item_ea:08x}  {disasm}"

            result[0] = f"{prototype}\n{asm_instructions}\n"

        execute_on_main_thread(_do)
        return result[0]

    def _get_pseudo_code(self, address: int, context_lines: int) -> List[Dict[str, Any]]:
        """Get decompiled pseudo-C code using Hex-Rays"""
        try:
            pseudo_text = self._pseudo_c_to_text(address)
            if not pseudo_text:
                return [{"error": "Failed to get pseudo-C text (Hex-Rays not available?)"}]

            lines = []
            for line_num, line in enumerate(pseudo_text.split('\n')):
                original_line = line
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                lines.append({
                    "address": "",
                    "content": original_line,
                    "is_current": False,
                    "line_number": line_num + 1
                })

            return lines

        except Exception as e:
            return [{"error": f"Failed to generate pseudo code: {str(e)}"}]

    def _pseudo_c_to_text(self, addr: int) -> Optional[str]:
        """Convert to pseudo-C using Hex-Rays decompiler.

        All IDA API calls are marshalled to the main thread so this
        method is safe to call from background threads.
        """
        result = [None]

        def _do():
            try:
                func = ida_funcs.get_func(addr)
                if not func:
                    return

                cfunc = ida_hexrays.decompile(func.start_ea)
                if not cfunc:
                    return

                result[0] = str(cfunc)
            except Exception as e:
                log.log_warn(f"Decompilation/Hex-Rays error at 0x{addr:x}: {e}")

        execute_on_main_thread(_do)
        return result[0]

    def get_hexdump(self, address: int, size: int = 256) -> Dict[str, Any]:
        """Get hexdump for address range"""
        if not _IN_IDA:
            return {"error": "Not running inside IDA Pro"}

        result = {
            "address": f"0x{address:x}",
            "size": size,
            "lines": [],
            "error": None
        }

        try:
            data = ida_bytes.get_bytes(address, size)
            if not data:
                result["error"] = "Failed to read data at address"
                return result

            for i in range(0, len(data), 16):
                line_addr = address + i
                line_data = data[i:i + 16]

                hex_bytes = ' '.join(f'{b:02x}' for b in line_data)
                hex_bytes = hex_bytes.ljust(47)

                ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)

                result["lines"].append({
                    "address": f"0x{line_addr:08x}",
                    "hex": hex_bytes,
                    "ascii": ascii_repr,
                    "bytes": line_data.hex()
                })

        except Exception as e:
            result["error"] = f"Failed to generate hexdump: {str(e)}"

        return result

    def get_line_with_context(self, address: int, view_level: ViewLevel, context_lines: int = 5) -> Dict[str, Any]:
        """Get line at address with N lines of context above and below."""
        if not _IN_IDA:
            return {"error": "Not running inside IDA Pro"}

        try:
            target_addr = f"0x{address:x}"

            if view_level == ViewLevel.PSEUDO_C:
                return self._get_pseudo_line_with_context(address, context_lines)
            else:
                return self._get_asm_line_with_context(address, context_lines)

        except Exception as e:
            return {"error": f"Failed to get line with context: {str(e)}"}

    def _get_pseudo_line_with_context(self, address: int, context_lines: int = 5) -> Dict[str, Any]:
        """Get pseudo-C line at address with context."""
        target_addr = f"0x{address:x}"

        func = ida_funcs.get_func(address)
        if not func:
            return {"error": "No function found at address"}

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"error": "Decompilation failed"}

            # Get full pseudo-C and split into lines
            code = str(cfunc)
            code_lines = code.split('\n')

            # Build lines list
            all_lines = []
            for i, line in enumerate(code_lines):
                if line.strip():
                    all_lines.append({
                        "address": "",
                        "content": line,
                        "line_number": i + 1
                    })

            if not all_lines:
                return {"error": "No pseudo-C lines"}

            # For pseudo-C, pick middle of function as "current"
            current_index = len(all_lines) // 2

            current_line = all_lines[current_index].copy()
            current_line["is_current"] = True

            start_index = max(0, current_index - context_lines)
            lines_before = all_lines[start_index:current_index]
            end_index = min(len(all_lines), current_index + context_lines + 1)
            lines_after = all_lines[current_index + 1:end_index]

            return {
                "address": target_addr,
                "view_level": "pseudo_c",
                "current_line": current_line,
                "lines_before": lines_before,
                "lines_after": lines_after,
                "function_context": self._get_function_context(address)
            }
        except Exception as e:
            return {"error": f"Failed to get pseudo-C context: {str(e)}"}

    def _get_asm_line_with_context(self, address: int, context_lines: int = 5) -> Dict[str, Any]:
        """Get assembly line at address with context."""
        target_addr = f"0x{address:x}"

        func = ida_funcs.get_func(address)
        if not func:
            # Single instruction outside function
            disasm = idc.generate_disasm_line(address, 0)
            if disasm:
                return {
                    "address": target_addr,
                    "view_level": "assembly",
                    "current_line": {
                        "address": target_addr,
                        "content": disasm,
                        "is_current": True,
                    },
                    "lines_before": [],
                    "lines_after": [],
                    "function_context": None
                }
            return {"error": "No instruction found at address"}

        # Collect all instructions in function
        asm_instructions = []
        for item_ea in idautils.FuncItems(func.start_ea):
            disasm = idc.generate_disasm_line(item_ea, 0)
            asm_instructions.append({
                "address": f"0x{item_ea:x}",
                "content": disasm or "???",
            })

        if not asm_instructions:
            return {"error": "No assembly instructions found"}

        # Find current instruction
        current_index = 0
        for i, instr in enumerate(asm_instructions):
            if instr["address"] == target_addr:
                current_index = i
                break

        current_line = asm_instructions[current_index].copy()
        current_line["is_current"] = True

        start_index = max(0, current_index - context_lines)
        lines_before = asm_instructions[start_index:current_index]
        end_index = min(len(asm_instructions), current_index + context_lines + 1)
        lines_after = asm_instructions[current_index + 1:end_index]

        return {
            "address": target_addr,
            "view_level": "assembly",
            "current_line": current_line,
            "lines_before": lines_before,
            "lines_after": lines_after,
            "function_context": self._get_function_context(address)
        }

    def get_line_context(self, address: int, view_level: ViewLevel) -> Dict[str, Any]:
        """Get specific line context at cursor position"""
        if not _IN_IDA:
            return {"error": "Not running inside IDA Pro"}

        try:
            current_line = None

            if view_level == ViewLevel.ASM:
                disasm = idc.generate_disasm_line(address, 0)
                if disasm:
                    current_line = {
                        "address": f"0x{address:x}",
                        "content": disasm,
                        "is_current": True,
                    }
            elif view_level == ViewLevel.PSEUDO_C:
                func = ida_funcs.get_func(address)
                if func:
                    try:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            current_line = {
                                "address": f"0x{address:x}",
                                "content": str(cfunc).split('\n')[0],
                                "is_current": True,
                            }
                    except Exception:
                        pass

            if not current_line:
                current_line = {
                    "address": f"0x{address:x}",
                    "content": "No instruction found at address",
                    "error": "Could not retrieve instruction"
                }

            return {
                "address": f"0x{address:x}",
                "view_level": view_level.value,
                "line": current_line,
                "context": self._get_function_context(address)
            }

        except Exception as e:
            return {
                "address": f"0x{address:x}",
                "view_level": view_level.value,
                "error": f"Failed to get line context: {str(e)}"
            }

    def get_triage_metadata(self) -> Dict[str, Any]:
        """Get comprehensive triage information about the binary"""
        if not _IN_IDA:
            return {"error": "Not running inside IDA Pro"}

        metadata = {
            "basic_info": self._get_binary_info(),
            "imports": self._get_imports(),
            "exports": self._get_exports(),
            "strings": self._get_interesting_strings(),
            "entry_points": self._get_entry_points(),
            "security_features": self._get_security_features(),
        }

        return metadata

    def _get_imports(self) -> List[Dict[str, Any]]:
        """Get imported functions using IDA's import enumeration"""
        imports = []

        try:
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                module_name = ida_nalt.get_import_module_name(i)

                def imp_cb(ea, name, ordinal):
                    if name:
                        full_name = f"{module_name}::{name}" if module_name else name
                        imports.append({
                            "name": full_name,
                            "address": f"0x{ea:x}",
                            "namespace": module_name,
                        })
                    return True  # Continue enumeration

                ida_nalt.enum_import_names(i, imp_cb)
        except Exception:
            pass

        return imports[:50]

    def _get_exports(self) -> List[Dict[str, Any]]:
        """Get exported functions using IDA's entry points"""
        exports = []

        try:
            for i, ordinal, ea, name in idautils.Entries():
                if name:
                    exports.append({
                        "name": name,
                        "address": f"0x{ea:x}",
                        "namespace": None,
                    })
        except Exception:
            pass

        return exports[:50]

    def _get_interesting_strings(self) -> List[Dict[str, Any]]:
        """Get potentially interesting strings from the binary"""
        strings = []

        try:
            for s in idautils.Strings():
                value = str(s)
                if len(value) > 4:
                    strings.append({
                        "value": value,
                        "address": f"0x{s.ea:x}",
                        "length": s.length,
                        "type": str(s.strtype)
                    })
        except Exception:
            pass

        return strings[:100]

    def _get_entry_points(self) -> List[Dict[str, Any]]:
        """Get all entry points in the binary"""
        entries = []

        try:
            entry_ea = idc.get_inf_attr(idc.INF_START_EA)
            if entry_ea and entry_ea != idaapi.BADADDR:
                entries.append({
                    "name": "main_entry",
                    "address": f"0x{entry_ea:x}",
                    "type": "primary"
                })

            # Look for common entry point names
            for func_ea in idautils.Functions():
                func_name = ida_funcs.get_func_name(func_ea)
                if func_name and func_name.lower() in ['main', '_main', 'start', '_start', 'wmain']:
                    entries.append({
                        "name": func_name,
                        "address": f"0x{func_ea:x}",
                        "type": "function_entry"
                    })
        except Exception:
            pass

        return entries

    def _get_security_features(self) -> Dict[str, Any]:
        """Analyze security features and mitigations"""
        features = {
            "nx_bit": False,
            "stack_canaries": False,
            "aslr": False,
            "pie": False,
            "relro": False,
            "stripped": True,
        }

        try:
            # Check for named symbols (indicates not stripped)
            named_count = 0
            for func_ea in idautils.Functions():
                name = ida_funcs.get_func_name(func_ea)
                if name and not name.startswith('sub_'):
                    named_count += 1
                if named_count > 10:
                    features["stripped"] = False
                    break
        except Exception:
            pass

        return features
