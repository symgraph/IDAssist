#!/usr/bin/env python3

"""
IDAssist - IDA Pro Plugin for LLM-Assisted Reverse Engineering

This is the IDA plugin_t entry point. It registers IDAssist as a persistent
plugin that opens a dockable window with AI-powered analysis tabs.

Target: IDA Pro 9.x (uses ida_typeinf unified API, PySide6).
"""

import os
import sys

import idaapi
import ida_kernwin
import ida_idp


# Ensure our package root is importable
_PLUGIN_DIR = os.path.dirname(os.path.realpath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)


PLUGIN_NAME = "IDAssist"
PLUGIN_HOTKEY = "Ctrl+Shift+A"
PLUGIN_COMMENT = "LLM-assisted reverse engineering"
PLUGIN_HELP = "Opens the IDAssist panel for AI-powered binary analysis"
def _load_version():
    import json
    try:
        meta_path = os.path.join(_PLUGIN_DIR, "ida-plugin.json")
        with open(meta_path, "r") as f:
            return json.load(f)["plugin"]["version"]
    except Exception:
        return "0.0.0"

PLUGIN_VERSION = _load_version()


# ---------------------------------------------------------------------------
# Context menu action handlers
# ---------------------------------------------------------------------------

class ExplainFunctionAction(ida_kernwin.action_handler_t):
    """Context menu: Explain the current function."""

    def activate(self, ctx):
        try:
            from src.views.idassist_form import IDAssistForm
            IDAssistForm.open()
            form = IDAssistForm._instance
            if form and hasattr(form, 'explain_controller'):
                form.tabs.setCurrentWidget(form.explain_view)
                form.explain_controller.explain_function()
        except Exception as e:
            ida_kernwin.msg(f"[IDAssist] ERROR: {e}\n")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class RenameSuggestionsAction(ida_kernwin.action_handler_t):
    """Context menu: Get rename suggestions for the current function."""

    def activate(self, ctx):
        try:
            from src.views.idassist_form import IDAssistForm
            IDAssistForm.open()
            form = IDAssistForm._instance
            if form and hasattr(form, 'actions_controller'):
                form.tabs.setCurrentWidget(form.actions_view)
                form.actions_controller.analyze_function()
        except Exception as e:
            ida_kernwin.msg(f"[IDAssist] ERROR: {e}\n")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class AskAboutSelectionAction(ida_kernwin.action_handler_t):
    """Context menu: Ask about selected code in Query tab."""

    def activate(self, ctx):
        try:
            from src.views.idassist_form import IDAssistForm
            IDAssistForm.open()
            form = IDAssistForm._instance
            if form and hasattr(form, 'query_controller'):
                form.tabs.setCurrentWidget(form.query_view)
                # Pre-fill with #func macro
                if hasattr(form.query_view, 'set_query_text'):
                    form.query_view.set_query_text("What does this function do? #func")
        except Exception as e:
            ida_kernwin.msg(f"[IDAssist] ERROR: {e}\n")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class ExplainHotkeyAction(ida_kernwin.action_handler_t):
    """Hotkey Ctrl+Shift+E: Explain current function."""

    def activate(self, ctx):
        ExplainFunctionAction().activate(ctx)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class QueryHotkeyAction(ida_kernwin.action_handler_t):
    """Hotkey Ctrl+Shift+Q: Focus Query tab with context."""

    def activate(self, ctx):
        AskAboutSelectionAction().activate(ctx)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# IDB Hooks for auto-refresh
# ---------------------------------------------------------------------------

class IDAssistIDBHooks(ida_idp.IDB_Hooks):
    """IDB hooks to detect renames and function changes."""

    def renamed(self, ea, new_name, is_local):
        """A name was changed in the IDB."""
        try:
            from src.views.idassist_form import IDAssistForm
            form = IDAssistForm._instance
            if form and hasattr(form, 'semantic_graph_controller'):
                # Mark graph as potentially stale
                controller = form.semantic_graph_controller
                if hasattr(controller, 'on_name_changed'):
                    controller.on_name_changed(ea, new_name)
        except Exception:
            pass
        return 0

    def func_added(self, pfn):
        """A new function was created."""
        return 0

    def func_updated(self, pfn):
        """A function was modified."""
        return 0


# ---------------------------------------------------------------------------
# Popup hooks for context menus
# ---------------------------------------------------------------------------

class IDAssistPopupHooks(ida_kernwin.UI_Hooks):
    """UI hooks to add IDAssist actions to context menus."""

    def finish_populating_widget_popup(self, widget, popup):
        wtype = ida_kernwin.get_widget_type(widget)
        # Add to disassembly and pseudocode views
        if wtype in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            ida_kernwin.attach_action_to_popup(
                widget, popup, "idassist:explain_function", "IDAssist/")
            ida_kernwin.attach_action_to_popup(
                widget, popup, "idassist:rename_suggestions", "IDAssist/")
            ida_kernwin.attach_action_to_popup(
                widget, popup, "idassist:ask_about_selection", "IDAssist/")


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class _DeferredOpenHook(ida_kernwin.UI_Hooks):
    """One-shot hook to open IDAssist panel after IDA's UI is fully ready."""

    def __init__(self, plugin):
        super().__init__()
        self._plugin = plugin

    def ready_to_run(self):
        self._plugin.run(0)
        self.unhook()


class IDAssistPlugin(idaapi.plugin_t):
    """IDA plugin_t implementation for IDAssist."""

    flags = idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def __init__(self):
        super().__init__()
        self._idb_hooks = None
        self._popup_hooks = None
        self._deferred_hook = None

    def init(self):
        """Called when IDA loads the plugin. Return PLUGIN_KEEP to stay resident."""
        try:
            from src.ida_compat import log
            log.log_info(f"IDAssist v{PLUGIN_VERSION} loaded")

            # Register context menu actions
            self._register_actions()

            # Install IDB hooks
            self._idb_hooks = IDAssistIDBHooks()
            self._idb_hooks.hook()

            # Install popup hooks for context menus
            self._popup_hooks = IDAssistPopupHooks()
            self._popup_hooks.hook()

            # Defer panel open until IDA's UI is fully ready
            self._deferred_hook = _DeferredOpenHook(self)
            self._deferred_hook.hook()

            return idaapi.PLUGIN_KEEP
        except Exception as e:
            ida_kernwin.msg(f"[IDAssist] ERROR: Failed to initialize: {e}\n")
            return idaapi.PLUGIN_SKIP

    def _register_actions(self):
        """Register all context menu and hotkey actions."""
        actions = [
            # Context menu actions
            ida_kernwin.action_desc_t(
                "idassist:explain_function",
                "IDAssist: Explain Function",
                ExplainFunctionAction(),
                "Ctrl+Shift+E",
                "Explain the current function using AI",
                -1
            ),
            ida_kernwin.action_desc_t(
                "idassist:rename_suggestions",
                "IDAssist: Rename Suggestions",
                RenameSuggestionsAction(),
                None,
                "Get AI-powered rename suggestions",
                -1
            ),
            ida_kernwin.action_desc_t(
                "idassist:ask_about_selection",
                "IDAssist: Ask About Selection",
                AskAboutSelectionAction(),
                "Ctrl+Shift+Q",
                "Ask AI about the current code",
                -1
            ),
        ]

        for desc in actions:
            ida_kernwin.register_action(desc)

    def run(self, arg):
        """Called when the user activates the plugin (hotkey or menu)."""
        try:
            from src.views.idassist_form import IDAssistForm
            IDAssistForm.open()
        except Exception as e:
            ida_kernwin.msg(f"[IDAssist] ERROR: Failed to open panel: {e}\n")
            import traceback
            ida_kernwin.msg(traceback.format_exc() + "\n")

    def term(self):
        """Called when IDA is shutting down."""
        try:
            # Unregister actions
            for action_id in ["idassist:explain_function",
                              "idassist:rename_suggestions",
                              "idassist:ask_about_selection"]:
                ida_kernwin.unregister_action(action_id)

            # Unhook
            if self._idb_hooks:
                self._idb_hooks.unhook()
            if self._popup_hooks:
                self._popup_hooks.unhook()

            # Shutdown services
            from src.services.service_registry import get_service_registry
            registry = get_service_registry()
            if registry.is_initialized():
                registry.shutdown()

            from src.ida_compat import log
            log.log_info("IDAssist unloaded")
        except Exception:
            pass


def PLUGIN_ENTRY():
    """IDA plugin entry point."""
    return IDAssistPlugin()
