#!/usr/bin/env python3

"""
IDAssist PluginForm - Dockable widget container for IDAssist tabs.

Subclasses ``idaapi.PluginForm`` and hosts a QTabWidget with all
analysis tabs (Explain, Query, Actions, Semantic Graph, RAG, SymGraph, Settings).
"""

import idaapi
import ida_kernwin

from src.ida_compat import log, get_binary_hash


class IDAssistUIHooks(ida_kernwin.UI_Hooks):
    """UI hooks to track cursor position changes in IDA.

    When the user navigates to a different address, this hook notifies
    all registered controllers so they can refresh context.
    """

    def __init__(self):
        super().__init__()
        self._listeners = []

    def add_listener(self, callback):
        """Register a callback(ea) to be called on cursor change."""
        if callback not in self._listeners:
            self._listeners.append(callback)

    def remove_listener(self, callback):
        """Unregister a cursor-change callback."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    def screen_ea_changed(self, ea, prev_ea):
        """Called by IDA when the cursor moves to a new address."""
        for listener in self._listeners:
            try:
                listener(ea)
            except Exception as e:
                log.log_error(f"UI hook listener error: {e}")

    def current_widget_changed(self, widget, prev_widget):
        """Track which IDA code view was last active."""
        try:
            if widget:
                wtype = ida_kernwin.get_widget_type(widget)
                if wtype == ida_kernwin.BWN_PSEUDOCODE:
                    from src.services.binary_context_service import set_tracked_view_level, ViewLevel
                    set_tracked_view_level(ViewLevel.PSEUDO_C)
                elif wtype == ida_kernwin.BWN_DISASM:
                    from src.services.binary_context_service import set_tracked_view_level, ViewLevel
                    set_tracked_view_level(ViewLevel.ASM)
        except Exception:
            pass


class IDAssistForm(idaapi.PluginForm):
    """Singleton dockable form hosting the IDAssist tab widget."""

    _instance = None
    _ui_hooks = None

    @classmethod
    def open(cls):
        """Open (or focus) the singleton IDAssist panel."""
        if cls._instance is None:
            cls._instance = IDAssistForm()
        cls._instance.Show(
            "IDAssist",
            options=(
                idaapi.PluginForm.WOPN_TAB
                | idaapi.PluginForm.WOPN_RESTORE
                | idaapi.PluginForm.WOPN_PERSIST
            ),
        )

    @classmethod
    def get_ui_hooks(cls):
        """Get the shared UI hooks instance."""
        if cls._ui_hooks is None:
            cls._ui_hooks = IDAssistUIHooks()
            cls._ui_hooks.hook()
        return cls._ui_hooks

    def OnCreate(self, form):
        """Called by IDA when the form is first created."""
        try:
            from src.qt_compat import QTabWidget, QVBoxLayout, QWidget

            # Convert IDA form handle to a PySide6 widget
            parent = self.FormToPyQtWidget(form)

            # Root layout
            layout = QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)

            # Tab widget
            self.tabs = QTabWidget()

            # Initialize all tabs
            self._init_explain_tab()
            self._init_query_tab()
            self._init_actions_tab()
            self._init_semantic_graph_tab()
            self._init_symgraph_tab()
            self._init_rag_tab()
            self._init_settings_tab()

            layout.addWidget(self.tabs)
            parent.setLayout(layout)

            # Initialize binary context for all controllers
            self._initialize_binary_context()

            log.log_info("IDAssist panel created with all tabs")

        except Exception as e:
            log.log_error(f"Failed to create IDAssist panel: {e}")
            import traceback
            log.log_error(traceback.format_exc())

    def _initialize_binary_context(self):
        """Initialize binary hash and context for all controllers that need it."""
        try:
            binary_hash = get_binary_hash()
            if not binary_hash:
                log.log_warn("No binary loaded - context initialization deferred")
                return

            # Initialize controllers that have initialize_binary()
            for controller_attr in ['explain_controller', 'query_controller',
                                     'actions_controller', 'semantic_graph_controller',
                                     'symgraph_controller']:
                controller = getattr(self, controller_attr, None)
                if controller and hasattr(controller, 'initialize_binary'):
                    try:
                        controller.initialize_binary()
                    except Exception as e:
                        log.log_warn(f"Failed to init binary for {controller_attr}: {e}")

            # Set initial cursor offset for all controllers
            import ida_kernwin
            ea = ida_kernwin.get_screen_ea()
            for controller_attr in ['explain_controller', 'query_controller',
                                     'actions_controller', 'semantic_graph_controller']:
                controller = getattr(self, controller_attr, None)
                if controller and hasattr(controller, 'set_current_offset'):
                    try:
                        controller.set_current_offset(ea)
                    except Exception:
                        pass

            log.log_info(f"Binary context initialized (hash: {binary_hash[:16]}...)")
        except Exception as e:
            log.log_error(f"Failed to initialize binary context: {e}")

    def _init_settings_tab(self):
        """Initialize the Settings tab with its controller."""
        try:
            from src.views.settings_tab_view import SettingsTabView
            from src.controllers.settings_controller import SettingsController

            self.settings_view = SettingsTabView()
            self.settings_controller = SettingsController(self.settings_view)
            self.tabs.addTab(self.settings_view, "Settings")
        except Exception as e:
            log.log_error(f"Failed to init Settings tab: {e}")

    def _init_explain_tab(self):
        """Initialize the Explain tab."""
        try:
            from src.views.explain_tab_view import ExplainTabView
            from src.controllers.explain_controller import ExplainController

            self.explain_view = ExplainTabView()
            self.explain_controller = ExplainController(self.explain_view)
            self.tabs.addTab(self.explain_view, "Explain")
            self.explain_view.rlhf_feedback_requested.connect(self.explain_controller.handle_rlhf_feedback)

            # Register for cursor changes
            hooks = self.get_ui_hooks()
            hooks.add_listener(self._on_explain_address_changed)
        except Exception as e:
            log.log_error(f"Failed to init Explain tab: {e}")

    def _on_explain_address_changed(self, ea):
        """Handle address change for explain controller."""
        if hasattr(self, 'explain_controller'):
            self.explain_controller.set_current_offset(ea)

    def _init_query_tab(self):
        """Initialize the Query tab."""
        try:
            from src.views.query_tab_view import QueryTabView
            from src.controllers.query_controller import QueryController

            self.query_view = QueryTabView()
            self.query_controller = QueryController(self.query_view)
            self.tabs.addTab(self.query_view, "Query")
            self.query_view.rlhf_feedback_requested.connect(self.query_controller.handle_rlhf_feedback)

            # Register for cursor changes
            hooks = self.get_ui_hooks()
            hooks.add_listener(self._on_query_address_changed)
        except Exception as e:
            log.log_error(f"Failed to init Query tab: {e}")

    def _on_query_address_changed(self, ea):
        """Handle address change for query controller."""
        if hasattr(self, 'query_controller'):
            self.query_controller.set_current_offset(ea)

    def _init_actions_tab(self):
        """Initialize the Actions tab."""
        try:
            from src.views.actions_tab_view import ActionsTabView
            from src.controllers.actions_controller import ActionsController

            self.actions_view = ActionsTabView()
            self.actions_controller = ActionsController(self.actions_view)
            self.tabs.addTab(self.actions_view, "Actions")

            hooks = self.get_ui_hooks()
            hooks.add_listener(self._on_actions_address_changed)
        except Exception as e:
            log.log_error(f"Failed to init Actions tab: {e}")

    def _on_actions_address_changed(self, ea):
        """Handle address change for actions controller."""
        if hasattr(self, 'actions_controller'):
            self.actions_controller.set_current_offset(ea)

    def _init_semantic_graph_tab(self):
        """Initialize the Semantic Graph tab."""
        try:
            from src.views.semantic_graph_tab_view import SemanticGraphTabView
            from src.controllers.semantic_graph_controller import SemanticGraphController

            self.semantic_graph_view = SemanticGraphTabView()
            self.semantic_graph_controller = SemanticGraphController(self.semantic_graph_view)
            self.tabs.addTab(self.semantic_graph_view, "Semantic Graph")

            # Register for cursor changes
            hooks = self.get_ui_hooks()
            hooks.add_listener(self._on_semantic_graph_address_changed)
        except Exception as e:
            log.log_error(f"Failed to init Semantic Graph tab: {e}")

    def _on_semantic_graph_address_changed(self, ea):
        """Handle address change for semantic graph controller."""
        if hasattr(self, 'semantic_graph_controller'):
            self.semantic_graph_controller.set_current_offset(ea)

    def _init_rag_tab(self):
        """Initialize the RAG tab."""
        try:
            from src.views.rag_tab_view import RagTabView
            from src.controllers.rag_controller import RAGController

            self.rag_view = RagTabView()
            self.rag_controller = RAGController(self.rag_view)
            self.tabs.addTab(self.rag_view, "RAG")
        except Exception as e:
            log.log_error(f"Failed to init RAG tab: {e}")

    def _init_symgraph_tab(self):
        """Initialize the SymGraph tab."""
        try:
            from src.views.symgraph_tab_view import SymGraphTabView
            from src.controllers.symgraph_controller import SymGraphController

            self.symgraph_view = SymGraphTabView()
            self.symgraph_controller = SymGraphController(
                self.symgraph_view,
                query_controller=getattr(self, 'query_controller', None),
            )
            self.tabs.addTab(self.symgraph_view, "SymGraph")
        except Exception as e:
            log.log_error(f"Failed to init SymGraph tab: {e}")

    def OnClose(self, form):
        """Called by IDA when the form is closed."""
        try:
            # Unhook UI hooks
            if IDAssistForm._ui_hooks is not None:
                IDAssistForm._ui_hooks.unhook()
                IDAssistForm._ui_hooks = None

            log.log_info("IDAssist panel closed")
        except Exception as e:
            log.log_error(f"Error closing IDAssist panel: {e}")
        finally:
            IDAssistForm._instance = None
