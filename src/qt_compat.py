"""
Qt5/Qt6 compatibility shim.

PySide6 (IDA >= 9.2) is tried first; falls back to PyQt5 (IDA <= 9.1).
Consumer files should use explicit imports:
    from ..qt_compat import QWidget, Signal, exec_dialog, ...
"""

try:
    from PySide6.QtCore import *      # noqa: F401,F403
    from PySide6.QtGui import *       # noqa: F401,F403
    from PySide6.QtWidgets import *   # noqa: F401,F403
    from PySide6.QtCore import Signal
    from PySide6.QtGui import QAction
    QT_BINDING = "PySide6"
except ImportError:
    from PyQt5.QtCore import *        # noqa: F401,F403
    from PyQt5.QtGui import *         # noqa: F401,F403
    from PyQt5.QtWidgets import *     # noqa: F401,F403
    from PyQt5.QtCore import pyqtSignal as Signal  # noqa: F401
    from PyQt5.QtWidgets import QAction  # noqa: F401
    QT_BINDING = "PyQt5"

QT_AVAILABLE = QT_BINDING is not None


_STOP_BUTTON_STYLE_PROPERTY = "_idassist_stop_button_base_stylesheet"
STOP_BUTTON_STYLESHEET = """
QPushButton {
    background-color: #ff6b6b;
    color: white;
    border: 1px solid #e85a5a;
    border-radius: 4px;
}
QPushButton:hover {
    background-color: #ff5c5c;
}
QPushButton:pressed {
    background-color: #e85a5a;
}
QPushButton:disabled {
    background-color: #d98c8c;
    color: #f5f5f5;
}
""".strip()


def exec_dialog(obj, *args):
    """Cross-binding .exec() wrapper (PyQt5 uses .exec_())."""
    if hasattr(obj, "exec"):
        return obj.exec(*args)
    return obj.exec_(*args)


def utc_timezone():
    """Cross-binding UTC QTimeZone."""
    if hasattr(QTimeZone, "utc"):
        return QTimeZone.utc()
    return QTimeZone(0)


def apply_stop_button_style(button):
    """Apply a cross-platform stop-state style to a button."""
    if button is None:
        return

    base_stylesheet = button.property(_STOP_BUTTON_STYLE_PROPERTY)
    if base_stylesheet is None:
        base_stylesheet = button.styleSheet()
        button.setProperty(_STOP_BUTTON_STYLE_PROPERTY, base_stylesheet)

    if base_stylesheet:
        button.setStyleSheet(f"{base_stylesheet}\n{STOP_BUTTON_STYLESHEET}")
    else:
        button.setStyleSheet(STOP_BUTTON_STYLESHEET)

    style = button.style()
    if style is not None:
        style.unpolish(button)
        style.polish(button)
    button.update()


def clear_stop_button_style(button):
    """Restore a button's pre-stop stylesheet."""
    if button is None:
        return

    base_stylesheet = button.property(_STOP_BUTTON_STYLE_PROPERTY)
    if base_stylesheet is None:
        button.setStyleSheet("")
    else:
        button.setStyleSheet(base_stylesheet)
        button.setProperty(_STOP_BUTTON_STYLE_PROPERTY, None)

    style = button.style()
    if style is not None:
        style.unpolish(button)
        style.polish(button)
    button.update()
