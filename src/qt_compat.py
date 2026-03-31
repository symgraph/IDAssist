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
