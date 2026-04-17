#!/usr/bin/env python3

"""
IDA Compatibility Layer - Provides logging, main-thread execution, and utility functions
for the IDAssist plugin running inside IDA Pro.
"""

import os
import hashlib

try:
    import idaapi
    import ida_kernwin
    import ida_nalt

    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class IDALogger:
    """Logger that wraps ida_kernwin.msg() for IDA output window logging.

    Provides the same interface as binaryninja.log.Logger so copied code
    works with a simple ``from src.ida_compat import log`` replacement.
    """

    PREFIX = "[IDAssist]"

    @staticmethod
    def log_debug(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} DEBUG: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} DEBUG: {msg}")

    @staticmethod
    def log_info(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} INFO: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} INFO: {msg}")

    @staticmethod
    def log_warn(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} WARN: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} WARN: {msg}")

    @staticmethod
    def log_error(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} ERROR: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} ERROR: {msg}")


# Global logger instance - replaces binaryninja.log usage across the codebase
log = IDALogger()


def execute_on_main_thread(callback):
    """Execute a callback on IDA's main thread.

    IDA requires all IDB modifications to happen on the main thread.
    This wraps ``idaapi.execute_sync()`` with ``MFF_FAST``.

    Args:
        callback: A callable (no arguments) to execute on the main thread.

    Returns:
        The return value of ``idaapi.execute_sync()``.
    """
    if not _IN_IDA:
        # Outside IDA, just call directly
        return callback()

    return idaapi.execute_sync(callback, idaapi.MFF_FAST)


def get_user_data_dir():
    """Get the IDAssist user data directory.

    Returns:
        Path to ``~/.idapro/idassist/`` (created if it doesn't exist).
    """
    if _IN_IDA:
        user_dir = idaapi.get_user_idadir()
    else:
        user_dir = os.path.expanduser("~/.idapro")

    data_dir = os.path.join(user_dir, "idassist")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def get_binary_hash():
    """Get SHA-256 hash of the currently loaded binary.

    Returns:
        Hex-encoded SHA-256 hash string, or empty string on failure.
    """
    try:
        if not _IN_IDA:
            return ""

        # Prefer the original input SHA-256 stored in the IDB so detached
        # .i64/.idb databases still resolve to the correct binary identity.
        retrieve_input_sha256 = getattr(ida_nalt, "retrieve_input_file_sha256", None)
        if callable(retrieve_input_sha256):
            sha256_bytes = retrieve_input_sha256()
            if sha256_bytes:
                sha256_hex = sha256_bytes.hex()
                log.log_debug("Resolved binary hash from stored IDB input SHA-256")
                return sha256_hex

        input_path = ida_nalt.get_input_file_path()
        if not input_path or not os.path.exists(input_path):
            return ""

        sha256 = hashlib.sha256()
        with open(input_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        sha256_hex = sha256.hexdigest()
        log.log_debug("Resolved binary hash from input file path")
        return sha256_hex

    except Exception as e:
        log.log_error(f"Failed to compute binary hash: {e}")
        return ""


def is_in_ida():
    """Check if we are running inside IDA Pro."""
    return _IN_IDA
