"""Verbose terminal logging for the tunnel server.

The terminal output is the live view of what the server is doing; the CSV file
written by :mod:`server.inspector` is the machine readable record of the same
thing.  Both are produced at the same time, the log is never a replacement for
the CSV.

The tag style follows the original server: ``[*]`` status, ``[+]`` success,
``[!]`` error, ``[TUNNEL]`` a new flow, ``[>]`` traffic towards the internet
and ``[<--]`` traffic coming back.
"""

import os
import sys

#: verbosity thresholds
QUIET = 0
NORMAL = 1
VERBOSE = 2

_LEVELS = {"quiet": QUIET, "normal": NORMAL, "verbose": VERBOSE}

_COLORS = {
    "info": "\033[36m",  # cyan
    "ok": "\033[32m",  # green
    "warn": "\033[33m",  # yellow
    "error": "\033[31m",  # red
    "tunnel": "\033[35m",  # magenta
    "resp": "\033[34m",  # blue
    "up": "\033[36m",  # cyan
    "dim": "\033[90m",  # grey
}
_RESET = "\033[0m"

_state = {"level": VERBOSE, "color": True}


def _enable_virtual_terminal():
    """Turn on ANSI escape sequences for the Windows console."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _setup_color():
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return _enable_virtual_terminal()
    return True


def configure(level="verbose", color=None):
    """Set the verbosity.  ``level`` is one of quiet/normal/verbose."""
    _state["level"] = _LEVELS.get(level, VERBOSE)
    _state["color"] = _setup_color() if color is None else bool(color)


def set_level(level):
    configure(level)


def get_level():
    for name, value in _LEVELS.items():
        if value == _state["level"]:
            return name
    return "verbose"


def _paint(tag, color):
    if not _state["color"]:
        return "[%s]" % tag
    return "%s[%s]%s" % (_COLORS.get(color, ""), tag, _RESET)


def log(tag, message, level=NORMAL, color="info"):
    """Print one log line.

    ``level`` is the minimum verbosity at which the line is shown; error
    lines use ``QUIET`` so they survive ``--quiet``.
    """
    if level > _state["level"]:
        return
    sys.stdout.write("%s %s\n" % (_paint(tag, color), message))
    sys.stdout.flush()


def info(message, level=NORMAL):
    log("*", message, level, "info")


def ok(message, level=NORMAL):
    log("+", message, level, "ok")


def warn(message, level=QUIET):
    log("!", message, level, "warn")


def error(message, level=QUIET):
    log("!", message, level, "error")


def detail(message):
    """A per packet line, only shown in verbose mode."""
    log(">", message, VERBOSE, "up")


def response(message):
    log("<--", message, VERBOSE, "resp")


def tunnel(message):
    log("TUNNEL", message, NORMAL, "tunnel")
