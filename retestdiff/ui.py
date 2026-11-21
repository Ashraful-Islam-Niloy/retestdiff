"""Tiny colour helper (stdlib only). Honours NO_COLOR and non-terminal output."""
from __future__ import annotations

import os
import sys

_CODES = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36", "grey": "90", "bold": "1"}

if os.name == "nt":  # makes ANSI colours work in the Windows 10/11 console
    os.system("")


def _enabled(stream) -> bool:  # noqa: ANN001
    return "NO_COLOR" not in os.environ and hasattr(stream, "isatty") and stream.isatty()


def style(text: str, colour: str, stream=None) -> str:  # noqa: ANN001
    if not _enabled(stream or sys.stdout):
        return text
    return f"\033[{_CODES[colour]}m{text}\033[0m"
