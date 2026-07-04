from __future__ import annotations

import atexit

from .cleanup import cleanup_generated_files, disable_bytecode_writes
from .tui import main as run_tui


def main() -> None:
    disable_bytecode_writes()
    atexit.register(cleanup_generated_files)
    try:
        run_tui()
    finally:
        cleanup_generated_files()
