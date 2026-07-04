from __future__ import annotations

import os
import shutil
from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def disable_bytecode_writes() -> None:
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")


def cleanup_generated_files() -> None:
    root = project_root()
    for path in root.rglob("__pycache__"):
        shutil.rmtree(path, ignore_errors=True)
    for path in root.rglob("*.pyc"):
        try:
            path.unlink()
        except OSError:
            pass
    for path in root.rglob("*.pyo"):
        try:
            path.unlink()
        except OSError:
            pass
