"""Shared filesystem policy for project inspection and scanner traversal."""

from __future__ import annotations

import os
from pathlib import Path
from collections.abc import Iterator


IGNORED_DIR_NAMES = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "env",
    "node_modules",
    "target",
    "venv",
    "vendor",
})


def is_ignored_path(path: Path, root: Path | None = None) -> bool:
    """Return whether a path is inside a generated/dependency directory."""
    candidate = path if root is None else path.relative_to(root)
    return any(part in IGNORED_DIR_NAMES for part in candidate.parts)


def iter_project_files(root: Path) -> Iterator[Path]:
    """Yield files under *root* while pruning ignored directories."""
    if root.is_file():
        if not is_ignored_path(root):
            yield root
        return
    if not root.is_dir():
        return

    for current, dirs, files in os.walk(root, topdown=True):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIR_NAMES)
        for name in sorted(files):
            path = Path(current) / name
            if not is_ignored_path(path, root):
                yield path


def iter_project_files_matching(root: Path, suffixes: set[str] | None = None) -> Iterator[Path]:
    """Yield project files, optionally restricted by lowercase suffix."""
    for path in iter_project_files(root):
        if suffixes is None or path.suffix.lower() in suffixes:
            yield path
