#!/usr/bin/env python3
"""Repository entry point for the Vera campaign runner.

The implementation lives in :mod:`vera_cycle.cli`; this file keeps the
operator-facing path (``python3 neutrino_cycle.py``) stable across the package
reorganisation. Run without arguments for the interactive wizard.
"""
from __future__ import annotations

import sys
import os

MIN_VERSION = (3, 12)


def _fail(message: str) -> None:
    sys.stderr.write(message + "\n")
    raise SystemExit(2)


def _ensure_interpreter() -> None:
    """Re-exec under the repository venv when the default python3 is too old.

    The package uses PEP 701 f-strings (backslashes and repeated quotes inside
    f-string expressions), which only parse on 3.12+. Hosts whose system
    python3 is 3.10 would otherwise die with a SyntaxError on import.
    """
    if sys.version_info >= MIN_VERSION:
        return
    venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv", "bin", "python")
    running_venv = os.path.abspath(sys.prefix) == os.path.dirname(os.path.dirname(os.path.abspath(venv_python)))
    if os.path.exists(venv_python) and not running_venv:
        os.execv(venv_python, [venv_python, os.path.abspath(__file__), *sys.argv[1:]])
    _fail(
        "neutrino_cycle.py requires Python "
        + ".".join(str(part) for part in MIN_VERSION)
        + " or newer, but this interpreter is "
        + ".".join(str(part) for part in sys.version_info[:3])
        + ".\nCreate the venv once:\n"
        "    curl -LsSf https://astral.sh/uv/install.sh | sh\n"
        "    uv python install 3.12\n"
        "    uv venv --python 3.12 .venv\n"
        "    uv pip install -r requirements.txt\n"
        "Then run: .venv/bin/python neutrino_cycle.py"
    )


_ensure_interpreter()

from vera_cycle.cli import BASE, main  # noqa: E402  (import guarded by version check)

__all__ = ["BASE", "main"]


if __name__ == "__main__":
    sys.exit(main())
