"""Execute notebooks top to bottom in a fresh kernel and save their outputs in place.

Usage: .venv/bin/python scripts/run_notebooks.py [notebook ...]
With no arguments, runs every notebooks/*.ipynb in name order.

A fresh top-to-bottom run gives the k-th code cell the execution count [k],
which is the cell number README.md cites.
"""

import sys
import time
from pathlib import Path

import nbformat
from nbclient import NotebookClient
from nbclient.exceptions import CellExecutionError

ROOT = Path(__file__).resolve().parent.parent


def shown(path: Path) -> Path:
    """path relative to the repository root when inside it, else as given (a copy run elsewhere)."""
    return path.relative_to(ROOT) if path.is_relative_to(ROOT) else path


def run(path: Path) -> bool:
    nb = nbformat.read(path, as_version=4)
    client = NotebookClient(
        nb,
        kernel_name="python3",
        timeout=3600,
        resources={"metadata": {"path": str(path.parent)}},
    )
    start = time.perf_counter()
    try:
        client.execute()
        ok = True
    except CellExecutionError as err:
        print(f"FAIL {shown(path)}\n{err}", file=sys.stderr)
        ok = False
    nbformat.write(nb, path)
    if ok:
        print(f"ok   {shown(path)} ({time.perf_counter() - start:.1f} s)")
    return ok


def main(argv: list[str]) -> int:
    paths = [Path(a).resolve() for a in argv] or sorted((ROOT / "notebooks").glob("*.ipynb"))
    results = [run(p) for p in paths]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
