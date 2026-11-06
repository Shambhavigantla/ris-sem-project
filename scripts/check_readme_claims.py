"""Check every number README.md states against the notebook cell that printed it.

Usage: .venv/bin/python scripts/check_readme_claims.py

Cell k is the k-th code cell, i.e. execution count [k] after a fresh Run All.
Run scripts/run_notebooks.py first so outputs are current.

Two kinds of README tables are checked.

Claim tables, anywhere in README.md, with the header  | Claim | Value | Notebook | Cell |
  An exact Value (backticks stripped) must appear verbatim in that cell's saved output, not as
  part of a longer word or number (`p = 2` does not match `p = 28`).
  A Value written `[label]~<number> [unit]` is a measurement that changes between runs (a
  timing, an observed noise maximum): it passes when the output contains the label, then a
  number within a factor of 2 of the stated one, then the unit. Give a label when the cell
  prints other numbers that could match on their own, e.g. `max |2e''| = ~5000`.

Sourced tables: a Markdown table directly after a line  Source: `notebooks/<file>.ipynb`, cell <k>.
  The cell prints the table with display.markdown_table, and every row of the README table must
  appear verbatim as a line of that cell's output. These tables are one run's numbers: after
  rerunning a notebook, paste its new tables into README.md.
"""

import re
import sys
from pathlib import Path

import nbformat

ROOT = Path(__file__).resolve().parent.parent
CLAIM_HEADER = ["Claim", "Value", "Notebook", "Cell"]
SOURCE = re.compile(r"^Source: `(notebooks/[^`]+\.ipynb)`, cell (\d+)\.?$")
NUMBER = r"[-+]?\d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?"
TOLERANCE = 2.0


def cells_of(line: str) -> list[str]:
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def is_separator(line: str) -> bool:
    return set(line.strip()) <= set("|-: ")


def claim_rows(readme: str) -> list[list[str]]:
    """Every data row of every claim table in the README."""
    rows, inside = [], False
    for line in readme.splitlines():
        if not line.startswith("|"):
            inside = False
            continue
        cells = cells_of(line)
        if cells == CLAIM_HEADER:
            inside = True
        elif inside and not is_separator(line):
            rows.append(cells)
    return rows


def sourced_tables(readme: str) -> list[tuple[str, int, list[str]]]:
    """(notebook, cell, table data lines) for every table introduced by a Source: line."""
    lines = readme.splitlines()
    tables = []
    for i, line in enumerate(lines):
        match = SOURCE.match(line.strip())
        if match is None:
            continue
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        table = []
        while j < len(lines) and lines[j].startswith("|"):
            table.append(lines[j].strip())
            j += 1
        if len(table) < 3:
            raise ValueError(f"README line {i + 1}: a Source: line must be followed by a Markdown table")
        tables.append((match.group(1), int(match.group(2)), table[2:]))
    return tables


def cell_output(notebook: Path, k: int) -> str:
    nb = nbformat.read(notebook, as_version=4)
    code = [c for c in nb.cells if c.cell_type == "code"]
    cell = code[k - 1]
    parts = []
    for out in cell.get("outputs", []):
        if out.output_type == "stream":
            parts.append(out.text)
        elif "data" in out:
            parts.append(out.data.get("text/plain", ""))
    return "".join(parts)


def exact_found(value: str, output: str) -> bool:
    before = r"(?<![0-9A-Za-z_])" if value[:1].isalnum() else ""
    after = r"(?![0-9A-Za-z_])" if value[-1:].isalnum() else ""
    return re.search(before + re.escape(value) + after, output) is not None


def approx_found(value: str, output: str) -> bool:
    match = re.fullmatch(rf"(.*?)~\s*({NUMBER})\s*(\S.*)?", value)
    if match is None:
        raise ValueError(f"malformed approximate value {value!r}")
    label = re.escape(match.group(1).rstrip()) + r"\s*" if match.group(1).strip() else ""
    stated = float(match.group(2).replace(",", ""))
    unit = re.escape(match.group(3) or "")
    for found in re.finditer(rf"{label}({NUMBER})\s*{unit}(?![A-Za-z])", output):
        measured = float(found.group(1).replace(",", ""))
        if stated == measured == 0 or (stated * measured > 0 and max(stated, measured) / min(stated, measured) <= TOLERANCE):
            return True
    return False


def main() -> int:
    readme = (ROOT / "README.md").read_text()
    rows = claim_rows(readme)
    failures = 0
    for claim, value, notebook, cell in rows:
        value = value.strip("`")
        output = cell_output(ROOT / notebook, int(cell))
        ok = approx_found(value, output) if "~" in value else exact_found(value, output)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {notebook} [{cell}] {value!r}  {claim}")
    print(f"{len(rows) - failures}/{len(rows)} claims found in their cells")

    table_rows = table_failures = 0
    for notebook, cell, lines in sourced_tables(readme):
        printed = {line.strip() for line in cell_output(ROOT / notebook, cell).splitlines()}
        missing = [line for line in lines if line not in printed]
        table_rows += len(lines)
        table_failures += len(missing)
        print(f"{'ok  ' if not missing else 'FAIL'} {notebook} [{cell}] table of {len(lines)} rows")
        for line in missing:
            print(f"     not printed by the cell: {line}")
    print(f"{table_rows - table_failures}/{table_rows} sourced table rows found in their cells")
    return 1 if failures or table_failures or not rows else 0


if __name__ == "__main__":
    sys.exit(main())
