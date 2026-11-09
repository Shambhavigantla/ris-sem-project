"""Check the report: current numbers, a clean build, and the open to-do boxes.

Usage: .venv/bin/python report/tools/check_report.py [--final]   (from the repository root)

1. The generated numbers and tables match the saved notebook outputs (make_numbers.py --check).
2. latexmk builds report/main.tex without errors, undefined references, undefined citations or
   multiply defined labels.
3. It lists every \\todo box left in the sections and every name placeholder in main.tex.

Without --final, open to-do boxes are reported but allowed. With --final, any open box or placeholder
fails the check: the report is done when this passes.
"""

import re
import subprocess
import sys
from pathlib import Path

REPORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPORT / "tools"))
import make_numbers  # noqa: E402

LOG_PROBLEMS = {
    "error": re.compile(r"^! (.+)$", re.M),
    "undefined reference": re.compile(r"LaTeX Warning: Reference `([^']+)' on page \d+ undefined"),
    "undefined citation": re.compile(r"LaTeX Warning: Citation `([^']+)' on page \d+ undefined"),
    "multiply defined label": re.compile(r"LaTeX Warning: Label `([^']+)' multiply defined"),
}
PLACEHOLDERS = ("[Partner name]", "[Roll number]")


def open_todos() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted((REPORT / "sections").glob("*.tex")):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if "\\todo{" in line and not line.lstrip().startswith("%"):
                found.append((path.name, number, line.strip()[:90]))
    return found


def main(argv: list[str]) -> int:
    final = "--final" in argv
    failures = 0

    stale = [p for p, text in make_numbers.generate().items() if not p.exists() or p.read_text() != text]
    print(f"{'ok  ' if not stale else 'FAIL'} generated numbers match the notebooks"
          + (f" (stale: {', '.join(p.name for p in stale)}; run report/tools/make_numbers.py)" if stale else ""))
    failures += bool(stale)

    build = subprocess.run(["latexmk", "-interaction=nonstopmode", "main.tex"], cwd=REPORT, capture_output=True, text=True)
    log = (REPORT / "build" / "main.log").read_text(errors="replace") if (REPORT / "build" / "main.log").exists() else ""
    problems = {kind: sorted(set(rx.findall(log))) for kind, rx in LOG_PROBLEMS.items()}
    built = build.returncode == 0 and not any(problems.values())
    print(f"{'ok  ' if built else 'FAIL'} latexmk builds report/build/main.pdf (exit {build.returncode})")
    for kind, items in problems.items():
        for item in items:
            print(f"     {kind}: {item}")
    failures += not built

    overfull = re.findall(r"Overfull \\hbox \(([\d.]+)pt too wide\)", log)
    wide = [w for w in overfull if float(w) > 10]
    print(f"{'ok  ' if not wide else 'warn'} no line sticks out more than 10pt"
          + (f" ({len(wide)} do; search build/main.log for 'Overfull')" if wide else ""))

    todos = open_todos()
    main_tex = (REPORT / "main.tex").read_text()
    placeholders = [p for p in PLACEHOLDERS if p in main_tex]
    state = "FAIL" if final and (todos or placeholders) else ("ok  " if not (todos or placeholders) else "open")
    print(f"{state} {len(todos)} to-do boxes and {len(placeholders)} name placeholders left")
    for name, number, text in todos:
        print(f"     sections/{name}:{number}  {text}")
    for p in placeholders:
        print(f"     main.tex  {p}")
    failures += final and bool(todos or placeholders)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
