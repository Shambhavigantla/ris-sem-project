"""Generate the report's numbers and tables from the saved notebook outputs.

Usage: .venv/bin/python report/tools/make_numbers.py [--check]   (from the repository root)

Writes report/generated/numbers.tex (one LaTeX macro per measured value, each commented with
its notebook and cell), report/generated/tables/*.tex (the Markdown tables the notebooks print,
as booktabs tabulars) and report/generated/provenance.tex (an appendix table mapping every
macro to its cell). With --check it writes nothing and exits 1 if any file would change, so a
stale report is caught after the notebooks are rerun.

Every value comes from a notebook cell, the same source README.md cites, so the report and the
README cannot disagree. A pattern that stops matching raises an error instead of guessing.
"""

import math
import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from check_readme_claims import cell_output  # noqa: E402

OUT = ROOT / "report" / "generated"


@dataclass(frozen=True)
class Number:
    """One measured value: the macro that holds it, its cell, and a regex whose group 1 is the value as printed."""

    macro: str
    notebook: str
    cell: int
    pattern: str
    meaning: str


@dataclass(frozen=True)
class Table:
    """The index-th Markdown table a cell prints, written to tables/<name>.tex."""

    name: str
    notebook: str
    cell: int
    index: int


NB = {
    "01": "01_preliminaries", "02": "02_register_login", "03": "03_outsource_retrieve", "04": "04_server_key_update",
    "05": "05_costs", "06": "06_param_ii_offline_guessing", "07": "07_counter_index", "08": "08_search_scaling",
}
LAST_CELL = {"01": 13, "02": 13, "03": 17, "04": 13, "05": 14, "06": 8, "07": 18, "08": 8}

NUMBERS = [
    Number("MachineCPU", "01", 13, r"^CPU: (.+)$", "processor and logical CPUs of the test machine"),
    Number("MachineMemory", "01", 13, r"^memory: (.+)$", "memory of the test machine"),
    Number("MachineOS", "01", 13, r"^OS: (.+)$", "operating system kernel of the test machine"),
    Number("MachinePython", "01", 13, r"^Python: (.+)$", "Python version"),
    Number("MachinePackages", "01", 13, r"^packages: (.+)$", "package versions"),
    Number("ParamQ", "01", 2, r"PARAM I\s+q = (\d+)", "modulus q of Table II"),
    Number("ParamNOne", "01", 2, r"PARAM I\s+q = \d+\s+n = (\d+)", "ring degree n of PARAM I"),
    Number("ParamNTwo", "01", 2, r"PARAM II\s+q = \d+\s+n = (\d+)", "ring degree n of PARAM II"),
    Number("ParamEll", "01", 2, r"PARAM I\s+.*?ell = (\d+)", "gadget width ell"),
    Number("ParamP", "01", 2, r"PARAM I\s+.*?p = (\d+)", "rounding modulus p"),
    Number("ParamSigma", "01", 2, r"PARAM I\s+.*?sigma = ([\d.]+)", "standard deviation sigma of chi_sigma"),
    Number("ParamL", "01", 2, r"PARAM I\s+.*?L = (\d+)", "input bit length L"),
    Number("SizePublicVector", "01", 2, r"each \S+ \((\d+ B)\)", "size of each of a, a_0, a_1"),
    Number("RingProductsExact", "01", 3, r"(\d+/\d+) random products", "random ring products equal to the exact reference"),
    Number("PrfOutputBits", "01", 5, r"F_k\(x\) has (\d+) bits", "output bits of one BP PRF evaluation"),
    Number("ToprfNoiseMax", "01", 10, r"max \|2e''\| = (\d+)", "largest TOPRF noise coefficient in one run"),
    Number("ToprfLoginNoiseMax", "01", 10, r"max \|F' - F\| = (\d+)", "largest difference between two TOPRF outputs"),
    Number("QuarterQ", "01", 10, r"q/4 = (\d+)", "q/4, the extractor's noise bound"),
    Number("KeyBytes", "01", 11, r"K_u:\s+\S+ \((\d+ B)\)", "size of K_u and of an HKDF output"),
    Number("RegisterN", "02", 2, r"N = (\d+), t = \d+, mu = \d+", "servers in notebook 02"),
    Number("RegisterT", "02", 2, r"N = \d+, t = (\d+), mu = \d+", "threshold in notebook 02"),
    Number("MuLimit", "02", 2, r"N = \d+, t = \d+, mu = (\d+)", "attempt limit mu in notebook 02"),
    Number("SizeToprfRequest", "02", 4, r"TOPRF request per server: (\d+ B)", "TOPRF request to each server"),
    Number("SizeToprfResponse", "02", 4, r"(\d+ B)\s*$", "Register TOPRF response from each server"),
    Number("SizePkU", "02", 5, r"pk_u = \S+ \((\d+ B)\)", "size of pk_u (ML-DSA-44 public key)"),
    Number("SizeRegisterKeyMessage", "02", 5, r"RegisterKeyMessage: (\d+ B)", "Register step 2 message"),
    Number("SizeLoginResponse", "02", 6, r"L1 response per server: (\d+ B)", "Login L1 response from each server"),
    Number("SizeLoginProof", "02", 6, r"L2 proof per server: (\d+ B)", "Login L2 proof to each server"),
    Number("LoginsIdentical", "02", 10, r"(\d+/\d+) logins gave byte-identical K_u", "repeated logins with byte-identical K_u"),
    Number("LoginMedian", "02", 10, r"over \d+ runs: median (\S+ m?s)", "median time of one Login with t servers"),
    Number("SizeSigCt", "03", 4, r"sig_Ct\s+(\d+ B)", "size of sig_Ct (ML-DSA-44 signature)"),
    Number("SizeCt", "03", 4, r"Ct (\d+ B) \+", "size of the index ciphertext Ct"),
    Number("SizeOutsourceRequest", "03", 4, r"= (\d+ B) with the user id", "Outsource request for a 149-byte document"),
    Number("SizeRetrieveRequest", "03", 9, r"RetrieveRequest, (\d+ B)", "Retrieve request to each server"),
    Number("RTwoAllServers", "03", 10, r"R2 on all 3 servers: (\S+ m?s)", "time of R2 on all 3 servers, 7 items"),
    Number("RecoveredItems", "03", 12, r"recovered items (\[[^\]]*\])", "items recovered for the keyword medical"),
    Number("SizeKeyShare", "04", 4, r"S_1\s+0\s+\S+ \(\d+ B\)\s+\S+ \((\d+ B)\)", "size of a key share k_i"),
    Number("SizeUpdateShare", "04", 5, r"one KeyUpdateShare, bytes fields: (\d+ B)", "payload of one key update share"),
    Number("SizeUpdateAll", "04", 5, r"all 9 shares of the update: (\d+ B)", "all shares of one key update, N = 3"),
    Number("UpdateSharesAccepted", "04", 6, r"shares accepted: (\d+ of \d+)", "key update shares that pass step 4"),
    Number("UpdateEpochsAfterTwo", "04", 11, r"epochs: (\[[^\]]*\])", "epochs after two key updates"),
    Number("AxMedian", "05", 3, r"^a_x\s+(\S+ m?s)", "median time of one PRF chain a_x"),
    Number("CostChecks", "05", 12, r"failures over all (\d+) checked runs", "timed runs whose result was checked"),
    Number("CostFailures", "05", 12, r"failures over all \d+ checked runs: (\d+)", "failed checks over the timed runs"),
    Number("ParamIISigmaSqrtN", "06", 2, r"sigma sqrt\(n\) = ([\d.]+)", "spread of phi(r) at PARAM II"),
    Number("ParamIIRadius", "06", 2, r"search radius R = (\d+)", "search radius of the offline test"),
    Number("ParamIITau", "06", 2, r"match threshold tau = (\d+)", "match threshold at PARAM II"),
    Number("ParamIIGuesses", "06", 3, r"(\d+) guesses against one request", "dictionary size"),
    Number("ParamIIAttackTime", "06", 3, r"against one request in (\S+ s)", "time to test the dictionary"),
    Number("ParamIITrueResidual", "06", 4, r"true password residual:\s+(\d+)", "residual of the real password at PARAM II"),
    Number("ParamIIMinWrong", "06", 4, r"smallest wrong-guess residual:\s+(\d+)", "smallest wrong-guess residual at PARAM II"),
    Number("ParamIIMaxWrong", "06", 4, r"largest wrong-guess residual:\s+(\d+)", "largest wrong-guess residual at PARAM II"),
    Number("ParamITau", "06", 5, r"match threshold tau = (\d+)", "match threshold at PARAM I"),
    Number("ParamIReal", "06", 5, r"residual of the real password:\s+(\d+)", "residual of the real password at PARAM I"),
    Number("ParamISmallest", "06", 5, r"smallest residual of any guess:\s+(\d+)", "smallest residual of any guess at PARAM I"),
    Number("CiLabelBytes", "07", 4, r"label (\d+ B) \+ entry", "size of a counter-index label"),
    Number("CiEntryBytes", "07", 4, r"entry (\d+ B) \+ C", "size of a counter-index entry"),
    Number("CiOutsourceRequestBytes", "07", 4, r"= (\d+ B) with the user id", "counter-index Outsource request for item 1"),
    Number("CiSealedBytes", "07", 5, r"sealed (\d+ B)", "sealed counter table"),
    Number("CiUploadBytes", "07", 5, r"CounterTableUpload to each server: (\d+ B)", "counter table upload to each server"),
    Number("CiSearchRequestBytes", "07", 9, r"LabelSearchRequest, (\d+ B)", "label search request for c_w = 3"),
    Number("CiFetchRequestBytes", "07", 12, r"FileFetchRequest for items \[1\], (\d+ B)", "file fetch request for one item"),
    Number("CiLookups", "07", 13, r"lookups per server (\[[^\]]*\])", "lookups per server in one search"),
    Number("CiReplayItems", "07", 14, r"replaying the kept request: hits per server \[[^\]]*\], items (\[[^\]]*\])", "items a replayed old request finds"),
    Number("CiNewSearchItems", "07", 14, r"a new search by Alice: \d+ labels, items (\[[^\]]*\])", "items a new search finds"),
    Number("CiNewDeviceVersions", "07", 16, r"versions returned (\[[^\]]*\])", "counter table versions a new device gets"),
    Number("ScalingChecks", "08", 6, r"failures over all (\d+) checked runs", "timed scaling runs whose result was checked"),
    Number("ScalingFailures", "08", 6, r"failures over all \d+ checked runs: (\d+)", "failed checks over the scaling runs"),
    Number("ScalingLookups", "08", 6, r"lookups per server in every counter index run: (\[[^\]]*\])", "lookups per server in every run"),
]
PHASE_ROWS = [
    ("RegisterUser", "Register", "user"), ("RegisterServer", "Register", r"one server \(S_1\)"),
    ("LoginUser", "Login", "user"), ("LoginServer", "Login", r"one server \(S_1\)"),
    ("OutsourceUser", r"Outsource \(100 KB\)", "user"), ("OutsourceServer", r"Outsource \(100 KB\)", r"one server \(S_1\)"),
    ("RetrieveUser", "Retrieve", "user"), ("RetrieveServer", "Retrieve", r"one server \(S_1\)"),
    ("KeyUpdateServer", "Key update", r"one server \(S_1\)"), ("KeyUpdateRound", "Key update", r"all \d+ servers"),
]
NUMBERS += [
    Number(f"Cost{macro}", "05", 13, rf"^\| {phase} \| (?:{party}) \| (\S+ m?s) \|", f"median of {macro} in notebook 05")
    for macro, phase, party in PHASE_ROWS
]
NUMBERS += [
    Number("CostSignMedian", "05", 13, r"^\| ML-DSA-44 sign \| (\S+ m?s) \|", "median ML-DSA-44 signature"),
    Number("CostVerifyMedian", "05", 13, r"^\| ML-DSA-44 verify \| (\S+ m?s) \|", "median ML-DSA-44 verification"),
    Number("CostAesMedian", "05", 13, r"^\| AES-256-GCM encrypt 100 KB \| (\S+ m?s) \|", "median AES-256-GCM encryption of 100 KB"),
]
NUMBERS += [
    Number(f"Traffic{macro}", "05", 13, rf"^\| {phase} \| \d+ B \| \d+ B \| \d+ B \| (\d+ B) \|", f"total bytes of {macro}, N = 3")
    for macro, phase in (("Register", "Register"), ("Login", "Login"), ("Outsource", r"Outsource \(100 KB\)"),
                         ("Retrieve", "Retrieve"), ("KeyUpdate", "Key update"))
]
NUMBERS += [
    Number(f"Wall{word}", key, LAST_CELL[key], r"kernel: (\d+ s) wall", f"wall time of notebook {key}")
    for key, word in zip(NB, ("One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight"))
] + [
    Number(f"Peak{word}", key, LAST_CELL[key], r"peak memory (\d+ MiB)", f"peak memory of notebook {key}")
    for key, word in zip(NB, ("One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight"))
]

TABLES = [
    Table("cost_blocks", "05", 13, 0),
    Table("cost_phases", "05", 13, 1),
    Table("cost_traffic", "05", 13, 2),
    Table("param_ii", "06", 7, 0),
    Table("search_scaling", "08", 7, 0),
]

LATEX_SPECIAL = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_",
                 "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}"}


def escape(text: str) -> str:
    return "".join(LATEX_SPECIAL.get(ch, ch) for ch in text)


def path_of(key: str) -> str:
    return f"notebooks/{NB[key]}.ipynb"


def output(key: str, cell: int) -> str:
    return cell_output(ROOT / path_of(key), cell)


def extract(number: Number) -> str:
    found = re.search(number.pattern, output(number.notebook, number.cell), re.M)
    if found is None:
        raise SystemExit(f"{number.macro}: /{number.pattern}/ not found in {path_of(number.notebook)}, cell {number.cell}")
    return found.group(1)


def markdown_tables(key: str, cell: int) -> list[list[list[str]]]:
    tables, current = [], []
    for line in output(key, cell).splitlines():
        if line.startswith("|"):
            if not set(line) <= set("|-: "):
                current.append([c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))])
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)
    return tables


def latex_cell(text: str) -> str:
    times = re.fullmatch(r"(\d+)x", text)
    return f"{times.group(1)}$\\times$" if times else escape(text)


def tabular(rows: list[list[str]], source: str) -> str:
    header, body = rows[0], rows[1:]
    align = "".join("r" if all(re.match(r"\d", row[c]) for row in body) else "l" for c in range(len(header)))
    lines = [f"% generated by report/tools/make_numbers.py from {source}", f"\\begin{{tabular}}{{{align}}}", r"\toprule",
             " & ".join(f"\\textbf{{{escape(h)}}}" for h in header) + r" \\", r"\midrule"]
    lines += [" & ".join(latex_cell(c) for c in row) + r" \\" for row in body]
    lines += [r"\bottomrule", r"\end{tabular}", ""]
    return "\n".join(lines)


def seconds(text: str) -> float:
    value, unit = text.split()
    return float(value) * (1e-3 if unit == "ms" else 1.0)


def derived(scaling: list[list[str]]) -> list[tuple[str, str, str]]:
    """Ranges over the search-scaling table: (macro, value, meaning)."""
    body = scaling[1:]
    paper = [seconds(r[2]) for r in body]
    index = [seconds(r[3]) for r in body]
    speedup = [int(r[8].rstrip("x")) for r in body]
    ms = lambda v: f"{v * 1e3:.3g} ms"
    return [
        ("ScalingPaperMin", ms(min(paper)), "fastest paper slowest-server median over the grid"),
        ("ScalingPaperMax", ms(max(paper)), "slowest paper slowest-server median over the grid"),
        ("ScalingIndexMin", ms(min(index)), "fastest counter-index slowest-server median over the grid"),
        ("ScalingIndexMax", ms(max(index)), "slowest counter-index slowest-server median over the grid"),
        ("ScalingSpeedupMin", str(min(speedup)), "smallest speed-up at the slowest server"),
        ("ScalingSpeedupMax", str(max(speedup)), "largest speed-up at the slowest server"),
        ("ScalingSpeedupMedian", str(round(statistics.median(speedup))), "median speed-up at the slowest server"),
    ]


# The paper's own timings in seconds: Table IV (user side, PARAM II, N = t = 2) and Table III (one PRF).
PAPER_USER_PHASES = {"RegisterUser": 0.99e-3, "LoginUser": 0.64e-3, "OutsourceUser": 16.05e-3, "RetrieveUser": 30.95e-3}
PAPER_PRF = 0.554e-3


def two_figures(x: float) -> str:
    """x rounded to two significant figures, with thousands separators: 1404 -> 1,400."""
    return f"{round(x, 1 - math.floor(math.log10(x))):,.0f}"


def from_measured(measured: dict[str, str], phases: list[list[str]]) -> list[tuple[str, str, str, str]]:
    """Values computed from other macros and the cost table: (macro, value, source, meaning)."""
    ratios = "notebook 05, cell 13, over the paper's Table IV"
    rows = [(f"Ratio{m}", two_figures(seconds(measured[f"Cost{m}"]) / paper), ratios,
             f"our {m} median divided by the paper's") for m, paper in PAPER_USER_PHASES.items()]
    rows.append(("RatioPrf", two_figures(seconds(measured["AxMedian"]) / PAPER_PRF),
                 "notebook 05, cell 3, over the paper's Table III", "our PRF chain divided by the paper's PRF time"))
    products = (int(measured["ParamL"]) - 1) * int(measured["ParamEll"]) ** 2
    rows.append(("RingProductsChain", f"{products:,}", "notebook 01, cell 2 (derived)",
                 "ring products in one PRF chain, (L - 1) ell^2"))
    shares = [int(r[5].rstrip("%")) for r in phases[1:] if r[1] == "user"]
    rows.append(("ChainShareMin", f"{min(shares)}%", "notebook 05, cell 13 (derived from the table)",
                 "smallest share of a user phase spent in PRF chains"))
    return rows


def readme_tests() -> str:
    found = re.search(r"the unit suite passed in full: (\d+) tests", (ROOT / "README.md").read_text())
    if found is None:
        raise SystemExit("README.md no longer states the unit-test count")
    return found.group(1)


def generate() -> dict[Path, str]:
    files: dict[Path, str] = {}
    values = [(n.macro, extract(n), f"notebook {n.notebook}, cell {n.cell}", n.meaning) for n in NUMBERS]
    tables = {}
    for t in TABLES:
        found = markdown_tables(t.notebook, t.cell)
        if len(found) <= t.index:
            raise SystemExit(f"{t.name}: {path_of(t.notebook)}, cell {t.cell} prints {len(found)} tables")
        tables[t.name] = found[t.index]
        files[OUT / "tables" / f"{t.name}.tex"] = tabular(found[t.index], f"{path_of(t.notebook)}, cell {t.cell}")
    scaling_source = "notebook 08, cell 7 (derived from the table)"
    values += [(m, v, scaling_source, meaning) for m, v, meaning in derived(tables["search_scaling"])]
    values += from_measured({m: v for m, v, _, _ in values}, tables["cost_phases"])
    values.append(("UnitTests", readme_tests(), "README.md, Results (the unittest run)",
                   "unit tests that passed on the test machine"))
    lines = ["% generated by report/tools/make_numbers.py; do not edit. Rerun it after rerunning the notebooks."]
    lines += [f"\\newcommand{{\\{m}}}{{{escape(v)}}}% {src}: {meaning}" for m, v, src, meaning in values]
    files[OUT / "numbers.tex"] = "\n".join(lines) + "\n"
    head = r"\toprule \textbf{Macro and value} & \textbf{Source} & \textbf{Meaning} \\ \midrule"
    rows = [r"\begin{longtable}{p{0.36\linewidth}p{0.27\linewidth}p{0.29\linewidth}}",
            r"\caption{Every generated value and the notebook cell that printed it.}\label{tab:provenance}\\",
            head, r"\endfirsthead", head, r"\endhead"]
    rows += [f"\\texttt{{\\textbackslash {m}}}: {escape(v)} & {escape(src)} & {escape(meaning)} \\\\" for m, v, src, meaning in values]
    rows += [r"\bottomrule", r"\end{longtable}", ""]
    files[OUT / "provenance.tex"] = "% generated by report/tools/make_numbers.py; do not edit.\n" + "\n".join(rows)
    return files


def main(argv: list[str]) -> int:
    files = generate()
    if "--check" in argv:
        stale = [p for p, text in files.items() if not p.exists() or p.read_text() != text]
        for p in stale:
            print(f"stale: {p.relative_to(ROOT)}")
        print(f"{len(files) - len(stale)}/{len(files)} generated files current")
        return 1 if stale else 0
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    count = files[OUT / "numbers.tex"].count("\\newcommand")
    print(f"wrote {len(files)} files to {OUT.relative_to(ROOT)}: {count} numbers, {len(TABLES)} tables")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
