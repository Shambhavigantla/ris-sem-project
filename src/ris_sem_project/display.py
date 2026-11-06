"""Presentation helpers for the demonstration notebooks. Nothing here computes protocol values.

Every function turns a value the protocol already produced (bytes on the wire, an ItemScan
from R2 or R3, rows of facts) into a short string for print().
"""

import dataclasses
from collections.abc import Iterable, Sequence

import numpy as np

from .index import ItemScan, ScanOutcome


def peek(data: bytes, width: int = 8) -> str:
    """'3fa1…9c02 (1792 B)': the first and last width // 2 hex digits and the length."""
    text = data.hex()
    half = width // 2
    shown = text if len(text) <= width else f"{text[:half]}…{text[-half:]}"
    return f"{shown} ({len(data)} B)"


def bits(data: bytes, width: int = 16) -> str:
    """'14336 bits, 7170 ones: 01101001…10110010' for a packed bit string."""
    unpacked = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    text = "".join(map(str, unpacked[:width])) + "…" + "".join(map(str, unpacked[-width:]))
    return f"{unpacked.size} bits, {int(unpacked.sum())} ones: {text}"


def payload_size(value: object) -> int:
    """Total length of the bytes and str fields of a message, recursing into dataclasses and tuples.

    Ints (ids, counters) and None are not counted.
    """
    match value:
        case bytes():
            return len(value)
        case str():
            return len(value.encode())
        case tuple() | list():
            return sum(payload_size(v) for v in value)
        case _ if dataclasses.is_dataclass(value):
            return sum(payload_size(getattr(value, f.name)) for f in dataclasses.fields(value))
        case _:
            return 0


def table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    """A fixed-width text table, one column per header, cells left-aligned."""
    cells = [list(map(str, headers))] + [list(map(str, row)) for row in rows]
    widths = [max(len(row[c]) for row in cells) for c in range(len(headers))]
    lines = ["  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip() for row in cells]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def markdown_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    """A Markdown table, ready to paste into README.md, whose rows the README checker finds verbatim."""
    lines = ["| " + " | ".join(map(str, headers)) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |" for row in rows]
    return "\n".join(lines)


SCAN_HEADERS = ("item", "Dec(dsk, Ct)", "rho", "v (from Ct)", "Ver sig_C", "PRF(dsk, rho)", "v == PRF", "outcome")
"""Column names for scan_row."""

_REACHED = {
    ScanOutcome.DECRYPT_FAILED: 0,
    ScanOutcome.MALFORMED: 1,
    ScanOutcome.SIGNATURE_INVALID: 2,
    ScanOutcome.PRF_MISMATCH: 3,
    ScanOutcome.MATCH: 3,
}
"""How many of the three checks after Dec ran: parse (rho, v, sig_C), Ver, then v == PRF(dsk, rho)."""


def scan_row(scan: ItemScan) -> tuple[str, ...]:
    """One SCAN_HEADERS row for the check of one item; '-' marks a step that did not run."""
    reached = _REACHED[scan.outcome]
    decrypted = "fail" if scan.outcome is ScanOutcome.DECRYPT_FAILED else "ok"
    rho = "-" if scan.rho is None else str(scan.rho)
    v = "-" if scan.v is None else peek(scan.v)
    verified = "-" if reached < 2 else str(scan.outcome is not ScanOutcome.SIGNATURE_INVALID)
    v_recomputed = "-" if scan.v_recomputed is None else peek(scan.v_recomputed)
    equal = "-" if reached < 3 else str(scan.outcome is ScanOutcome.MATCH)
    return (str(scan.item_id), decrypted, rho, v, verified, v_recomputed, equal, scan.outcome.name)
