"""Figures for the README and the report, drawn with matplotlib. Presentation only: nothing here
computes protocol values.

Each function takes values a notebook already measured and returns a matplotlib Figure. `save`
writes it as SVG and as PNG to docs/figures/, or to QPASE_FIGURES_DIR when that is set (a
verification run writes its figures next to its evidence instead of into the repository).

Figures use matplotlib's default light style on white, whatever the user's matplotlibrc says.
The series colours are matplotlib's blue, orange and cyan: its default third colour, green, cannot
be told from orange with red-green colour blindness, and cyan can.
"""

import math
import os
from collections.abc import Mapping, Sequence
from pathlib import Path

import matplotlib.style
from matplotlib.figure import Figure
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter

COLORS = ("tab:blue", "tab:orange", "tab:cyan")
OTHER = "tab:gray"
PNG_DPI = 200


def compact(value: float, _position: object = None) -> str:
    """1, 10, 100, 1K, 10K, 1M: compact tick labels for an axis that reaches 10,000."""
    for size, suffix in ((1e9, "G"), (1e6, "M"), (1e3, "K")):
        if value >= size:
            return f"{value / size:g}{suffix}"
    return f"{value:g}"


def seconds(value: float, _position: object = None) -> str:
    """A duration in seconds as 10 µs, 1 ms, 100 ms or 1 s."""
    if value < 1e-3:
        return f"{value * 1e6:g} µs"
    if value < 1:
        return f"{value * 1e3:g} ms"
    return f"{value:g} s"


def _light():
    return matplotlib.style.context("default")


def _decades(values: Sequence[float]) -> tuple[float, float]:
    """Log-axis limits at the powers of ten around the values, so both ends carry a tick label."""
    return 10.0 ** math.floor(math.log10(min(values))), 10.0 ** math.ceil(math.log10(max(values)))


def save(figure: Figure, name: str, source: str = "") -> Path:
    """Write figure to docs/figures/<name> as SVG and next to it as PNG, and return the SVG path.

    source (for example the notebook cell and the CPU) goes into both files' metadata.
    """
    directory = Path(os.environ.get("QPASE_FIGURES_DIR") or Path(__file__).resolve().parents[2] / "docs" / "figures")
    directory.mkdir(parents=True, exist_ok=True)
    svg = directory / name
    with _light():
        figure.savefig(svg, format="svg", facecolor="white", metadata={"Description": source, "Date": None})
        figure.savefig(svg.with_suffix(".png"), format="png", dpi=PNG_DPI, facecolor="white",
                       metadata={"Description": source})
    return svg


def scaling_panels(
    panels: Sequence[tuple[str, Mapping[str, Sequence[tuple[float, float]]]]],
    *,
    title: str,
    x_label: str,
    y_label: str,
) -> Figure:
    """One log-log panel per entry, sharing the y axis. panels: (panel title, {series: [(x, seconds), ...]}).
    A series keeps its colour in every panel."""
    names = list(dict.fromkeys(name for _, series in panels for name in series))
    with _light():
        figure = Figure(figsize=(10, 3.9), layout="constrained")
        axes = figure.subplots(1, len(panels), sharey=True, squeeze=False)[0]
        for ax, (panel_title, series) in zip(axes, panels):
            for name, points in series.items():
                xs, ys = zip(*points)
                ax.plot(xs, ys, marker="o", color=COLORS[names.index(name)], label=name)
            ax.set_xscale("log")
            ax.set_yscale("log")
            ax.set_title(panel_title)
            ax.grid(True, which="major", alpha=0.3)
            ax.xaxis.set_major_formatter(FuncFormatter(compact))
        axes[0].set_ylim(*_decades([y for _, series in panels for points in series.values() for _, y in points]))
        axes[0].yaxis.set_major_formatter(FuncFormatter(seconds))
        axes[0].set_ylabel(y_label)
        axes[0].legend(loc="center left")
        figure.supxlabel(x_label)
        figure.suptitle(title, fontweight="bold")
    return figure


def dot_rows(
    rows: Sequence[tuple[str, Mapping[str, tuple[float, float, float]]]],
    series: Sequence[str],
    *,
    title: str,
    x_label: str,
) -> Figure:
    """A dot plot on a log time axis: one row per label, one point per series at the median with an
    error bar from the fastest to the slowest run. rows: (label, {series: (median, low, high) in seconds})."""
    with _light():
        figure = Figure(figsize=(8, 0.6 * len(rows) + 1.6), layout="constrained")
        ax = figure.subplots()
        offsets = {name: (k - (len(series) - 1) / 2) * 0.22 for k, name in enumerate(series)}
        for k, name in enumerate(series):
            points = [(r, by[name]) for r, (_, by) in enumerate(rows) if name in by]
            ys = [r + offsets[name] for r, _ in points]
            medians = [m for _, (m, _, _) in points]
            errors = [[m - low for _, (m, low, _) in points], [high - m for _, (m, _, high) in points]]
            ax.errorbar(medians, ys, xerr=errors, fmt="o", color=COLORS[k], capsize=3, label=name)
        ax.set_yticks(range(len(rows)), [label for label, _ in rows])
        ax.invert_yaxis()
        ax.set_xscale("log")
        ax.set_xlim(*_decades([v for _, by in rows for triple in by.values() for v in triple]))
        ax.xaxis.set_major_formatter(FuncFormatter(seconds))
        ax.grid(True, axis="x", which="major", alpha=0.3)
        ax.set_xlabel(x_label)
        ax.legend(loc="lower left")
        ax.set_title(title, fontweight="bold")
    return figure


def stacked_bars(
    rows: Sequence[tuple[str, Mapping[str, float]]],
    series: Sequence[str],
    *,
    title: str,
    x_label: str,
    unit: float = 1000,
    unit_name: str = "kB",
) -> Figure:
    """Horizontal bars, one per label, stacked by series, with the total at the bar end.
    rows: (label, {series: amount}); amounts are divided by unit for display."""
    with _light():
        figure = Figure(figsize=(8, 0.6 * len(rows) + 1.6), layout="constrained")
        ax = figure.subplots()
        left = [0.0] * len(rows)
        for k, name in enumerate(series):
            widths = [by.get(name, 0) / unit for _, by in rows]
            ax.barh(range(len(rows)), widths, left=left, height=0.6, color=COLORS[k], edgecolor="white", label=name)
            left = [a + b for a, b in zip(left, widths)]
        for r, total in enumerate(left):
            ax.annotate(f"{total:.1f} {unit_name}", (total, r), xytext=(4, 0), textcoords="offset points", va="center")
        ax.set_yticks(range(len(rows)), [label for label, _ in rows])
        ax.invert_yaxis()
        ax.set_xlim(0, max(left) * 1.18)
        ax.grid(True, axis="x", alpha=0.3)
        ax.set_axisbelow(True)
        ax.set_xlabel(x_label)
        ax.legend(loc="lower right")
        ax.set_title(title, fontweight="bold")
    return figure


def residual_strips(
    rows: Sequence[tuple[str, Sequence[float], float, float]],
    *,
    title: str,
    x_label: str,
    highlight: str,
    others: str,
) -> Figure:
    """One strip per row on a log axis: the highlighted guess, the other guesses with their count, and
    the row's threshold as a vertical line. rows: (label, other residuals, highlighted residual, threshold)."""
    with _light():
        figure = Figure(figsize=(8, 1.2 * len(rows) + 1.6), layout="constrained")
        ax = figure.subplots()
        for r, (_, rest, real, tau) in enumerate(rows):
            ax.scatter(rest, [r + 0.15] * len(rest), s=18, color=OTHER, alpha=0.6, zorder=2)
            ax.annotate(f"{len(rest)} {others}{'es' if others.endswith('s') else 's'}", (min(rest), r + 0.15),
                        xytext=(-6, 0), textcoords="offset points", ha="right", va="center")
            ax.scatter([real], [r - 0.15], s=60, color=COLORS[0], zorder=3)
            ax.vlines(tau, r - 0.35, r + 0.35, color="black", linewidth=1.5, zorder=1)
            ax.annotate(f"τ = {tau:g}", (tau, r - 0.35), xytext=(4, 0), textcoords="offset points", va="top")
        ax.set_yticks(range(len(rows)), [label for label, *_ in rows])
        ax.set_ylim(len(rows) + 0.1, -0.5)
        ax.set_xscale("log")
        ax.set_xlim(*_decades([v for _, rest, real, tau in rows for v in (*rest, real, tau)]))
        ax.xaxis.set_major_formatter(FuncFormatter(compact))
        ax.grid(True, axis="x", which="major", alpha=0.3)
        ax.set_xlabel(x_label)
        ax.legend(
            handles=[
                Line2D([], [], marker="o", linestyle="", color=COLORS[0], markersize=7, label=highlight),
                Line2D([], [], marker="o", linestyle="", color=OTHER, alpha=0.6, markersize=5, label=others),
                Line2D([], [], color="black", linewidth=1.5, label="match threshold τ"),
            ],
            loc="lower center", ncols=3,
        )
        ax.set_title(title, fontweight="bold")
    return figure
