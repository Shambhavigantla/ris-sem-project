import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from ris_sem_project import bench, figures
from ris_sem_project.display import markdown_table


def legend_labels(ax) -> list[str]:
    return [t.get_text() for t in ax.get_legend().get_texts()]


def annotations(ax) -> list[str]:
    return [t.get_text() for t in ax.texts]


class LabelTest(unittest.TestCase):
    def test_tick_labels(self):
        self.assertEqual([figures.compact(v) for v in (1, 100, 1_000, 100_000, 1e8)], ["1", "100", "1K", "100K", "100M"])
        self.assertEqual([figures.seconds(v) for v in (1e-5, 1e-3, 0.1, 1, 10)], ["10 µs", "1 ms", "100 ms", "1 s", "10 s"])


class FigureTest(unittest.TestCase):
    def test_scaling_panels_plot_every_series_in_every_panel_on_log_axes(self):
        panels = [(f"N = {n}", {"paper": [(100, 0.5), (1000, 0.7)], "index": [(100, 0.004), (1000, 0.005)]}) for n in (3, 5)]
        figure = figures.scaling_panels(panels, title="T", x_label="files", y_label="time")
        self.assertEqual([ax.get_title() for ax in figure.axes], ["N = 3", "N = 5"])
        for ax in figure.axes:
            self.assertEqual((ax.get_xscale(), ax.get_yscale()), ("log", "log"))
            self.assertEqual([list(line.get_ydata()) for line in ax.get_lines()], [[0.5, 0.7], [0.004, 0.005]])
            self.assertEqual(ax.get_ylim(), (0.001, 1.0))
        self.assertEqual(legend_labels(figure.axes[0]), ["paper", "index"])
        self.assertEqual(figure.get_suptitle(), "T")

    def test_dot_rows_label_each_row_and_series(self):
        rows = [("Login", {"user": (1.9, 1.8, 2.0), "server": (0.006, 0.005, 0.007)}), ("Key update", {"server": (0.1, 0.07, 0.15)})]
        (ax,) = figures.dot_rows(rows, ["user", "server"], title="T", x_label="time").axes
        self.assertEqual([t.get_text() for t in ax.get_yticklabels()], ["Login", "Key update"])
        self.assertEqual(legend_labels(ax), ["user", "server"])
        self.assertEqual(ax.get_xlim(), (0.001, 10.0))

    def test_stacked_bars_print_each_total(self):
        rows = [("Register", {"up": 181398, "down": 344064}), ("Key update", {"between": 39264})]
        (ax,) = figures.stacked_bars(rows, ["up", "down", "between"], title="T", x_label="kB").axes
        self.assertEqual(annotations(ax), ["525.5 kB", "39.3 kB"])
        self.assertEqual(legend_labels(ax), ["up", "down", "between"])

    def test_residual_strips_count_the_other_guesses_and_mark_each_threshold(self):
        rows = [("PARAM II", [9e7, 1e8, 1.05e8], 344, 1249), ("PARAM I", [9e7, 1e8], 1e8, 1159)]
        (ax,) = figures.residual_strips(rows, title="T", x_label="r", highlight="real", others="wrong guess").axes
        self.assertEqual(annotations(ax), ["3 wrong guesses", "τ = 1249", "2 wrong guesses", "τ = 1159"])
        self.assertEqual(legend_labels(ax), ["real", "wrong guess", "match threshold τ"])
        self.assertEqual(ax.get_xlim(), (100.0, 1e9))

    def test_save_writes_svg_and_png_with_the_source_to_the_override_directory(self):
        figure = figures.stacked_bars([("A", {"x": 1000})], ["x"], title="T", x_label="kB")
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"QPASE_FIGURES_DIR": directory}):
            svg = figures.save(figure, "x.svg", "cell 1")
            self.assertEqual(svg, Path(directory) / "x.svg")
            root = ET.parse(svg).getroot()
            self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
            self.assertIn("cell 1", svg.read_text())
            png = svg.with_suffix(".png").read_bytes()
            self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
            self.assertIn(b"cell 1", png)


class ReportTextTest(unittest.TestCase):
    def test_markdown_table_has_a_row_per_input_and_escapes_pipes(self):
        lines = markdown_table(("a", "b"), [(1, "x|y"), (2, "z")]).splitlines()
        self.assertEqual(lines, ["| a | b |", "| --- | --- |", "| 1 | x\\|y |", "| 2 | z |"])

    def test_system_summary_and_kernel_usage_name_the_machine(self):
        summary = bench.system_summary().splitlines()
        self.assertEqual([line.split(":")[0] for line in summary], ["CPU", "memory", "OS", "Python", "packages"])
        self.assertIn("matplotlib", summary[-1])
        self.assertIn(bench.cpu_model(), bench.kernel_usage())
        self.assertRegex(bench.kernel_usage(), r"^kernel: \d+ s wall, \d+ s CPU, peak memory \d+ MiB, on ")


if __name__ == "__main__":
    unittest.main()
