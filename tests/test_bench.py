import time
import types
import unittest
from unittest import mock

import numpy as np

from ris_sem_project import bench
from ris_sem_project.primitives.bp_prf import BPPRF, encode_input
from ris_sem_project.primitives.ring import Ring

Q = 2**28 - 57
N = 8
L = 6
RING = Ring(Q, N)
RNG = np.random.default_rng(9)


def ok_trial(clock):
    clock("U", time.sleep, 0.001)
    clock("S_1", time.sleep, 0.002)
    return True, ["message"]


class MeasureTest(unittest.TestCase):
    def test_runs_and_ordered_range(self):
        measured = bench.measure(ok_trial, runs=5)
        self.assertEqual(len(measured.runs), 5)
        self.assertEqual(len(measured.mhz), 5)
        self.assertEqual(measured.wire, ["message"])
        for party, floor in (("U", 0.001), ("S_1", 0.002)):
            timing = measured.timing(party)
            self.assertEqual(timing.runs, 5)
            self.assertLessEqual(timing.low, timing.median)
            self.assertLessEqual(timing.median, timing.high)
            self.assertGreaterEqual(timing.low, floor)
            self.assertEqual(timing.median, measured.median(party))

    def test_trial_runs_once_for_the_warmup_and_once_per_timed_run(self):
        calls = []

        def trial(clock):
            calls.append(1)
            return True, []

        bench.measure(trial, runs=4)
        self.assertEqual(len(calls), 5)

    def test_failures_count_the_warmup_and_every_failed_run(self):
        outcomes = iter([False, True, False, False, True, True])
        measured = bench.measure(lambda clock: (next(outcomes), []), runs=5)
        self.assertEqual(measured.failures, 3)
        self.assertEqual(measured.with_failures(2).failures, 5)

    def test_derive_adds_the_sum_of_parts_per_run(self):
        derived = bench.measure(ok_trial, runs=3).derive("both", ["U", "S_1"])
        for run in derived.runs:
            self.assertEqual(run["both"], run["U"] + run["S_1"])

    def test_alternating_runs_the_companion_on_the_same_clock(self):
        seen = []

        def companion(clock):
            clock("extra", time.sleep, 0)
            seen.append(clock)
            return False, []

        measured = bench.measure(bench.alternating(ok_trial, companion), runs=2)
        self.assertEqual(len(seen), 3)
        self.assertEqual(measured.failures, 3)
        self.assertIn("extra", measured.runs[0])

    def test_clock_forgets_the_party_after_a_call_that_raises(self):
        clock = bench.Clock()
        with self.assertRaises(ZeroDivisionError):
            clock("U", lambda: 1 / 0)
        self.assertIsNone(clock.party)
        self.assertIn("U", clock.seconds)


class CountAXTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        a0, a1 = RNG.integers(0, Q, (RING.ell, N)), RNG.integers(0, Q, (RING.ell, N))
        cls.prf = BPPRF(RING, a0, a1, L)
        cls.x = encode_input(b"password", L)

    def test_counts_per_party_and_returns_the_same_value(self):
        expected = self.prf.a_x(self.x)
        clock = bench.Clock()
        with bench.count_a_x(clock):
            first = clock("U", self.prf.a_x, self.x)
            clock("U", self.prf.a_x, self.x)
            clock("S_1", self.prf.a_x, self.x)
            self.prf.a_x(self.x)
        self.assertEqual(dict(clock.chains), {"U": 2, "S_1": 1})
        self.assertTrue(np.array_equal(first, expected))

    def test_restores_the_method_on_exit(self):
        original = BPPRF.a_x
        with bench.count_a_x(bench.Clock()):
            self.assertIsNot(BPPRF.a_x, original)
        self.assertIs(BPPRF.a_x, original)

    def test_restores_the_method_when_the_block_raises(self):
        original = BPPRF.a_x
        with self.assertRaises(RuntimeError):
            with bench.count_a_x(bench.Clock()):
                raise RuntimeError("boom")
        self.assertIs(BPPRF.a_x, original)

    def test_measure_reports_the_warmup_chains_only(self):
        def trial(clock):
            clock("U", self.prf.a_x, self.x)
            clock("U", self.prf.a_x, self.x)
            return True, []

        measured = bench.measure(trial, runs=2)
        self.assertEqual(measured.chains, {"U": 2})
        self.assertEqual(measured.chain_count(["U"]), 2)
        with self.assertRaises(KeyError):
            measured.chain_count(["S_1"])


class PinTest(unittest.TestCase):
    def test_missing_cpu_is_skipped_without_raising(self):
        before = bench.current_affinity()
        pinning = bench.pin_to_cpu(10**6)
        self.assertFalse(pinning.pinned)
        self.assertIn(str(10**6), pinning.reason)
        self.assertEqual(pinning.affinity, before)
        self.assertEqual(bench.current_affinity(), before)
        self.assertIn("did not pin", pinning.describe())

    def test_skips_when_the_os_cannot_pin(self):
        with mock.patch.object(bench, "os", types.SimpleNamespace()):
            pinning = bench.pin_to_cpu(0)
        self.assertFalse(pinning.pinned)
        self.assertIn("sched_setaffinity", pinning.reason)

    @unittest.skipUnless(hasattr(bench.os, "sched_setaffinity"), "no CPU affinity on this OS")
    def test_pins_to_an_allowed_cpu(self):
        allowed = bench.current_affinity()
        self.addCleanup(bench.os.sched_setaffinity, 0, set(allowed))
        pinning = bench.pin_to_cpu(allowed[-1])
        self.assertTrue(pinning.pinned)
        self.assertEqual(pinning.affinity, (allowed[-1],))
        self.assertEqual(bench.current_affinity(), (allowed[-1],))

    def test_unreadable_cpu_files_give_placeholders(self):
        self.assertIsNone(bench.cpu_file(10**6, "cpufreq/scaling_cur_freq"))
        self.assertEqual(bench.cpu_mhz(10**6), 0)
        self.assertEqual(bench.sibling_cpus(10**6), ())
        self.assertIn("unreadable", bench.cpu_summary(10**6))

    def test_busy_share_needs_both_snapshots_to_have_the_cpu(self):
        before = bench.LoadSnapshot(load=(0.0, 0.0, 0.0), jiffies={2: (100, 60)})
        after = bench.LoadSnapshot(load=(0.0, 0.0, 0.0), jiffies={2: (200, 110)})
        self.assertAlmostEqual(bench.busy_share(before, after, 2), 0.5)
        self.assertIsNone(bench.busy_share(before, after, 3))
        self.assertIn("CPU 3", bench.busy_summary(before, after, 3))


class SchoolbookTest(unittest.TestCase):
    def test_negacyclic_schoolbook_wraps_x_to_minus_one(self):
        q = 17
        row, small = np.array([0, 0, 0, 1]), np.array([0, 2, 0, 0])
        self.assertEqual(bench.negacyclic_schoolbook(row, small, q).tolist(), [(-2) % q, 0, 0, 0])

    def test_negacyclic_schoolbook_agrees_with_ring_mul(self):
        a, small = RNG.integers(0, Q, N), RNG.integers(-5, 6, N)
        self.assertEqual(bench.negacyclic_schoolbook(a, small, Q).tolist(), RING.mul(a, small % Q).tolist())


class FormatTest(unittest.TestCase):
    def test_duration_units(self):
        self.assertEqual(bench.duration(1.5), "1.50 s")
        self.assertEqual(bench.duration(0.25), "250 ms")
        self.assertEqual(bench.duration(0.0123), "12.3 ms")
        self.assertEqual(bench.in_ms(0.2), "200 ms")
        self.assertEqual(bench.sizes_text([5, 5]), "5")
        self.assertEqual(bench.sizes_text([5, 6]), "5 / 6")


class FillerTest(unittest.TestCase):
    """The notebook 08 filler helpers, on stand-in servers that have only the state they write."""

    def test_qpase_filler_appends_items_of_the_given_size_that_no_key_opens(self):
        from ris_sem_project.primitives.symmetric import decrypt

        server = types.SimpleNamespace(storage={"alice": ["real item"]})
        total = bench.fill_qpase_storage(server, "alice", 5, 4256, 10_000, b"C")
        items = server.storage["alice"]
        self.assertEqual(total, 6)
        self.assertEqual(items[0], "real item")
        self.assertEqual([item.item_id for item in items[1:]], list(range(10_000, 10_005)))
        self.assertEqual({len(item.index_ct) for item in items[1:]}, {4256})
        self.assertEqual(len({item.index_ct for item in items[1:]}), 5)
        self.assertIsNone(decrypt(bytes(32), items[1].index_ct))
        with self.assertRaises(ValueError):
            bench.fill_qpase_storage(server, "alice", 1, 27, 0, b"C")

    def test_counter_index_filler_adds_rows_of_the_given_entry_size(self):
        server = types.SimpleNamespace(index={})
        self.assertEqual(bench.fill_counter_index(server, "alice", 50, 108), 50)
        self.assertEqual(bench.fill_counter_index(server, "alice", 7, 108), 57)
        rows = server.index["alice"]
        self.assertEqual({len(label) for label in rows}, {32})
        self.assertEqual({len(entry) for entry in rows.values()}, {108})

    def test_spread_evenly(self):
        self.assertEqual(bench.spread_evenly(97, 3), [33, 32, 32])
        self.assertEqual(bench.spread_evenly(0, 2), [0, 0])
        with self.assertRaises(ValueError):
            bench.spread_evenly(5, 0)


if __name__ == "__main__":
    unittest.main()
