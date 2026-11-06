"""Measurement code for notebooks 05 (Sec. VI cost tables) and 08 (search scaling). Nothing here is protocol code.

The fill_* helpers write filler straight into server state for notebook 08 and skip Outsource.

It pins the process to one CPU, reads that CPU's clock and load, times the party calls of a
trial, counts failed checks, counts PRF chains a_x per party, and formats the results. A trial
is `trial(clock) -> (ok, wire)`: it makes the party calls of one protocol phase through `clock`
and returns whether its result was correct.

numpy, BPPRF and the table printer are imported inside the functions that need them. That keeps
`import ris_sem_project.bench` free of numpy, so a notebook can call `pin_to_cpu` before numpy
starts its thread pools.
"""

import importlib.metadata
import os
import platform
import resource
import sys
import statistics
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from numpy.typing import NDArray

PIN_CPU = 2
"""The CPU the cost runs are pinned to when it exists, and whose clock is read after each run."""

RUNS = 7
"""Timed runs per item, after one warmup run."""

Trial = Callable[["Clock"], tuple[bool, Sequence[Any]]]


@dataclass(frozen=True, slots=True, kw_only=True)
class Pinning:
    """What `pin_to_cpu` did: whether the process is now pinned, and the affinity it ended with."""

    cpu: int
    pinned: bool
    affinity: tuple[int, ...]
    reason: str

    def describe(self) -> str:
        if self.pinned:
            return f"pinned the kernel main thread to CPU {self.cpu}"
        return f"did not pin: {self.reason}; affinity left at {list(self.affinity)}"


def current_affinity() -> tuple[int, ...]:
    """The CPUs the calling thread may run on, sorted; empty where the OS exposes no affinity."""
    getter = getattr(os, "sched_getaffinity", None)
    return tuple(sorted(getter(0))) if getter else ()


def pin_to_cpu(cpu: int = PIN_CPU) -> Pinning:
    """Pin the calling thread to `cpu` if it is among its allowed CPUs. Never raises for a missing CPU."""
    before = current_affinity()
    if not hasattr(os, "sched_setaffinity"):
        return Pinning(cpu=cpu, pinned=False, affinity=before, reason="this OS has no sched_setaffinity")
    if cpu not in before:
        return Pinning(cpu=cpu, pinned=False, affinity=before, reason=f"CPU {cpu} is not among the allowed CPUs {list(before)}")
    try:
        os.sched_setaffinity(0, {cpu})
    except OSError as err:
        return Pinning(cpu=cpu, pinned=False, affinity=before, reason=f"sched_setaffinity failed ({err})")
    return Pinning(cpu=cpu, pinned=True, affinity=current_affinity(), reason="")


def cpu_file(cpu: int, name: str) -> str | None:
    """The text of /sys/devices/system/cpu/cpu<cpu>/<name>, or None when it is absent or unreadable."""
    try:
        return Path(f"/sys/devices/system/cpu/cpu{cpu}/{name}").read_text().strip()
    except OSError:
        return None


def _mhz(text: str | None) -> int | None:
    try:
        return int(text) // 1000 if text is not None else None
    except ValueError:
        return None


def cpu_mhz(cpu: int = PIN_CPU) -> int:
    """The current clock of `cpu` in MHz from cpufreq, 0 when it cannot be read."""
    return _mhz(cpu_file(cpu, "cpufreq/scaling_cur_freq")) or 0


def cpu_summary(cpu: int = PIN_CPU) -> str:
    """'CPU 2: max 4800 MHz, governor powersave, hyperthread siblings 2,3', each field 'unreadable' if missing."""
    max_mhz = _mhz(cpu_file(cpu, "cpufreq/cpuinfo_max_freq"))
    governor = cpu_file(cpu, "cpufreq/scaling_governor") or "unreadable"
    siblings = cpu_file(cpu, "topology/thread_siblings_list") or "unreadable"
    return f"CPU {cpu}: max {f'{max_mhz} MHz' if max_mhz is not None else 'unreadable'}, governor {governor}, hyperthread siblings {siblings}"


def cpu_model() -> str:
    """The 'model name' of the first CPU in /proc/cpuinfo, 'unknown' when absent."""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def memory_total_gib() -> float | None:
    """MemTotal from /proc/meminfo in GiB, None when unreadable."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) / 2**20
    except (OSError, ValueError, IndexError):
        pass
    return None


def system_summary() -> str:
    """The machine and software a notebook ran on, one fact per line."""
    memory = memory_total_gib()
    versions = []
    for package in ("numpy", "cryptography", "dilithium-py", "ipykernel", "nbclient", "matplotlib"):
        try:
            versions.append(f"{package} {importlib.metadata.version(package)}")
        except importlib.metadata.PackageNotFoundError:
            versions.append(f"{package} missing")
    return "\n".join([
        f"CPU: {cpu_model()}, {os.cpu_count()} logical CPUs",
        f"memory: {memory:.1f} GiB" if memory is not None else "memory: unreadable",
        f"OS: {platform.system()} {platform.release()} ({platform.machine()})",
        f"Python: {sys.version.split()[0]}",
        f"packages: {', '.join(versions)}",
    ])


def kernel_usage() -> str:
    """What running this notebook cost: wall time since this process started, its CPU time and its
    peak resident memory. Called in a notebook's last cell, the process is that notebook's kernel."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    cpu_seconds = usage.ru_utime + usage.ru_stime
    peak_mib = usage.ru_maxrss / 1024
    try:
        start_ticks = int(Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19])
        wall = float(Path("/proc/uptime").read_text().split()[0]) - start_ticks / os.sysconf("SC_CLK_TCK")
        wall_text = f"{wall:.0f} s wall"
    except (OSError, ValueError, IndexError):
        wall_text = "wall time unreadable"
    return f"kernel: {wall_text}, {cpu_seconds:.0f} s CPU, peak memory {peak_mib:.0f} MiB, on {cpu_model()}"


def sibling_cpus(cpu: int = PIN_CPU) -> tuple[int, ...]:
    """The hyperthread siblings of `cpu` (itself excluded), from a list like '2,3' or '2-3'."""
    text = cpu_file(cpu, "topology/thread_siblings_list")
    if text is None:
        return ()
    found: set[int] = set()
    try:
        for part in text.split(","):
            low, _, high = part.partition("-")
            found.update(range(int(low), int(high or low) + 1))
    except ValueError:
        return ()
    return tuple(sorted(found - {cpu}))


@dataclass(frozen=True, slots=True, kw_only=True)
class LoadSnapshot:
    """The load average and per-CPU jiffies (total, idle) at one moment."""

    load: tuple[float, float, float]
    jiffies: dict[int, tuple[int, int]]


def snapshot() -> LoadSnapshot:
    """Read the 1, 5, 15 minute load average and /proc/stat. The jiffies are empty if /proc/stat is unreadable."""
    jiffies: dict[int, tuple[int, int]] = {}
    try:
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("cpu") and line[3].isdigit():
                row = line.split()
                jiffies[int(row[0][3:])] = (sum(map(int, row[1:])), int(row[4]) + int(row[5]))
    except (OSError, ValueError, IndexError):
        jiffies = {}
    return LoadSnapshot(load=os.getloadavg(), jiffies=jiffies)


def busy_share(before: LoadSnapshot, after: LoadSnapshot, cpu: int) -> float | None:
    """The fraction of `cpu`'s time between two snapshots not spent idle, None if either lacks the CPU."""
    if cpu not in before.jiffies or cpu not in after.jiffies:
        return None
    total = after.jiffies[cpu][0] - before.jiffies[cpu][0]
    idle = after.jiffies[cpu][1] - before.jiffies[cpu][1]
    return 1 - idle / total if total else None


def busy_summary(before: LoadSnapshot, after: LoadSnapshot, cpu: int = PIN_CPU) -> str:
    """One line with how busy `cpu` and its hyperthread siblings were between two snapshots."""

    def share(c: int) -> str:
        value = busy_share(before, after, c)
        return "unavailable" if value is None else f"{value:.0%}"

    parts = [f"CPU {cpu} (the kernel) {share(cpu)}"] + [f"CPU {s} (its hyperthread sibling) {share(s)}" for s in sibling_cpus(cpu)]
    return "busy share over the whole run: " + ", ".join(parts)


class Clock:
    """Adds the time and minor page faults of each party call to that party; `chains` is filled by `count_a_x`."""

    def __init__(self) -> None:
        self.seconds: defaultdict[str, float] = defaultdict(float)
        self.faults: defaultdict[str, int] = defaultdict(int)
        self.chains: defaultdict[str, int] = defaultdict(int)
        self.party: str | None = None

    def __call__(self, party: str, method: Callable[..., Any], *args: Any) -> Any:
        self.party = party
        faults = resource.getrusage(resource.RUSAGE_SELF).ru_minflt
        start = time.perf_counter()
        try:
            return method(*args)
        finally:
            self.seconds[party] += time.perf_counter() - start
            self.faults[party] += resource.getrusage(resource.RUSAGE_SELF).ru_minflt - faults
            self.party = None


@contextmanager
def count_a_x(clock: Clock) -> Iterator[None]:
    """Count the `BPPRF.a_x` calls made inside `clock(party, ...)` calls into `clock.chains[party]`.

    The only place that wraps `a_x`. The original method is put back on exit, also after an exception.
    """
    from .primitives.bp_prf import BPPRF

    original = BPPRF.a_x

    def counted(prf: BPPRF, x: Any) -> Any:
        if clock.party is not None:
            clock.chains[clock.party] += 1
        return original(prf, x)

    BPPRF.a_x = counted
    try:
        yield
    finally:
        BPPRF.a_x = original


@dataclass(frozen=True, slots=True, kw_only=True)
class Timing:
    """Median and min-max range of one party's per-run seconds over `runs` runs."""

    median: float
    low: float
    high: float
    runs: int


@dataclass(frozen=True, slots=True, kw_only=True)
class Measured:
    """`runs` and `faults` hold one {party: value} dict per timed run. `failures` counts the warmup too."""

    runs: tuple[dict[str, float], ...]
    faults: tuple[dict[str, int], ...]
    failures: int
    chains: dict[str, int]
    wire: Sequence[Any]
    mhz: tuple[int, ...]

    def samples(self, party: str) -> list[float]:
        return [run[party] for run in self.runs]

    def median(self, party: str) -> float:
        return statistics.median(self.samples(party))

    def mean(self, party: str) -> float:
        return statistics.mean(self.samples(party))

    def median_faults(self, party: str) -> float:
        return statistics.median(run[party] for run in self.faults)

    def timing(self, party: str) -> Timing:
        samples = self.samples(party)
        return Timing(median=statistics.median(samples), low=min(samples), high=max(samples), runs=len(samples))

    def chain_count(self, parties: Iterable[str]) -> int:
        """The a_x calls counted in the warmup run for these parties; a party that made no call raises KeyError."""
        return sum(self.chains[party] for party in parties)

    def with_failures(self, extra: int) -> Measured:
        return replace(self, failures=self.failures + extra)

    def derive(self, label: str, parts: Iterable[str]) -> Measured:
        """Add `label` to every run as the sum of the `parts` seconds of that run."""
        parts = tuple(parts)
        return replace(self, runs=tuple({**run, label: sum(run[p] for p in parts)} for run in self.runs))


def measure(trial: Trial, runs: int = RUNS, *, cpu: int = PIN_CPU) -> Measured:
    """Run `trial` once as a warmup that counts PRF chains, then `runs` timed times.

    Every run, the warmup included, must return ok = True or it is added to `failures`. After each
    timed run the clock of `cpu` is read. `wire` is the last timed run's messages.
    """
    warmup = Clock()
    with count_a_x(warmup):
        ok, _ = trial(warmup)
    chains = {party: warmup.chains[party] for party in warmup.seconds}
    failures = int(not ok)
    timed, faults, mhz = [], [], []
    wire: Sequence[Any] = ()
    for _ in range(runs):
        clock = Clock()
        ok, wire = trial(clock)
        mhz.append(cpu_mhz(cpu))
        failures += not ok
        timed.append(dict(clock.seconds))
        faults.append(dict(clock.faults))
    return Measured(runs=tuple(timed), faults=tuple(faults), failures=failures, chains=chains, wire=wire, mhz=tuple(mhz))


def alternating(trial: Trial, companion: Trial) -> Trial:
    """A trial that runs `companion` right after `trial` on the same clock and is ok only if both are."""

    def both(clock: Clock) -> tuple[bool, Sequence[Any]]:
        ok, wire = trial(clock)
        return ok and companion(clock)[0], wire

    return both


def duration(seconds: float) -> str:
    if seconds >= 1:
        return f"{seconds:.2f} s"
    ms = seconds * 1e3
    return f"{ms:.0f} ms" if ms >= 100 else f"{ms:.1f} ms" if ms >= 10 else f"{ms:.2f} ms" if ms >= 0.1 else f"{ms:.3f} ms"


def in_ms(seconds: float) -> str:
    return f"{seconds * 1e3:.0f} ms" if seconds >= 0.01 else f"{seconds * 1e3:.2f} ms"


def spread(samples: Sequence[float]) -> str:
    return f"{duration(min(samples))} to {duration(max(samples))}"


def sizes_text(sizes: Sequence[int]) -> str:
    return str(sizes[0]) if len(set(sizes)) == 1 else " / ".join(map(str, sizes))


def report(measured: Measured, parties: Sequence[str], name: str, cpu: int = PIN_CPU) -> None:
    """Print the median and range of each party, the failure count and the clock read after each run."""
    from .display import table

    rows = [(p, duration(measured.timing(p).median), spread(measured.samples(p)), len(measured.runs)) for p in parties]
    print(table(("party", "median", "range (min to max)", "runs"), rows))
    print(f"{name} failures: {measured.failures} of {len(measured.runs) + 1} runs (warmup included)")
    print(f"CPU {cpu} clock read after each run: median {statistics.median(measured.mhz)} MHz, {min(measured.mhz)} to {max(measured.mhz)} MHz")


def negacyclic_schoolbook(row: NDArray[Any], small: NDArray[Any], q: int) -> NDArray[Any]:
    """row * small in Z_q[X]/(X^n + 1) by int64 convolution: a reference for Ring.mul when `small` has small entries."""
    import numpy as np

    n = len(row)
    full = np.convolve(row, small)
    return (full[:n] - np.append(full[n:], 0)) % q


def fill_qpase_storage(server: Any, user_id: str, count: int, index_ct_size: int, first_item_id: int, data_ct: bytes) -> int:
    """Append `count` filler items for the paper's scheme straight into `server.storage[user_id]`.

    Not protocol code: this skips Outsource, its signature check and the M-slot limit, so that notebook 08
    can reach 10^5 stored items without a PRF chain and a signature per item. Each filler Ct is AES-256-GCM
    of random bytes under its own fresh random key, `index_ct_size` bytes long like a real Ct, so Dec(dsk, Ct)
    fails at the tag exactly as for another keyword's item. Every filler shares the one `data_ct`, which R2
    never reads for an item that fails Dec. Item ids run from `first_item_id`. Returns the new item count.
    """
    from .parties.types import StoredItem
    from .primitives.symmetric import KEY_SIZE, NONCE_SIZE, TAG_SIZE, encrypt

    if index_ct_size < NONCE_SIZE + TAG_SIZE:
        raise ValueError(f"a Ct is at least {NONCE_SIZE + TAG_SIZE} bytes, got {index_ct_size}")
    items = server.storage.setdefault(user_id, [])
    for k in range(count):
        index_ct = encrypt(os.urandom(KEY_SIZE), os.urandom(index_ct_size - NONCE_SIZE - TAG_SIZE))
        items.append(StoredItem(index_ct=index_ct, data_ct=data_ct, item_id=first_item_id + k))
    return len(items)


def fill_counter_index(server: Any, user_id: str, count: int, entry_size: int) -> int:
    """Add `count` filler rows for the counter index straight into `server.index[user_id]`.

    Not protocol code: this skips Outsource, its signature check and the M-row limit, and stores no file.
    Each row is a random 32-byte label and a random entry of `entry_size` bytes, the length of a real entry.
    Returns the new row count.
    """
    from .counter_index import LABEL_SIZE

    rows = server.index.setdefault(user_id, {})
    target = len(rows) + count
    while len(rows) < target:
        rows[os.urandom(LABEL_SIZE)] = os.urandom(entry_size)
    return len(rows)


def spread_evenly(total: int, parts: int) -> list[int]:
    """`total` split into `parts` counts that differ by at most one, the larger ones first."""
    if parts < 1 or total < 0:
        raise ValueError(f"need parts >= 1 and total >= 0, got {parts} and {total}")
    base, extra = divmod(total, parts)
    return [base + (k < extra) for k in range(parts)]
