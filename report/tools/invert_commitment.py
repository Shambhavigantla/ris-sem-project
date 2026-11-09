"""Show that a key-update commitment h = H(alpha) reveals alpha (report Section 5.6.2).

Usage: .venv/bin/python report/tools/invert_commitment.py   (from the repository root)

H(x) = A_H x mod q with the implementation's own A_H at PARAM I. Gauss-Jordan elimination
modulo the prime q solves A_H x = h; the script exits 1 unless A_H has full rank and the
solution equals the random alpha that was committed to.
"""

import sys

import numpy as np

from ris_sem_project.params import PARAM_I
from ris_sem_project.primitives.linear_hash import _matrix, linear_hash
from ris_sem_project.primitives.ring import Ring


def solve_mod(a: np.ndarray, h: np.ndarray, q: int) -> np.ndarray | None:
    """x with a x = h mod q, or None if a is singular mod q. Products stay below q^2 < 2^63."""
    n = a.shape[0]
    m = np.concatenate([a, h.reshape(n, 1)], axis=1) % q
    for col in range(n):
        nonzero = np.flatnonzero(m[col:, col])
        if nonzero.size == 0:
            return None
        pivot = col + int(nonzero[0])
        m[[col, pivot]] = m[[pivot, col]]
        m[col] = m[col] * pow(int(m[col, col]), -1, q) % q
        factors = m[:, col].copy()
        factors[col] = 0
        m = (m - factors[:, None] * m[col][None, :] % q) % q
    return m[:, n]


def main() -> int:
    ring = Ring(PARAM_I.q, PARAM_I.n)
    alpha = np.random.default_rng().integers(0, ring.q, ring.n, dtype=np.int64)
    recovered = solve_mod(_matrix(ring.q, ring.n).copy(), linear_hash(ring, alpha), ring.q)
    full_rank = recovered is not None
    print(f"A_H ({ring.n} x {ring.n}) has full rank mod q = {ring.q}: {full_rank}")
    match = full_rank and np.array_equal(recovered, alpha)
    print(f"alpha recovered from its commitment H(alpha): {match}")
    return 0 if match else 1


if __name__ == "__main__":
    sys.exit(main())
