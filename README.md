# QPASE in Python

This repository implements QPASE from Jiang and Wang, "QPASE: Quantum-Resistant Password-Authenticated
Searchable Encryption for Cloud Storage", IEEE Transactions on Information Forensics and Security, vol. 19,
2024. The paper is `QPASE_Quantum-Resistant_Password-Authenticated_Searchable_Encryption_for_Cloud_Storage.pdf`.

A user remembers only an identity and a password. A threshold of `t` out of `N` servers runs a lattice
TOPRF on the password, from which the user derives a key `K_u`, a Dilithium key pair and one search key
`dsk` per keyword. The user stores encrypted documents with an encrypted keyword index on any server.
To search, the user sends `dsk` to every server. Each server returns the items whose index matches,
and only the user can decrypt them. The code follows the paper's Sections II and IV and Figs. 1, 2, 5
and 6. Where the paper is incomplete or inconsistent, the choice made is listed in
[Where this differs from the paper](#where-this-differs-from-the-paper).

The design and every decision behind it are in `docs/implementation-plan.md`.

## Module map

Everything lives in `src/ris_sem_project/`. The notebooks only call these modules.

- `params.py` holds the Table II parameter sets `PARAM_I` and `PARAM_II`, `setup()` (Setup, Sec. IV-A), and `Lattice`, which parses `pp` once.
- `primitives/ring.py` is exact arithmetic in `R_q = Z_q[X]/(X^n + 1)`.
- `primitives/sampling.py` has the uniform samplers and the discrete Gaussian `chi_sigma` (Definition 3).
- `primitives/gadget.py` is `G^{-1}`, the binary decomposition (Sec. II-B).
- `primitives/bp_prf.py` is the Banerjee-Peikert lattice PRF `F_k(x)` (Lemma 1).
- `primitives/extractor.py` is Ding's robust extractor, the hint `S` and the extractor `E` (Definition 8).
- `primitives/secret_sharing.py` has Shamir sharing over `R_q`, integer Lagrange coefficients and the DKG (Definitions 11-12).
- `primitives/toprf.py` is the variant TOPRF `Pi_TOPRF` (Figs. 1-2, Theorem 1).
- `primitives/hkdf.py` and `primitives/prf.py` are the HKDF and PRF of Setup, both built on the BP PRF (Definitions 9-10).
- `primitives/signature.py` wraps ML-DSA-44 (CRYSTALS-Dilithium) with key generation from a seed.
- `primitives/symmetric.py` wraps AES-256-GCM.
- `primitives/encoding.py` is the length-prefixed encoding of signed and encrypted tuples.
- `primitives/linear_hash.py` is the linear hash `H(x) = A_H x mod q` behind the key-update commitments (decision 6).
- `index.py` builds the searchable index `Ct` of one document (O1) and runs the check of R2 and R3.
- `parties/` has the abstract `User`, `Server` and adversary classes, the wire messages in `types.py`, and the concrete `QPASEUser` and `QPASEServer`, including the server key update steps.
- `protocol.py` runs whole phases (DKG, Register, Login, Outsource, Retrieve, server key update) and returns a record of every message.
- `root_attack.py` is the PARAM II offline password test shown in notebook 06.
- `display.py` formats values for the notebooks and computes nothing.

The notebooks in `notebooks/` show each phase with the data that crosses the wire:

- `01_preliminaries.ipynb` covers the building blocks of Sec. II.
- `02_register_login.ipynb` covers the DKG, Register and Login (Sec. IV-A to IV-C, Fig. 5).
- `03_outsource_retrieve.ipynb` stores real documents on the servers and searches them (Sec. IV-D and IV-E, Fig. 6).
- `04_server_key_update.ipynb` refreshes every server's key share and shows users are unaffected (Sec. IV-F, Lemma 3).
- `05_costs.ipynb` measures our own computation and communication costs per phase.
- `06_param_ii_offline_guessing.ipynb` shows why the demos do not use PARAM II.

## Server key update

Sec. IV-F. Each epoch, every server `S_j` samples a polynomial `[F]_j` of degree `t - 1` with constant term 0,
commits to its coefficients with `H`, and sends `S_i` the share `F_ji = [F]_j(i)`, encrypted and signed. `S_i`
checks the signature, the epoch and `H(F_ji) = sum_k i^k h_k`, then sets `k_i' = k_i + sum_j F_ji`, recomputes
`pk_i`, resets every `mu_u` and starts the next epoch. The shares of the master key `K` move, `K` itself does not
(Lemma 3), so every user logs in with the same `K_u` and retrieves the same documents. `protocol.key_update` checks
every share on every server before any server applies its update, so the servers never end up in different epochs.

## Set up

`.venv/` is not in git. To create it, install [uv](https://docs.astral.sh/uv/) and run this in the repository root:

```sh
uv sync
```

`uv sync` builds `.venv/` with Python 3.14 and the packages pinned in `uv.lock`, including the dev packages that
the notebook runner needs. Every command below uses that environment through `.venv/bin/python`.

## Run the tests

From the repository root:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

## Run the notebooks

To run every notebook in `notebooks/` top to bottom in a fresh kernel and save its outputs:

```sh
.venv/bin/python scripts/run_notebooks.py
```

To run some of them, pass their paths, for example `.venv/bin/python scripts/run_notebooks.py notebooks/03_outsource_retrieve.ipynb`.
Each notebook ends with assertion cells, so a notebook that runs without error means the property it shows held.

To check every row of [Numeric claims](#numeric-claims) against the saved notebook outputs:

```sh
.venv/bin/python scripts/check_readme_claims.py
```

## Known security gaps

Two gaps came out of building and testing the scheme. Both are documented here, and neither is fixed, because a
fix needs a design the paper does not give.

- **PARAM II in this ring allows offline password guessing.** Table II gives PARAM II the degree `n = 595`. This
  code runs it in the scheme text's ring `Z_q[X]/(X^n + 1)` (decision 1). Since 595 is odd, `X = -1` is a root
  of `X^595 + 1`, and evaluating at `-1` maps each ring-LWE sample to a one-dimensional one. A single server can
  then test password guesses offline against one blinded TOPRF request.
  `notebooks/06_param_ii_offline_guessing.ipynb` shows it. The paper's security estimate for `n = 595` likely
  assumes plain LWE, where this attack does not apply, so the flaw belongs to this reading of the parameters and is
  not proven of the paper. Every other notebook runs on PARAM I (`n = 512`), where `X^512 + 1` has no root mod `q` and the
  attack finds nothing (notebook 06, PARAM I control).
- **The key-update commitments hide nothing.** Sec. IV-F checks `H(F_ji) = sum_k i^k H(alpha_k)`, so `H` must be
  linear. This code uses `H(x) = A_H x mod q` with a square `A_H`, which is invertible mod `q`, so the broadcast
  `h_k = H(alpha_k)` reveal `alpha_k`, every share `F_ji` and every key delta to an eavesdropper. Every linear `H`
  on uniform inputs has this problem. If it is injective it can be inverted, and if it compresses, a dealer can
  compute a kernel vector and change a share without changing `H`. The shares still verify and `K` still holds, but
  the update no longer protects a key share that leaked in an earlier epoch. A fix needs a hiding commitment with
  randomness, which the paper does not specify.

## Where this differs from the paper

`docs/implementation-plan.md` Part 2 explains each item.

- The scheme runs in the ring `R_q = Z_q[X]/(X^n + 1)` of Sec. II-B and Fig. 2, not with the plain-LWE matrices of Fig. 1 (decision 1).
- `q = 2^28 - 57` is not NTT-friendly, so ring products use a complex FFT on split coefficients, which is exact (decision 2).
- The TOPRF combines with the sign that the algebra of Theorem 1's proof gives, accepts only server subsets with integer Lagrange coefficients, and draws the DKG contributions, `r` and `e` from `chi_sigma` (decision 3).
- The extractor hint `sigma = S(F)` is computed at Register, stored by every server and returned at Login, so the same password gives the same `K_u` (decision 4). Fig. 2 computes the hint from a different value.
- DKG sharing polynomials have degree `t - 1`, so any `t` servers can run Login (decision 5).
- Key-update commitments use a linear hash `H(x) = A_H x mod q`, because the check in Sec. IV-F needs a homomorphic `H` (decision 6). Each server adds the shares it receives without the printed `lambda_{i,j}`, which keeps `K` unchanged.
- The paper assumes secure server-to-server channels. `E(i, .)` stands in for them with AES-256-GCM under a key per server pair, set up by `protocol.setup_servers`. Each server signs its update shares with its own ML-DSA-44 key.
- As printed, Login step L1 adds 1 to `mu_u` on every attempt, successful or not, and only the key update resets it. A user therefore gets `mu` logins per epoch in total, not `mu` failed ones.
- Values the paper leaves open are fixed as `p = 2`, `sigma = 3.2` and `L = 128`, with AES-256-GCM and ML-DSA-44 (decision 7).
- `sigma` is the standard deviation of `chi_sigma`, as the text of Definition 3 says. Its printed density would make it the width parameter.
- HKDF and the PRF use the BP lattice PRF in place of HMAC. The Dilithium seed is the start of `HKDF(K_u, "QPASE/sig")`.
- Outsource and Retrieve are authorized by `sig_Ct` and `sig_dsk` under `pk_u`, not by a passed L3. Retrieve reaches all `N` servers and Login only `t`, so an L3 gate would lock the other servers out of R2.
- The Gaussian sampler and the extractor are not constant-time. This is demonstration code.
- Multi-keyword search (Sec. IV-G) is an extension the paper sketches outside Figs. 5-6. This implementation leaves it out, and queries take one keyword.

## Numeric claims

Cell `k` is the `k`-th code cell of the notebook, which is execution count `[k]` after a fresh run with
`scripts/run_notebooks.py`. A value written `~x unit` changes between runs. The checker accepts a
printed value within a factor of 2 of it.

| Claim | Value | Notebook | Cell |
| --- | --- | --- | --- |
| Table II modulus q = 2^28 - 57 | `q = 268435399` | notebooks/01_preliminaries.ipynb | 2 |
| PARAM I ring degree | `n = 512` | notebooks/01_preliminaries.ipynb | 2 |
| PARAM II ring degree | `n = 595` | notebooks/01_preliminaries.ipynb | 2 |
| Gadget width, ceil(log2 q) | `ell = 28` | notebooks/01_preliminaries.ipynb | 2 |
| Rounding modulus of the BP PRF | `p = 2` | notebooks/01_preliminaries.ipynb | 2 |
| Standard deviation of chi_sigma | `sigma = 3.2` | notebooks/01_preliminaries.ipynb | 2 |
| Bit length of PRF and TOPRF inputs | `L = 128` | notebooks/01_preliminaries.ipynb | 2 |
| Size of each public a, a_0, a_1 | `57344 B` | notebooks/01_preliminaries.ipynb | 2 |
| Random R_q products equal to an exact integer reference | `3/3` | notebooks/01_preliminaries.ipynb | 3 |
| Output bits of one BP PRF evaluation | `14336 bits` | notebooks/01_preliminaries.ipynb | 5 |
| Median time of one BP PRF evaluation, 7 runs | `over 7 runs: median ~0.6 s` | notebooks/01_preliminaries.ipynb | 6 |
| Largest TOPRF noise coefficient 2e'' in one run | `max \|2e''\| = ~5000` | notebooks/01_preliminaries.ipynb | 10 |
| q/4, the extractor's noise bound | `q/4 = 67108849` | notebooks/01_preliminaries.ipynb | 10 |
| Size of K_u and of an HKDF output | `1792 B` | notebooks/01_preliminaries.ipynb | 11 |
| Servers, threshold and attempt limit in notebook 02 | `N = 3, t = 2, mu = 14` | notebooks/02_register_login.ipynb | 2 |
| TOPRF request to each server (user id and b) | `57349 B` | notebooks/02_register_login.ipynb | 4 |
| Register TOPRF response from each server | `114688 B` | notebooks/02_register_login.ipynb | 4 |
| Size of pk_u (ML-DSA-44 public key) | `1312 B` | notebooks/02_register_login.ipynb | 5 |
| Register step 2 message (pk_u and hint) | `RegisterKeyMessage: 3109 B` | notebooks/02_register_login.ipynb | 5 |
| Login L1 response from each server | `L1 response per server: 117792 B` | notebooks/02_register_login.ipynb | 6 |
| Login L2 proof to each server | `L2 proof per server: 2457 B` | notebooks/02_register_login.ipynb | 6 |
| Repeated correct logins with byte-identical K_u | `10/10 logins gave byte-identical K_u` | notebooks/02_register_login.ipynb | 10 |
| Median time of one Login with 2 servers, 10 runs | `over 10 runs: median ~2.3 s` | notebooks/02_register_login.ipynb | 10 |
| Attempt count at which S_2 refuses L1 | `mu_u = 14 reached the limit mu = 14` | notebooks/02_register_login.ipynb | 11 |
| Size of the index ciphertext Ct | `Ct 4256 B` | notebooks/03_outsource_retrieve.ipynb | 4 |
| Size of sig_Ct (ML-DSA-44 signature) | `sig_Ct 2420 B` | notebooks/03_outsource_retrieve.ipynb | 4 |
| Retrieve request to each server (user id, dsk, sig_dsk) | `RetrieveRequest, 4217 B` | notebooks/03_outsource_retrieve.ipynb | 9 |
| Time of R2 on all 3 servers, 7 stored items, 3 matches | `R2 on all 3 servers: ~1.4 s` | notebooks/03_outsource_retrieve.ipynb | 10 |
| Items recovered for the keyword medical | `recovered items [1, 3, 6]` | notebooks/03_outsource_retrieve.ipynb | 12 |
| Key update shares that pass step 4, N = 3 | `shares accepted: 9 of 9` | notebooks/04_server_key_update.ipynb | 6 |
| Payload of one key update share at t = 2 (h, E(i, F_ji), sig_j) | `6544 B` | notebooks/04_server_key_update.ipynb | 5 |
| Size of a key share k_i | `(2048 B)` | notebooks/04_server_key_update.ipynb | 4 |
| Epochs after two key updates | `epochs: [2, 2, 2]` | notebooks/04_server_key_update.ipynb | 11 |
| PARAM II ring degree is odd | `n = 595 (odd: True)` | notebooks/06_param_ii_offline_guessing.ipynb | 1 |
| Match threshold of the offline test at PARAM II | `match threshold tau = 1249` | notebooks/06_param_ii_offline_guessing.ipynb | 2 |
| Residual of the real password at PARAM II | `true password residual: ~344` | notebooks/06_param_ii_offline_guessing.ipynb | 4 |
| Smallest residual of a wrong guess at PARAM II | `smallest wrong-guess residual: ~9.2e7` | notebooks/06_param_ii_offline_guessing.ipynb | 4 |
| Guesses matched at PARAM I | `matched guesses: []` | notebooks/06_param_ii_offline_guessing.ipynb | 5 |
| Kernel pinned to one performance core for the cost runs | `kernel main thread affinity: [2]` | notebooks/05_costs.ipynb | 1 |
| Median time of one PRF chain a_x, 7 runs | `one PRF chain a_x: median ~490 ms` | notebooks/05_costs.ipynb | 3 |
| Median time of one ML-DSA-44 signature, 101 runs | `ML-DSA-44 sign: median ~20 ms` | notebooks/05_costs.ipynb | 4 |
| Register at the user, 7 runs | `Register at U: median ~1400 ms` | notebooks/05_costs.ipynb | 5 |
| Login at the user, 7 runs | `Login at U: median ~1900 ms` | notebooks/05_costs.ipynb | 6 |
| Outsource of a 100 KB document at the user, 7 runs | `at U: median ~1000 ms` | notebooks/05_costs.ipynb | 7 |
| Retrieve at the user, 7 runs | `Retrieve at U: median ~1600 ms` | notebooks/05_costs.ipynb | 8 |
| R2 at one server holding 10 items, 2 matching, 7 runs | `(10 items, 2 match): median ~1000 ms` | notebooks/05_costs.ipynb | 8 |
| One key update round among 3 servers, 15 runs | `whole round, N = 3: median ~290 ms` | notebooks/05_costs.ipynb | 9 |
| Share of Login time at the user spent in its 4 PRF chains | `Login at U: 4 PRF chains, share in chains ~97%` | notebooks/05_costs.ipynb | 10 |
| What limits Login at a server | `Login at S_1: 0 PRF chains, share in chains 0%, limiter ML-DSA-44 verify (~80%)` | notebooks/05_costs.ipynb | 10 |
| Register traffic per direction | `Register: U -> S 181398 B, S -> U 344064 B, S -> S 0 B` | notebooks/05_costs.ipynb | 11 |
| Login traffic per direction | `Login: U -> S 119612 B, S -> U 235648 B, S -> S 0 B` | notebooks/05_costs.ipynb | 11 |
| Outsource traffic for a 100 KB document | `Outsource: U -> S 106709 B, S -> U 0 B, S -> S 0 B` | notebooks/05_costs.ipynb | 11 |
| Retrieve traffic, 2 matching 100 KB documents | `Retrieve: U -> S 12645 B, S -> U 208568 B, S -> S 0 B` | notebooks/05_costs.ipynb | 11 |
| Key update traffic between servers, N = 3 | `Key update: U -> S 0 B, S -> U 0 B, S -> S 39264 B` | notebooks/05_costs.ipynb | 11 |
| Failed checks over every timed run | `failures over all 270 checked runs: 0` | notebooks/05_costs.ipynb | 12 |
| Counter index: label and entry sizes | `label 32 B + entry 108 B` | notebooks/07_counter_index.ipynb | 4 |
| Counter index: Outsource request for item 1 | `= 2742 B with the user id` | notebooks/07_counter_index.ipynb | 4 |
| Sealed counter table, one 1024-byte block | `sealed 1072 B` | notebooks/07_counter_index.ipynb | 5 |
| Counter table upload to each server | `CounterTableUpload to each server: 3497 B` | notebooks/07_counter_index.ipynb | 5 |
| Keywords found in any server's stored bytes | `{'invoice': [], 'medical': [], 'meeting': [], 'travel': []}` | notebooks/07_counter_index.ipynb | 7 |
| Label search request for c_w = 3, to each server | `LabelSearchRequest, 2521 B` | notebooks/07_counter_index.ipynb | 9 |
| File fetch request for one item | `FileFetchRequest for items [1], 2425 B` | notebooks/07_counter_index.ipynb | 12 |
| Files recovered for medical, and lookups per server | `recovered items [1, 3, 6], equal to the originals; lookups per server [3, 3, 3]` | notebooks/07_counter_index.ipynb | 13 |
| A kept search request replayed after a new upload | `replaying the kept request: hits per server [1, 1, 1], items [1, 3, 6]` | notebooks/07_counter_index.ipynb | 14 |
| A new search after that upload | `4 labels, items [1, 3, 6, 8]` | notebooks/07_counter_index.ipynb | 14 |
| Paper's scheme: a kept dsk tested on a later upload | `with the kept dsk: MATCH` | notebooks/07_counter_index.ipynb | 15 |
| Counter table versions a new device gets at L4 | `versions returned [8, 8]` | notebooks/07_counter_index.ipynb | 16 |
