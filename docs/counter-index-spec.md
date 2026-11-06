# Implementation spec for the counter-based search index

This spec tells you how to build our proposed improvement to QPASE in this repository. The improvement is
Part 3 of `QPASE_Paper_Presentation_counter_index-2.pdf` (slides 14 to 20). It replaces the per-file search
tags with a counter-based encrypted dictionary, so that search becomes table lookups and later uploads stay
hidden from earlier searches (forward privacy).

Read this whole page before you write code. This spec makes every design decision the slides leave open. If
something here turns out to be wrong, change this spec in the same pull request as the code, and say why.

## What exists today

`main` implements the paper as specified. Pull request #1 merged it from `feat/qpase-implementation`. Branch
from `main`. The parts you build on:

- `parties/qpase_user.py` has `QPASEUser`. After Login it holds a session with `K_u`, the HKDF `h = Hkdf(K_u)`,
  the signing keys `(pk_u, sk_u)` and the file key `k_enc`. `QPASEUser.search_key(w)` returns
  `dsk = HKDF(K_u, w)` and caches it for the session.
- `parties/qpase_server.py` has `QPASEServer`. It runs the DKG, Register, Login, the paper's Outsource and
  Retrieve, and the server key update.
- `protocol.py` runs whole phases and returns a record of every message (`setup_servers`, `register`, `login`,
  `outsource`, `retrieve`, `key_update`).
- `primitives/` has the lattice PRF `prf(bp, key, data)`, `Hkdf`, AES-256-GCM (`symmetric.encrypt`,
  `symmetric.decrypt`, `symmetric.aes_key`), ML-DSA-44 (`signature.sign`, `signature.verify`) and the
  length-prefixed wire encoding (`encoding.pack`, `encoding.unpack`, `encoding.int_bytes`).
- `index.py` builds today's per-file tag `Ct = Enc(dsk, (rho, v, sig_C))`. The server finds matches by trying `dsk` on
  every stored `Ct` (`scan_item`).
- `bench.py` has the timing helpers that `notebooks/05_costs.ipynb` uses.

The two problems this work fixes, both visible in today's code:

1. The server keeps `dsk` from a search request and can test every later upload with `scan_item`. So the scheme
   has no forward privacy.
2. `QPASEServer.retrieve_scan` tries `dsk` on every stored item, so search work grows with total storage, not with
   the number of matches.

## The scheme

Notation follows the paper and the slides. `w` is a keyword, `c_w` is the number of files filed under `w` so far,
`i` is a file's item id, and `C = Enc(k_enc, d)` is the encrypted file, unchanged from today. This spec says
"file" for the user's data. "Item" means only today's stored `(Ct, C, i)`.

### Keys, all derived on the user's device

| Key | Definition | Leaves the device? |
| --- | --- | --- |
| `K_w` | `QPASEUser.search_key(w)`, the old `dsk = HKDF(K_u, w)` | Never |
| `k_ptr` | bytes 0 to 31 of `h.derive(b"QPASE/ci/keys")` | Never |
| `k_ctr` | bytes 32 to 63 of the same output | Never |

Derive `k_ptr` and `k_ctr` once per session, with one HKDF call. Each `derive` runs one lattice PRF chain, so
one call for both saves a chain.

### Labels

The `j`-th file filed under keyword `w` gets the label

```
label(w, j) = first 32 bytes of prf(lattice.prf, K_w, b"QPASE/ci/label/" + int_bytes(j, 8))
```

for `j = 1, 2, ...`. A label is 256 bits. Put this in one function, `counter_index.label(lattice, k_w, j)`.

Each label costs one lattice PRF chain at the user, about 490 ms (README, notebook 05 cell 3). A search for a
keyword with `c_w` files therefore costs `c_w` chains at the user. We keep the scheme's PRF on purpose, so the
improvement adds no new primitive. Because the label is one function, a faster quantum-safe PRF can replace it
later if the measurements show user-side label time is the bottleneck.

### Index rows

A row is one label and its entry. The server keeps the rows in a dictionary per user, from label to entry:

```
entry = symmetric.encrypt(k_ptr, pack(label, int_bytes(i), sha3_256(C)))
```

- The entry hides which file the row points to. The server learns it only when the user fetches the file at R4
  (slide 16).
- Putting `label` inside the entry stops a server from moving an entry to another label.
- Putting `sha3_256(C)` inside the entry binds the file to the row, so a server cannot return a different
  `C` for the same item id.

Store one row per file. Each file has one keyword, as in the rest of this codebase.

### Counter table

The counter table maps each keyword to `c_w`. The user keeps it in memory during a session. The servers keep a
sealed copy, so a user who logs in from another device gets the same counters.

- **Plaintext.** `json.dumps(counts, sort_keys=True).encode()`.
- **Padding.** Pad the plaintext with zero bytes to the next multiple of 1024 bytes. The padding hides the exact
  number of keywords from the servers.
- **Sealed form.** `sealed = symmetric.encrypt(k_ctr, pack(int_bytes(version, 8), plaintext, padding))`.
- **Upload.** Send `CounterTableUpload(user_id, version, sealed, signature)` with
  `signature = sign(sk_u, pack(user_id.encode(), int_bytes(version, 8), sealed))`.
- **Where it lives.** Upload it to all `N` servers, so that any `t` of them can serve it at Login.
- **Versions.** `version` starts at 1 with the first upload and goes up by 1 with every change. A server accepts
  an upload only if the signature verifies under `pk_u` and `version` is greater than the version it holds.
- **No table yet.** A user with no stored table has an empty table at version 0.

### Phases

Register, Login (L1 to L3) and the server key update do not change. `K_u` does not change across a
key update, so `K_w`, the labels and the counter table stay valid.

**Login, extra step L4.** After L3 succeeds on the contacted servers, the user asks each of them for its stored
`CounterTableUpload`. The user keeps the uploads whose signature verifies under `pk_u` and whose sealed table
opens under `k_ctr` with the same version inside as the signed `version`, and takes the one with the highest
version. If no upload passes these checks, the table is empty at version 0. A user object that logs in again
keeps its own table if that is newer than every upload.
The server serves the table only to a user who has passed L3 in the current session. A new `new_session` for
the user ends the old session, so the user must pass L3 again.

**Outsource, replaces O1 and O2.**

1. The user sets `j = c_w + 1`, computes `label(w, j)`, `C` and the entry.
2. The user sends `IndexedOutsourceRequest(user_id, label, entry, item_id, data_ct, signature)` to one server
   `S_i` of its choice, with `signature = sign(sk_u, pack(label, entry, int_bytes(item_id), data_ct))`.
3. `S_i` verifies the signature under `pk_u`. It rejects the request if the label is already in the user's
   dictionary or the user's `M` rows are full. Otherwise it stores the row and stores `C` under `item_id`. It
   evicts nothing.
4. Only after `S_i` accepts does the user set `c_w = j` and upload the new counter table to all `N` servers.
5. If `S_i` answers `DUPLICATE_LABEL`, an earlier upload stored the row but its table upload did not
   finish. The user sets `c_w = j` without uploading the table, and retries once from step 1 with the next label.
   Search still finds the earlier row, because it asks for every label from 1 to `c_w`.

   A server checks only its own rows. If the earlier row is on another server, `S_i` stores the new row under
   the same label. Both rows are genuine, so R3 keeps every valid row and not one per label.

**Retrieve, replaces R1 to R3.**

1. **R1.** If `c_w = 0`, return no files and contact no server. Otherwise the user computes `label(w, j)` for
   each `j` from 1 to `c_w` and sends `LabelSearchRequest(user_id, labels, signature)` to all `N` servers, with
   `signature = sign(sk_u, pack(*labels))`. The user does not know which server holds which row.
2. **R2.** Each server verifies the signature and looks up each label in the user's dictionary. It does
   `c_w` hash-table lookups and scans nothing. It returns `LabelSearchResponse(server_id, hits)`, where
   `hits` holds the `(label, entry)` pairs it found.
3. **R3.** The user drops a row whose label is not one it asked for in R1. Otherwise a server could answer a
   search with a row of another keyword, whose entry would open correctly. The user opens each remaining entry
   with `k_ptr` and checks that the label inside equals the label it was returned for. It drops entries that
   fail, and records the item id and the file hash from each entry it keeps. A row that several servers return
   is kept once.
4. **R4.** The user sends `FileFetchRequest(user_id, item_ids, signature)` to each server that returned hits,
   with `signature = sign(sk_u, pack(*[int_bytes(i) for i in item_ids]))`. The server returns
   `FileFetchResponse(server_id, files)`, where `files` holds the `(item_id, data_ct)` pairs.
5. The user checks `sha3_256(data_ct)` against the hash from the entry, then decrypts `d = Dec(k_enc, C)`.

Retrieve takes two round trips because the server cannot follow an encrypted pointer. The server learns which
files the search returned at R4. The slides list this leakage as a cost we accept.

### What the server learns

| Event | Server learns |
| --- | --- |
| Outsource | A new row (random-looking label and entry), the file `C` under its item id, and the counter table's size in 1024-byte blocks and its version |
| Search | `c_w` labels, which of them hit on this server, and which files the user then fetches |
| Repeated search for the same `w` | The same labels again, so it can link the two searches (search pattern) |
| Upload after a search | Nothing that links the new row to the old labels. It never had `K_w`, so it cannot compute `label(w, c_w + 1)` |

This gives forward privacy. It does not give backward privacy, and this codebase has no deletion.

## Changes to the code

Keep the paper's scheme working unchanged. The comparison notebook runs both schemes on the same servers.

### New module `src/ris_sem_project/counter_index.py`

The module holds pure functions and frozen dataclasses. It keeps no party state.

- `label(lattice, k_w, j) -> bytes`
- `index_keys(hkdf) -> IndexKeys`, with fields `k_ptr` and `k_ctr`
- `seal_entry(k_ptr, label, item_id, data_ct) -> bytes`
- `open_entry(k_ptr, label, entry) -> OpenedEntry | None`, with fields `item_id` and `file_hash`. Return `None` when
  decryption fails or the label inside differs.
- `CounterTable` (frozen) with `version: int` and `counts: Mapping[Keyword, int]`. It has
  `count(w)`, which is 0 for an unknown keyword, and `bump(w) -> CounterTable`, which returns a copy with `c_w + 1`
  and `version + 1`.
- `seal_counter_table(k_ctr, table) -> bytes` and `open_counter_table(k_ctr, sealed) -> CounterTable | None`

### Wire messages in `parties/types.py`

Add these as `@dataclass(frozen=True, slots=True, kw_only=True)`, like the existing messages:

| Message | Fields | Direction |
| --- | --- | --- |
| `IndexedOutsourceRequest` | `user_id`, `label`, `entry`, `item_id`, `data_ct`, `signature` | U to S_i |
| `CounterTableUpload` | `user_id`, `version`, `sealed`, `signature` | U to every S |
| `LabelSearchRequest` | `user_id`, `labels: tuple[bytes, ...]`, `signature` | U to every S |
| `LabelSearchResponse` | `server_id`, `hits: tuple[tuple[bytes, bytes], ...]` | S to U |
| `FileFetchRequest` | `user_id`, `item_ids: tuple[int, ...]`, `signature` | U to S |
| `FileFetchResponse` | `server_id`, `files: tuple[tuple[int, bytes], ...]` | S to U |

### Server in `parties/counter_index_server.py`

`CounterIndexServer(QPASEServer)` reuses Register, Login and the key update. It adds four pieces of per-user
state. They are `index: dict[UserID, dict[bytes, bytes]]`, `files: dict[UserID, dict[int, bytes]]`, the latest
`CounterTableUpload`, and the set of users that passed L3 this session. It also adds these methods:

- `indexed_outsource_store(request) -> StoreOutcome`. This is Outsource step 3. `StoreOutcome` is an enum with
  `STORED`, `MALFORMED`, `BAD_SIGNATURE`, `DUPLICATE_LABEL` and `FULL`, so the user can tell a duplicate label
  (step 5) from the other rejections. `MALFORMED` covers a label that is not 32 bytes and an item id that does
  not fit in 4 bytes, which the signature check cannot encode.
- `store_counter_table(upload) -> bool`. Accept only a valid signature and a higher version.
- `counter_table(user_id) -> CounterTableUpload | None`. Serve only a user who passed L3, else raise
  `ProtocolAbort`. Record L3 by overriding `login_verify`: call the parent, then remember an accepted user and
  forget a rejected one. Override `new_session` to forget the user too.
- `label_search(request) -> LabelSearch`. `LabelSearch` is a frozen record holding the `LabelSearchResponse` and
  the number of lookups done, for the notebooks. It is the same idea as `RetrieveScan`. Raise `ProtocolAbort` on a
  bad signature.
- `fetch_files(request) -> FileFetchResponse`. Raise `ProtocolAbort` on a bad signature, and skip item ids it does
  not hold.

`M` (`capacity`) bounds rows per user. Reject when it is full, because evicting a row would break the counters.

### User in `parties/counter_index_user.py`

`CounterIndexUser(QPASEUser)` adds the counter table and the index keys to the logged-in session, and these
methods:

- `load_counter_tables(uploads)` for Login step L4
- `indexed_outsource(keyword, data, item_id) -> IndexedOutsourceRequest`, which does not advance the counter
- `confirm_outsource(keyword) -> CounterTableUpload`, which advances the counter after the server accepted, and
  returns the upload for all servers
- `skip_label(keyword) -> CounterTable`, which advances the counter without an upload, for Outsource step 5
- `label_search_request(keyword) -> LabelSearchRequest | None`, which returns `None` when `c_w = 0`
- `open_hits(keyword, responses) -> list[OpenedHit]`, for R3
- `fetch_request(item_ids) -> FileFetchRequest`
- `open_files(hits, responses) -> list[bytes]`, which checks each hash and decrypts

The session also exposes `counter_table` and `index_keys` as read-only properties for the notebooks. It caches
each label for the session, as `QPASEUser` caches each `K_w`, so an upload's label is not computed again when the
user searches in the same session.

### `protocol.py`

- Give `setup_servers` a parameter `server_type: type[QPASEServer] = QPASEServer`, so it can build
  `CounterIndexServer` instances. Existing callers do not change.
- Add `ci_login`, `ci_outsource` and `ci_retrieve`, which follow the phases above. Each returns a frozen run record
  holding every message, like `LoginRun` and `RetrieveRun`. `IndexedRetrieveRun` holds the labels, each server's
  `LabelSearch`, the opened hits, the fetch requests and responses, and the recovered files.

### `bench.py`

Add the filler helpers that notebook 08 needs (see [Measure it](#measure-it)), with docstrings that say they write
straight into server state and skip Outsource: `fill_qpase_storage`, `fill_counter_index`, and `spread_evenly`,
which splits a storage size over the servers.

## Tests in `tests/test_counter_index.py`

Use PARAM I with `N = 3` and `t = 2`, and build expected results from the table of files in the test, not from
running the code.

- A search returns exactly the files filed under the keyword, byte-equal, from rows spread over all three
  servers.
- A keyword with no files returns nothing and contacts no server.
- **Forward privacy.** Search for `w`, keep the `LabelSearchRequest`, then upload a new file under `w`. Replaying
  the old request returns the old files and not the new one.
- **Today's scheme for contrast.** Keep the `RetrieveRequest` of a QPASE search, upload a new item under the same
  keyword, and show that `index.scan_item` with the kept `dsk` returns `MATCH` for the new item.
- `K_w` never appears in any byte field of any message the user sends in Outsource or Retrieve.
- A user object on a "new device" logs in and gets the same counters as the first.
- The server rejects a stale counter-table version and a table signed by another user.
- The server rejects a duplicate label, and the user recovers by moving to the next label.
- R3 drops an entry moved to another label. R4 rejects a swapped `C` by its hash.
- A search request or fetch request with a bad signature raises `ProtocolAbort`.
- A search still returns the same files after `protocol.key_update`.
- `LabelSearch` reports exactly `c_w` lookups, whatever the storage size.

## Notebooks

The repository rules apply. Notebooks import from `src/` and implement nothing themselves. End every notebook
with assertion cells. Every number the README states must be a row in its `## Numeric claims` table, citing the
notebook and the code cell that prints it.

### `notebooks/07_counter_index.ipynb`

Mirror `03_outsource_retrieve.ipynb` with the same seven files, so readers can compare the two notebooks side by
side:

1. Setup, Register, and Login with step L4.
2. Outsource every file. Print each row the server stores (label, entry size) and show that no keyword
   appears in server state.
3. Print the counter table the user holds and the sealed copy the servers hold (size, version).
4. Search for `medical`. Print the labels, each server's lookups and hits, the opened entries, the fetch, and the
   plaintexts.
5. Run the forward-privacy demonstration. Upload a new `medical` file and replay the old request. The new file
   does not come back. Then run today's scheme, where the kept `dsk` matches the new item.
6. Log in from a new user object and show that it gets the same counters.

### `notebooks/08_search_scaling.ipynb`

See [Measure it](#measure-it).

## Measure it

The project plan on slide 20 commits us to measuring search time against storage size for both schemes, with
`N = 3, 5, 7` servers.

**What to measure.**
- Time the search at each server for today's R2 (`retrieve_scan`) and for `label_search`. Use storage sizes of
  10^2, 10^3, 10^4 and 10^5 files per user, spread evenly over the servers.
- Give each run `c_w = 3` real matching files and `t = 2`.
- For each run, report the slowest server, the sum over servers, and the user's time.

**How to measure.** Follow `.claude/skills/benchmark-checklist/SKILL.md`. Pin to one core with
`bench.pin_to_cpu`, and use `bench.measure` for one warmup, at least five runs, the median and the range. Check
every run's result and print a failure count.

**Filler.** Do not build filler files through Outsource. A real file costs at least one PRF chain of about
490 ms and one ML-DSA signature of about 20 ms (README, notebook 05 cells 3 and 4), so 10^5 real files would take
about 14 hours. That figure is arithmetic on those two rows, not a measurement. Instead, write filler straight into
server state with the new `bench` helpers:

- For today's scheme, use a `Ct` that is AES-256-GCM under a fresh random key, of the same length as a real
  `Ct` (4256 B, README, notebook 03 cell 4). The server cannot tell it apart from another keyword's item,
  because `Dec(dsk, Ct)` fails at the tag the same way for both.
- For the counter index, use a random 32-byte label and a random entry of a real entry's length.

The three matching files go through the real Outsource path in both schemes.

**What we expect before measuring.** Today's R2 should grow linearly with storage, because each non-matching item
costs one failed AES-GCM tag check. The counter index's lookups should take the same time at every storage size. With AES-GCM a failed check is
cheap, so the gap may only show at the larger sizes. Report the measured crossover, not the expectation.

## Order of work

Each unit ends with the full test suite green. Open one pull request per unit.

1. **`counter_index.py` and its unit tests in `tests/test_counter_index_functions.py`.** These are pure functions,
   so this unit depends on no other unit.
2. **Wire messages, `CounterIndexServer`, `CounterIndexUser`, the `protocol.py` functions and
   `tests/test_counter_index.py`.** This depends on unit 1. One person should own it, because the files depend on
   each other.
3. **Notebook 07 and its README rows.** This depends on unit 2.
4. **The `bench.py` filler helpers, notebook 08 and its README rows.** This depends on unit 2 and can run in
   parallel with unit 3.
5. **README.** Add the new modules to the module map, add both notebooks to the notebook list, and add a section on
   the counter index that covers its leakage table and costs.

## Repository rules

- Set up your environment once. `.venv/` is not in git, so you build your own from the committed lock file.
  Install [uv](https://docs.astral.sh/uv/), then run `uv sync` in the repository root. It creates `.venv/` with
  Python 3.14, the locked packages numpy, cryptography and dilithium-py, and the dev packages ipykernel and
  nbclient that the notebook runner needs. uv downloads Python 3.14 if you do not have it.
- Do not add or upgrade dependencies on your own. If you need a new package, agree it with the team first, then add
  it with `uv add` in a commit of its own and commit the updated `uv.lock`.
- If you use Claude Code in this repository, run `uv sync` yourself. `CLAUDE.md` does not let the agent install
  anything.
- Run the tests with `.venv/bin/python -m unittest discover -s tests`.
- Run notebooks only with `.venv/bin/python scripts/run_notebooks.py <path>`. It runs each one top to bottom in a
  fresh kernel, so cell `k` is execution count `[k]`.
- Check the README claims with `.venv/bin/python scripts/check_readme_claims.py`. Write a value that changes
  between runs as `label ~number unit`, for example `median ~490 ms`. Write exact values verbatim.
- Match the existing style. Wire messages are frozen dataclasses with docstrings in the paper's notation. Validate
  bytes from another party where they arrive, raise `ProtocolAbort` for a protocol failure, and add comments only
  for a reason the code cannot show.
- Use PARAM I everywhere. PARAM II is unsafe in this ring (README, "Known security gaps").
- Log in with server subsets that have integer Lagrange coefficients. `{1, ..., t}` always works.
