"""The counter-based search index (docs/counter-index-spec.md), our improvement to QPASE.

The j-th file filed under keyword w gets the label label(w, j) = PRF(K_w, j), truncated to 256 bits,
where K_w = HKDF(K_u, w) is the paper's dsk and never leaves U. A server stores one row
label -> entry per file, with entry = Enc(k_ptr, (label, i, H(C))). U keeps c_w, the number of files
filed under w, in a counter table that the servers hold sealed under k_ctr. A search sends the labels
for j = 1..c_w, so a server does c_w dictionary lookups and cannot compute the label of a later upload.

Pure functions and frozen records only. No party state lives here.
"""

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .params import Lattice
from .parties.types import Keyword
from .primitives.encoding import bytes_int, int_bytes, pack, unpack
from .primitives.hkdf import Hkdf
from .primitives.prf import prf
from .primitives.symmetric import KEY_SIZE, decrypt, encrypt

LABEL_SIZE = 32
"""Bytes of a label: 256 bits."""

ITEM_ID_SIZE = 4
"""Bytes of an item id i inside an entry, as int_bytes(i) writes it."""

FILE_HASH_SIZE = 32
"""Bytes of SHA3-256(C)."""

VERSION_SIZE = 8
"""Bytes of the counter table version on the wire."""

TABLE_BLOCK = 1024
"""The counter table plaintext is zero-padded to a multiple of this many bytes."""

KEYS_INFO = b"QPASE/ci/keys"
"""HKDF info for (k_ptr, k_ctr)."""

LABEL_INFO = b"QPASE/ci/label/"
"""PRF input prefix of a label."""


@dataclass(frozen=True, slots=True, kw_only=True)
class IndexKeys:
    """k_ptr seals the entries, k_ctr seals the counter table. Both stay on U's device."""

    k_ptr: bytes
    k_ctr: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class OpenedEntry:
    """An entry U opened with k_ptr: the file it points to and the hash that file must have."""

    item_id: int
    file_hash: bytes
    """SHA3-256(C) of the file the row was made for."""


@dataclass(frozen=True, slots=True, kw_only=True)
class CounterTable:
    """c_w for every keyword U has filed a file under, and the table's version.

    A keyword that is not in counts has c_w = 0. Version 0 is the empty table a user has before
    the first upload.
    """

    version: int = 0
    counts: Mapping[Keyword, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 <= self.version < 1 << (8 * VERSION_SIZE):
            raise ValueError(f"version must fit in {VERSION_SIZE} bytes, got {self.version}")
        counts = dict(self.counts)
        for keyword, count in counts.items():
            if not isinstance(keyword, str) or type(count) is not int or count < 1:
                raise ValueError(f"c_w must be a positive int under a str keyword, got {keyword!r}: {count!r}")
        object.__setattr__(self, "counts", MappingProxyType(counts))

    def count(self, keyword: Keyword) -> int:
        """c_w, 0 for a keyword with no files."""
        return self.counts.get(keyword, 0)

    def bump(self, keyword: Keyword) -> CounterTable:
        """A copy with c_w + 1 and version + 1."""
        return CounterTable(version=self.version + 1, counts={**self.counts, keyword: self.count(keyword) + 1})


def label(lattice: Lattice, k_w: bytes, j: int) -> bytes:
    """label(w, j) = the first 32 bytes of PRF(K_w, "QPASE/ci/label/" || j), for j >= 1.

    One lattice PRF chain. This is the only place a label is computed, so a faster PRF can replace it.
    """
    if not 1 <= j < 1 << 64:
        raise ValueError(f"j must be in [1, 2^64), got {j}")
    return prf(lattice.prf, k_w, LABEL_INFO + int_bytes(j, 8))[:LABEL_SIZE]


def index_keys(hkdf: Hkdf) -> IndexKeys:
    """(k_ptr, k_ctr) = bytes 0-31 and 32-63 of HKDF(K_u, "QPASE/ci/keys"), from one HKDF call."""
    out = hkdf.derive(KEYS_INFO)
    return IndexKeys(k_ptr=out[:KEY_SIZE], k_ctr=out[KEY_SIZE : 2 * KEY_SIZE])


def file_hash(data_ct: bytes) -> bytes:
    """SHA3-256(C)."""
    return hashlib.sha3_256(data_ct).digest()


def seal_entry(k_ptr: bytes, label: bytes, item_id: int, data_ct: bytes) -> bytes:
    """entry = Enc(k_ptr, (label, i, SHA3-256(C)))."""
    return encrypt(k_ptr, pack(label, int_bytes(item_id, ITEM_ID_SIZE), file_hash(data_ct)))


def open_entry(k_ptr: bytes, label: bytes, entry: bytes) -> OpenedEntry | None:
    """Dec(k_ptr, entry), or None if it fails, is malformed, or holds a label other than `label`."""
    plaintext = decrypt(k_ptr, entry)
    if plaintext is None:
        return None
    try:
        inside, item_id, digest = unpack(plaintext, 3)
    except ValueError:
        return None
    if len(item_id) != ITEM_ID_SIZE or len(digest) != FILE_HASH_SIZE or not hmac.compare_digest(inside, label):
        return None
    return OpenedEntry(item_id=bytes_int(item_id), file_hash=digest)


def seal_counter_table(k_ctr: bytes, table: CounterTable) -> bytes:
    """Enc(k_ctr, (version, plaintext, padding)) with plaintext = the sorted JSON of the counts and
    padding = zero bytes up to the next multiple of 1024 bytes of plaintext."""
    plaintext = json.dumps(dict(table.counts), sort_keys=True).encode()
    padding = bytes(-len(plaintext) % TABLE_BLOCK)
    return encrypt(k_ctr, pack(int_bytes(table.version, VERSION_SIZE), plaintext, padding))


def open_counter_table(k_ctr: bytes, sealed: bytes) -> CounterTable | None:
    """The table inside a sealed counter table, or None if it does not decrypt or is malformed."""
    plaintext = decrypt(k_ctr, sealed)
    if plaintext is None:
        return None
    try:
        version, body, padding = unpack(plaintext, 3)
        if len(version) != VERSION_SIZE or any(padding) or (len(body) + len(padding)) % TABLE_BLOCK:
            return None
        counts = json.loads(body)
        if not isinstance(counts, dict):
            return None
        return CounterTable(version=bytes_int(version), counts=counts)
    except ValueError:
        return None
