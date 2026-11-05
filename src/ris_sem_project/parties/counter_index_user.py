"""U for the counter-based search index (docs/counter-index-spec.md).

It is a QPASEUser, so Register, Login L1 to L3 and the paper's Outsource and Retrieve are unchanged.
The logged-in session gains the index keys (k_ptr, k_ctr), derived once with one HKDF call, and the
counter table {w: c_w}. K_w = HKDF(K_u, w) is the paper's dsk and never leaves the device: only labels
computed from it do. Labels are cached for the session, as search keys already are.
"""

import hmac
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..counter_index import (
    CounterTable,
    IndexKeys,
    file_hash,
    index_keys,
    label,
    open_counter_table,
    open_entry,
    seal_counter_table,
    seal_entry,
)
from ..primitives.encoding import int_bytes, pack
from ..primitives.signature import sign, verify
from ..primitives.symmetric import decrypt, encrypt
from .qpase_user import QPASEUser, _Session
from .types import (
    CounterTableUpload,
    FileFetchRequest,
    FileFetchResponse,
    IndexedOutsourceRequest,
    Keyword,
    LabelSearchRequest,
    LabelSearchResponse,
    PublicParams,
    ServerID,
    UserID,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class OpenedHit:
    """R3 for one row a server returned: the label, its position j, and the file its entry points to."""

    server_id: ServerID
    """The server that returned the row, which R4 asks for the file."""
    label: bytes
    position: int
    """j, with label = label(w, j)."""
    item_id: int
    file_hash: bytes
    """SHA3-256(C) of the file the row was made for."""


@dataclass(slots=True, kw_only=True)
class _IndexSession:
    """The counter-index part of one logged-in session."""

    session: _Session
    keys: IndexKeys
    table: CounterTable = field(default_factory=CounterTable)
    labels: dict[tuple[Keyword, int], bytes] = field(default_factory=dict)


class CounterIndexUser(QPASEUser):
    """QPASEUser plus the counter table, the index keys and the counter-index Outsource and Retrieve."""

    def __init__(self, pp: PublicParams, user_id: UserID, password: str) -> None:
        super().__init__(pp, user_id, password)
        self._index_session: _IndexSession | None = None

    @property
    def counter_table(self) -> CounterTable:
        """The counter table of the logged-in session."""
        return self._index().table

    @property
    def index_keys(self) -> IndexKeys:
        """(k_ptr, k_ctr) of the logged-in session."""
        return self._index().keys

    def load_counter_tables(self, uploads: Sequence[CounterTableUpload | None]) -> CounterTable:
        """Login step L4: keep the uploads whose signature verifies under pk_u and whose sealed table opens
        under k_ctr with the signed version, and take the highest version, or the session's own table if
        that is higher. With no usable upload the table stays empty at version 0."""
        index = self._index()
        best = index.table
        for upload in uploads:
            if upload is None or upload.user_id != self.user_id:
                continue
            signed = pack(self.user_id.encode(), int_bytes(upload.version, 8), upload.sealed)
            if not verify(index.session.pk, signed, upload.signature):
                continue
            table = open_counter_table(index.keys.k_ctr, upload.sealed)
            if table is not None and table.version == upload.version and table.version > best.version:
                best = table
        index.table = best
        return best

    def indexed_outsource(self, keyword: Keyword, data: bytes, item_id: int) -> IndexedOutsourceRequest:
        """Outsource steps 1-2 for j = c_w + 1: label(w, j), C = Enc(K_u, d), the entry and the signature.

        c_w is not advanced here, only by confirm_outsource after the server stored the row.
        """
        if not 0 <= item_id < 1 << 32:
            raise ValueError(f"item id must fit in 4 bytes, got {item_id}")
        session, index = self._session(), self._index()
        row_label = self._label(keyword, index.table.count(keyword) + 1)
        data_ct = encrypt(session.k_enc, data)
        entry = seal_entry(index.keys.k_ptr, row_label, item_id, data_ct)
        signature = sign(session.sk, pack(row_label, entry, int_bytes(item_id), data_ct))
        return IndexedOutsourceRequest(
            user_id=self.user_id, label=row_label, entry=entry, item_id=item_id, data_ct=data_ct, signature=signature
        )

    def skip_label(self, keyword: Keyword) -> CounterTable:
        """Outsource step 5: the server already holds label(w, c_w + 1), so set c_w to it. Not uploaded."""
        index = self._index()
        index.table = index.table.bump(keyword)
        return index.table

    def confirm_outsource(self, keyword: Keyword) -> CounterTableUpload:
        """Outsource step 4, after the server stored the row: c_w += 1, and the signed sealed table for all N servers."""
        session, index = self._session(), self._index()
        index.table = index.table.bump(keyword)
        version = index.table.version
        sealed = seal_counter_table(index.keys.k_ctr, index.table)
        signature = sign(session.sk, pack(self.user_id.encode(), int_bytes(version, 8), sealed))
        return CounterTableUpload(user_id=self.user_id, version=version, sealed=sealed, signature=signature)

    def label_search_request(self, keyword: Keyword) -> LabelSearchRequest | None:
        """R1: label(w, j) for j = 1..c_w and Sign(sk_u, labels), or None when c_w = 0."""
        session, index = self._session(), self._index()
        count = index.table.count(keyword)
        if count == 0:
            return None
        labels = tuple(self._label(keyword, j) for j in range(1, count + 1))
        return LabelSearchRequest(user_id=self.user_id, labels=labels, signature=sign(session.sk, pack(*labels)))

    def open_hits(self, keyword: Keyword, responses: Sequence[LabelSearchResponse]) -> list[OpenedHit]:
        """R3: keep a returned row only if its label is one U asked for and its entry opens under k_ptr
        with that same label inside. Ordered by j.

        Two servers can hold genuine rows under one label when a table upload was lost and the next
        upload went to another server (spec, Outsource step 5), so every valid row is kept. A row that
        several servers return is kept once, from the first of them.
        """
        index = self._index()
        asked = {self._label(keyword, j): j for j in range(1, index.table.count(keyword) + 1)}
        kept: dict[tuple[int, int, bytes], OpenedHit] = {}
        for response in responses:
            for row_label, entry in response.hits:
                position = asked.get(row_label)
                if position is None:
                    continue
                opened = open_entry(index.keys.k_ptr, row_label, entry)
                if opened is not None:
                    kept.setdefault(
                        (position, opened.item_id, opened.file_hash),
                        OpenedHit(
                            server_id=response.server_id,
                            label=row_label,
                            position=position,
                            item_id=opened.item_id,
                            file_hash=opened.file_hash,
                        ),
                    )
        return sorted(kept.values(), key=lambda hit: (hit.position, hit.item_id))

    def fetch_request(self, item_ids: Sequence[int]) -> FileFetchRequest:
        """R4: the item ids and Sign(sk_u, item ids)."""
        ids = tuple(item_ids)
        signature = sign(self._session().sk, pack(*(int_bytes(i) for i in ids)))
        return FileFetchRequest(user_id=self.user_id, item_ids=ids, signature=signature)

    def open_files(self, hits: Sequence[OpenedHit], responses: Sequence[FileFetchResponse]) -> list[bytes]:
        """R5: for each hit, the first returned C with its item id and SHA3-256(C) equal to the hash in the
        entry, decrypted to d = Dec(K_u, C). A hit without such a C is dropped. Ordered by item id."""
        session = self._session()
        returned: dict[int, list[bytes]] = {}
        for response in responses:
            for item_id, data_ct in response.files:
                returned.setdefault(item_id, []).append(data_ct)
        files = []
        for hit in sorted(hits, key=lambda h: h.item_id):
            for data_ct in returned.get(hit.item_id, []):
                if hmac.compare_digest(file_hash(data_ct), hit.file_hash):
                    data = decrypt(session.k_enc, data_ct)
                    if data is not None:
                        files.append(data)
                        break
        return files

    def _label(self, keyword: Keyword, j: int) -> bytes:
        index = self._index()
        if (keyword, j) not in index.labels:
            index.labels[(keyword, j)] = label(self._lattice, self.search_key(keyword), j)
        return index.labels[(keyword, j)]

    def _index(self) -> _IndexSession:
        """The counter-index state of the current session, created with (k_ptr, k_ctr) on first use."""
        session = self._session()
        if self._index_session is None or self._index_session.session is not session:
            self._index_session = _IndexSession(session=session, keys=index_keys(session.hkdf))
        return self._index_session
