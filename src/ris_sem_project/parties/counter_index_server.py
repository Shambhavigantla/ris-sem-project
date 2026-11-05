"""S_i for the counter-based search index (docs/counter-index-spec.md).

It is a QPASEServer, so Register, Login, the server key update and the paper's Outsource and Retrieve
are unchanged and both schemes run on the same servers. Per user it adds the index rows
{label: entry}, the files {i: C}, the latest signed counter table, and whether the user passed L3
in its current session. A search is one dictionary lookup per requested label and scans nothing.
"""

from dataclasses import dataclass
from enum import Enum, auto

from ..counter_index import LABEL_SIZE
from ..primitives.encoding import int_bytes, pack
from ..primitives.signature import verify
from .qpase_server import QPASEServer
from .types import (
    CounterTableUpload,
    FileFetchRequest,
    FileFetchResponse,
    IndexedOutsourceRequest,
    LabelSearchRequest,
    LabelSearchResponse,
    LoginProof,
    ProtocolAbort,
    PublicParams,
    ServerID,
    SessionID,
    UserID,
)


class StoreOutcome(Enum):
    """What S_i did with one IndexedOutsourceRequest."""

    STORED = auto()
    """The row and C are stored."""
    MALFORMED = auto()
    """The label is not 32 bytes or the item id does not fit in 4 bytes."""
    BAD_SIGNATURE = auto()
    """Ver(pk_u, (label, entry, i, C), sig) failed."""
    DUPLICATE_LABEL = auto()
    """The user already has a row under this label: an earlier table upload did not finish."""
    FULL = auto()
    """The user's M rows are taken. Nothing is evicted, since that would break the counters."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LabelSearch:
    """R2 at one S_i: its response and how many dictionary lookups it did."""

    server_id: ServerID
    response: LabelSearchResponse
    lookups: int


class CounterIndexServer(QPASEServer):
    """QPASEServer plus the counter-index rows, files and sealed counter tables."""

    def __init__(self, pp: PublicParams, server_id: ServerID, capacity: int = 1000) -> None:
        """capacity is M, here the number of index rows S_i holds per user."""
        super().__init__(pp, server_id, capacity)
        self.index: dict[UserID, dict[bytes, bytes]] = {}
        """{label: entry} per user."""
        self.files: dict[UserID, dict[int, bytes]] = {}
        """{i: C} per user."""
        self.counter_tables: dict[UserID, CounterTableUpload] = {}
        """The highest-version counter table each user uploaded."""
        self._logged_in: set[UserID] = set()

    def new_session(self, user_id: UserID) -> SessionID:
        """A new Login replaces the old session, so the user must pass L3 again before L4."""
        self._logged_in.discard(user_id)
        return super().new_session(user_id)

    def login_verify(self, proof: LoginProof) -> bool:
        """L3 as in QPASEServer, also recording whether the user passed it for L4."""
        accepted = super().login_verify(proof)
        if accepted:
            self._logged_in.add(proof.user_id)
        else:
            self._logged_in.discard(proof.user_id)
        return accepted

    def indexed_outsource_store(self, request: IndexedOutsourceRequest) -> StoreOutcome:
        """Outsource step 3: verify the signature, refuse a known label or a full index, else store."""
        record = self._registered(request.user_id)
        if len(request.label) != LABEL_SIZE or not 0 <= request.item_id < 1 << 32:
            return StoreOutcome.MALFORMED
        signed = pack(request.label, request.entry, int_bytes(request.item_id), request.data_ct)
        if not verify(record.user_pk, signed, request.signature):
            return StoreOutcome.BAD_SIGNATURE
        rows = self.index.setdefault(request.user_id, {})
        if request.label in rows:
            return StoreOutcome.DUPLICATE_LABEL
        if len(rows) >= self.capacity:
            return StoreOutcome.FULL
        rows[request.label] = request.entry
        self.files.setdefault(request.user_id, {})[request.item_id] = request.data_ct
        return StoreOutcome.STORED

    def store_counter_table(self, upload: CounterTableUpload) -> bool:
        """Keep the upload iff Ver(pk_u, (ID_u, version, sealed), sig) and version beats the one held."""
        record = self._registered(upload.user_id)
        if not 1 <= upload.version < 1 << 64:
            return False
        signed = pack(upload.user_id.encode(), int_bytes(upload.version, 8), upload.sealed)
        if not verify(record.user_pk, signed, upload.signature):
            return False
        held = self.counter_tables.get(upload.user_id)
        if held is not None and upload.version <= held.version:
            return False
        self.counter_tables[upload.user_id] = upload
        return True

    def counter_table(self, user_id: UserID) -> CounterTableUpload | None:
        """Login step L4: the stored table, only for a user who passed L3 in its current session."""
        self._registered(user_id)
        if user_id not in self._logged_in:
            raise ProtocolAbort(f"{user_id!r} has not passed L3 at S_{self.server_id} in this session")
        return self.counter_tables.get(user_id)

    def label_search(self, request: LabelSearchRequest) -> LabelSearch:
        """R2: abort unless Ver(pk_u, labels, sig); then one lookup per label."""
        record = self._registered(request.user_id)
        if not verify(record.user_pk, pack(*request.labels), request.signature):
            raise ProtocolAbort("the label search signature does not verify under pk_u")
        rows = self.index.get(request.user_id, {})
        hits = tuple((label, rows[label]) for label in request.labels if label in rows)
        return LabelSearch(
            server_id=self.server_id,
            response=LabelSearchResponse(server_id=self.server_id, hits=hits),
            lookups=len(request.labels),
        )

    def fetch_files(self, request: FileFetchRequest) -> FileFetchResponse:
        """R4: abort unless Ver(pk_u, item ids, sig); return (i, C) for each requested id held here."""
        record = self._registered(request.user_id)
        if not all(0 <= i < 1 << 32 for i in request.item_ids):
            raise ProtocolAbort("an item id does not fit in 4 bytes")
        if not verify(record.user_pk, pack(*(int_bytes(i) for i in request.item_ids)), request.signature):
            raise ProtocolAbort("the file fetch signature does not verify under pk_u")
        held = self.files.get(request.user_id, {})
        return FileFetchResponse(
            server_id=self.server_id, files=tuple((i, held[i]) for i in request.item_ids if i in held)
        )
