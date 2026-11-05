"""Whole QPASE phases (Sec. IV-A to IV-F, Fig. 5-6), run by moving messages between parties.

The ci_* functions run the counter-index Login, Outsource and Retrieve of docs/counter-index-spec.md
on CounterIndexServer instances, which also run every phase of the paper.

Each function returns a record of every message it moved and what U computed from them, so a
notebook can show a run without re-implementing a step.
"""

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations_with_replacement

from .counter_index import CounterTable
from .parties.counter_index_server import CounterIndexServer, LabelSearch, StoreOutcome
from .parties.counter_index_user import CounterIndexUser, OpenedHit
from .parties.qpase_server import PeerLink, QPASEServer, RetrieveScan, ShareCheck, ShareOutcome
from .parties.qpase_user import OpenedItem, QPASEUser
from .parties.types import (
    CounterTableUpload,
    DKGShare,
    FileFetchRequest,
    FileFetchResponse,
    IndexedOutsourceRequest,
    Keyword,
    KeyUpdateShare,
    LabelSearchRequest,
    LoginProof,
    OutsourceRequest,
    ProtocolAbort,
    PublicParams,
    RegisterKeyMessage,
    RetrieveRequest,
    ServerID,
    TOPRFRequest,
    TOPRFResponse,
)
from .primitives.symmetric import KEY_SIZE


@dataclass(frozen=True, slots=True, kw_only=True)
class DKGRun:
    """The DKG among the N servers (Definition 12)."""

    shares: dict[ServerID, dict[ServerID, DKGShare]]
    """shares[i][j] = [s_i]_j, dealt by S_i to S_j."""


@dataclass(frozen=True, slots=True, kw_only=True)
class KeyUpdateRun:
    """One server key update (Sec. IV-F) among all N servers."""

    shares: dict[ServerID, dict[ServerID, KeyUpdateShare]]
    """shares[j][i] = F_v^(omega) and sig_j, dealt by S_j to S_i."""
    checks: dict[tuple[ServerID, ServerID], ShareCheck]
    """checks[(j, i)] = step 4 at S_i for the share from S_j, before anything was applied."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RegisterRun:
    """Register (Sec. IV-B) on all N servers."""

    requests: dict[ServerID, TOPRFRequest]
    responses: dict[ServerID, TOPRFResponse]
    k_u: bytes
    """K_u, which U drops once step 2 is sent."""
    key_message: RegisterKeyMessage


@dataclass(frozen=True, slots=True, kw_only=True)
class LoginRun:
    """Login (Sec. IV-C) on t servers."""

    requests: dict[ServerID, TOPRFRequest]
    responses: dict[ServerID, TOPRFResponse]
    """L1, each carrying pk_u and sigma."""
    k_u: bytes
    user_pk: bytes
    """pk_u as every contacted server returned it."""
    proofs: dict[ServerID, LoginProof]
    """L2: sig_u over each server's own sid, all accepted in L3."""


@dataclass(frozen=True, slots=True, kw_only=True)
class OutsourceRun:
    """Outsource (Sec. IV-D) to one server."""

    server_id: ServerID
    request: OutsourceRequest


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrieveRun:
    """Retrieve (Sec. IV-E) from every server."""

    request: RetrieveRequest
    scans: dict[ServerID, RetrieveScan]
    """R2 at each S_i, with its response L_i."""
    opened: tuple[OpenedItem, ...]
    """R3, one entry per distinct returned item."""

    @property
    def documents(self) -> list[bytes]:
        """Every recovered d, ordered by item id."""
        return [o.data for o in self.opened if o.data is not None]


def dkg(servers: Mapping[ServerID, QPASEServer]) -> DKGRun:
    """The DKG (Definition 12): Genshare at every S_i, then Genkey at every S_j over the shares addressed to it."""
    dealt = {i: server.dkg_genshare() for i, server in servers.items()}
    for j, server in servers.items():
        server.dkg_genkey([dealt[i][j] for i in servers])
    return DKGRun(shares=dealt)


def setup_servers(
    pp: PublicParams, capacity: int = 1000, server_type: type[QPASEServer] = QPASEServer
) -> dict[ServerID, QPASEServer]:
    """S_1, ..., S_N of server_type with M = capacity, keyed by the DKG.

    Every server also learns every server's ML-DSA-44 verification key, and every pair (S_j, S_i),
    S_j = S_i included, gets a fresh channel key for E(i, .) of the key update.
    """
    servers = {i: server_type(pp, i, capacity) for i in range(1, pp.N + 1)}
    for i, j in combinations_with_replacement(servers, 2):
        channel_key = os.urandom(KEY_SIZE)
        servers[i].add_peer(j, PeerLink(verification_key=servers[j].verification_key, channel_key=channel_key))
        servers[j].add_peer(i, PeerLink(verification_key=servers[i].verification_key, channel_key=channel_key))
    dkg(servers)
    return servers


def key_update(servers: Mapping[ServerID, QPASEServer]) -> KeyUpdateRun:
    """Steps 1-3 at every S_j, step 4's check at every S_i, then step 5 at every S_i.

    A share that fails any check raises ProtocolAbort before any server applies its update, so
    the servers stay in one epoch under one K.
    """
    dealt = {j: server.key_update_shares() for j, server in servers.items()}
    received = {i: [dealt[j][i] for j in servers] for i in servers}
    checks = {(c.sender, c.receiver): c for i, server in servers.items() for c in server.key_update_check(received[i])}
    rejected = {pair: c.outcome.name for pair, c in checks.items() if c.outcome is not ShareOutcome.ACCEPTED}
    if rejected:
        raise ProtocolAbort(f"key update shares rejected, keyed by (sender, receiver): {rejected}")
    for i, server in servers.items():
        server.key_update_apply(received[i])
    return KeyUpdateRun(shares=dealt, checks=checks)


def register(user: QPASEUser, servers: Mapping[ServerID, QPASEServer]) -> RegisterRun:
    """Steps 1-3 with every server: duplicate check, TOPRF, then pk_u and sigma stored everywhere."""
    for server in servers.values():
        server.register_user(user.user_id)
    requests = user.toprf_request(sorted(servers))
    responses = {i: servers[i].toprf_evaluate(request) for i, request in requests.items()}
    k_u = user.toprf_finalize(list(responses.values()))
    key_message = user.register_keygen(k_u)
    for server in servers.values():
        server.register_store_key(key_message)
    return RegisterRun(requests=requests, responses=responses, k_u=k_u, key_message=key_message)


def login(user: QPASEUser, servers: Mapping[ServerID, QPASEServer], server_ids: Sequence[ServerID]) -> LoginRun:
    """L1 with the contacted servers, which must agree on pk_u; then L2 and L3 with each one's own sid.

    Raises ValueError for an unusable subset before any server is contacted, and ProtocolAbort
    when a server refuses L1, the password is wrong (L2), or a server rejects sig_u (L3).
    """
    requests = user.toprf_request(server_ids)
    responses = {i: servers[i].toprf_evaluate(request) for i, request in requests.items()}
    user_pks = {response.user_pk for response in responses.values()}
    if len(user_pks) != 1 or None in user_pks:
        raise ProtocolAbort("the contacted servers do not return one pk_u")
    (user_pk,) = user_pks
    k_u = user.toprf_finalize(list(responses.values()))
    proofs = {}
    for i in requests:
        proofs[i] = user.login_verify(k_u, user_pk, servers[i].new_session(user.user_id))
        if not servers[i].login_verify(proofs[i]):
            raise ProtocolAbort(f"S_{i} rejected sig_u")
    return LoginRun(requests=requests, responses=responses, k_u=k_u, user_pk=user_pk, proofs=proofs)


def outsource(user: QPASEUser, server: QPASEServer, keyword: Keyword, data: bytes, item_id: int) -> OutsourceRun:
    """O1 at U, O2 at the chosen server, which must accept sig_Ct."""
    request = user.outsource(keyword, data, item_id)
    if not server.outsource_store(request):
        raise ProtocolAbort(f"S_{server.server_id} rejected sig_Ct")
    return OutsourceRun(server_id=server.server_id, request=request)


def retrieve(user: QPASEUser, servers: Mapping[ServerID, QPASEServer], keyword: Keyword) -> RetrieveRun:
    """R1 to every server, R2 on each, R3 over all returned lists."""
    request = user.retrieve_request([keyword])
    scans = {i: server.retrieve_scan(request) for i, server in servers.items()}
    opened = user.retrieve_open([keyword], [scan.response for scan in scans.values()])
    return RetrieveRun(request=request, scans=scans, opened=tuple(opened))


# --------------------------------------------------------------------------
# Counter-based search index (docs/counter-index-spec.md)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class IndexedLoginRun:
    """Login L1 to L3 as in `login`, then L4 on the same servers."""

    login: LoginRun
    uploads: dict[ServerID, CounterTableUpload | None]
    """L4: the counter table each contacted server returned, None from a server that holds none."""
    table: CounterTable
    """The counter table U kept."""


@dataclass(frozen=True, slots=True, kw_only=True)
class IndexedOutsourceRun:
    """Counter-index Outsource of one file to one server, then the new counter table to every server."""

    server_id: ServerID
    requests: tuple[IndexedOutsourceRequest, ...]
    """One request, or two when the first label was a DUPLICATE_LABEL."""
    outcomes: tuple[StoreOutcome, ...]
    """The server's answer to each request."""
    upload: CounterTableUpload
    """The counter table sent to all N servers, which all accepted it."""

    @property
    def request(self) -> IndexedOutsourceRequest:
        """The request the server stored."""
        return self.requests[-1]


@dataclass(frozen=True, slots=True, kw_only=True)
class IndexedRetrieveRun:
    """Counter-index Retrieve R1 to R5. Every field is empty when c_w = 0, since then no server is contacted."""

    request: LabelSearchRequest | None
    """R1, sent to every server."""
    searches: dict[ServerID, LabelSearch]
    """R2 at each server, with its lookup count."""
    hits: tuple[OpenedHit, ...]
    """R3: the rows U kept."""
    fetch_requests: dict[ServerID, FileFetchRequest]
    """R4, to each server that returned a kept row."""
    fetch_responses: dict[ServerID, FileFetchResponse]
    files: tuple[bytes, ...]
    """R5: every recovered d, ordered by item id."""

    @property
    def labels(self) -> tuple[bytes, ...]:
        """label(w, j) for j = 1..c_w."""
        return () if self.request is None else self.request.labels


def ci_login(
    user: CounterIndexUser, servers: Mapping[ServerID, CounterIndexServer], server_ids: Sequence[ServerID]
) -> IndexedLoginRun:
    """`login`, then L4: every contacted server's stored counter table, of which U keeps the newest valid one."""
    run = login(user, servers, server_ids)
    uploads = {i: servers[i].counter_table(user.user_id) for i in run.requests}
    table = user.load_counter_tables(list(uploads.values()))
    return IndexedLoginRun(login=run, uploads=uploads, table=table)


def ci_outsource(
    user: CounterIndexUser,
    servers: Mapping[ServerID, CounterIndexServer],
    server_id: ServerID,
    keyword: Keyword,
    data: bytes,
    item_id: int,
) -> IndexedOutsourceRun:
    """Steps 1-3 with the chosen server; on DUPLICATE_LABEL step 5 retries once with the next label.
    Once stored, step 4: c_w += 1 and the new counter table goes to all N servers.

    Raises ProtocolAbort if the server refuses the row or a server refuses the table.
    """
    requests, outcomes = [], []
    for attempt in range(2):
        requests.append(user.indexed_outsource(keyword, data, item_id))
        outcomes.append(servers[server_id].indexed_outsource_store(requests[-1]))
        if outcomes[-1] is StoreOutcome.STORED:
            break
        if outcomes[-1] is not StoreOutcome.DUPLICATE_LABEL or attempt == 1:
            raise ProtocolAbort(f"S_{server_id} refused the row: {outcomes[-1].name}")
        user.skip_label(keyword)
    upload = user.confirm_outsource(keyword)
    refused = [i for i, server in servers.items() if not server.store_counter_table(upload)]
    if refused:
        raise ProtocolAbort(f"servers {refused} refused counter table version {upload.version}")
    return IndexedOutsourceRun(server_id=server_id, requests=tuple(requests), outcomes=tuple(outcomes), upload=upload)


def ci_retrieve(
    user: CounterIndexUser, servers: Mapping[ServerID, CounterIndexServer], keyword: Keyword
) -> IndexedRetrieveRun:
    """R1 to every server, R2 on each, R3 at U, R4 to each server that returned a kept row, R5 at U."""
    request = user.label_search_request(keyword)
    if request is None:
        return IndexedRetrieveRun(request=None, searches={}, hits=(), fetch_requests={}, fetch_responses={}, files=())
    searches = {i: server.label_search(request) for i, server in servers.items()}
    hits = user.open_hits(keyword, [search.response for search in searches.values()])
    wanted: dict[ServerID, list[int]] = {}
    for hit in hits:
        wanted.setdefault(hit.server_id, []).append(hit.item_id)
    fetch_requests = {i: user.fetch_request(sorted(ids)) for i, ids in sorted(wanted.items())}
    fetch_responses = {i: servers[i].fetch_files(fetch) for i, fetch in fetch_requests.items()}
    files = user.open_files(hits, list(fetch_responses.values()))
    return IndexedRetrieveRun(
        request=request,
        searches=searches,
        hits=tuple(hits),
        fetch_requests=fetch_requests,
        fetch_responses=fetch_responses,
        files=tuple(files),
    )
