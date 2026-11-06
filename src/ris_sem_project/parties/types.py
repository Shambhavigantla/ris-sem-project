"""Shared data types for the QPASE parties.

Every value that crosses the wire is a frozen dataclass whose cryptographic
payloads are already serialised to ``bytes``. Lattice arithmetic happens inside
the concrete party implementations; the boundary between parties is bytes only.

Notation follows Jiang & Wang, "QPASE", IEEE TIFS 19 (2024), Sections III-IV.
"""

from dataclasses import dataclass, field

type UserID = str
"""ID_u: the user's identity."""

type ServerID = int
"""Index i of server S_i, in [1, N]. Also its evaluation point for secret sharing."""

type SessionID = bytes
"""sid: identifier of one protocol session (signed in Login step L2)."""

type Keyword = str
"""w: a search keyword."""


class ProtocolAbort(Exception):
    """A party "outputs 0 and aborts" in the paper's protocol description."""


@dataclass(frozen=True, slots=True, kw_only=True)
class PublicParams:
    """pp <- Setup(1^kappa) (Section IV-A).

    The two published parameter sets use q = 2^28 - 57 with n = 512 or n = 595.
    """

    q: int
    """Modulus of R_q."""
    p: int
    """Rounding modulus, floor(.)_p : R_q -> R_p."""
    n: int
    """Ring / LWE dimension."""
    ell: int
    """ell = ceil(log2 q), width of the gadget vector G."""
    L: int
    """Bit length of the binary-encoded password x in {0,1}^L."""
    sigma: float
    """Gaussian width of the error distribution."""
    N: int
    """Total number of servers."""
    t: int
    """Threshold: number of servers needed in Login."""
    mu: int
    """Per-epoch upper limit on failed logins for one user."""
    a: bytes
    """Public a in R_q^{1 x ell} (Section IV-A); also the public matrix A of key update step 5."""
    a0: bytes
    """Public a_0 in R_q^{1 x ell}, fixed for the TOPRF input encoding a_x (Section II-B)."""
    a1: bytes
    """Public a_1 in R_q^{1 x ell}, fixed for the TOPRF input encoding a_x (Section II-B)."""


# --------------------------------------------------------------------------
# Server-side state
# --------------------------------------------------------------------------


@dataclass(slots=True, kw_only=True)
class UserRecord:
    """What S_i stores per user after Register step 3: (ID_u, pk_u, sigma, mu_u)."""

    user_id: UserID
    user_pk: bytes | None = None
    """pk_u (Dilithium); None until Register step 2 completes."""
    hint: bytes | None = None
    """The extractor hint sigma = S(F_reg), packed ell * n bits, stored in Register step 3.

    Plan decision 4's deviation from Fig. 2, which has no stored hint. None until step 3.
    """
    fail_count: int = 0
    """mu_u: login attempts counted in the current epoch."""


@dataclass(frozen=True, slots=True, kw_only=True)
class StoredItem:
    """(Ct, C, i) stored by S_i in Outsource step O2."""

    index_ct: bytes
    """Ct = Enc(dsk, (rho, v, sig_C)): the searchable index ciphertext."""
    data_ct: bytes
    """C = Enc(K_u, d): the encrypted document."""
    item_id: int
    """i: the document index."""


# --------------------------------------------------------------------------
# TOPRF (Register step 1, Login step L1)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class TOPRFRequest:
    """U -> S_i: the blinded password input of Pi_TOPRF."""

    user_id: UserID
    blinded_input: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class TOPRFResponse:
    """S_i -> U: the server's partial evaluation of Pi_TOPRF."""

    server_id: ServerID
    evaluation: bytes
    """S_i's partial evaluation under its key share k_i."""
    server_pk: bytes
    """pk_i = a k_i + 2e_i, unrounded (plan decision 4), used by U to unblind."""
    user_pk: bytes | None = None
    """pk_u, returned by S_i in Login step L1 (None during Register)."""
    hint: bytes | None = None
    """sigma = S(F_reg), returned with pk_u in Login step L1 (None during Register).

    Plan decision 4's deviation from Fig. 2: U extracts K_u = E(F_login, sigma) with the hint
    computed at Register, so the same password gives the same K_u at every Login.
    """


# --------------------------------------------------------------------------
# Register / Login
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class RegisterKeyMessage:
    """U -> S_i, Register step 2: pk_u from (pk_u, sk_u) <- Gen(1^kappa, K_u), and the hint sigma."""

    user_id: UserID
    user_pk: bytes
    hint: bytes
    """sigma = S(F_reg), packed ell * n bits, computed by U in Register step 1.

    Plan decision 4's deviation from Fig. 2: S_i stores it and returns it at every Login.
    """


@dataclass(frozen=True, slots=True, kw_only=True)
class LoginProof:
    """U -> S_i, Login step L2: sig_u <- Sign(sk_u', (ID_u, sid))."""

    user_id: UserID
    session_id: SessionID
    signature: bytes


# --------------------------------------------------------------------------
# Outsource / Retrieve
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class OutsourceRequest:
    """U -> S_i, Outsource step O1: (Ct, C, i) and sig_Ct."""

    user_id: UserID
    item: StoredItem
    signature: bytes
    """sig_Ct <- Sign(sk_u, (Ct, C, i))."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrieveRequest:
    """U -> S_i, Retrieve step R1: dsk and sig_dsk.

    The multi-keyword extension (Section IV-G) sends one dsk_j per keyword.
    """

    user_id: UserID
    search_keys: tuple[bytes, ...]
    """dsk_j <- HKDF(K_u, w_j), one per queried keyword."""
    signature: bytes
    """sig_dsk <- Sign(sk_u, dsk)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrieveResponse:
    """S_i -> U, Retrieve step R2: the search list L_i."""

    server_id: ServerID
    results: tuple[StoredItem, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------
# Server-to-server: DKG (Definition 12) and key update (Section IV-F)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class DKGShare:
    """S_i -> S_j: [s_i]_j from Genshare, consumed by Genkey at S_j."""

    sender: ServerID
    receiver: ServerID
    share: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class KeyUpdateShare:
    """S_j -> S_i, key update step 3: F_v^(omega) and sig_j."""

    sender: ServerID
    receiver: ServerID
    epoch: int
    """omega: the epoch this update moves away from."""
    commitments: tuple[bytes, ...]
    """h = {H_j(alpha_k)} for k in [1, t-1]."""
    encrypted_share: bytes
    """E(i, F_ji): S_j's update share for S_i, encrypted to S_i."""
    signature: bytes
    """sig_j <- Sign(sk_j, (id, F_v^(omega)))."""


# --------------------------------------------------------------------------
# Counter-based search index (docs/counter-index-spec.md)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class IndexedOutsourceRequest:
    """U -> S_i, counter-index Outsource step 2: one index row and the file C."""

    user_id: UserID
    label: bytes
    """label(w, j) for j = c_w + 1: 256 bits of PRF(K_w, j)."""
    entry: bytes
    """Enc(k_ptr, (label, i, SHA3-256(C)))."""
    item_id: int
    """i: the id C is stored under."""
    data_ct: bytes
    """C = Enc(K_u, d), as in the paper's Outsource."""
    signature: bytes
    """Sign(sk_u, (label, entry, i, C))."""


@dataclass(frozen=True, slots=True, kw_only=True)
class CounterTableUpload:
    """U -> every S: the counter table {w: c_w}, sealed under k_ctr and padded to 1024-byte blocks."""

    user_id: UserID
    version: int
    """Starts at 1 and goes up by 1 with every change. A server keeps only a higher version."""
    sealed: bytes
    """Enc(k_ctr, (version, table, zero padding))."""
    signature: bytes
    """Sign(sk_u, (ID_u, version, sealed))."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LabelSearchRequest:
    """U -> every S, counter-index Retrieve R1: the labels for j = 1..c_w of one keyword."""

    user_id: UserID
    labels: tuple[bytes, ...]
    signature: bytes
    """Sign(sk_u, labels)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class LabelSearchResponse:
    """S_i -> U, counter-index Retrieve R2: the (label, entry) rows S_i holds among the requested labels."""

    server_id: ServerID
    hits: tuple[tuple[bytes, bytes], ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True, kw_only=True)
class FileFetchRequest:
    """U -> S_i, counter-index Retrieve R4: the item ids of the files U wants from S_i."""

    user_id: UserID
    item_ids: tuple[int, ...]
    signature: bytes
    """Sign(sk_u, item ids)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class FileFetchResponse:
    """S_i -> U, counter-index Retrieve R4: (i, C) for each requested id S_i holds."""

    server_id: ServerID
    files: tuple[tuple[int, bytes], ...] = field(default_factory=tuple)
