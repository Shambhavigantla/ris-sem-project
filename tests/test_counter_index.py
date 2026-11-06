"""The counter-based search index end to end (docs/counter-index-spec.md, unit 2), at PARAM I with N = 3, t = 2."""

import dataclasses
import unittest
from dataclasses import replace
from unittest import mock

from ris_sem_project import bench, protocol
from ris_sem_project.counter_index import CounterTable
from ris_sem_project.index import ScanOutcome, scan_item
from ris_sem_project.params import PARAM_I, Lattice, setup
from ris_sem_project.parties import (
    FileFetchResponse,
    LabelSearchResponse,
    ProtocolAbort,
)
from ris_sem_project.parties.counter_index_server import CounterIndexServer, StoreOutcome
from ris_sem_project.parties.counter_index_user import CounterIndexUser

PASSWORD = "correct horse battery staple"

FILES = (
    (1, "medical", 1, b"Blood panel, 14 Sep 2026. Haemoglobin 14.1 g/dL, LDL 2.9 mmol/L, HbA1c 5.2%. No follow-up."),
    (2, "travel", 2, b"Booking KX42QP: Mumbai BOM to Lisbon LIS, 3 Nov 2026 09:40, seat 23A, one checked bag."),
    (3, "medical", 2, b"Lumbar spine MRI: mild disc bulge at L4-L5, no nerve compression. Physiotherapy advised."),
    (4, "medical", 3, b"Vaccination record: influenza 2026/27 dose given 2 Oct 2026, batch FL2611, left arm."),
    (5, "travel", 3, b"Hotel Alfama confirmation 88231: 3-7 Nov 2026, 4 nights, double room, breakfast included."),
)
"""(item id i, keyword w, server S_i the file is outsourced to, file d). medical has a row on every server."""


def flip(data: bytes) -> bytes:
    middle = len(data) // 2
    return data[:middle] + bytes([data[middle] ^ 1]) + data[middle + 1 :]


def filed(keyword: str) -> list[bytes]:
    """The files filed under keyword, ordered by item id, read from FILES."""
    return [d for _, w, _, d in sorted(FILES) if w == keyword]


def byte_fields(value: object) -> list[bytes]:
    """Every bytes value inside a message, recursing into dataclasses, tuples and lists."""
    if isinstance(value, bytes):
        return [value]
    if isinstance(value, (tuple, list)):
        return [b for v in value for b in byte_fields(v)]
    if dataclasses.is_dataclass(value):
        return [b for f in dataclasses.fields(value) for b in byte_fields(getattr(value, f.name))]
    return []


class CounterIndexTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pp = setup(PARAM_I, N=3, t=2, mu=50)
        cls.lattice = Lattice.from_pp(cls.pp)
        cls.servers = protocol.setup_servers(cls.pp, server_type=CounterIndexServer)
        cls.alice = CounterIndexUser(cls.pp, "alice", PASSWORD)
        cls.registered = protocol.register(cls.alice, cls.servers)
        cls.first_login = protocol.ci_login(cls.alice, cls.servers, (1, 2))
        cls.outsourced = {
            i: protocol.ci_outsource(cls.alice, cls.servers, server_id, w, d, i) for i, w, server_id, d in FILES
        }
        cls.rows_after_outsource = sum(len(server.index["alice"]) for server in cls.servers.values())
        cls.medical = protocol.ci_retrieve(cls.alice, cls.servers, "medical")

    def test_first_login_starts_from_an_empty_table(self):
        self.assertEqual(self.first_login.uploads, {1: None, 2: None})
        self.assertEqual(self.first_login.table, CounterTable())

    def test_search_returns_exactly_the_files_filed_under_the_keyword(self):
        self.assertEqual(list(self.medical.files), filed("medical"))
        self.assertEqual({hit.server_id for hit in self.medical.hits}, {1, 2, 3})
        self.assertEqual([hit.position for hit in self.medical.hits], [1, 2, 3])
        self.assertEqual(set(self.medical.fetch_requests), {1, 2, 3})
        travel = protocol.ci_retrieve(self.alice, self.servers, "travel")
        self.assertEqual(list(travel.files), filed("travel"))
        self.assertEqual(set(travel.fetch_requests), {2, 3})

    def test_each_outsource_stores_one_row_and_uploads_the_table_everywhere(self):
        self.assertTrue(all(run.outcomes == (StoreOutcome.STORED,) for run in self.outsourced.values()))
        self.assertEqual([run.upload.version for run in self.outsourced.values()], [1, 2, 3, 4, 5])
        for i, w, server_id, _ in FILES:
            request = self.outsourced[i].request
            self.assertEqual(self.servers[server_id].index["alice"][request.label], request.entry)
            self.assertEqual(self.servers[server_id].files["alice"][i], request.data_ct)
        self.assertEqual(self.rows_after_outsource, len(FILES))

    def test_keyword_with_no_files_returns_nothing_and_contacts_no_server(self):
        patches = [
            mock.patch.object(server, method, side_effect=AssertionError("contacted"))
            for server in self.servers.values()
            for method in ("label_search", "fetch_files")
        ]
        for patch in patches:
            patch.start()
        try:
            run = protocol.ci_retrieve(self.alice, self.servers, "taxes")
        finally:
            for patch in patches:
                patch.stop()
        self.assertIsNone(run.request)
        self.assertEqual((run.labels, run.searches, run.hits, run.files), ((), {}, (), ()))

    def test_forward_privacy_an_old_search_request_does_not_find_a_later_upload(self):
        old_file, new_file = b"Receipt 0001: groceries, EUR 54.10.", b"Receipt 0002: pharmacy, EUR 12.35."
        protocol.ci_outsource(self.alice, self.servers, 1, "receipts", old_file, 301)
        kept = protocol.ci_retrieve(self.alice, self.servers, "receipts")
        self.assertEqual(kept.files, (old_file,))
        new_row = protocol.ci_outsource(self.alice, self.servers, 2, "receipts", new_file, 302).request
        self.assertNotIn(new_row.label, kept.labels)
        replayed = {i: server.label_search(kept.request) for i, server in self.servers.items()}
        returned = [label for search in replayed.values() for label, _ in search.response.hits]
        self.assertEqual(returned, list(kept.labels))
        hits = self.alice.open_hits("receipts", [search.response for search in replayed.values()])
        fetches = [self.servers[h.server_id].fetch_files(self.alice.fetch_request([h.item_id])) for h in hits]
        self.assertEqual(self.alice.open_files(hits, fetches), [old_file])
        self.assertEqual(protocol.ci_retrieve(self.alice, self.servers, "receipts").files, (old_file, new_file))

    def test_todays_scheme_for_contrast_a_kept_dsk_matches_a_later_upload(self):
        protocol.outsource(self.alice, self.servers[1], "invoices", b"Invoice 2026-0417, EUR 186.40.", 401)
        kept = protocol.retrieve(self.alice, self.servers, "invoices").request
        later = protocol.outsource(self.alice, self.servers[3], "invoices", b"Invoice 2026-0533, EUR 92.00.", 402)
        pk_u = self.registered.key_message.user_pk
        scan = scan_item(self.lattice, pk_u, kept.search_keys[0], later.request.item)
        self.assertIs(scan.outcome, ScanOutcome.MATCH)

    def test_K_w_and_the_index_keys_never_appear_in_any_message_U_sends(self):
        travel = protocol.ci_retrieve(self.alice, self.servers, "travel")
        messages = [run.requests for run in self.outsourced.values()] + [run.upload for run in self.outsourced.values()]
        for run in (self.medical, travel):
            messages += [run.request, list(run.fetch_requests.values())]
        sent = byte_fields(messages)
        keys = self.alice.index_keys
        secrets = {f"K_{w}": self.alice.search_key(w) for w in ("medical", "travel")} | {
            "k_ptr": keys.k_ptr,
            "k_ctr": keys.k_ctr,
        }
        for name, secret in secrets.items():
            for piece in (secret, secret[:32]):
                with self.subTest(name, length=len(piece)):
                    self.assertFalse(any(piece in field for field in sent))

    def test_a_new_device_logs_in_and_gets_the_same_counters(self):
        other = CounterIndexUser(self.pp, "alice", PASSWORD)
        run = protocol.ci_login(other, self.servers, (2, 3))
        self.assertEqual(run.table, self.alice.counter_table)
        self.assertGreaterEqual(run.table.count("medical"), 3)
        self.assertEqual(protocol.ci_retrieve(other, self.servers, "medical").files, self.medical.files)

    def test_counter_table_is_served_only_after_L3_in_the_current_session(self):
        server = self.servers[1]
        server.new_session("alice")
        with self.assertRaises(ProtocolAbort):
            server.counter_table("alice")
        protocol.ci_login(self.alice, self.servers, (1, 2))
        self.assertIsNotNone(server.counter_table("alice"))

    def test_server_rejects_a_stale_counter_table_and_one_signed_by_another_user(self):
        server = self.servers[1]
        held = server.counter_tables["alice"]
        self.assertFalse(server.store_counter_table(held))
        self.assertFalse(server.store_counter_table(self.outsourced[1].upload))
        bob = CounterIndexUser(self.pp, "bob", "bob's own passphrase")
        protocol.register(bob, self.servers)
        protocol.ci_login(bob, self.servers, (1, 2))
        bobs = bob.confirm_outsource("medical")
        self.assertTrue(server.store_counter_table(bobs))
        forged = replace(bobs, user_id="alice", version=held.version + 100)
        self.assertFalse(server.store_counter_table(forged))
        self.assertIs(server.counter_tables["alice"], held)

    def test_duplicate_label_is_rejected_and_the_user_moves_to_the_next_label(self):
        first, second = b"Letter from the landlord, 2 Oct.", b"Letter from the bank, 9 Oct."
        lost = self.alice.indexed_outsource("letters", first, 501)
        self.assertIs(self.servers[2].indexed_outsource_store(lost), StoreOutcome.STORED)
        self.assertEqual(self.alice.counter_table.count("letters"), 0, "the table upload of the first file is lost")
        run = protocol.ci_outsource(self.alice, self.servers, 2, "letters", second, 502)
        self.assertEqual(run.outcomes, (StoreOutcome.DUPLICATE_LABEL, StoreOutcome.STORED))
        self.assertEqual(run.requests[0].label, lost.label)
        self.assertEqual(self.alice.counter_table.count("letters"), 2)
        self.assertEqual(protocol.ci_retrieve(self.alice, self.servers, "letters").files, (first, second))

    def test_server_refuses_a_tampered_row_or_one_beyond_M(self):
        request = self.outsourced[1].request
        server = self.servers[1]
        before = dict(server.index["alice"])
        for name, tampered, outcome in (
            ("entry", replace(request, entry=flip(request.entry)), StoreOutcome.BAD_SIGNATURE),
            ("C", replace(request, data_ct=flip(request.data_ct)), StoreOutcome.BAD_SIGNATURE),
            ("i", replace(request, item_id=99), StoreOutcome.BAD_SIGNATURE),
            ("short label", replace(request, label=request.label[:31]), StoreOutcome.MALFORMED),
            ("item id too large", replace(request, item_id=1 << 32), StoreOutcome.MALFORMED),
        ):
            with self.subTest(name):
                self.assertIs(server.indexed_outsource_store(tampered), outcome)
        self.assertEqual(server.index["alice"], before)
        small = CounterIndexServer(self.pp, 1, capacity=1)
        small.register_user("alice")
        small.register_store_key(self.registered.key_message)
        self.assertIs(small.indexed_outsource_store(self.outsourced[1].request), StoreOutcome.STORED)
        self.assertIs(small.indexed_outsource_store(self.outsourced[3].request), StoreOutcome.FULL)
        self.assertEqual(len(small.index["alice"]), 1)

    def test_R3_drops_moved_or_foreign_rows_and_R5_drops_a_swapped_C(self):
        hits = {hit.position: hit for hit in self.medical.hits}
        labels = self.medical.labels
        rows = {label: entry for s in self.medical.searches.values() for label, entry in s.response.hits}
        travel_row = (self.outsourced[2].request.label, self.outsourced[2].request.entry)
        forged = LabelSearchResponse(
            server_id=1, hits=((labels[0], rows[labels[1]]), travel_row, (labels[2], rows[labels[2]]))
        )
        kept = self.alice.open_hits("medical", [forged])
        self.assertEqual([(h.position, h.item_id) for h in kept], [(3, hits[3].item_id)])
        data = {i: self.outsourced[i].request.data_ct for i in (1, 3)}
        swapped = FileFetchResponse(server_id=1, files=((1, data[3]),))
        self.assertEqual(self.alice.open_files([hits[1]], [swapped]), [])
        honest = FileFetchResponse(server_id=1, files=((1, data[3]), (1, data[1])))
        self.assertEqual(self.alice.open_files([hits[1]], [honest]), [filed("medical")[0]])

    def test_bad_signatures_on_search_and_fetch_requests_abort(self):
        request, fetch = self.medical.request, self.medical.fetch_requests[1]
        for name, call in (
            ("search signature", lambda: self.servers[1].label_search(replace(request, signature=flip(request.signature)))),
            ("search labels", lambda: self.servers[1].label_search(replace(request, labels=request.labels[:-1]))),
            ("search user", lambda: self.servers[1].label_search(replace(request, user_id="bob"))),
            ("fetch signature", lambda: self.servers[1].fetch_files(replace(fetch, signature=flip(fetch.signature)))),
            ("fetch ids", lambda: self.servers[1].fetch_files(replace(fetch, item_ids=(2,)))),
            ("fetch id too large", lambda: self.servers[1].fetch_files(replace(fetch, item_ids=(1 << 32,)))),
        ):
            with self.subTest(name), self.assertRaises(ProtocolAbort):
                call()

    def test_search_returns_the_same_files_after_a_server_key_update(self):
        protocol.key_update(self.servers)
        other = CounterIndexUser(self.pp, "alice", PASSWORD)
        protocol.ci_login(other, self.servers, (1, 2))
        self.assertEqual(protocol.ci_retrieve(other, self.servers, "medical").files, self.medical.files)

    def test_label_search_does_c_w_lookups_whatever_the_storage_size(self):
        before = {i: s.label_search(self.medical.request) for i, s in self.servers.items()}
        for server in self.servers.values():
            bench.fill_counter_index(server, "alice", 300, len(self.outsourced[1].request.entry))
        after = {i: s.label_search(self.medical.request) for i, s in self.servers.items()}
        for i in self.servers:
            with self.subTest(server=i):
                self.assertEqual(before[i].lookups, len(self.medical.labels))
                self.assertEqual(after[i].lookups, len(self.medical.labels))
                self.assertEqual(after[i].response, before[i].response)


if __name__ == "__main__":
    unittest.main()
