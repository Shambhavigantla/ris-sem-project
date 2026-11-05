"""The pure functions of counter_index.py (spec unit 1). Party and protocol tests are in test_counter_index.py."""

import os
import unittest

from ris_sem_project import counter_index as ci
from ris_sem_project.params import PARAM_I, Lattice, setup
from ris_sem_project.primitives import symmetric
from ris_sem_project.primitives.encoding import int_bytes, pack
from ris_sem_project.primitives.hkdf import Hkdf


def flip(data: bytes) -> bytes:
    middle = len(data) // 2
    return data[:middle] + bytes([data[middle] ^ 1]) + data[middle + 1 :]


class LabelAndKeysTest(unittest.TestCase):
    """label() and index_keys() run the lattice PRF, so they share one Lattice at PARAM I."""

    @classmethod
    def setUpClass(cls):
        cls.lattice = Lattice.from_pp(setup(PARAM_I, N=3, t=2, mu=1))
        bits = cls.lattice.ring.ell * cls.lattice.ring.n // 8
        cls.k_w, cls.k_other = os.urandom(bits), os.urandom(bits)
        cls.labels = {j: ci.label(cls.lattice, cls.k_w, j) for j in (1, 2)}

    def test_label_is_32_bytes_deterministic_and_distinct_per_j_and_key(self):
        self.assertEqual({len(lab) for lab in self.labels.values()}, {ci.LABEL_SIZE})
        self.assertEqual(ci.label(self.lattice, self.k_w, 1), self.labels[1])
        self.assertNotEqual(self.labels[1], self.labels[2])
        self.assertNotEqual(ci.label(self.lattice, self.k_other, 1), self.labels[1])

    def test_label_rejects_j_outside_one_to_two_to_the_64(self):
        for j in (0, -1, 1 << 64):
            with self.subTest(j=j), self.assertRaises(ValueError):
                ci.label(self.lattice, self.k_w, j)

    def test_index_keys_are_the_first_two_32_byte_blocks_of_one_hkdf_output(self):
        hkdf = Hkdf(self.lattice.prf, self.k_w)
        keys = ci.index_keys(hkdf)
        out = hkdf.derive(ci.KEYS_INFO)
        self.assertEqual((keys.k_ptr, keys.k_ctr), (out[:32], out[32:64]))
        self.assertNotEqual(keys.k_ptr, keys.k_ctr)


class EntryTest(unittest.TestCase):
    def setUp(self):
        self.k_ptr = os.urandom(32)
        self.label = os.urandom(ci.LABEL_SIZE)
        self.data_ct = os.urandom(177)
        self.entry = ci.seal_entry(self.k_ptr, self.label, 7, self.data_ct)

    def test_open_returns_the_item_id_and_the_hash_of_C(self):
        opened = ci.open_entry(self.k_ptr, self.label, self.entry)
        self.assertEqual(opened, ci.OpenedEntry(item_id=7, file_hash=ci.file_hash(self.data_ct)))

    def test_entry_length_is_fixed(self):
        other = ci.seal_entry(self.k_ptr, os.urandom(32), 2**32 - 1, os.urandom(100_000))
        self.assertEqual(len(other), len(self.entry))

    def test_open_fails_under_another_label_another_key_or_a_flipped_bit(self):
        for name, args in (
            ("another label", (self.k_ptr, os.urandom(ci.LABEL_SIZE), self.entry)),
            ("another key", (os.urandom(32), self.label, self.entry)),
            ("flipped bit", (self.k_ptr, self.label, flip(self.entry))),
            ("truncated", (self.k_ptr, self.label, self.entry[:20])),
        ):
            with self.subTest(name):
                self.assertIsNone(ci.open_entry(*args))

    def test_open_fails_on_a_well_encrypted_but_malformed_plaintext(self):
        for name, plaintext in (
            ("not three fields", pack(self.label, int_bytes(7))),
            ("short item id", pack(self.label, b"\x07", ci.file_hash(self.data_ct))),
            ("short hash", pack(self.label, int_bytes(7), b"\x00" * 31)),
        ):
            with self.subTest(name):
                self.assertIsNone(ci.open_entry(self.k_ptr, self.label, symmetric.encrypt(self.k_ptr, plaintext)))


class CounterTableTest(unittest.TestCase):
    def test_count_is_zero_for_an_unknown_keyword_and_bump_returns_a_new_version(self):
        empty = ci.CounterTable()
        self.assertEqual((empty.version, empty.count("medical")), (0, 0))
        once = empty.bump("medical")
        twice = once.bump("medical").bump("travel")
        self.assertEqual((once.version, once.count("medical")), (1, 1))
        self.assertEqual((twice.version, dict(twice.counts)), (3, {"medical": 2, "travel": 1}))
        self.assertEqual(empty.count("medical"), 0, "bump does not change the original")

    def test_counts_cannot_be_changed_in_place(self):
        table = ci.CounterTable(version=1, counts={"medical": 1})
        with self.assertRaises(TypeError):
            table.counts["medical"] = 5

    def test_invalid_tables_are_rejected(self):
        for name, kwargs in (
            ("negative version", dict(version=-1)),
            ("version too large", dict(version=1 << 64)),
            ("zero count", dict(counts={"w": 0})),
            ("bool count", dict(counts={"w": True})),
            ("non-str keyword", dict(counts={1: 1})),
        ):
            with self.subTest(name), self.assertRaises(ValueError):
                ci.CounterTable(**kwargs)


class SealedCounterTableTest(unittest.TestCase):
    def setUp(self):
        self.k_ctr = os.urandom(32)
        self.table = ci.CounterTable(version=4, counts={"medical": 3, "travel": 1})

    def test_round_trip(self):
        self.assertEqual(ci.open_counter_table(self.k_ctr, ci.seal_counter_table(self.k_ctr, self.table)), self.table)
        empty = ci.CounterTable()
        self.assertEqual(ci.open_counter_table(self.k_ctr, ci.seal_counter_table(self.k_ctr, empty)), empty)

    def test_sealed_size_moves_only_in_1024_byte_blocks(self):
        overhead = symmetric.NONCE_SIZE + symmetric.TAG_SIZE + 3 * 4 + ci.VERSION_SIZE
        small = ci.seal_counter_table(self.k_ctr, self.table)
        many = ci.CounterTable(version=9, counts={f"keyword-{k}": k + 1 for k in range(40)})
        self.assertEqual(len(small), overhead + ci.TABLE_BLOCK)
        self.assertEqual(len(ci.seal_counter_table(self.k_ctr, ci.CounterTable())), overhead + ci.TABLE_BLOCK)
        self.assertEqual((len(ci.seal_counter_table(self.k_ctr, many)) - overhead) % ci.TABLE_BLOCK, 0)

    def test_open_fails_under_another_key_or_a_flipped_bit(self):
        sealed = ci.seal_counter_table(self.k_ctr, self.table)
        self.assertIsNone(ci.open_counter_table(os.urandom(32), sealed))
        self.assertIsNone(ci.open_counter_table(self.k_ctr, flip(sealed)))

    def test_open_fails_on_a_well_encrypted_but_malformed_table(self):
        version = int_bytes(1, ci.VERSION_SIZE)
        body = b'{"medical": 1}'
        pad = bytes(ci.TABLE_BLOCK - len(body))
        for name, plaintext in (
            ("short version", pack(b"\x01", body, pad)),
            ("non-zero padding", pack(version, body, b"\x01" + pad[1:])),
            ("not padded to a block", pack(version, body, pad[1:])),
            ("not JSON", pack(version, b"{" + bytes(ci.TABLE_BLOCK - 1), b"")),
            ("JSON list", pack(version, b"[1]", bytes(ci.TABLE_BLOCK - 3))),
            ("zero count", pack(version, b'{"w": 0}', bytes(ci.TABLE_BLOCK - 8))),
        ):
            with self.subTest(name):
                self.assertIsNone(ci.open_counter_table(self.k_ctr, symmetric.encrypt(self.k_ctr, plaintext)))


if __name__ == "__main__":
    unittest.main()
