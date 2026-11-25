"""Тести ЛР4.  Запуск:  python -m unittest -v test_signature.py"""
import os
import tempfile
import unittest

import signature as S
import forgery

NAME, DOB = "Рязанцева Олександра Сергіївна", "16.05.2006"


class TestSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = S.generate_keys(NAME, DOB, "test-secret")
        cls.dir = tempfile.mkdtemp()
        cls.doc = os.path.join(cls.dir, "doc.txt")
        with open(cls.doc, "w", encoding="utf-8") as f:
            f.write("Лабораторна робота № 4")

    def test_keys_are_deterministic(self):
        again = S.generate_keys(NAME, DOB, "test-secret")
        self.assertEqual(again["public"]["n"], self.keys["public"]["n"])

    def test_secret_changes_key(self):
        other = S.generate_keys(NAME, DOB, "other")
        self.assertNotEqual(other["public"]["n"], self.keys["public"]["n"])

    def test_key_size(self):
        self.assertGreaterEqual(self.keys["public"]["n"].bit_length(), 2047)

    def test_keys_are_related(self):
        pub, prv = self.keys["public"], self.keys["private"]
        self.assertEqual(pow(pow(42, prv["d"], prv["n"]), pub["e"], pub["n"]), 42)

    def test_mod_inverse(self):
        self.assertEqual(S.mod_inverse(3, 11), 4)        # 3*4 = 12 = 1 mod 11

    def test_prime_test(self):
        self.assertTrue(S._is_probable_prime(2 ** 127 - 1))
        self.assertFalse(S._is_probable_prime(2 ** 128 + 1))

    def test_sign_and_verify_all_hashes(self):
        for algo in S.HASHES:
            sig = S.sign_file(self.doc, self.keys["private"], algo, self.doc + algo + ".sig")
            self.assertTrue(S.verify_file(self.doc, sig["sig_path"], self.keys["public"])["valid"], algo)

    def test_forgery_detected(self):
        sig = S.sign_file(self.doc, self.keys["private"])
        rows = forgery.run_all(self.doc, sig["sig_path"], self.keys["public"], NAME, DOB,
                               os.path.join(self.dir, "f"))
        self.assertTrue(all(r["ok"] for r in rows))

    def test_save_load_key(self):
        p = os.path.join(self.dir, "pub.json")
        S.save_key(self.keys["public"], p)
        self.assertEqual(S.load_key(p)["n"], self.keys["public"]["n"])

    def test_empty_secret(self):
        with self.assertRaises(ValueError):
            S.generate_keys(NAME, DOB, "")

    def test_avalanche(self):
        h1, h2 = S.hash_bytes(b"lab 4"), S.hash_bytes(b"lab 5")
        self.assertGreater(S.bit_difference(h1, h2), 80)


if __name__ == "__main__":
    unittest.main()
