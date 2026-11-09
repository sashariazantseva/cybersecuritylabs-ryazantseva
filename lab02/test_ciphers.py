"""Автоматичні тести ЛР2.  Запуск:  python -m unittest -v test_ciphers.py"""
import unittest

import ciphers as C
import analysis as A

NAME = "Рязанцева Олександра Сергіївна"
DOB = "16.05.2006"
TEXT = "Таємниця листування — право кожної людини, навіть якщо листи пише студентка ХНЕУ."


class TestKeys(unittest.TestCase):
    def test_caesar_key_is_digit_sum(self):
        # 1+6+0+5+2+0+0+6 = 20
        self.assertEqual(C.caesar_key(DOB, "ua"), 20)
        self.assertEqual(C.caesar_key(DOB, "en"), 20)

    def test_vigenere_key_from_surname(self):
        self.assertEqual(C.vigenere_key(NAME, "ua"), "РЯЗАНЦЕВА")
        self.assertEqual(C.vigenere_key(NAME, "en"), "RIAZANTSEVA")

    def test_affine_key(self):
        self.assertEqual(C.affine_key(DOB, "ua"), (5, 16))
        # місяць 13 не буває, тому перевіримо підбір a на іншій даті: 03 і N=33 -> НСД=3
        self.assertEqual(C.affine_key("01.03.2000", "ua")[0], 4)

    def test_bad_date(self):
        with self.assertRaises(ValueError):
            C.caesar_key("31.02.2006")


class TestCiphers(unittest.TestCase):
    def test_round_trip_all(self):
        for alpha, text in (("ua", TEXT), ("en", "Secret letters keep our friendship safe.")):
            keys = C.personal_keys(NAME, DOB, alpha)
            for name, r in C.encrypt_all(text, keys, alpha).items():
                self.assertTrue(r["ok"], f"{name}/{alpha}")
                self.assertNotEqual(r["cipher"], text)

    def test_known_values_match_cryptii(self):
        # Значення звірені з cryptii.com
        self.assertEqual(C.caesar_encrypt("HELLO", 3, "en"), "KHOOR")
        self.assertEqual(C.vigenere_encrypt("ATTACK AT DAWN", "LEMON", "en"), "LXFOPV EF RNHR")
        self.assertEqual(C.affine_encrypt("AFFINE", 5, 8, "en"), "IHHWVC")

    def test_case_and_symbols_preserved(self):
        self.assertEqual(C.caesar_encrypt("Аб, 12!", 1), "Бв, 12!")

    def test_affine_rejects_bad_a(self):
        with self.assertRaises(ValueError):
            C.affine_encrypt("ТЕСТ", 3, 1, "ua")     # НСД(3, 33) = 3

    def test_vigenere_rejects_bad_key(self):
        with self.assertRaises(ValueError):
            C.vigenere_encrypt("текст", "KEY", "ua")  # латинський ключ для UA


class TestAnalysis(unittest.TestCase):
    def test_brute_force_finds_shift(self):
        cipher = C.caesar_encrypt(TEXT, 20)
        rows = A.brute_force_caesar(cipher)
        self.assertEqual(len(rows), 32)               # усі зсуви 1..32
        self.assertEqual(rows[0]["shift"], 20)
        self.assertEqual(rows[0]["text"], TEXT)

    def test_crack_foreign_message(self):
        # Чужий шифротекст з невідомим ключем
        secret = "Зустрічаємося завтра біля головного корпусу університету о десятій ранку."
        cipher = C.caesar_encrypt(secret, 11)
        self.assertEqual(A.crack_caesar(cipher)["text"], secret)

    def test_vigenere_flattens_frequencies(self):
        keys = C.personal_keys(NAME, DOB)
        res = C.encrypt_all(TEXT, keys)
        ic_plain = A.index_of_coincidence(TEXT)
        self.assertAlmostEqual(A.index_of_coincidence(res["Цезар"]["cipher"]), ic_plain)
        self.assertLess(A.index_of_coincidence(res["Віженер"]["cipher"]), ic_plain)

    def test_key_space(self):
        ks = A.key_space("ua", 9)
        self.assertEqual(ks["Цезар"], 32)
        self.assertEqual(ks["Афінний"], 20 * 33 - 1)  # φ(33)=20
        self.assertEqual(ks["Віженер"], 33 ** 9)


if __name__ == "__main__":
    unittest.main()
