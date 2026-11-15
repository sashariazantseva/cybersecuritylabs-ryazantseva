"""Тести ЛР3.  Запуск:  python -m unittest -v test_stego.py"""
import os
import tempfile
import unittest

from PIL import Image

import stego
import cipher
import analysis as A

MESSAGE = "Рязанцева Олександра Сергіївна, 16.05.2006"


class TestStego(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cover = os.path.join(self.dir, "cover.png")
        # тестове зображення з "шумом", схожим на фото
        img = Image.new("RGB", (120, 80))
        img.putdata([((x * 7 + y * 3) % 256, (x * y) % 256, (x + 2 * y) % 256)
                     for y in range(80) for x in range(120)])
        img.save(self.cover)
        self.out = os.path.join(self.dir, "stego.png")

    def test_bits_round_trip(self):
        self.assertEqual(stego.bits_to_bytes(stego.text_to_bits("Ря")), "Ря".encode())
        self.assertEqual(stego.text_to_bits("A"), [0, 1, 0, 0, 0, 0, 0, 1])

    def test_hide_and_extract(self):
        stego.hide_message(self.cover, MESSAGE, self.out)
        self.assertEqual(stego.extract_message(self.out), MESSAGE)

    def test_each_channel(self):
        for ch in ("R", "G", "B", "RG"):
            stego.hide_message(self.cover, MESSAGE, self.out, ch)
            self.assertEqual(stego.extract_message(self.out, ch), MESSAGE)

    def test_only_lsb_changes(self):
        stego.hide_message(self.cover, MESSAGE, self.out)
        c = A.compare(self.cover, self.out)
        self.assertEqual(c["max_difference"], 1)
        self.assertGreater(c["psnr_db"], 50)

    def test_no_message(self):
        with self.assertRaises(ValueError):
            stego.extract_message(self.cover)

    def test_too_long(self):
        with self.assertRaises(ValueError):
            stego.hide_message(self.cover, "x" * 10000, self.out)

    def test_jpeg_not_allowed(self):
        with self.assertRaises(ValueError):
            stego.hide_message(self.cover, MESSAGE, os.path.join(self.dir, "a.jpg"))

    def test_encrypted(self):
        enc = cipher.encrypt(MESSAGE, "РЯЗАНЦЕВА")
        stego.hide_message(self.cover, enc, self.out)
        self.assertNotEqual(stego.extract_message(self.out), MESSAGE)
        self.assertEqual(cipher.decrypt(stego.extract_message(self.out), "РЯЗАНЦЕВА"), MESSAGE)

    def test_chi_square_detects_random_payload(self):
        cap = stego.capacity(Image.open(self.cover))
        stego.hide_bytes(self.cover, os.urandom(cap), self.out)
        self.assertGreater(A.chi_square_attack(self.out)[0]["p_hidden"], 0.5)

    def test_strip_metadata(self):
        img = Image.open(self.cover)
        exif = Image.Exif()
        exif[0x010F] = "TestCamera"                 # Make
        jpg = os.path.join(self.dir, "photo.jpg")
        img.save(jpg, exif=exif)
        self.assertIn("Make", A.read_exif(jpg))
        clean = A.strip_metadata(jpg, os.path.join(self.dir, "clean.jpg"))
        self.assertEqual(A.read_exif(clean)["Кількість тегів EXIF"], "0")


if __name__ == "__main__":
    unittest.main()
