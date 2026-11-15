"""
Консольна демонстрація ЛР3: усі етапи без графічного інтерфейсу.
Результати зберігаються в папку results/.

Запуск:  python demo.py                 (без EXIF)
         python demo.py IMG_5079.HEIC   (+ аналіз метаданих власного фото)
"""
import json
import os
import sys
from pathlib import Path

from PIL import Image

import stego
import cipher
import analysis as A

HERE = Path(__file__).parent
IMG, RES = HERE / "images", HERE / "results"
MESSAGE = "Рязанцева Олександра Сергіївна, 16.05.2006"
KEY = "РЯЗАНЦЕВА"


def main():
    RES.mkdir(exist_ok=True)
    cover, st = str(IMG / "cover.png"), str(IMG / "stego.png")
    report = {}

    # Етап 1-3: приховування та витягування власних даних
    print("1) Покроково:")
    for r in stego.explain(MESSAGE, cover, 6):
        print(f"   {r['pixel']}: {r['old_bin']} + біт {r['bit']} -> {r['new_bin']}")
    info = stego.hide_message(cover, MESSAGE, st)
    out = stego.extract_message(st)
    print("2) Сховано:", info, "\n   Витягнуто:", out, "| збіг:", out == MESSAGE)
    report["hide"] = {**info, "message": MESSAGE, "extracted": out}

    # зашифрований варіант
    enc = cipher.encrypt(MESSAGE, KEY)
    stego.hide_message(cover, enc, str(IMG / "stego_encrypted.png"))
    got = stego.extract_message(str(IMG / "stego_encrypted.png"))
    report["encrypted"] = {"hidden": enc, "decrypted": cipher.decrypt(got, KEY)}
    print("   Зашифровано Віженером:", enc)

    # Етап 4: аналіз змін
    cmp = A.compare(cover, st)
    report["compare"] = cmp
    print("3) Порівняння:", {k: round(v, 4) if isinstance(v, float) else v for k, v in cmp.items()})
    A.diff_map(cover, st, str(RES / "diff_map.png"))
    A.diff_map(cover, st, str(RES / "diff_map_zoom.png"), zoom_rows=20)

    # JPEG знищує повідомлення
    Image.open(st).save(RES / "stego_as_jpeg.jpg", quality=95)
    try:
        stego.extract_message(str(RES / "stego_as_jpeg.jpg"))
        jpeg = "повідомлення збереглось"
    except (ValueError, UnicodeDecodeError) as e:
        jpeg = f"повідомлення знищено: {e}"
    report["jpeg_test"] = jpeg
    print("4) Після збереження в JPEG:", jpeg)

    # Пошук прихованого: атака χ² на чисте фото, наш стего і великий випадковий вміст
    test = str(IMG / "test_random_50.png")
    Image.open(cover).crop((0, 0, 600, 600)).save(RES / "_crop.png")
    cap = stego.capacity(Image.open(RES / "_crop.png"))
    stego.hide_bytes(str(RES / "_crop.png"), os.urandom(cap // 2), test)
    os.remove(RES / "_crop.png")
    report["chi_square"] = {}
    for name, path in (("cover", cover), ("stego", st), ("test_random_50", test)):
        rows = A.chi_square_attack(path)
        report["chi_square"][name] = rows
        A.lsb_plane(path, str(RES / f"lsb_{name}.png"))
        print(f"5) χ² {name}:", [r["p_hidden"] for r in rows])

    # EXIF власного фото
    if len(sys.argv) > 1:
        photo = sys.argv[1]
        before = A.read_exif(photo)
        clean = A.strip_metadata(photo, str(RES / (Path(photo).stem + "_clean.jpg")))
        after = A.read_exif(clean)
        report["exif"] = {"before": before, "after": after}
        print("6) EXIF до:", before, "\n   EXIF після:", after)

    (RES / "demo.json").write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                              default=str), encoding="utf-8")
    print("\nГотово, результати в папці results/")


if __name__ == "__main__":
    main()
