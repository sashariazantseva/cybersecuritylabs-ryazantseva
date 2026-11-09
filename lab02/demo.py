"""
Консольна демонстрація ЛР2 (без GUI): друкує всі результати та зберігає їх
у папку results/ (JSON, CSV, PNG-графік).

Запуск:  python demo.py
"""
import csv
import json
from pathlib import Path

from matplotlib.figure import Figure

import ciphers as C
import analysis as A
from app import NAME, DOB, TEXT_UA, TEXT_EN, draw_frequency_chart

OUT = Path(__file__).parent / "results"


def run(alpha: str, text: str) -> dict:
    keys = C.personal_keys(NAME, DOB, alpha)
    res = C.encrypt_all(text, keys, alpha)
    table = A.compare(text, res, keys, alpha)
    brute = A.brute_force_caesar(res["Цезар"]["cipher"], alpha)

    print(f"\n=== Алфавіт {alpha.upper()} ({len(C.get_alphabet(alpha))} літер) ===")
    print("Ключі:", keys)
    print("Текст:", text)
    for name, r in res.items():
        print(f"{name:8} | {r['cipher']}  | відновлено: {r['ok']}")
    print("\nПорівняння:")
    for row in table:
        print("  ", row)
    print(f"\nBrute force: найкращий зсув {brute[0]['shift']} (χ²={brute[0]['chi2']})")

    fig = Figure(figsize=(10, 5.6), dpi=120)
    draw_frequency_chart(fig, text, res, alpha)
    fig.savefig(OUT / f"frequency_{alpha}.png")

    with open(OUT / f"brute_force_{alpha}.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["shift", "chi2", "text"])
        w.writeheader()
        w.writerows(sorted(brute, key=lambda r: r["shift"]))

    return {"keys": {**keys, "affine": list(keys["affine"])}, "text": text,
            "results": res, "comparison": table,
            "brute_force_best": brute[0]}


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    print("Автор:", NAME, "| гр. 6.04.122.010.23.3")
    data = {"author": NAME, "ua": run("ua", TEXT_UA), "en": run("en", TEXT_EN)}
    # Вправа з Cryptii (крок 1.2): ім'я латиницею, Цезар зі зсувом 7
    latin_name = " ".join(C.transliterate(w) for w in NAME.split())
    data["cryptii_name"] = {"text": latin_name, "shift": 7,
                            "cipher": C.caesar_encrypt(latin_name, 7, "en")}
    print("\nCryptii, крок 1.2:", data["cryptii_name"])
    (OUT / "demo.json").write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
    print("\nРезультати збережено у папці results/")
