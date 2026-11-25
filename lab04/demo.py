"""
Консольна демонстрація ЛР4.  Запуск:  python demo.py
Секретне слово вводиться з клавіатури і ніде не зберігається.
"""
import json
import sys
from getpass import getpass
from pathlib import Path

import signature as S
import forgery

HERE = Path(__file__).parent
NAME = "Рязанцева Олександра Сергіївна"
DOB = "16.05.2006"


def main(secret: str):
    keys = S.generate_keys(NAME, DOB, secret)
    (HERE / "keys").mkdir(exist_ok=True)
    S.save_key(keys["public"], HERE / "keys" / "public_key.json")
    S.save_key(keys["private"], HERE / "keys" / "private_key.json")
    print("Ключі згенеровано. Відбиток:", S.fingerprint(keys["public"]))
    report = {"fingerprint": S.fingerprint(keys["public"]), "n_bits": keys["public"]["n"].bit_length(),
              "signed": [], "forgery": {}}

    for doc in sorted((HERE / "documents").iterdir()):
        if doc.suffix == ".sig" or "_змінене" in doc.stem:
            continue
        sig = S.sign_file(str(doc), keys["private"], "SHA-256")
        res = S.verify_file(str(doc), sig["sig_path"], keys["public"])
        print(f"{doc.name}: хеш {sig['hash'][:16]}…  ->  {res['verdict']}")
        report["signed"].append({"document": doc.name, "hash": sig["hash"], "valid": res["valid"]})
        rows = forgery.run_all(str(doc), sig["sig_path"], keys["public"], NAME, DOB,
                               str(HERE / "results" / "forgery"))
        report["forgery"][doc.name] = rows
        for r in rows:
            print(f"   {r['Сценарій']:18} {r['Результат']:12} {'✔' if r['ok'] else '✘'}")

    cv = HERE / "documents" / "Резюме_Рязанцева.pdf"
    for algo in S.HASHES:
        S.sign_file(str(cv), keys["private"], algo, str(HERE / "results" / f"resume_{algo}.sig"))
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "demo.json").write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                                encoding="utf-8")
    # для наступних запусків залишаємо стандартний підпис SHA-256
    S.sign_file(str(cv), keys["private"], "SHA-256")
    print("Готово, результати в results/")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else getpass("Секретне слово: "))
