"""
Самообмін повідомленнями (крок 3.2–3.4 ЛР2).

Одногрупника для обміну не було, тому обмін змодельовано в дві окремі ролі:

  ВІДПРАВНИК  python self_exchange.py send ["текст"]
      шифрує повідомлення Цезарем з ВИПАДКОВИМ зсувом (не з моєї дати!),
      у файл ciphertext.txt записує ЛИШЕ шифротекст, а ключ і хеш оригіналу
      ховає окремо в sender_secret.json (його отримувач не відкриває).

  ОТРИМУВАЧ   у програмі app.py → вкладка «Обмін» → «Відкрити файл…»
      → ciphertext.txt → «Зламати». Ключ програма знаходить сама.

  ПЕРЕВІРКА   python self_exchange.py check "розшифрований текст"
      порівнює SHA-256 розшифрованого тексту з хешем оригіналу.
"""
import hashlib
import json
import secrets
import sys
from pathlib import Path

import ciphers as C

DIR = Path(__file__).parent / "results" / "self_exchange"
DEFAULT_MSG = ("Зустріч перенесено на четвер о п'ятнадцятій годині біля "
               "головного корпусу університету. Ключ до цього повідомлення не передається.")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def send(message: str) -> None:
    alpha = C.detect_alphabet(message)
    n = len(C.get_alphabet(alpha))
    shift = secrets.randbelow(n - 1) + 1          # випадковий зсув 1..N-1
    cipher = C.caesar_encrypt(message, shift, alpha)
    DIR.mkdir(parents=True, exist_ok=True)
    (DIR / "ciphertext.txt").write_text(cipher, encoding="utf-8")
    (DIR / "sender_secret.json").write_text(json.dumps(
        {"shift": shift, "alphabet": alpha, "sha256_original": sha256(message)},
        ensure_ascii=False, indent=2), encoding="utf-8")
    print("Відправник: шифротекст збережено у", DIR / "ciphertext.txt")
    print("Шифротекст:", cipher)
    print("Ключ НЕ показується — він лише у sender_secret.json")


def check(decrypted: str) -> None:
    secret = json.loads((DIR / "sender_secret.json").read_text(encoding="utf-8"))
    ok = sha256(decrypted) == secret["sha256_original"]
    print("Справжній зсув відправника:", secret["shift"])
    print("Розшифрування збігається з оригіналом:", "ТАК ✔" if ok else "НІ ✘")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "send":
        send(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MSG)
    elif len(sys.argv) >= 3 and sys.argv[1] == "check":
        check(sys.argv[2])
    else:
        print(__doc__)
