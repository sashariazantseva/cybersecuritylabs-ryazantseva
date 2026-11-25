"""
ЛР4 "Особистий цифровий підпис" - спрощена система цифрових підписів на основі RSA.
Автор: Рязанцева О.С., гр. 6.04.122.010.23.3

Як це працює:
  1. З ПІБ + дати народження + секретного слова рахується SHA-256 - це "зерно".
  2. Із зерна генеруються два великі прості числа p і q (по 1024 біти).
  3. Публічний ключ: (n, e), де n = p*q, e = 65537.
     Приватний ключ: d, таке що e*d = 1 (mod (p-1)(q-1)).
  4. Підпис:   s = H^d mod n      (H - хеш документа як число)
     Перевірка: s^e mod n == H     (якщо збігається - підпис дійсний)

Без d (приватного ключа) підробити s неможливо, а d неможливо отримати з (n, e),
бо для цього треба розкласти n на p і q.

Бібліотека hashlib використовується тільки для хеш-функцій,
генерація простих чисел і RSA написані самостійно.
"""
import hashlib
import json
from datetime import datetime
from pathlib import Path

HASHES = {
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
    "SHA3-256": hashlib.sha3_256,
    "BLAKE2b": hashlib.blake2b,
}
E = 65537
BITS = 1024                       # розмір кожного простого числа


# ------------------------------------------------------------- хешування
def hash_bytes(data: bytes, algo: str = "SHA-256") -> str:
    return HASHES[algo](data).hexdigest()


def hash_file(path: str, algo: str = "SHA-256") -> str:
    return hash_bytes(Path(path).read_bytes(), algo)


# ---------------------------------------------- генерація простих чисел
def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Тест Міллера-Рабіна (власна реалізація)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for i in range(rounds):
        a = 2 + int.from_bytes(hashlib.sha256(f"{n}:{i}".encode()).digest(), "big") % (n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_from_seed(seed: bytes, label: str, bits: int) -> int:
    """Детерміноване "випадкове" число з зерна: однакові дані -> однаковий ключ."""
    out, counter = b"", 0
    while len(out) * 8 < bits:
        out += hashlib.sha256(seed + label.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    num = int.from_bytes(out, "big") >> (len(out) * 8 - bits)
    return num | (1 << (bits - 1)) | 1          # старший біт = 1, число непарне


def _prime_from_seed(seed: bytes, label: str, bits: int) -> int:
    n = _random_from_seed(seed, label, bits)
    while not (_is_probable_prime(n) and (n - 1) % E != 0):
        n += 2
    return n


def mod_inverse(a: int, m: int) -> int:
    """Обернене число за модулем (розширений алгоритм Евкліда)."""
    old_r, r, old_s, s = a, m, 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError("Оберненого числа не існує")
    return old_s % m


# --------------------------------------------------------- пара ключів
def generate_keys(full_name: str, dob: str, secret: str) -> dict:
    """Пара ключів з персональних даних. Без секретного слова її не відтворити."""
    if not secret:
        raise ValueError("Секретне слово не може бути порожнім")
    datetime.strptime(dob, "%d.%m.%Y")         # перевірка дати
    seed = hashlib.sha256(f"{full_name}|{dob}|{secret}".encode("utf-8")).digest()
    p = _prime_from_seed(seed, "p", BITS)
    q = _prime_from_seed(seed, "q", BITS)
    n = p * q
    d = mod_inverse(E, (p - 1) * (q - 1))
    public = {"owner": full_name, "n": n, "e": E}
    private = {"owner": full_name, "n": n, "d": d}
    return {"public": public, "private": private, "seed": seed.hex()}


def fingerprint(public: dict) -> str:
    """Відбиток публічного ключа - коротка "назва" ключа, як у GPG."""
    h = hashlib.sha256(f"{public['n']}:{public['e']}".encode()).hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def save_key(key: dict, path: str) -> None:
    data = {k: (hex(v) if isinstance(v, int) and v > 1 << 64 else v) for k, v in key.items()}
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_key(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: (int(v, 16) if isinstance(v, str) and v.startswith("0x") else v) for k, v in data.items()}


# ------------------------------------------------------- підпис і перевірка
def sign_hash(hash_hex: str, private: dict) -> int:
    """s = H^d mod n - "шифрування" хешу приватним ключем."""
    h = int(hash_hex, 16)
    if h >= private["n"]:
        raise ValueError("Хеш більший за модуль ключа")
    return pow(h, private["d"], private["n"])


def recover_hash(signature: int, public: dict) -> int:
    """s^e mod n - "розшифрування" підпису публічним ключем."""
    return pow(signature, public["e"], public["n"])


def sign_file(path: str, private: dict, algo: str = "SHA-256", sig_path: str | None = None) -> dict:
    h = hash_file(path, algo)
    s = sign_hash(h, private)
    sig = {
        "document": Path(path).name,
        "signer": private["owner"],
        "algorithm": algo,
        "hash": h,
        "signature": hex(s),
        "signed_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
    }
    sig_path = sig_path or str(path) + ".sig"
    Path(sig_path).write_text(json.dumps(sig, ensure_ascii=False, indent=2), encoding="utf-8")
    sig["sig_path"] = sig_path
    return sig


def verify_file(path: str, sig_path: str, public: dict) -> dict:
    """Перевіряє, чи документ не змінено і чи підпис зроблено власником ключа."""
    sig = json.loads(Path(sig_path).read_text(encoding="utf-8"))
    current = hash_file(path, sig["algorithm"])
    recovered = recover_hash(int(sig["signature"], 16), public)
    valid = recovered == int(current, 16)
    return {
        "valid": valid,
        "algorithm": sig["algorithm"],
        "current_hash": current,
        "recovered_hash": f"{recovered:0{len(current)}x}"[-len(current):] if recovered < 1 << (4 * len(current)) else hex(recovered)[:len(current) + 2] + "…",
        "signer": sig["signer"],
        "signed_at": sig["signed_at"],
        "verdict": "Підпис ДІЙСНИЙ" if valid else "Підпис ПІДРОБЛЕНИЙ або документ змінено",
    }


# ------------------------------------------------- лавинний ефект хешу
def bit_difference(h1: str, h2: str) -> int:
    """Скільки бітів відрізняється у двох хешах однакової довжини."""
    return bin(int(h1, 16) ^ int(h2, 16)).count("1")
