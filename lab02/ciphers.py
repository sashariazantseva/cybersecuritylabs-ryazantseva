"""
ЛР2 «Захист особистих повідомлень» — власна реалізація класичних шифрів.
Автор: Рязанцева Олександра Сергіївна, гр. 6.04.122.010.23.3

Модуль містить:
  * два алфавіти: український (33 літери) та латинський (26 літер);
  * шифр Цезаря, шифр Віженера та афінний шифр (шифрування + розшифрування);
  * генерацію ключів з персональних даних (ПІБ та дата народження).

Готові криптобібліотеки НЕ використовуються — уся логіка написана вручну.
Символи, яких немає в алфавіті (пробіли, цифри, розділові знаки), не змінюються.
"""
from datetime import datetime
from math import gcd

# ---------------------------------------------------------------- алфавіти
UA = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"   # 33 літери
EN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"          # 26 літер
ALPHABETS = {"ua": UA, "en": EN}


def get_alphabet(name: str) -> str:
    """Повертає рядок алфавіту за назвою 'ua' або 'en'."""
    if name not in ALPHABETS:
        raise ValueError("Алфавіт має бути 'ua' або 'en'")
    return ALPHABETS[name]


def detect_alphabet(text: str) -> str:
    """Визначає, яких літер у тексті більше — кириличних чи латинських."""
    ua = sum(ch.upper() in UA for ch in text)
    en = sum(ch.upper() in EN for ch in text)
    return "ua" if ua >= en else "en"


def _shift_char(ch: str, shift: int, alphabet: str) -> str:
    """Зсуває одну літеру на shift позицій по колу, зберігаючи регістр."""
    upper = ch.upper()
    if upper not in alphabet:
        return ch                       # не літера алфавіту — без змін
    new = alphabet[(alphabet.index(upper) + shift) % len(alphabet)]
    return new if ch.isupper() else new.lower()


# ------------------------------------------------------------ шифр Цезаря
# Формула: C = (P + k) mod N,  P = (C - k) mod N
def caesar_encrypt(text: str, shift: int, alpha: str = "ua") -> str:
    alphabet = get_alphabet(alpha)
    return "".join(_shift_char(ch, shift, alphabet) for ch in text)


def caesar_decrypt(text: str, shift: int, alpha: str = "ua") -> str:
    return caesar_encrypt(text, -shift, alpha)


# ---------------------------------------------------------- шифр Віженера
# Формула: C[i] = (P[i] + K[j mod L]) mod N, де j — номер ЛІТЕРИ в тексті.
# Ключ просувається лише на літерах (як на сайті Cryptii).
def _vigenere(text: str, key: str, alpha: str, sign: int) -> str:
    alphabet = get_alphabet(alpha)
    key = key.upper()
    if not key or any(k not in alphabet for k in key):
        raise ValueError("Ключ має складатися лише з літер обраного алфавіту")
    shifts = [alphabet.index(k) for k in key]   # ключ -> список зсувів
    result, j = [], 0
    for ch in text:
        if ch.upper() in alphabet:
            result.append(_shift_char(ch, sign * shifts[j % len(shifts)], alphabet))
            j += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_encrypt(text: str, key: str, alpha: str = "ua") -> str:
    return _vigenere(text, key, alpha, +1)


def vigenere_decrypt(text: str, key: str, alpha: str = "ua") -> str:
    return _vigenere(text, key, alpha, -1)


# ------------------------------------------------------------ афінний шифр
# Формула: C = (a*P + b) mod N,  P = a^(-1) * (C - b) mod N
# Умова: НСД(a, N) = 1, інакше розшифрування неможливе.
def mod_inverse(a: int, n: int) -> int:
    """Обернене за модулем число: a * x ≡ 1 (mod n). Розширений алгоритм Евкліда."""
    old_r, r, old_s, s = a % n, n, 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError(f"a={a} не взаємно просте з N={n}: оберненого немає")
    return old_s % n


def _affine_char(ch: str, func, alphabet: str) -> str:
    upper = ch.upper()
    if upper not in alphabet:
        return ch
    new = alphabet[func(alphabet.index(upper)) % len(alphabet)]
    return new if ch.isupper() else new.lower()


def affine_encrypt(text: str, a: int, b: int, alpha: str = "ua") -> str:
    alphabet = get_alphabet(alpha)
    n = len(alphabet)
    mod_inverse(a, n)                   # перевірка коректності ключа
    return "".join(_affine_char(ch, lambda p: a * p + b, alphabet) for ch in text)


def affine_decrypt(text: str, a: int, b: int, alpha: str = "ua") -> str:
    alphabet = get_alphabet(alpha)
    n = len(alphabet)
    a_inv = mod_inverse(a, n)
    return "".join(_affine_char(ch, lambda c: a_inv * (c - b), alphabet) for ch in text)


# ---------------------------------------------- ключі з персональних даних
def parse_dob(dob: str) -> datetime:
    """Перевіряє дату у форматі ДД.ММ.РРРР (у т.ч. що така дата існує)."""
    try:
        return datetime.strptime(dob.strip(), "%d.%m.%Y")
    except ValueError:
        raise ValueError("Дата має бути у форматі ДД.ММ.РРРР") from None


def caesar_key(dob: str, alpha: str = "ua") -> int:
    """Зсув Цезаря = сума цифр дати народження mod N (0 замінюємо на 1)."""
    parse_dob(dob)
    n = len(get_alphabet(alpha))
    shift = sum(int(d) for d in dob if d.isdigit()) % n
    return shift or 1


# Транслітерація за постановою КМУ №55 (2010) — для латинської версії ключа
_TRANSLIT = {
    "А": "A", "Б": "B", "В": "V", "Г": "H", "Ґ": "G", "Д": "D", "Е": "E",
    "Є": "IE", "Ж": "ZH", "З": "Z", "И": "Y", "І": "I", "Ї": "I", "Й": "I",
    "К": "K", "Л": "L", "М": "M", "Н": "N", "О": "O", "П": "P", "Р": "R",
    "С": "S", "Т": "T", "У": "U", "Ф": "F", "Х": "KH", "Ц": "TS", "Ч": "CH",
    "Ш": "SH", "Щ": "SHCH", "Ь": "", "Ю": "IU", "Я": "IA", "'": "", "’": "",
}
_TRANSLIT_FIRST = {"Є": "YE", "Ї": "YI", "Й": "Y", "Ю": "YU", "Я": "YA"}


def transliterate(word: str) -> str:
    """Рязанцева -> RIAZANTSEVA (на початку слова Я -> YA, всередині -> IA)."""
    out = []
    for i, ch in enumerate(word.upper()):
        table = _TRANSLIT_FIRST if i == 0 and ch in _TRANSLIT_FIRST else _TRANSLIT
        out.append(table.get(ch, ch))
    return "".join(out)


def vigenere_key(full_name: str, alpha: str = "ua") -> str:
    """Ключ Віженера = прізвище (перше слово ПІБ) у потрібному алфавіті."""
    surname = full_name.split()[0].upper()
    key = surname if alpha == "ua" else transliterate(surname)
    alphabet = get_alphabet(alpha)
    return "".join(ch for ch in key if ch in alphabet)


def affine_key(dob: str, alpha: str = "ua") -> tuple[int, int]:
    """a = місяць народження (якщо не взаємно простий з N — беремо наступне число),
    b = день народження mod N."""
    d = parse_dob(dob)
    n = len(get_alphabet(alpha))
    a = d.month
    while gcd(a, n) != 1 or a == 1:      # a=1 перетворює шифр на звичайний Цезар
        a += 1
    return a, d.day % n


def personal_keys(full_name: str, dob: str, alpha: str = "ua") -> dict:
    """Усі ключі однією структурою — зручно для GUI, звіту й тестів."""
    a, b = affine_key(dob, alpha)
    return {
        "caesar": caesar_key(dob, alpha),
        "vigenere": vigenere_key(full_name, alpha),
        "affine": (a, b),
    }


def encrypt_all(text: str, keys: dict, alpha: str = "ua") -> dict:
    """Шифрує текст трьома методами й одразу перевіряє розшифрування."""
    a, b = keys["affine"]
    enc = {
        "Цезар": caesar_encrypt(text, keys["caesar"], alpha),
        "Віженер": vigenere_encrypt(text, keys["vigenere"], alpha),
        "Афінний": affine_encrypt(text, a, b, alpha),
    }
    dec = {
        "Цезар": caesar_decrypt(enc["Цезар"], keys["caesar"], alpha),
        "Віженер": vigenere_decrypt(enc["Віженер"], keys["vigenere"], alpha),
        "Афінний": affine_decrypt(enc["Афінний"], a, b, alpha),
    }
    return {name: {"cipher": enc[name], "restored": dec[name],
                   "ok": dec[name] == text} for name in enc}
