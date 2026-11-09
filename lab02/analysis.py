"""
Криптоаналіз і порівняння шифрів для ЛР2.

  * частоти літер у тексті;
  * індекс збігів (Index of Coincidence) — числова міра «нерівномірності» тексту;
  * brute force шифру Цезаря + автоматичний вибір кандидата методом хі-квадрат
    (порівняння частот кандидата з типовими частотами мови);
  * таблиця порівняння алгоритмів.
"""
from math import gcd
from ciphers import get_alphabet, caesar_decrypt

# Наближені частоти літер (%) у текстах українською та англійською мовами
FREQ_UA = {
    "А": 7.2, "Б": 1.7, "В": 5.2, "Г": 1.6, "Ґ": 0.01, "Д": 3.5, "Е": 1.7,
    "Є": 0.8, "Ж": 0.9, "З": 2.3, "И": 6.1, "І": 5.7, "Ї": 0.6, "Й": 0.8,
    "К": 3.5, "Л": 3.6, "М": 3.1, "Н": 6.5, "О": 9.4, "П": 2.9, "Р": 4.7,
    "С": 4.1, "Т": 5.5, "У": 4.0, "Ф": 0.3, "Х": 1.2, "Ц": 1.0, "Ч": 1.8,
    "Ш": 0.9, "Щ": 0.5, "Ь": 2.9, "Ю": 0.4, "Я": 3.0,
}
FREQ_EN = {
    "A": 8.2, "B": 1.5, "C": 2.8, "D": 4.3, "E": 12.7, "F": 2.2, "G": 2.0,
    "H": 6.1, "I": 7.0, "J": 0.15, "K": 0.77, "L": 4.0, "M": 2.4, "N": 6.7,
    "O": 7.5, "P": 1.9, "Q": 0.1, "R": 6.0, "S": 6.3, "T": 9.1, "U": 2.8,
    "V": 1.0, "W": 2.4, "X": 0.15, "Y": 2.0, "Z": 0.07,
}
LANG_FREQ = {"ua": FREQ_UA, "en": FREQ_EN}


def letter_counts(text: str, alpha: str = "ua") -> dict:
    """Скільки разів трапляється кожна літера алфавіту."""
    alphabet = get_alphabet(alpha)
    counts = {ch: 0 for ch in alphabet}
    for ch in text.upper():
        if ch in counts:
            counts[ch] += 1
    return counts


def letter_freq(text: str, alpha: str = "ua") -> dict:
    """Частоти літер у відсотках."""
    counts = letter_counts(text, alpha)
    total = sum(counts.values()) or 1
    return {ch: 100 * c / total for ch, c in counts.items()}


def index_of_coincidence(text: str, alpha: str = "ua") -> float:
    """IC = Σ n_i(n_i-1) / (L(L-1)). Звичайний текст ≈ 0.055–0.067,
    випадковий набір літер ≈ 1/N (0.030 для UA, 0.038 для EN)."""
    counts = letter_counts(text, alpha).values()
    total = sum(counts)
    if total < 2:
        return 0.0
    return sum(c * (c - 1) for c in counts) / (total * (total - 1))


def chi_squared(text: str, alpha: str = "ua") -> float:
    """Наскільки частоти тексту відрізняються від типових для мови.
    Чим МЕНШЕ значення — тим більше текст схожий на справжню мову."""
    counts = letter_counts(text, alpha)
    total = sum(counts.values())
    if total == 0:
        return float("inf")
    expected = LANG_FREQ[alpha]
    score = 0.0
    for ch, observed in counts.items():
        exp = total * expected[ch] / 100
        score += (observed - exp) ** 2 / exp
    return score


def brute_force_caesar(cipher: str, alpha: str = "ua") -> list[dict]:
    """Перебирає ВСІ можливі зсуви (1..N-1) і оцінює кожного кандидата.
    Повертає список, відсортований від найімовірнішого до найменш імовірного."""
    n = len(get_alphabet(alpha))
    rows = []
    for shift in range(1, n):
        candidate = caesar_decrypt(cipher, shift, alpha)
        rows.append({"shift": shift, "text": candidate,
                     "chi2": round(chi_squared(candidate, alpha), 1)})
    return sorted(rows, key=lambda r: r["chi2"])


def crack_caesar(cipher: str, alpha: str = "ua") -> dict:
    """Автоматичний злам без ключа: найкращий кандидат за хі-квадрат."""
    return brute_force_caesar(cipher, alpha)[0]


def key_space(alpha: str, vigenere_len: int) -> dict:
    """Кількість можливих ключів для кожного шифру."""
    n = len(get_alphabet(alpha))
    phi = sum(1 for a in range(1, n) if gcd(a, n) == 1)   # кількість допустимих a
    return {
        "Цезар": n - 1,
        "Віженер": n ** vigenere_len,
        "Афінний": phi * n - 1,
    }


def changed_letters(plain: str, cipher: str) -> float:
    """Частка літер, які змінилися після шифрування (%)."""
    pairs = [(p, c) for p, c in zip(plain, cipher) if p.isalpha()]
    if not pairs:
        return 0.0
    return 100 * sum(p != c for p, c in pairs) / len(pairs)


def compare(plain: str, results: dict, keys: dict, alpha: str = "ua") -> list[dict]:
    """Порівняльна таблиця для звіту та GUI."""
    space = key_space(alpha, len(keys["vigenere"]))
    key_text = {
        "Цезар": f"зсув {keys['caesar']}",
        "Віженер": keys["vigenere"],
        "Афінний": "a={}, b={}".format(*keys["affine"]),
    }
    rows = [{"Метод": "Відкритий текст", "Ключ": "—", "Довжина": len(plain),
             "IC": round(index_of_coincidence(plain, alpha), 4),
             "Змінено літер, %": 0, "Кількість ключів": "—"}]
    for name, r in results.items():
        rows.append({
            "Метод": name,
            "Ключ": key_text[name],
            "Довжина": len(r["cipher"]),
            "IC": round(index_of_coincidence(r["cipher"], alpha), 4),
            "Змінено літер, %": round(changed_letters(plain, r["cipher"]), 1),
            "Кількість ключів": f"{space[name]:,}".replace(",", " "),
        })
    return rows
