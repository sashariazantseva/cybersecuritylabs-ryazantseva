"""
Шифр Віженера з ЛР2 - для шифрування тексту ПЕРЕД приховуванням.
Навіть якщо хтось знайде приховані біти, без ключа він побачить лише набір літер.
"""
UA = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"


def _vigenere(text: str, key: str, sign: int) -> str:
    key = key.upper()
    if not key or any(k not in UA for k in key):
        raise ValueError("Ключ має складатися з українських літер")
    shifts = [UA.index(k) for k in key]
    out, j = [], 0
    for ch in text:
        up = ch.upper()
        if up in UA:
            new = UA[(UA.index(up) + sign * shifts[j % len(shifts)]) % len(UA)]
            out.append(new if ch.isupper() else new.lower())
            j += 1                       # ключ просувається лише на літерах
        else:
            out.append(ch)
    return "".join(out)


def encrypt(text: str, key: str) -> str:
    return _vigenere(text, key, +1)


def decrypt(text: str, key: str) -> str:
    return _vigenere(text, key, -1)
