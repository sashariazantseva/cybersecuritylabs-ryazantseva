"""
ЛР3 "Невидимі дані у власних файлах" - LSB-стеганографія.
Автор: Рязанцева О.С., гр. 6.04.122.010.23.3

Ідея: кожен піксель має три канали (R, G, B) від 0 до 255.
Молодший біт (LSB) майже не впливає на колір: 200 і 201 оком не розрізнити.
Тому в молодші біти можна записати біти повідомлення.

Формат прихованих даних:
    START (4 байти) + текст у UTF-8 + END (4 байти)
Маркери потрібні, щоб при витягуванні знати, де починається і де закінчується повідомлення.

Бібліотека Pillow використовується тільки для читання/запису пікселів,
логіка приховування написана самостійно.
"""
from PIL import Image

START = b"ST3G"          # маркер початку
END = b"\x00END"         # маркер кінця (0-байт не трапляється у звичайному тексті)
CHANNELS = {"R": 0, "G": 1, "B": 2}


# ------------------------------------------------- текст <-> біти
def text_to_bits(text: str) -> list[int]:
    """'Ря' -> байти UTF-8 -> список бітів [1,1,0,1,0,0,0,0, ...]"""
    bits = []
    for byte in text.encode("utf-8"):
        for i in range(7, -1, -1):          # від старшого біта до молодшого
            bits.append((byte >> i) & 1)
    return bits


def bytes_to_bits(data: bytes) -> list[int]:
    return [(b >> i) & 1 for b in data for i in range(7, -1, -1)]


def bits_to_bytes(bits: list[int]) -> bytes:
    """Кожні 8 бітів складаємо назад в один байт."""
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


# ---------------------------------------------------------- місткість
def capacity(img: Image.Image, channels: str = "RGB") -> int:
    """Скільки байтів тексту можна сховати (без маркерів)."""
    total_bits = img.width * img.height * len(channels)
    return total_bits // 8 - len(START) - len(END)


def _positions(img: Image.Image, channels: str):
    """Порядок запису: піксель за пікселем зліва направо, зверху вниз,
    у кожному пікселі - обрані канали."""
    idx = [CHANNELS[c] for c in channels]
    for y in range(img.height):
        for x in range(img.width):
            for c in idx:
                yield x, y, c


# ------------------------------------------------------- приховування
def hide_message(image_path: str, message: str, output_path: str,
                 channels: str = "RGB") -> dict:
    """Ховає текст у молодші біти пікселів і зберігає результат у PNG."""
    if not output_path.lower().endswith(".png"):
        raise ValueError("Зберігати треба у PNG: JPEG стискає зображення і знищує молодші біти")
    return hide_bytes(image_path, message.encode("utf-8"), output_path, channels)


def hide_bytes(image_path: str, payload: bytes, output_path: str,
               channels: str = "RGB") -> dict:
    """Те саме для довільних байтів (використовується для тесту атаки χ²)."""
    img = Image.open(image_path).convert("RGB")
    data = START + payload + END
    bits = bytes_to_bits(data)
    if len(bits) > img.width * img.height * len(channels):
        raise ValueError(f"Повідомлення завелике: максимум {capacity(img, channels)} байтів")

    pixels = img.load()
    changed = 0
    for bit, (x, y, c) in zip(bits, _positions(img, channels)):
        px = list(pixels[x, y])
        new_value = (px[c] & 0b11111110) | bit     # обнуляємо LSB і записуємо біт
        if new_value != px[c]:
            changed += 1
        px[c] = new_value
        pixels[x, y] = tuple(px)
    img.save(output_path, "PNG")
    return {"bits": len(bits), "changed_values": changed,
            "pixels_used": -(-len(bits) // len(channels)),
            "capacity_bytes": capacity(img, channels)}


# -------------------------------------------------------- витягування
def extract_message(image_path: str, channels: str = "RGB") -> str:
    """Читає молодші біти, шукає маркери START ... END і повертає текст."""
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()
    buf = bytearray()
    byte, n = 0, 0
    for x, y, c in _positions(img, channels):
        byte = (byte << 1) | (pixels[x, y][c] & 1)    # беремо тільки LSB
        n += 1
        if n == 8:
            buf.append(byte)
            byte, n = 0, 0
            if len(buf) == len(START) and bytes(buf) != START:
                raise ValueError("Маркер початку не знайдено: у файлі немає повідомлення")
            if buf.endswith(END) and len(buf) >= len(START) + len(END):
                return buf[len(START):-len(END)].decode("utf-8")
    raise ValueError("Маркер кінця не знайдено")


# ------------------------------------------- покрокова демонстрація
def explain(message: str, image_path: str, count: int = 8) -> list[dict]:
    """Показує, що відбувається з першими значеннями каналів (для звіту й GUI)."""
    img = Image.open(image_path).convert("RGB")
    bits = bytes_to_bits(START + message.encode("utf-8") + END)
    rows = []
    for i, (x, y, c) in enumerate(_positions(img, "RGB")):
        if i >= count:
            break
        old = img.getpixel((x, y))[c]
        new = (old & 0b11111110) | bits[i]
        rows.append({"pixel": f"({x},{y}) {'RGB'[c]}", "old": old, "old_bin": f"{old:08b}",
                     "bit": bits[i], "new": new, "new_bin": f"{new:08b}"})
    return rows
