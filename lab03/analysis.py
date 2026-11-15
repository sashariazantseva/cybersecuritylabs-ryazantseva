"""
Аналіз стегоконтейнера та пошук прихованих даних.

  * compare()        - чим стегоконтейнер відрізняється від оригіналу
  * diff_map()       - карта відмінностей (змінені пікселі підсвічуються)
  * lsb_plane()      - зображення з молодших бітів (видно, де є "шум")
  * chi_square_attack() - статистична атака Вестфельда на LSB
  * read_exif() / strip_metadata() - метадані фото та їх очищення
"""
import math
import os

import numpy as np
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

try:                                    # HEIC (фото з iPhone) - якщо встановлено pillow-heif
    import pillow_heif
    pillow_heif.register_heif_opener()
except ImportError:
    pass


def load(path: str) -> np.ndarray:
    return np.asarray(Image.open(path).convert("RGB"), dtype=np.int16)


# ------------------------------------------------------- порівняння
def compare(original: str, stego: str) -> dict:
    a, b = load(original), load(stego)
    if a.shape != b.shape:
        raise ValueError("Зображення мають різний розмір")
    diff = np.abs(a - b)
    changed_px = int(np.any(diff > 0, axis=2).sum())
    total_px = a.shape[0] * a.shape[1]
    mse = float((diff.astype(np.float64) ** 2).mean())
    return {
        "size_original_bytes": os.path.getsize(original),
        "size_stego_bytes": os.path.getsize(stego),
        "width": a.shape[1], "height": a.shape[0],
        "changed_pixels": changed_px,
        "changed_percent": 100 * changed_px / total_px,
        "changed_R": int((diff[..., 0] > 0).sum()),
        "changed_G": int((diff[..., 1] > 0).sum()),
        "changed_B": int((diff[..., 2] > 0).sum()),
        "max_difference": int(diff.max()),
        # PSNR: чим більше, тим менше помітні зміни (>50 дБ - оком не видно)
        "psnr_db": float("inf") if mse == 0 else 10 * math.log10(255 ** 2 / mse),
    }


def diff_map(original: str, stego: str, out_path: str, zoom_rows: int | None = None) -> str:
    """Змінені пікселі - червоні, незмінені - сірі (затемнений оригінал)."""
    a, b = load(original), load(stego)
    changed = np.any(a != b, axis=2)
    base = (a.mean(axis=2) * 0.35 + 140).astype(np.uint8)
    rgb = np.stack([base] * 3, axis=2)
    rgb[changed] = [220, 30, 30]
    img = Image.fromarray(rgb)
    if zoom_rows:                       # збільшений фрагмент верхніх рядків
        img = img.crop((0, 0, zoom_rows * 4, zoom_rows)).resize(
            (zoom_rows * 4 * 8, zoom_rows * 8), Image.NEAREST)
    img.save(out_path)
    return out_path


# ----------------------------------------------------- пошук прихованого
def lsb_plane(path: str, out_path: str, channel: int = 0) -> str:
    """Біт 0 -> чорний, біт 1 -> білий. У чистому фото видно контури,
    у місцях із прихованими даними - рівномірний шум."""
    a = load(path)
    plane = ((a[..., channel] & 1) * 255).astype(np.uint8)
    Image.fromarray(plane).save(out_path)
    return out_path


def lsb_ones_ratio(path: str) -> float:
    """Частка одиниць серед молодших бітів (у будь-якому фото приблизно 0.5)."""
    return float((load(path) & 1).mean())


def _chi2_sf(x: float, k: int) -> float:
    """P(χ² > x) для k ступенів свободи (наближення Вілсона-Гілферті, без scipy)."""
    if k <= 0:
        return 1.0
    z = ((x / k) ** (1 / 3) - (1 - 2 / (9 * k))) / math.sqrt(2 / (9 * k))
    return 0.5 * math.erfc(z / math.sqrt(2))


def chi_square_attack(path: str, steps: int = 10) -> list[dict]:
    """Атака Вестфельда: LSB-заміна вирівнює кількість значень у парах (2k, 2k+1).
    Беремо все більшу частину зображення (з початку) і рахуємо ймовірність того,
    що там є приховані дані. Близько 1 - дані є, близько 0 - немає."""
    flat = load(path).reshape(-1)        # значення каналів у порядку запису
    rows = []
    for i in range(1, steps + 1):
        part = flat[: len(flat) * i // steps]
        hist = np.bincount(part, minlength=256).astype(np.float64)
        even, odd = hist[0::2], hist[1::2]
        expected = (even + odd) / 2
        mask = expected > 5
        chi2 = float((((even[mask] - expected[mask]) ** 2) / expected[mask]).sum())
        p = 1 - _chi2_sf(chi2, int(mask.sum()) - 1)
        rows.append({"percent": 100 * i // steps, "chi2": chi2,
                     "p_hidden": round(1 - p, 4)})
    return rows


# --------------------------------------------------------------- EXIF
def _to_degrees(v) -> float:
    d, m, s = (float(x) for x in v)
    return d + m / 60 + s / 3600


def read_exif(path: str, mask_gps: bool = True) -> dict:
    """Основні метадані фото. Координати за замовчуванням частково приховані."""
    exif = Image.open(path).getexif()
    info = {TAGS.get(k, k): v for k, v in exif.items()}
    try:
        info.update({TAGS.get(k, k): v for k, v in exif.get_ifd(0x8769).items()})
    except Exception:
        pass
    gps = {}
    try:
        gps = {GPSTAGS.get(k, k): v for k, v in exif.get_ifd(0x8825).items()}
    except Exception:
        pass
    if "ExposureTime" in info and float(info["ExposureTime"]) > 0:
        info["ExposureTime"] = f"1/{round(1 / float(info['ExposureTime']))} c"
    if "FNumber" in info:
        info["FNumber"] = f"f/{float(info['FNumber']):.2f}"
    result = {k: str(info[k]) for k in ("Make", "Model", "Software", "DateTimeOriginal",
                                        "OffsetTimeOriginal", "LensModel", "ExposureTime",
                                        "FNumber", "ISOSpeedRatings", "ExifImageWidth",
                                        "ExifImageHeight") if k in info}
    if "GPSLatitude" in gps:
        lat, lon = _to_degrees(gps["GPSLatitude"]), _to_degrees(gps["GPSLongitude"])
        if mask_gps:
            result["GPS"] = "є (координати приховано у звіті)"
        else:
            result["GPS"] = f"{lat:.6f} {gps.get('GPSLatitudeRef', '')}, {lon:.6f} {gps.get('GPSLongitudeRef', '')}"
        if "GPSHPositioningError" in gps:
            result["GPS точність, м"] = f"{float(gps['GPSHPositioningError']):.1f}"
        if "GPSImgDirection" in gps:
            result["Напрямок камери, °"] = f"{float(gps['GPSImgDirection']):.0f}"
        if "GPSAltitude" in gps:
            result["Висота, м"] = f"{float(gps['GPSAltitude']):.0f}"
    result["Кількість тегів EXIF"] = str(len(info) + len(gps))
    return result


def strip_metadata(path: str, out_path: str) -> str:
    """Створює копію фото тільки з пікселів - без EXIF, GPS і т.д."""
    img = Image.open(path).convert("RGB")
    clean = Image.fromarray(np.asarray(img))      # нове зображення: тільки пікселі
    if out_path.lower().endswith((".jpg", ".jpeg")):
        clean.save(out_path, quality=92)
    else:
        clean.save(out_path)
    return out_path
