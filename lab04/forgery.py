"""
Тестування підробки підписів (крок 4 методички).

Для кожного сценарію створюється змінена копія документа або підпису
і перевіряється справжнім публічним ключем власника.
"""
import json
import shutil
from pathlib import Path

import signature as S


def _flip_one_char(src: Path, dst: Path) -> str:
    data = bytearray(src.read_bytes())
    if src.suffix.lower() == ".txt":
        text = data.decode("utf-8")
        i = text.find("4")
        text = text[:i] + "5" + text[i + 1:] if i >= 0 else text + "."
        dst.write_text(text, encoding="utf-8")
        return "у тексті змінено одну цифру (4 → 5)"
    data[len(data) // 2] ^= 0x01                 # змінюємо 1 біт посередині файлу
    dst.write_bytes(bytes(data))
    return "у файлі змінено 1 біт"


def run_all(document: str, sig_path: str, public: dict, owner: str, dob: str,
            workdir: str) -> list[dict]:
    doc, work = Path(document), Path(workdir)
    work.mkdir(parents=True, exist_ok=True)
    rows = []

    def check(name, how, doc_path, sig_file, expected):
        res = S.verify_file(str(doc_path), str(sig_file), public)
        rows.append({"Сценарій": name, "Що зроблено": how,
                     "Очікувано": "дійсний" if expected else "підроблений",
                     "Результат": "ДІЙСНИЙ" if res["valid"] else "ПІДРОБЛЕНИЙ",
                     "ok": res["valid"] == expected})

    # 0. оригінал
    check("Оригінал", "документ і підпис без змін", doc, sig_path, True)

    # 1. змінений документ (якщо є готова "підроблена" копія - беремо її)
    fake_copy = doc.with_name(doc.stem + "_змінене" + doc.suffix)
    if fake_copy.exists():
        changed, how = fake_copy, "у резюме змінено рік народження (2006 → 2005)"
    else:
        changed = work / ("changed_" + doc.name)
        how = _flip_one_char(doc, changed)
    check("Змінений документ", how, changed, sig_path, False)

    # 2. змінений підпис
    sig = json.loads(Path(sig_path).read_text(encoding="utf-8"))
    s = int(sig["signature"], 16) ^ 1
    bad_sig = work / "flipped_bit.sig"
    bad_sig.write_text(json.dumps({**sig, "signature": hex(s)}, ensure_ascii=False, indent=2), encoding="utf-8")
    check("Змінений підпис", "у підписі змінено 1 біт", doc, bad_sig, False)

    # 3. підпис чужим ключем (зловмисник знає ПІБ і дату, але не секретне слово)
    attacker = S.generate_keys(owner, dob, "123456")
    fake = S.sign_file(str(doc), attacker["private"], sig["algorithm"], str(work / "attacker.sig"))
    check("Чужий ключ", "зловмисник підписав своїм ключем (ПІБ і дата ті самі, секрет інший)",
          doc, fake["sig_path"], False)

    # 4. підпис від іншого документа
    other = work / "other.txt"
    other.write_text("Інший документ, який власник справді підписав.", encoding="utf-8")
    shutil.copy(sig_path, work / "copied.sig")
    check("Чужий документ", "справжній підпис перенесено на інший файл", other, work / "copied.sig", False)

    # 5. випадковий підпис
    rnd = work / "random.sig"
    rnd.write_text(json.dumps({**sig, "signature": hex(int(sig["hash"], 16) * 7 + 12345)},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    check("Вигаданий підпис", "підпис підібрано без приватного ключа", doc, rnd, False)
    return rows
