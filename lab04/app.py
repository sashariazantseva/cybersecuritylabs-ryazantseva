"""
ЛР4 "Особистий цифровий підпис" - графічний застосунок.
Автор: Рязанцева О.С., гр. 6.04.122.010.23.3

Вкладки:
  1. Ключі            - генерація пари ключів з ПІБ, дати і секретного слова
  2. Підписати        - хеш документа + підпис приватним ключем -> файл .sig
  3. Перевірити       - перевірка підпису публічним ключем
  4. Тест підробки    - зміна документа, зміна підпису, чужий ключ і т.д.
  5. Хеш і підпис     - чим хешування відрізняється від підписування

Запуск:  python app.py
"""
import os
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

import signature as S
import forgery

HERE = Path(__file__).parent
KEYS, DOCS, RES = HERE / "keys", HERE / "documents", HERE / "results"
NAME = "Рязанцева Олександра Сергіївна"
DOB = "16.05.2006"

ACCENT = "#2E4057"
SOFT = "#F4F1EA"
GREEN, RED = "#1E8A4C", "#B03A2E"


def short(x: int | str, n: int = 24) -> str:
    s = hex(x) if isinstance(x, int) else x
    return s if len(s) <= 2 * n else f"{s[:n]}…{s[-8:]}"


def rel(p: str) -> str:
    try:
        return str(Path(p).resolve().relative_to(HERE))
    except ValueError:
        return Path(p).name


class SignApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ЛР4 · Особистий цифровий підпис · Рязанцева О.С.")
        self.geometry("1100x760")
        self.configure(bg=SOFT)
        self.keys = None
        self._style()
        ttk.Label(self, text="Цифровий підпис документів (RSA-2048)",
                  style="Title.TLabel").pack(anchor="w", padx=12, pady=(10, 6))
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._tab_keys()
        self._tab_sign()
        self._tab_verify()
        self._tab_forgery()
        self._tab_hash()

    # ---------------------------------------------------------- стиль
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", font=("Segoe UI", 10), background=SOFT)
        s.configure("TNotebook", background=SOFT)
        s.configure("TNotebook.Tab", padding=(14, 6), font=("Segoe UI", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", "white")], foreground=[("selected", ACCENT)])
        s.configure("TFrame", background="white")
        s.configure("TLabel", background="white")
        s.configure("Title.TLabel", background=SOFT, foreground=ACCENT, font=("Segoe UI", 16, "bold"))
        s.configure("H.TLabel", font=("Segoe UI", 10, "bold"), foreground=ACCENT)
        s.configure("Accent.TButton", background=ACCENT, foreground="white",
                    font=("Segoe UI", 10, "bold"), padding=(12, 5))
        s.map("Accent.TButton", background=[("active", "#1E2B3B")])
        s.configure("Treeview", rowheight=26, font=("Segoe UI", 10))
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _text(self, parent, h):
        t = tk.Text(parent, height=h, wrap="word", font=("Consolas", 10), bg="#FBFAF7", relief="flat")
        t.tag_configure("b", font=("Consolas", 10, "bold"), foreground=ACCENT)
        return t

    def _need_keys(self):
        if not self.keys:
            messagebox.showinfo("Ключі", "Спочатку згенеруйте ключі на вкладці 1")
            return False
        return True

    # ------------------------------------------------------- 1. ключі
    def _tab_keys(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="1 · Ключі")
        form = ttk.Frame(f)
        form.pack(fill="x")
        self.name = tk.StringVar(value=NAME)
        self.dob = tk.StringVar(value=DOB)
        self.secret = tk.StringVar()
        for i, (lbl, var, show) in enumerate((("ПІБ:", self.name, ""), ("Дата народження:", self.dob, ""),
                                              ("Секретне слово:", self.secret, "•"))):
            ttk.Label(form, text=lbl).grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(form, textvariable=var, width=45, show=show).grid(row=i, column=1, sticky="w", padx=6)
        ttk.Button(form, text="Згенерувати ключі", style="Accent.TButton",
                   command=self.do_keys).grid(row=3, column=1, sticky="w", padx=6, pady=8)
        ttk.Label(f, text="Приватний ключ = SHA-256(ПІБ | дата | секретне слово) → прості p, q → d.   "
                          "Публічний ключ = (n = p·q, e = 65537).", wraplength=1000).pack(anchor="w")
        self.keys_out = self._text(f, 20)
        self.keys_out.pack(fill="both", expand=True, pady=8)

    def do_keys(self):
        try:
            self.keys = S.generate_keys(self.name.get().strip(), self.dob.get().strip(), self.secret.get())
        except ValueError as e:
            messagebox.showerror("Помилка", str(e))
            return
        KEYS.mkdir(exist_ok=True)
        S.save_key(self.keys["public"], KEYS / "public_key.json")
        S.save_key(self.keys["private"], KEYS / "private_key.json")
        pub, prv = self.keys["public"], self.keys["private"]
        o = self.keys_out
        o.delete("1.0", "end")
        o.insert("end", "Власник: ", "b"); o.insert("end", pub["owner"] + "\n")
        o.insert("end", "Зерно SHA-256: ", "b"); o.insert("end", short(self.keys["seed"], 16) + "\n\n")
        o.insert("end", "ПУБЛІЧНИЙ КЛЮЧ (можна давати всім)\n", "b")
        o.insert("end", f"  n = {short(pub['n'])}  ({pub['n'].bit_length()} біт)\n  e = {pub['e']}\n")
        o.insert("end", f"  відбиток: {S.fingerprint(pub)}\n\n")
        o.insert("end", "ПРИВАТНИЙ КЛЮЧ (тільки у власника)\n", "b")
        o.insert("end", f"  d = {short(prv['d'])}  ({prv['d'].bit_length()} біт)\n\n")
        o.insert("end", "Збережено: keys/public_key.json, keys/private_key.json\n")
        o.insert("end", "Перевірка зв'язку ключів: ", "b")
        test = 123456789
        ok = pow(pow(test, prv["d"], prv["n"]), pub["e"], pub["n"]) == test
        o.insert("end", f"(123456789^d)^e mod n = 123456789 → {'так ✔' if ok else 'ні'}")

    # ---------------------------------------------------- 2. підписати
    def _tab_sign(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="2 · Підписати")
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.doc = tk.StringVar(value="documents/Резюме_Рязанцева.pdf")
        ttk.Label(row, text="Документ:").pack(side="left")
        ttk.Entry(row, textvariable=self.doc, width=70).pack(side="left", padx=6)
        ttk.Button(row, text="Обрати…", command=lambda: self._pick(self.doc)).pack(side="left")
        row2 = ttk.Frame(f)
        row2.pack(fill="x", pady=8)
        ttk.Label(row2, text="Хеш-функція:").pack(side="left")
        self.algo = tk.StringVar(value="SHA-256")
        ttk.Combobox(row2, textvariable=self.algo, values=list(S.HASHES), width=12,
                     state="readonly").pack(side="left", padx=6)
        ttk.Button(row2, text="Підписати документ", style="Accent.TButton",
                   command=self.do_sign).pack(side="left", padx=10)
        self.sign_out = self._text(f, 20)
        self.sign_out.pack(fill="both", expand=True)

    def _pick(self, var, types=(("Усі файли", "*.*"),)):
        p = filedialog.askopenfilename(filetypes=types)
        if p:
            var.set(p)

    def do_sign(self):
        if not self._need_keys():
            return
        sig = S.sign_file(self.doc.get(), self.keys["private"], self.algo.get())
        o = self.sign_out
        o.delete("1.0", "end")
        o.insert("end", "Документ: ", "b"); o.insert("end", rel(self.doc.get()) + "\n")
        o.insert("end", f"1) Хеш {sig['algorithm']}:\n", "b"); o.insert("end", f"   {sig['hash']}\n\n")
        o.insert("end", "2) Підпис s = H^d mod n:\n", "b")
        o.insert("end", f"   {short(sig['signature'], 40)}\n\n")
        o.insert("end", "3) Збережено у файл: ", "b"); o.insert("end", rel(sig["sig_path"]) + "\n")
        o.insert("end", f"   підписант: {sig['signer']}, час: {sig['signed_at']}\n\n")
        o.insert("end", "Сам документ не змінюється, підпис зберігається окремим файлом .sig")
        self.v_doc.set(self.doc.get())
        self.v_sig.set(rel(sig["sig_path"]))

    # ---------------------------------------------------- 3. перевірити
    def _tab_verify(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="3 · Перевірити")
        self.v_doc = tk.StringVar(value="documents/Резюме_Рязанцева.pdf")
        self.v_sig = tk.StringVar(value="documents/Резюме_Рязанцева.pdf.sig")
        self.v_pub = tk.StringVar(value="keys/public_key.json")
        for i, (lbl, var) in enumerate((("Документ:", self.v_doc), ("Підпис (.sig):", self.v_sig),
                                        ("Публічний ключ:", self.v_pub))):
            ttk.Label(f, text=lbl).grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(f, textvariable=var, width=75).grid(row=i, column=1, padx=6)
            ttk.Button(f, text="…", width=3, command=lambda v=var: self._pick(v)).grid(row=i, column=2)
        ttk.Button(f, text="Перевірити підпис", style="Accent.TButton",
                   command=self.do_verify).grid(row=3, column=1, sticky="w", padx=6, pady=8)
        self.verdict = tk.Label(f, text="", font=("Segoe UI", 20, "bold"), bg="white")
        self.verdict.grid(row=4, column=0, columnspan=3, sticky="w", pady=6)
        self.verify_out = self._text(f, 12)
        self.verify_out.grid(row=5, column=0, columnspan=3, sticky="nsew")
        f.columnconfigure(1, weight=1)
        f.rowconfigure(5, weight=1)

    def do_verify(self):
        try:
            pub = S.load_key(self.v_pub.get())
            res = S.verify_file(self.v_doc.get(), self.v_sig.get(), pub)
        except (OSError, ValueError, KeyError) as e:
            messagebox.showerror("Помилка", str(e))
            return
        self.verdict.configure(text=("✔  " if res["valid"] else "✘  ") + res["verdict"],
                               fg=GREEN if res["valid"] else RED)
        o = self.verify_out
        o.delete("1.0", "end")
        o.insert("end", "Документ: ", "b"); o.insert("end", rel(self.v_doc.get()) + "\n")
        o.insert("end", "Підписант: ", "b"); o.insert("end", f"{res['signer']} ({res['signed_at']})\n")
        o.insert("end", "Відбиток ключа: ", "b"); o.insert("end", S.fingerprint(pub) + "\n\n")
        o.insert("end", f"Хеш документа зараз ({res['algorithm']}):\n", "b")
        o.insert("end", f"   {res['current_hash']}\n")
        o.insert("end", "Хеш, відновлений з підпису (s^e mod n):\n", "b")
        o.insert("end", f"   {res['recovered_hash']}\n\n")
        o.insert("end", "Хеші збігаються → документ не змінено, підписав власник ключа" if res["valid"]
                 else "Хеші НЕ збігаються → документ змінено або підпис зроблено іншим ключем")

    # ----------------------------------------------------- 4. підробка
    def _tab_forgery(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="4 · Тест підробки")
        ttk.Button(f, text="Запустити всі тести для обраного документа", style="Accent.TButton",
                   command=self.do_forgery).pack(anchor="w")
        cols = ("Сценарій", "Що зроблено", "Очікувано", "Результат")
        self.forg = ttk.Treeview(f, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (170, 520, 110, 140)):
            self.forg.heading(c, text=c)
            self.forg.column(c, width=w, anchor="w" if c == "Що зроблено" else "center")
        self.forg.tag_configure("valid", foreground=GREEN)
        self.forg.tag_configure("fake", foreground=RED)
        self.forg.pack(fill="x", pady=10)
        self.forg_note = ttk.Label(f, wraplength=1000, justify="left")
        self.forg_note.pack(anchor="w")

    def do_forgery(self):
        if not self._need_keys():
            return
        doc = self.v_doc.get()
        sig = self.v_sig.get()
        if not Path(sig).exists():
            S.sign_file(doc, self.keys["private"], self.algo.get(), sig)
        rows = forgery.run_all(doc, sig, self.keys["public"], self.name.get(), self.dob.get(),
                               str(RES / "forgery"))
        self.forg.delete(*self.forg.get_children())
        for r in rows:
            self.forg.insert("", "end", tags=("valid" if r["Результат"] == "ДІЙСНИЙ" else "fake",),
                             values=(r["Сценарій"], r["Що зроблено"], r["Очікувано"], r["Результат"]))
        passed = sum(r["ok"] for r in rows)
        self.forg_note.configure(text=(
            f"Пройдено {passed} з {len(rows)} перевірок. Будь-яка зміна документа або підпису виявляється, "
            "а підробити підпис без приватного ключа не вдалося: навіть якщо знати ПІБ і дату, "
            "без секретного слова виходить зовсім інший ключ."))

    # --------------------------------------------------- 5. хеш і підпис
    def _tab_hash(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="5 · Хеш і підпис")
        self.t1 = tk.StringVar(value="Рязанцева Олександра Сергіївна, дата народження: 16.05.2006")
        self.t2 = tk.StringVar(value="Рязанцева Олександра Сергіївна, дата народження: 16.05.2005")
        for i, var in enumerate((self.t1, self.t2)):
            ttk.Label(f, text=f"Текст {i + 1}:").grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(f, textvariable=var, width=80).grid(row=i, column=1, sticky="w", padx=6)
        ttk.Button(f, text="Порівняти", style="Accent.TButton",
                   command=self.do_hash).grid(row=2, column=1, sticky="w", padx=6, pady=8)
        self.hash_out = self._text(f, 18)
        self.hash_out.grid(row=3, column=0, columnspan=2, sticky="nsew")
        f.columnconfigure(1, weight=1)
        f.rowconfigure(3, weight=1)

    def do_hash(self):
        a, b = self.t1.get().encode(), self.t2.get().encode()
        o = self.hash_out
        o.delete("1.0", "end")
        for algo in ("SHA-256", "SHA3-256"):
            h1, h2 = S.hash_bytes(a, algo), S.hash_bytes(b, algo)
            o.insert("end", f"{algo}\n", "b")
            o.insert("end", f"  текст 1: {h1}\n  текст 2: {h2}\n")
            o.insert("end", f"  відрізняється {S.bit_difference(h1, h2)} з 256 бітів\n\n")
        o.insert("end", "Хешування", "b")
        o.insert("end", ": будь-хто може порахувати хеш, ключ не потрібен. Хеш показує, чи змінився "
                        "файл, але не показує, ХТО його створив (зловмисник змінить файл і порахує новий хеш).\n\n")
        o.insert("end", "Підписування", "b")
        o.insert("end", ": хеш «шифрується» приватним ключем. Перевірити може кожен публічним ключем, "
                        "а створити такий підпис може тільки власник приватного ключа. Тому підпис "
                        "доводить і цілісність, і автентичність (авторство).")


if __name__ == "__main__":
    os.chdir(HERE)          # щоб відносні шляхи працювали з будь-якої папки
    SignApp().mainloop()
