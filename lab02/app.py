"""
ЛР2 «Захист особистих повідомлень» — графічний застосунок (Tkinter).
Автор: Рязанцева О.С., гр. 6.04.122.010.23.3

Вкладки:
  1. Шифрування   — Цезар, Віженер, афінний шифр з ключами з персональних даних
  2. Порівняння   — таблиця: довжина, IC, % змінених літер, кількість ключів
  3. Brute force  — перебір усіх зсувів Цезаря + автоматичний вибір (хі-квадрат)
  4. Частоти      — графік частот літер до і після шифрування
  5. Обмін        — підготовка зашифрованого повідомлення та злам отриманого

Запуск:  python app.py
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import ciphers as C
import analysis as A

NAME = "Рязанцева Олександра Сергіївна"
DOB = "16.05.2006"
TEXT_UA = ("Таємниця листування — право кожної людини, навіть якщо листи "
           "пише студентка ХНЕУ.")
TEXT_EN = "Secret letters keep our friendship safe from strangers."

ACCENT = "#2E4057"      # основний колір інтерфейсу
SOFT = "#F4F1EA"        # світле тло
COLORS = {"Відкритий текст": "#7A7A7A", "Цезар": "#1F7A7A",
          "Віженер": "#2F6DB5", "Афінний": "#E09A2B"}
RESULTS = Path(__file__).parent / "results"


class CipherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ЛР2 · Захист особистих повідомлень · Рязанцева О.С.")
        self.geometry("1060x720")
        self.configure(bg=SOFT)
        self._style()
        self._header()
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._tab_encrypt()
        self._tab_compare()
        self._tab_brute()
        self._tab_freq()
        self._tab_exchange()
        self.run_all()

    # ------------------------------------------------------------ оформлення
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", font=("Segoe UI", 10), background=SOFT)
        s.configure("TNotebook", background=SOFT)
        s.configure("TNotebook.Tab", padding=(14, 6), font=("Segoe UI", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", "white")],
              foreground=[("selected", ACCENT)])
        s.configure("TFrame", background="white")
        s.configure("Head.TFrame", background=SOFT)
        s.configure("TLabel", background="white")
        s.configure("Head.TLabel", background=SOFT)
        s.configure("Title.TLabel", background=SOFT, foreground=ACCENT,
                    font=("Segoe UI", 16, "bold"))
        s.configure("Accent.TButton", background=ACCENT, foreground="white",
                    font=("Segoe UI", 10, "bold"), padding=(12, 5))
        s.map("Accent.TButton", background=[("active", "#1E2B3B")])
        s.configure("Treeview", rowheight=24, font=("Consolas", 10))
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _header(self):
        h = ttk.Frame(self, style="Head.TFrame")
        h.pack(fill="x", padx=12, pady=10)
        ttk.Label(h, text="Класичні шифри: Цезар · Віженер · Афінний",
                  style="Title.TLabel").grid(row=0, column=0, columnspan=7, sticky="w")
        ttk.Label(h, text="ПІБ:", style="Head.TLabel").grid(row=1, column=0, sticky="w")
        self.name = tk.StringVar(value=NAME)
        ttk.Entry(h, textvariable=self.name, width=34).grid(row=1, column=1, padx=6)
        ttk.Label(h, text="Дата народження:", style="Head.TLabel").grid(row=1, column=2)
        self.dob = tk.StringVar(value=DOB)
        ttk.Entry(h, textvariable=self.dob, width=12).grid(row=1, column=3, padx=6)
        ttk.Label(h, text="Алфавіт:", style="Head.TLabel").grid(row=1, column=4, padx=(10, 0))
        self.alpha = tk.StringVar(value="ua")
        for i, (val, txt) in enumerate((("ua", "UA (33)"), ("en", "EN (26)"))):
            tk.Radiobutton(h, text=txt, variable=self.alpha, value=val, bg=SOFT,
                           command=self._switch_alpha).grid(row=1, column=5 + i)
        self.keys_lbl = ttk.Label(h, style="Head.TLabel", foreground="#444")
        self.keys_lbl.grid(row=2, column=0, columnspan=7, sticky="w", pady=(4, 0))

    def _switch_alpha(self):
        """Під час зміни алфавіту підставляємо приклад тексту відповідною мовою."""
        self.text.delete("1.0", "end")
        self.text.insert("1.0", TEXT_UA if self.alpha.get() == "ua" else TEXT_EN)
        self.run_all()

    # ------------------------------------------------------- 1. шифрування
    def _tab_encrypt(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="1 · Шифрування")
        ttk.Label(f, text="Власний текст для шифрування:").pack(anchor="w")
        self.text = tk.Text(f, height=3, wrap="word", font=("Segoe UI", 11))
        self.text.insert("1.0", TEXT_UA)
        self.text.pack(fill="x", pady=(2, 8))
        ttk.Button(f, text="Зашифрувати всіма методами", style="Accent.TButton",
                   command=self.run_all).pack(anchor="w")
        self.enc_out = tk.Text(f, wrap="word", font=("Consolas", 11), bg="#FCFCFC")
        self.enc_out.pack(fill="both", expand=True, pady=(10, 0))
        for name, color in COLORS.items():
            self.enc_out.tag_configure(name, foreground=color, font=("Consolas", 11, "bold"))
        self.enc_out.tag_configure("ok", foreground="#1E8A4C")

    # -------------------------------------------------------- 2. порівняння
    def _tab_compare(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="2 · Порівняння")
        cols = ("Метод", "Ключ", "Довжина", "IC", "Змінено літер, %", "Кількість ключів")
        self.cmp = ttk.Treeview(f, columns=cols, show="headings", height=5)
        for c, w in zip(cols, (150, 150, 80, 80, 130, 200)):
            self.cmp.heading(c, text=c)
            self.cmp.column(c, width=w, anchor="center")
        self.cmp.pack(fill="x")
        self.cmp_note = tk.Text(f, wrap="word", height=14, font=("Segoe UI", 10),
                                relief="flat", bg="white")
        self.cmp_note.pack(fill="both", expand=True, pady=(12, 0))

    # ------------------------------------------------------- 3. brute force
    def _tab_brute(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="3 · Brute force")
        self.brute_lbl = ttk.Label(f, font=("Segoe UI", 10, "bold"), foreground=ACCENT)
        self.brute_lbl.pack(anchor="w", pady=(0, 6))
        cols = ("Зсув", "χ²", "Кандидат")
        self.brute = ttk.Treeview(f, columns=cols, show="headings")
        self.brute.heading("Зсув", text="Зсув")
        self.brute.heading("χ²", text="χ² (менше = краще)")
        self.brute.heading("Кандидат", text="Кандидат на відкритий текст")
        self.brute.column("Зсув", width=60, anchor="center")
        self.brute.column("χ²", width=130, anchor="center")
        self.brute.column("Кандидат", width=780)
        self.brute.tag_configure("best", background="#EDE4D3")
        sb = ttk.Scrollbar(f, command=self.brute.yview)
        self.brute.configure(yscrollcommand=sb.set)
        self.brute.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    # ------------------------------------------------------------ 4. частоти
    def _tab_freq(self):
        f = ttk.Frame(self.tabs, padding=6)
        self.tabs.add(f, text="4 · Частотний аналіз")
        self.fig = Figure(figsize=(10, 5.6), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=f)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    # -------------------------------------------------------------- 5. обмін
    def _tab_exchange(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="5 · Обмін повідомленнями")
        ttk.Label(f, text="Відправити: шифруємо повідомлення Цезарем (ключ НЕ передаємо)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.send_in = tk.Text(f, height=2, wrap="word", font=("Segoe UI", 11))
        self.send_in.insert("1.0", "Привіт! Це Саша. Якщо ти це прочитав, "
                                   "то шифр Цезаря справді легко зламати.")
        self.send_in.pack(fill="x", pady=4)
        ttk.Button(f, text="Зашифрувати та зберегти у файл",
                   style="Accent.TButton", command=self.send).pack(anchor="w")
        self.send_out = tk.Text(f, height=2, wrap="word", font=("Consolas", 11), bg="#FCFCFC")
        self.send_out.pack(fill="x", pady=(4, 14))

        ttk.Label(f, text="Отримати: вставте отриманий шифротекст — програма "
                          "знайде ключ сама", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.recv_in = tk.Text(f, height=3, wrap="word", font=("Consolas", 11))
        self.recv_in.pack(fill="x", pady=4)
        row = ttk.Frame(f)
        row.pack(anchor="w")
        ttk.Button(row, text="Відкрити файл…", command=self.load_received).pack(side="left")
        ttk.Button(row, text="Зламати (brute force + χ²)", style="Accent.TButton",
                   command=self.receive).pack(side="left", padx=8)
        self.recv_out = tk.Text(f, wrap="word", font=("Consolas", 11), bg="#FCFCFC")
        self.recv_out.pack(fill="both", expand=True, pady=(6, 0))

    # ================================================================ логіка
    def run_all(self):
        """Головна дія: рахуємо ключі, шифруємо, оновлюємо всі вкладки."""
        try:
            alpha = self.alpha.get()
            keys = C.personal_keys(self.name.get(), self.dob.get(), alpha)
            plain = self.text.get("1.0", "end").strip()
            if len(plain) < 20:
                raise ValueError("Текст має містити щонайменше 20 символів")
        except ValueError as e:
            messagebox.showerror("Помилка", str(e))
            return
        res = C.encrypt_all(plain, keys, alpha)
        a, b = keys["affine"]
        self.keys_lbl.config(text=(
            f"Ключі з персональних даних →  Цезар: зсув {keys['caesar']} (сума цифр дати) · "
            f"Віженер: «{keys['vigenere']}» (прізвище) · Афінний: a={a} (місяць), b={b} (день)"))
        self._fill_encrypt(plain, res, keys)
        self._fill_compare(plain, res, keys, alpha)
        self._fill_brute(res["Цезар"]["cipher"], alpha)
        self._fill_freq(plain, res, alpha)

    def _fill_encrypt(self, plain, res, keys):
        o = self.enc_out
        o.delete("1.0", "end")
        o.insert("end", "Відкритий текст\n", "Відкритий текст")
        o.insert("end", f"  {plain}\n\n")
        for name, r in res.items():
            o.insert("end", f"{name}\n", name)
            o.insert("end", f"  шифротекст:     {r['cipher']}\n")
            o.insert("end", f"  розшифровано:   {r['restored']}\n")
            o.insert("end", "  ✔ збігається з оригіналом\n\n" if r["ok"] else "  ✘ ПОМИЛКА\n\n",
                     "ok")

    def _fill_compare(self, plain, res, keys, alpha):
        self.cmp.delete(*self.cmp.get_children())
        rows = A.compare(plain, res, keys, alpha)
        for r in rows:
            self.cmp.insert("", "end", values=list(r.values()))
        rnd = 1 / len(C.get_alphabet(alpha))
        ic = {r["Метод"]: r["IC"] for r in rows}
        n = self.cmp_note
        n.delete("1.0", "end")
        n.insert("end", (
            f"IC (індекс збігів) — імовірність, що дві випадкові літери тексту однакові. "
            f"Для випадкового набору літер IC ≈ {rnd:.3f}.\n\n"
            f"• Цезар і Афінний: IC = {ic['Цезар']} — такий самий, як у відкритого тексту. "
            f"Це моноалфавітні шифри: кожна літера завжди замінюється однією й тією ж, "
            f"тому частоти просто «переставляються» і текст можна зламати частотним аналізом.\n"
            f"• Віженер: IC = {ic['Віженер']} — ближче до випадкового тексту. "
            f"Одна й та сама літера шифрується по-різному залежно від позиції ключа, "
            f"тому частоти «розмазуються». Це найбільш «нечитабельний» результат.\n\n"
            f"Найпростіше налаштувати: Цезар (одне число). Найскладніше: афінний "
            f"(потрібно, щоб a було взаємно простим з N).\n"
            f"Закономірності: у Цезаря й Афінного однакові літери → однакові символи, "
            f"зберігаються пробіли, довжина слів і розділові знаки."))

    def _fill_brute(self, cipher, alpha):
        self.brute.delete(*self.brute.get_children())
        rows = A.brute_force_caesar(cipher, alpha)
        best = rows[0]
        self.brute_lbl.config(text=f"Перевірено {len(rows)} зсувів. Найімовірніший: "
                                   f"зсув {best['shift']} (χ² = {best['chi2']})")
        for r in sorted(rows, key=lambda r: r["shift"]):
            tag = ("best",) if r is best else ()
            self.brute.insert("", "end", values=(r["shift"], r["chi2"], r["text"]), tags=tag)

    def _fill_freq(self, plain, res, alpha):
        draw_frequency_chart(self.fig, plain, res, alpha)
        self.canvas.draw()

    # ----------------------------------------------------------------- обмін
    def send(self):
        alpha = C.detect_alphabet(self.send_in.get("1.0", "end"))
        shift = C.caesar_key(self.dob.get(), alpha)
        cipher = C.caesar_encrypt(self.send_in.get("1.0", "end").strip(), shift, alpha)
        self.send_out.delete("1.0", "end")
        self.send_out.insert("1.0", cipher)
        RESULTS.mkdir(exist_ok=True)
        path = RESULTS / "message_for_partner.txt"
        path.write_text(cipher, encoding="utf-8")       # у файлі ЛИШЕ шифротекст
        messagebox.showinfo("Готово", f"Шифротекст збережено:\n{path}\n\nКлюч не передається!")

    def load_received(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            self.recv_in.delete("1.0", "end")
            self.recv_in.insert("1.0", Path(path).read_text(encoding="utf-8-sig"))

    def receive(self):
        cipher = self.recv_in.get("1.0", "end").strip()
        if not cipher:
            messagebox.showwarning("Порожньо", "Вставте отриманий шифротекст")
            return
        alpha = C.detect_alphabet(cipher)
        rows = A.brute_force_caesar(cipher, alpha)
        o = self.recv_out
        o.delete("1.0", "end")
        o.insert("end", f"Алфавіт: {alpha.upper()} · перевірено {len(rows)} зсувів\n")
        o.insert("end", f"Знайдений зсув: {rows[0]['shift']}  (χ² = {rows[0]['chi2']})\n\n")
        o.insert("end", f"Розшифроване повідомлення:\n{rows[0]['text']}\n\n")
        o.insert("end", "Наступні кандидати (для порівняння):\n")
        for r in rows[1:4]:
            o.insert("end", f"  зсув {r['shift']:>2} · χ²={r['chi2']:>7} · {r['text'][:70]}…\n")


def draw_frequency_chart(fig, plain, res, alpha):
    """4 гістограми частот літер: відкритий текст і три шифротексти.
    Функція окрема, щоб її можна було викликати і без GUI (demo.py)."""
    fig.clear()
    alphabet = C.get_alphabet(alpha)
    series = {"Відкритий текст": plain, **{k: v["cipher"] for k, v in res.items()}}
    for i, (name, txt) in enumerate(series.items(), start=1):
        ax = fig.add_subplot(2, 2, i)
        freq = A.letter_freq(txt, alpha)
        ax.bar(list(alphabet), [freq[ch] for ch in alphabet], color=COLORS[name], width=0.75)
        ax.set_title(f"{name}  ·  IC = {A.index_of_coincidence(txt, alpha):.4f}",
                     fontsize=10, color=COLORS[name], loc="left", fontweight="bold")
        ax.tick_params(axis="x", labelsize=7)
        ax.tick_params(axis="y", labelsize=8)
        ax.set_ylabel("%", fontsize=8)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        ax.grid(axis="y", alpha=0.25)
    fig.suptitle("Частоти літер до і після шифрування", fontsize=12, fontweight="bold")
    fig.tight_layout()


if __name__ == "__main__":
    CipherApp().mainloop()
