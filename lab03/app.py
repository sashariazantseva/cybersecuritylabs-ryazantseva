"""
ЛР3 "Невидимі дані у власних файлах" - графічний застосунок.
Автор: Рязанцева О.С., гр. 6.04.122.010.23.3

Вкладки:
  1. Як це працює      - текст -> біти -> молодші біти пікселів (покроково)
  2. Сховати / витягти - hide_message() та extract_message()
  3. Аналіз змін       - порівняння оригіналу і стегоконтейнера
  4. Пошук прихованого - LSB-площина, атака хі-квадрат, спроба витягнути дані
  5. Метадані EXIF     - що зберігає фото з телефона і як це очистити

Запуск:  python app.py
"""
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

from PIL import Image, ImageTk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import stego
import cipher
import analysis as A

HERE = Path(__file__).parent
IMAGES = HERE / "images"
RESULTS = HERE / "results"
MESSAGE = "Рязанцева Олександра Сергіївна, 16.05.2006"
KEY = "РЯЗАНЦЕВА"

ACCENT = "#2E4057"     # темно-синій
SOFT = "#F4F1EA"       # бежевий фон


def full(p: str) -> str:
    """Відносні шляхи рахуємо від папки програми."""
    return str(p if Path(p).is_absolute() else HERE / p)


class StegoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ЛР3 · Невидимі дані у власних файлах · Рязанцева О.С.")
        self.geometry("1100x760")
        self.configure(bg=SOFT)
        self._thumbs = []                  # щоб картинки не зникали
        self.cover = tk.StringVar(value="images/cover.png")
        self.stego_path = tk.StringVar(value="images/stego.png")
        self._style()
        ttk.Label(self, text="LSB-стеганографія: приховування тексту в зображенні",
                  style="Title.TLabel").pack(anchor="w", padx=12, pady=(10, 6))
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._tab_how()
        self._tab_hide()
        self._tab_compare()
        self._tab_search()
        self._tab_exif()
        self.update_how()

    # ------------------------------------------------------------ стиль
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", font=("Segoe UI", 10), background=SOFT)
        s.configure("TNotebook", background=SOFT)
        s.configure("TNotebook.Tab", padding=(14, 6), font=("Segoe UI", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", "white")],
              foreground=[("selected", ACCENT)])
        s.configure("TFrame", background="white")
        s.configure("TLabel", background="white")
        s.configure("TCheckbutton", background="white")
        s.configure("TRadiobutton", background="white")
        s.configure("Title.TLabel", background=SOFT, foreground=ACCENT,
                    font=("Segoe UI", 16, "bold"))
        s.configure("H.TLabel", font=("Segoe UI", 10, "bold"), foreground=ACCENT)
        s.configure("Accent.TButton", background=ACCENT, foreground="white",
                    font=("Segoe UI", 10, "bold"), padding=(12, 5))
        s.map("Accent.TButton", background=[("active", "#1E2B3B")])
        s.configure("Treeview", rowheight=24, font=("Consolas", 10))
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _thumb(self, label, path, size=(330, 330)):
        img = Image.open(path).convert("RGB")
        img.thumbnail(size)
        tk_img = ImageTk.PhotoImage(img)
        self._thumbs.append(tk_img)
        label.configure(image=tk_img)

    def _table(self, parent, cols, widths, height=8):
        t = ttk.Treeview(parent, columns=cols, show="headings", height=height)
        for c, w in zip(cols, widths):
            t.heading(c, text=c)
            t.column(c, width=w, anchor="center")
        return t

    # ------------------------------------------------- 1. як це працює
    def _tab_how(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="1 · Як це працює")
        ttk.Label(f, text="Повідомлення:", style="H.TLabel").pack(anchor="w")
        self.how_msg = tk.StringVar(value=MESSAGE)
        e = ttk.Entry(f, textvariable=self.how_msg, font=("Segoe UI", 11))
        e.pack(fill="x", pady=(2, 6))
        ttk.Button(f, text="Показати покроково", style="Accent.TButton",
                   command=self.update_how).pack(anchor="w")
        self.how_text = tk.Text(f, height=9, wrap="word", font=("Consolas", 10),
                                bg="#FBFAF7", relief="flat")
        self.how_text.pack(fill="x", pady=8)
        ttk.Label(f, text="Перші 9 значень каналів: що змінюється в пікселях",
                  style="H.TLabel").pack(anchor="w")
        cols = ("Піксель", "Було", "Було (біти)", "Біт повідомлення", "Стало (біти)", "Стало")
        self.how_table = self._table(f, cols, (110, 70, 130, 140, 130, 70), height=9)
        self.how_table.tag_configure("same", foreground="#888")
        self.how_table.pack(fill="x")

    def update_how(self):
        msg = self.how_msg.get()
        data = msg.encode("utf-8")
        t = self.how_text
        t.delete("1.0", "end")
        t.insert("end", f"1) Текст: {msg}\n")
        t.insert("end", f"2) UTF-8: {len(data)} байтів (кирилиця - 2 байти на літеру). "
                        f"Перші літери:\n")
        for ch in msg[:3]:
            bts = ch.encode("utf-8")
            t.insert("end", f"     '{ch}' -> {' '.join(f'{b:08b}' for b in bts)}\n")
        bits = len(stego.bytes_to_bits(stego.START + data + stego.END))
        t.insert("end", f"3) Додаємо маркери ST3G ... \\0END -> разом {bits} бітів\n")
        img = Image.open(full(self.cover.get()))
        t.insert("end", f"4) Фото {img.width}×{img.height}: {img.width * img.height * 3:,} "
                        f"молодших бітів (3 канали). Займаємо {bits / 3:.0f} пікселів "
                        f"= {100 * bits / (img.width * img.height * 3):.4f} % місткості\n"
                        .replace(",", " "))
        t.insert("end", "5) Кожен біт записуємо в молодший біт R, G або B: значення "
                        "змінюється максимум на 1 (з 255 можливих)")
        self.how_table.delete(*self.how_table.get_children())
        for r in stego.explain(msg, full(self.cover.get()), 9):
            tag = ("same",) if r["old"] == r["new"] else ()
            self.how_table.insert("", "end", tags=tag, values=(
                r["pixel"], r["old"], r["old_bin"], r["bit"], r["new_bin"], r["new"]))

    # -------------------------------------------- 2. сховати / витягти
    def _tab_hide(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="2 · Сховати / витягти")
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="Зображення:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.cover, width=70).grid(row=0, column=1, padx=6)
        ttk.Button(top, text="Обрати…", command=self.pick_cover).grid(row=0, column=2)
        ttk.Label(top, text="Повідомлення:").grid(row=1, column=0, sticky="w", pady=6)
        self.msg = tk.StringVar(value=MESSAGE)
        ttk.Entry(top, textvariable=self.msg, width=70).grid(row=1, column=1, padx=6)
        opts = ttk.Frame(f)
        opts.pack(fill="x", pady=4)
        ttk.Label(opts, text="Канали:").pack(side="left")
        self.channels = tk.StringVar(value="RGB")
        for ch in ("RGB", "R", "G", "B"):
            ttk.Radiobutton(opts, text=ch, variable=self.channels, value=ch).pack(side="left", padx=4)
        self.encrypt = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text=f"Зашифрувати Віженером перед приховуванням (ключ {KEY})",
                        variable=self.encrypt).pack(side="left", padx=20)
        btns = ttk.Frame(f)
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Сховати  →  stego.png", style="Accent.TButton",
                   command=self.do_hide).pack(side="left")
        ttk.Button(btns, text="Витягти з файлу…", command=self.do_extract).pack(side="left", padx=8)
        self.hide_out = tk.Text(f, height=6, wrap="word", font=("Consolas", 10),
                                bg="#FBFAF7", relief="flat")
        self.hide_out.pack(fill="x", pady=4)
        pics = ttk.Frame(f)
        pics.pack(fill="both", expand=True)
        for i, title in enumerate(("Оригінал", "Зі схованим повідомленням")):
            box = ttk.Frame(pics)
            box.grid(row=0, column=i, padx=10, sticky="n")
            ttk.Label(box, text=title, style="H.TLabel").pack()
            lbl = ttk.Label(box)
            lbl.pack()
            setattr(self, f"pic{i}", lbl)

    def pick_cover(self):
        p = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")])
        if p:
            self.cover.set(p)
            self.update_how()

    def do_hide(self):
        text = self.msg.get()
        if self.encrypt.get():
            text = cipher.encrypt(text, KEY)
        try:
            info = stego.hide_message(full(self.cover.get()), text, full(self.stego_path.get()),
                                      self.channels.get())
        except ValueError as e:
            messagebox.showerror("Помилка", str(e))
            return
        o = self.hide_out
        o.delete("1.0", "end")
        o.insert("end", f"Сховано: «{text}»\n")
        o.insert("end", f"Записано {info['bits']} бітів у {info['pixels_used']} пікселів "
                        f"(канали {self.channels.get()}); реально змінилось значень: "
                        f"{info['changed_values']} (інші біти вже збігались)\n")
        o.insert("end", f"Файл: {self.stego_path.get()}\n")
        o.insert("end", f"Витягнуто для перевірки: «{stego.extract_message(full(self.stego_path.get()), self.channels.get())}»")
        self._thumb(self.pic0, full(self.cover.get()))
        self._thumb(self.pic1, full(self.stego_path.get()))
        self.fill_compare()

    def do_extract(self, path=None):
        path = path or filedialog.askopenfilename(filetypes=[("Images", "*.png *.bmp *.jpg")])
        if not path:
            return
        o = self.hide_out
        o.delete("1.0", "end")
        try:
            text = stego.extract_message(path, self.channels.get())
        except ValueError as e:
            o.insert("end", f"{Path(path).name}: {e}")
            return
        o.insert("end", f"Файл: {Path(path).name}\nВитягнуто: «{text}»\n")
        if self.encrypt.get():
            o.insert("end", f"Розшифровано ключем {KEY}: «{cipher.decrypt(text, KEY)}»")

    # ------------------------------------------------ 3. аналіз змін
    def _tab_compare(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="3 · Аналіз змін")
        left = ttk.Frame(f)
        left.pack(side="left", fill="y")
        cols = ("Показник", "Значення")
        self.cmp = self._table(left, cols, (230, 170), height=11)
        self.cmp.pack(anchor="n")
        self.cmp_note = ttk.Label(left, wraplength=400, justify="left")
        self.cmp_note.pack(anchor="w", pady=8)
        right = ttk.Frame(f)
        right.pack(side="left", fill="both", expand=True, padx=10)
        ttk.Label(right, text="Карта відмінностей (червоне - змінені пікселі)",
                  style="H.TLabel").pack(anchor="w")
        self.diff_full = ttk.Label(right)
        self.diff_full.pack(side="left", anchor="n")
        zoom = ttk.Frame(right)
        zoom.pack(side="left", anchor="n", padx=10)
        ttk.Label(zoom, text="Збільшено: верхній лівий кут", style="H.TLabel").pack()
        self.diff_zoom = ttk.Label(zoom)
        self.diff_zoom.pack()

    def fill_compare(self):
        RESULTS.mkdir(exist_ok=True)
        c = A.compare(full(self.cover.get()), full(self.stego_path.get()))
        rows = [
            ("Розмір зображення", f"{c['width']}×{c['height']}"),
            ("Файл оригіналу, байт", f"{c['size_original_bytes']:,}".replace(",", " ")),
            ("Файл стего, байт", f"{c['size_stego_bytes']:,}".replace(",", " ")),
            ("Змінено пікселів", f"{c['changed_pixels']}"),
            ("Змінено пікселів, %", f"{c['changed_percent']:.4f}"),
            ("Змінено в каналі R", c["changed_R"]),
            ("Змінено в каналі G", c["changed_G"]),
            ("Змінено в каналі B", c["changed_B"]),
            ("Макс. різниця значення", c["max_difference"]),
            ("PSNR, дБ", f"{c['psnr_db']:.1f}"),
        ]
        self.cmp.delete(*self.cmp.get_children())
        for r in rows:
            self.cmp.insert("", "end", values=r)
        self.cmp_note.configure(text=(
            "Значення змінюються максимум на 1, тому оком різниці не видно. "
            "PSNR понад 50 дБ означає, що зміни непомітні. Розмір файлу майже "
            "не змінився, бо PNG стискає без втрат."))
        full_map = A.diff_map(full(self.cover.get()), full(self.stego_path.get()), str(RESULTS / "diff_map.png"))
        zoom = A.diff_map(full(self.cover.get()), full(self.stego_path.get()),
                          str(RESULTS / "diff_map_zoom.png"), zoom_rows=20)
        self._thumb(self.diff_full, full_map, (280, 500))
        self._thumb(self.diff_zoom, zoom, (330, 500))

    # -------------------------------------------- 4. пошук прихованого
    def _tab_search(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="4 · Пошук прихованого")
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Button(top, text="Перевірити зображення…", style="Accent.TButton",
                   command=self.do_search).pack(side="left")
        self.search_name = ttk.Label(top, style="H.TLabel")
        self.search_name.pack(side="left", padx=10)
        body = ttk.Frame(f)
        body.pack(fill="both", expand=True, pady=6)
        col = ttk.Frame(body)
        col.pack(side="left", anchor="n")
        ttk.Label(col, text="Молодші біти каналу R", style="H.TLabel").pack()
        self.lsb_img = ttk.Label(col)
        self.lsb_img.pack()
        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True, padx=10)
        self.search_out = tk.Text(right, height=9, wrap="word", font=("Consolas", 10),
                                  bg="#FBFAF7", relief="flat")
        self.search_out.pack(fill="x")
        self.fig = Figure(figsize=(6, 2.8), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=right)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def do_search(self, path=None):
        path = path or filedialog.askopenfilename(
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp")])
        if not path:
            return
        RESULTS.mkdir(exist_ok=True)
        self.search_name.configure(text=Path(path).name)
        plane = A.lsb_plane(path, str(RESULTS / f"lsb_{Path(path).stem}.png"))
        self._thumb(self.lsb_img, plane, (300, 450))
        o = self.search_out
        o.delete("1.0", "end")
        img = Image.open(path)
        o.insert("end", f"Формат: {img.format}, {img.width}×{img.height}\n")
        o.insert("end", f"Частка одиниць у LSB: {A.lsb_ones_ratio(path):.4f} (норма ≈ 0.5)\n")
        try:
            o.insert("end", f"Маркери ST3G знайдено! Текст: «{stego.extract_message(path)}»\n")
        except ValueError:
            o.insert("end", "Маркерів нашої програми немає\n")
        exif = A.read_exif(path)
        o.insert("end", f"Метадані: {exif.get('Кількість тегів EXIF', '0')} тегів EXIF")
        if "Model" in exif:
            o.insert("end", f" (камера {exif.get('Make', '')} {exif['Model']})")
        o.insert("end", "\n")
        rows = A.chi_square_attack(path)
        o.insert("end", "Атака χ²: ймовірність прихованих даних на початку файлу "
                        f"{rows[0]['p_hidden']:.2f}")
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        ax.plot([r["percent"] for r in rows], [r["p_hidden"] for r in rows],
                marker="o", color=ACCENT)
        ax.set_ylim(-0.05, 1.05)
        ax.set_xlabel("Перевірено зображення, %")
        ax.set_ylabel("P(є приховані дані)")
        ax.set_title("Атака хі-квадрат (Вестфельд)", fontsize=10, color=ACCENT, loc="left")
        ax.grid(alpha=0.3)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        self.fig.tight_layout()
        self.canvas.draw()

    # --------------------------------------------------------- 5. EXIF
    def _tab_exif(self):
        f = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(f, text="5 · Метадані EXIF")
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Button(top, text="Відкрити фото…", style="Accent.TButton",
                   command=self.do_exif).pack(side="left")
        ttk.Button(top, text="Очистити метадані", command=self.do_clean).pack(side="left", padx=8)
        self.exif_name = ttk.Label(top, style="H.TLabel")
        self.exif_name.pack(side="left", padx=10)
        body = ttk.Frame(f)
        body.pack(fill="both", expand=True, pady=8)
        for i, title in enumerate(("До очищення", "Після очищення")):
            box = ttk.Frame(body)
            box.pack(side="left", fill="both", expand=True, padx=6)
            ttk.Label(box, text=title, style="H.TLabel").pack(anchor="w")
            t = self._table(box, ("Тег", "Значення"), (170, 330), height=17)
            t.pack(fill="both", expand=True)
            setattr(self, f"exif{i}", t)
        self.exif_path = None

    def _fill_exif(self, table, path):
        table.delete(*table.get_children())
        data = A.read_exif(path)
        if data.get("Кількість тегів EXIF") == "0":
            table.insert("", "end", values=("-", "метаданих немає"))
            return
        for k, v in data.items():
            table.insert("", "end", values=(k, v))

    def do_exif(self, path=None):
        path = path or filedialog.askopenfilename(
            filetypes=[("Photos", "*.jpg *.jpeg *.heic *.png *.tif")])
        if path:
            self.exif_path = path
            self.exif_name.configure(text=Path(path).name)
            self._fill_exif(self.exif0, path)
            self.exif1.delete(*self.exif1.get_children())

    def do_clean(self):
        if not self.exif_path:
            messagebox.showinfo("EXIF", "Спочатку відкрийте фото")
            return
        RESULTS.mkdir(exist_ok=True)
        out = RESULTS / (Path(self.exif_path).stem + "_clean.jpg")
        A.strip_metadata(self.exif_path, str(out))
        self._fill_exif(self.exif1, str(out))
        self.exif_name.configure(text=f"{Path(self.exif_path).name}  →  {out.name}")


if __name__ == "__main__":
    StegoApp().mainloop()
