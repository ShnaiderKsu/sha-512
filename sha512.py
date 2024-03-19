import tkinter as tk
from tkinter import filedialog
from textwrap import wrap
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


def text_to_bits(text: str) -> str:
    # Конвертация текста в последовтельность битов
    bits = bin(int.from_bytes(text.encode(), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def ROTR(x, n: int, w: int = 64):
    # Функция циклического сдвига вправо
    return ((x >> n) | (x << (w - n))) & 0xffffffffffffffff


def SHR(x, n: int):
    # Функция сдвига вправо
    return (x >> n) & 0xffffffffffffffff


def sigma_0(x):
    # Функция sigma0{512} для SHA-512
    return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7)


def sigma_1(x):
    # Функция sigma1{512} для SHA-512
    return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6)


def eps_0(x):
    # Функция SIGMA_0{512} для SHA-512
    return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39)


def eps_1(x):
    # Функция SIGMA_1{512} для SHA-512
    return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41)


def Ch(x, y, z):
    # Функция Сh для SHA-512
    return ((x & y) ^ ((~ x) & z)) & 0xffffffffffffffff


def Maj(x, y, z):
    # Функция Maj для SHA-512
    return ((x & y) ^ (x & z) ^ (y & z)) & 0xffffffffffffffff


def K(t: int):
    # Возвращает нужный коэффициент для SHA-512
    k = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ]
    return k[t]


def sha_512(bits: str, num_bit: int = None):
    # Хэширование алгоритмом SHA-512
    if num_bit is not None:
        bit = '0' if bits[num_bit] == '1' else '1'
        bits = f"{bits[:num_bit]}{bit}{bits[num_bit + 1:]}"

    # Побитовое представление исходной длины сообщения
    bit_len = bin(len(bits))[2:].zfill(128)

    # Добавляем дополнительный единичный бит
    bits += '1'
    # Добавление нулевый битов до длины 896(mod 1024)
    while len(bits) % 1024 != 896:
        bits += '0'

    # Получаем блоки сообщений по 1024 бита
    blocks = wrap(f"{bits}{bit_len}", 1024)

    # Начальные значения хэш-функций
    h0, h1, h2, h3 = 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
    h4, h5, h6, h7 = 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

    # список, сохраняющий промежуточные значения хэш-функции
    # для подсчета изменившихся битов на каждом раунде
    avalanche = list()
    # Основной цикл - перебор всех 1024 битных блоков
    for block in blocks:
        # Разбиение на 64-битные слова -> каждое слово преобразуется в число
        w = list(map(lambda x: int(x, 2), wrap(block, 64)))
        # Подготовка списка преобразованных слов сообщения
        for t in range(16, 80):
            w.append((sigma_1(w[t - 2]) + w[t - 7] + sigma_0(w[t - 15]) + w[t - 16]) % (1 << 64))

        # Инициализация рабочих переменных
        a, b, c, d = h0, h1, h2, h3
        e, f, g, h = h4, h5, h6, h7

        # Внутренний цикл
        for t in range(80):
            T1 = (h + eps_1(e) + Ch(e, f, g) + K(t) + w[t]) % (1 << 64)
            T2 = (eps_0(a) + Maj(a, b, c)) % (1 << 64)
            h = g
            g = f
            f = e
            e = (d + T1) % (1 << 64)
            d = c
            c = b
            b = a
            a = (T1 + T2) % (1 << 64)

            avalanche.append([a, b, c, d, e, f, g, h])

        # Вычисление промежуточного значения хэш-функции
        h0, h1, h2, h3 = (a + h0) % (1 << 64), (b + h1) % (1 << 64), (c + h2) % (1 << 64), (d + h3) % (1 << 64)
        h4, h5, h6, h7 = (e + h4) % (1 << 64), (f + h5) % (1 << 64), (g + h6) % (1 << 64), (h + h7) % (1 << 64)

    # Результат
    hash_value = f"{h0:016x} {h1:016x} {h2:016x} {h3:016x} {h4:016x} {h5:016x} {h6:016x} {h7:016x}"
    return hash_value, avalanche


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("SHA-512")

        self.root.minsize(750, 700)
        self.root.maxsize(750, 700)

        # SHA-512
        self.label_title = tk.Label(root, text="SHA-512:", font=("Helvetica", 16))
        self.label_title.pack(side="top")

        # Фрейм для расположения элементов
        self.frame_input = tk.Frame(root)
        self.frame_input.pack(pady=(0, 5), side="top", padx=10, anchor="w")

        # Сообщение
        self.label_message = tk.Label(self.frame_input, text="Сообщение:")
        self.label_message.grid(row=0, column=0, sticky="w", padx=0, pady=(0, 5))

        # Поле ввода
        self.entry_message = tk.Text(self.frame_input, width=70, height=3)
        self.entry_message.grid(row=1, column=0, sticky="w", padx=0, pady=(0, 10))

        # Загрузить из файла
        self.button_load_file = tk.Button(self.frame_input, text="Загрузить из файла", command=self.load_from_file)
        self.button_load_file.grid(row=1, column=1, padx=30, pady=(0, 10))

        # Фрейм для расположения элементов
        self.frame_bit = tk.Frame(root)
        self.frame_bit.pack(pady=(0, 5), side="top", padx=10, anchor="w")

        # Номер бита
        self.label_bit_number = tk.Label(self.frame_bit, text="Номер бита:")
        self.label_bit_number.grid(row=0, column=0, sticky="e", padx=0, pady=(0, 5))

        self.entry_bit_number = tk.Entry(self.frame_bit, width=10)
        self.entry_bit_number.grid(row=0, column=1, sticky="w", padx=10, pady=(0, 5))

        # Устанавливаем валидацию для поля ввода номера бита
        self.vcmd = root.register(self.validate_bit_number)
        self.entry_bit_number.config(validate="key", validatecommand=(self.vcmd, "%P"))

        # Вычислить
        self.button_load_file = tk.Button(root, text="Вычислить", command=self.calculate)
        self.button_load_file.pack(pady=(0, 10))

        # Фрейм для расположения элементов
        self.frame_out = tk.Frame(root)
        self.frame_out.pack(pady=(0, 5), side="top", padx=10, anchor="w")

        # Хэш
        self.label_hash = tk.Label(self.frame_out, text="Хэш:")
        self.label_hash.grid(row=0, column=0, sticky="w", padx=0, pady=(0, 5))

        # Поле вывода
        self.text_hash = tk.Text(self.frame_out, width=70, height=3)
        self.text_hash.grid(row=1, column=0, sticky="w", padx=0, pady=(0, 5))

        # Сохранение в файл
        self.button_save_file = tk.Button(self.frame_out, text="Сохранить в файл", command=self.save_to_file)
        self.button_save_file.grid(row=1, column=1, padx=30, pady=(0, 5))

        # График
        self.label_avalanche = tk.Label(root, text="Лавинный эффект:", font=("Helvetica", 14))
        self.label_avalanche.pack(pady=(0, 5))

        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.fig.set_size_inches(4, 3)
        self.canvas.get_tk_widget().pack(pady=(0, 5), side="top", padx=10, anchor="s")

    def validate_bit_number(self, new_value):
        # Функция для валидации ввода номера бита
        if new_value == "":
            return True  # Разрешаем удаление, если поле пустое
        if new_value.isdigit():
            # Проверяем, что введено число
            if 0 <= int(new_value) <= 1023:
                return True
        return False

    def load_from_file(self):
        # Функция загрузки из файла
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename, 'r') as file:
                data = file.read()
                self.entry_message.delete("1.0", tk.END)
                self.entry_message.insert(tk.END, data)

    def save_to_file(self):
        # Функция сохранения в файл
        filename = filedialog.asksaveasfilename(defaultextension=".txt")
        if filename:
            with open(filename, 'w') as file:
                hash_text = self.text_hash.get("1.0", tk.END)
                file.write(hash_text)

    def draw_graph(self, x: list, y: list, bit: int):
        # Функция отрисовки графика лавинного эффекта
        plt.plot(x, y)

        plt.ylabel("Число изменившихся бит")
        plt.xlabel("Раунд")
        plt.title(f"Изменение в {bit} бите исходного сообщения:")

        self.canvas.draw()

    def calculate(self):
        # Кнопка вычислить
        message = self.entry_message.get("1.0", tk.END).strip()
        bit = self.entry_bit_number.get().strip()

        # сообщение в формате битов
        bits = text_to_bits(message) if message else ""
        bit = min(int(bit), len(bits) - 1) if bit else None

        sha512, avalanche = sha_512(bits, bit)

        if bit is not None and message:
            # Для лавинного эффекта считаем sha-512 без измененного бита
            sha512_, avalanche_orig = sha_512(bits)

            count = 0
            avalanche_y = list()
            for i in range(len(avalanche)):
                for x, y in zip(avalanche_orig[i], avalanche[i]):
                    count += bin(x ^ y)[2:].count('1')  # подсчет числа бит изменившихся с каждым раундом
                avalanche_y.append(count)
                count = 0

            x = range(1, len(avalanche) + 1)
            self.draw_graph(x, avalanche_y, bit)

        self.text_hash.delete("1.0", tk.END)
        self.text_hash.insert("1.0", sha512)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
