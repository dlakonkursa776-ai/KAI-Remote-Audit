import json, os, tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime
from common import *

import socket, ssl, threading, secrets, hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "KAI-Control-Center")])
    now = datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now.replace(year=now.year + 5))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    folder = DATA.parent
    cp, kp = folder / "control-cert.pem", folder / "control-key.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return str(cp), str(kp), fp

class Server:
    def __init__(self, ui):
        self.ui = ui
        self.token = secrets.token_urlsafe(32)
        self.cert, self.key, self.fp = make_cert()
        self.port = APP_PORT
        self.running = True
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.cert, self.key)
        threading.Thread(target=self.discovery, daemon=True, name="KAI-UDP-discovery").start()
        threading.Thread(target=self.listen, daemon=True, name="KAI-TCP-listener").start()

    def discovery(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", DISCOVERY_PORT))
            self.ui.root.after(0, self.ui.set_status,
                               f"Служба обнаружения запущена: UDP {DISCOVERY_PORT}.")
        except OSError as e:
            self.ui.root.after(0, self.ui.set_status,
                               f"ОШИБКА: не удалось запустить обнаружение UDP {DISCOVERY_PORT}: {e}")
            return
        s.settimeout(1)
        while self.running:
            try:
                data, addr = s.recvfrom(2048)
                if data == b"KAI_DISCOVER_V1":
                    beacon = json.dumps({"app": "KAI_CONTROL_V1", "port": self.port,
                        "token": self.token, "fingerprint": self.fp}).encode()
                    s.sendto(beacon, addr)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue
        s.close()

    def listen(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", self.port))
            s.listen(8)
            self.ui.root.after(0, self.ui.set_status,
                               f"Приём отчётов запущен: TCP {self.port}. Ожидание агентов.")
        except OSError as e:
            self.ui.root.after(0, self.ui.set_status,
                               f"ОШИБКА: не удалось открыть TCP {self.port}: {e}")
            return
        s.settimeout(1)
        while self.running:
            try:
                conn, addr = s.accept()
                threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
        s.close()

    def handle(self, raw, addr):
        try:
            with self.ctx.wrap_socket(raw, server_side=True) as c:
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 8192:
                    chunk = c.recv(4096)
                    if not chunk:
                        raise ValueError("Incomplete HTTP header")
                    data += chunk
                head, body = data.split(b"\r\n\r\n", 1)
                length = 0
                for line in head.decode("latin1").split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        length = int(line.split(":", 1)[1])
                if length < 0 or length > 20 * 1024 * 1024:
                    raise ValueError("Invalid report size")
                while len(body) < length:
                    chunk = c.recv(min(65536, length - len(body)))
                    if not chunk:
                        raise ValueError("Incomplete report body")
                    body += chunk
                req = json.loads(body[:length].decode("utf-8"))
                if req.get("token") != self.token:
                    raise ValueError("Invalid pairing token")
                report = req.get("report", {})
                name = report.get("system", {}).get("computer_name", "unknown")
                safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_")[:60] or "unknown"
                path = DATA / f"{safe}_{datetime.now():%Y%m%d_%H%M%S}.json"
                self.ui.root.after(0, self.ui.set_status,
                                   f"Отчёт принят от {name} ({addr[0]}). Сохранение данных…")
                path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
                self.ui.root.after(0, self.ui.refresh_reports)
                self.ui.root.after(0, self.ui.set_status,
                                   f"Отчёт сохранён: {name} ({addr[0]}), файл {path.name}")
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        except Exception as e:
            try:
                raw.close()
            except Exception:
                pass
            try:
                self.ui.root.after(0, self.ui.set_status, f"Ошибка соединения {addr[0]}: {e}")
            except Exception:
                pass

    def close(self):
        self.running = False



DATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "KAI" / "reports"
DATA.mkdir(parents=True, exist_ok=True)

def read_report(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}

def report_computer(report, path):
    return (report.get("system", {}).get("computer_name")
            or Path(path).stem.split("_")[0] or "unknown")


FIELD_NAMES = {
    "computer_name": "Имя компьютера", "user": "Пользователь",
    "os": "Операционная система", "windows_version": "Версия Windows",
    "architecture": "Архитектура", "ip_addresses": "IP-адреса",
    "boot_time": "Время запуска Windows", "collected_at": "Время сбора",
    "cpu": "Процессор", "logical_cores": "Логических ядер",
    "physical_cores": "Физических ядер", "cpu_percent": "Загрузка процессора",
    "ram_total_gb": "Всего оперативной памяти, ГБ",
    "ram_available_gb": "Доступно оперативной памяти, ГБ",
    "ram_percent": "Использование оперативной памяти, %",
    "disks": "Диски", "device": "Устройство", "mount": "Точка подключения",
    "filesystem": "Файловая система", "total_gb": "Объём, ГБ",
    "used_gb": "Занято, ГБ", "free_gb": "Свободно, ГБ", "percent": "Занято, %",
    "pid": "ID процесса", "name": "Название", "username": "Пользователь",
    "memory_mb": "Память, МБ", "cpu_percent": "Загрузка CPU, %",
    "status": "Состояние", "adapters": "Сетевые адаптеры",
    "connections": "Сетевые соединения", "family": "Тип адреса",
    "address": "Адрес", "netmask": "Маска сети", "type": "Тип соединения",
    "local": "Локальный адрес", "remote": "Удалённый адрес",
    "publisher": "Издатель", "version": "Версия",
    "source": "Источник данных", "events_text": "События Windows",
    "error": "Ошибка"
}

def readable_value(value):
    if value is None:
        return "Нет данных"
    if isinstance(value, bool):
        return "Да" if value else "Нет"
    if isinstance(value, list):
        if not value:
            return "Нет данных"
        if all(not isinstance(x, (dict, list)) for x in value):
            return ", ".join(str(x) for x in value)
        return "\n\n".join(
            f"{i}. " + readable_value(item).replace("\n", "\n   ")
            for i, item in enumerate(value, 1)
        )
    if isinstance(value, dict):
        if not value:
            return "Нет данных"
        lines = []
        for key, item in value.items():
            label = FIELD_NAMES.get(str(key), str(key).replace("_", " ").capitalize())
            rendered = readable_value(item)
            lines.append(f"{label}:\n{rendered}" if isinstance(item, (dict, list))
                         else f"{label}: {rendered}")
        return "\n".join(lines)
    return str(value)

def format_section(key, value):
    if key == "processes":
        if not value:
            return "Сведения о процессах не получены."
        rows = []
        for i, p in enumerate(value, 1):
            rows.append(
                f"{i}. {p.get('name') or 'Без названия'}\n"
                f"   ID процесса: {p.get('pid', '—')}\n"
                f"   Пользователь: {p.get('user') or 'нет данных'}\n"
                f"   Память: {p.get('memory_mb', '—')} МБ\n"
                f"   Загрузка CPU: {p.get('cpu_percent', '—')}%\n"
                f"   Состояние: {p.get('status') or 'нет данных'}"
            )
        return "\n\n".join(rows)
    if key == "software":
        if not value:
            return "Список установленных программ пуст или недоступен."
        return "\n\n".join(
            f"{i}. {p.get('name', 'Без названия')}\n"
            f"   Версия: {p.get('version') or 'не указана'}\n"
            f"   Издатель: {p.get('publisher') or 'не указан'}"
            for i, p in enumerate(value, 1)
        )
    return readable_value(value)

class Control:
    def __init__(self, root):
        self.root = root
        root.title("KAI Control Center")
        root.geometry("1180x760")
        root.minsize(900, 600)
        self.paths = {}
        self.current_path = None
        self.status = tk.StringVar(value="Загрузка сохранённых отчётов…")
        self.filter_text = tk.StringVar()
        self._build_ui()
        self.refresh_reports()
        self.server = Server(self)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.set_status(f"Запуск сетевых служб. Ожидаемые порты: UDP {DISCOVERY_PORT}, TCP {APP_PORT}.")

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=12)
        top.pack(fill="x")
        ttk.Label(top, text="KAI Remote Audit", font=("Segoe UI", 19, "bold")).pack(side="left")
        ttk.Label(top, text="Центр управления", foreground="gray").pack(side="left", padx=14)
        self.status_label = ttk.Label(self.root, textvariable=self.status, padding=(12, 4))
        self.status_label.pack(fill="x")
        self.activity = tk.Text(self.root, height=4, wrap="word", font=("Segoe UI", 9),
                                state="disabled", background="#f4f4f4")
        self.activity.pack(fill="x", padx=12, pady=(0, 6))
        self.log_activity("Центр управления запускается. Проверяется доступность сетевых портов.")

        main = ttk.Panedwindow(self.root, orient="horizontal")
        main.pack(fill="both", expand=True, padx=10, pady=8)
        left = ttk.Frame(main, padding=6)
        right = ttk.Frame(main, padding=6)
        main.add(left, weight=1)
        main.add(right, weight=3)

        ttk.Label(left, text="Компьютеры и история", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        search = ttk.Entry(left, textvariable=self.filter_text)
        search.pack(fill="x", pady=(7, 5))
        search.insert(0, "")
        self.filter_text.trace_add("write", lambda *_: self.refresh_reports())
        cols = ("pc", "ip", "time")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="extended", height=22)
        for col, title, width in [("pc", "Компьютер", 150), ("ip", "IP", 105), ("time", "Получен", 135)]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        actions = ttk.Frame(left)
        actions.pack(fill="x", pady=7)
        ttk.Button(actions, text="Обновить", command=self.refresh_reports).pack(side="left", padx=2)
        ttk.Button(actions, text="Экспорт JSON", command=self.export_report).pack(side="left", padx=2)
        ttk.Button(actions, text="Папка", command=lambda: os.startfile(DATA)).pack(side="left", padx=2)
        ttk.Button(left, text="Сравнить выбранные (2)", command=self.compare_reports).pack(fill="x", pady=3)

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)
        self.views = {}
        for key, title in [
            ("summary", "Сводка"), ("hardware", "Оборудование"),
            ("processes", "Процессы"), ("network", "Сеть"),
            ("software", "Программы"), ("events", "События Windows"),
            ("raw", "Полный JSON")
        ]:
            frame = ttk.Frame(self.notebook, padding=8)
            self.notebook.add(frame, text=title)
            text = tk.Text(frame, wrap="none", font=("Consolas", 9), state="disabled")
            y = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            x = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
            text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
            text.grid(row=0, column=0, sticky="nsew")
            y.grid(row=0, column=1, sticky="ns")
            x.grid(row=1, column=0, sticky="ew")
            frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
            self.views[key] = text

        bottom = ttk.Frame(self.root, padding=(12, 4))
        bottom.pack(fill="x")
        ttk.Label(bottom, text="Агент отправляет диагностический отчёт по локальной сети. Произвольное выполнение CMD в KAI не предусмотрено.",
                  foreground="gray").pack(anchor="w")

    def log_activity(self, value):
        if not hasattr(self, "activity"):
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        self.activity.configure(state="normal")
        self.activity.insert("end", f"{stamp} — {value}\\n")
        self.activity.see("end")
        self.activity.configure(state="disabled")

    def set_status(self, value):
        self.status.set(value)
        self.log_activity(value)

    def close(self):
        if hasattr(self, "server"):
            self.server.close()
        self.root.destroy()

    def refresh_reports(self):
        selected = set(self.tree.selection()) if hasattr(self, "tree") else set()
        if not hasattr(self, "tree"):
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.paths.clear()
        needle = self.filter_text.get().strip().lower()
        files = sorted(DATA.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in files:
            report = read_report(path)
            system = report.get("system", {})
            name = system.get("computer_name", path.stem)
            ip = ", ".join(system.get("ip_addresses", []) or [])
            stamp = system.get("collected_at", "")
            try:
                when = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M")
            except Exception:
                when = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            if needle and needle not in f"{name} {ip} {path.name}".lower():
                continue
            iid = self.tree.insert("", "end", values=(name, ip, when))
            self.paths[iid] = str(path)
        self.set_status(f"В истории: {len(self.paths)} отчётов. Папка: {DATA}")
        if selected:
            for iid, path in self.paths.items():
                if iid in selected:
                    self.tree.selection_add(iid)

    def on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        self.current_path = self.paths.get(sel[0])
        if self.current_path:
            self.show_report(read_report(self.current_path))

    def _put(self, key, value):
        widget = self.views[key]
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if isinstance(value, str):
            rendered = value
        else:
            rendered = json.dumps(value, ensure_ascii=False, indent=2, default=str)
        widget.insert("1.0", rendered if rendered else "Нет данных в отчёте.")
        widget.configure(state="disabled")

    def show_report(self, report):
        system = report.get("system", {})
        summary = {
            "Компьютер": system.get("computer_name"),
            "Пользователь": system.get("user"),
            "ОС": system.get("os"),
            "Версия Windows": system.get("windows_version"),
            "Архитектура": system.get("architecture"),
            "IP-адреса": system.get("ip_addresses"),
            "Время загрузки": system.get("boot_time"),
            "Собрано": system.get("collected_at"),
            "Процессов": len(report.get("processes", []) or []),
            "Установленных программ": len(report.get("software", []) or []),
        }
        self._put("summary", summary)
        self._put("hardware", format_section("hardware", report.get("hardware", {})))
        self._put("processes", format_section("processes", report.get("processes", [])))
        self._put("network", format_section("network", report.get("network", {})))
        self._put("software", format_section("software", report.get("software", [])))
        self._put("events", format_section("events", report.get("events", {})))
        self._put("raw", report)

    def selected_paths(self):
        return [self.paths[i] for i in self.tree.selection() if i in self.paths]

    def export_report(self):
        paths = self.selected_paths()
        if not paths:
            messagebox.showinfo("KAI", "Выберите отчёт.")
            return
        src = Path(paths[0])
        dest = filedialog.asksaveasfilename(
            defaultextension=".json", initialfile=src.name,
            filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")]
        )
        if dest:
            Path(dest).write_bytes(src.read_bytes())
            self.set_status(f"Экспортирован файл: {dest}")

    def compare_reports(self):
        paths = self.selected_paths()
        if len(paths) != 2:
            messagebox.showinfo("KAI", "Выберите ровно два отчёта в списке (Ctrl/Shift + щелчок).")
            return
        a, b = [read_report(p) for p in paths]
        sections = ["system", "hardware", "processes", "network", "software", "events"]
        diff = []
        for section in sections:
            if a.get(section) != b.get(section):
                diff.append(f"=== {section.upper()} ===\nПЕРВЫЙ ОТЧЁТ:\n"
                            f"{json.dumps(a.get(section), ensure_ascii=False, indent=2, default=str)}\n"
                            f"ВТОРОЙ ОТЧЁТ:\n"
                            f"{json.dumps(b.get(section), ensure_ascii=False, indent=2, default=str)}\n")
        win = tk.Toplevel(self.root)
        win.title("Сравнение отчётов")
        win.geometry("900x650")
        text = tk.Text(win, wrap="none", font=("Consolas", 9))
        sy = ttk.Scrollbar(win, orient="vertical", command=text.yview)
        sx = ttk.Scrollbar(win, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        text.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")
        sx.pack(side="bottom", fill="x")
        text.insert("1.0", "\n".join(diff) if diff else "Различий в диагностических разделах не найдено.")
        text.configure(state="disabled")

def main():
    root = tk.Tk()
    Control(root)
    root.mainloop()

if __name__ == "__main__":
    main()
