import json, os, re, tkinter as tk
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
    if key == "network":
        if not value:
            return "Сетевые сведения не получены."
        lines = []
        adapters = value.get("adapters", {}) if isinstance(value, dict) else {}
        family_names = {"2": "IPv4", "10": "IPv6", "23": "IPv6"}
        for adapter_name, addresses in adapters.items():
            if not isinstance(addresses, list):
                continue
            useful = [a for a in addresses if isinstance(a, dict) and a.get("address")]
            if not useful:
                continue
            lines.append(f"{adapter_name}")
            for item in useful:
                family = family_names.get(str(item.get("family")), "Адрес")
                lines.append(f"  {family}: {item.get('address', '—')}")
                if item.get("netmask"):
                    lines.append(f"  Маска: {item['netmask']}")
            lines.append("")
        connections = value.get("connections", []) if isinstance(value, dict) else []
        if not isinstance(connections, list):
            connections = []
        state_names = {
            "ESTABLISHED": "Активно",
            "LISTEN": "Ожидает подключения",
            "TIME_WAIT": "Завершает соединение",
            "CLOSE_WAIT": "Ожидает закрытия",
            "SYN_SENT": "Устанавливает соединение",
            "SYN_RECV": "Получает запрос",
            "FIN_WAIT1": "Закрытие соединения",
            "FIN_WAIT2": "Ожидает завершения",
            "CLOSED": "Закрыто",
            "NONE": "Не установлено",
        }
        def endpoint(raw):
            if not raw:
                return "—"
            # psutil namedtuple string form: addr(ip='1.2.3.4', port=443)
            match = re.search(r"ip=['\"](.*?)['\"],\s*port=(\d+)", str(raw))
            if match:
                host, port = match.groups()
                return f"{host}:{port}"
            return str(raw)
        lines.append("СОЕДИНЕНИЯ")
        lines.append(f"Всего записей: {len(connections)}")
        lines.append("")
        for i, item in enumerate(connections[:100], 1):
            if not isinstance(item, dict):
                continue
            local = endpoint(item.get("local"))
            remote = endpoint(item.get("remote"))
            raw_state = str(item.get("status") or "NONE")
            state = state_names.get(raw_state, raw_state.replace("_", " ").capitalize())
            pid = item.get("pid")
            lines.append(
                f"{i}. {local}  →  {remote}\n"
                f"   Состояние: {state}\n"
                f"   Процесс ID: {pid if pid is not None else 'нет данных'}"
            )
        if len(connections) > 100:
            lines.append("")
            lines.append(f"Показаны первые 100 из {len(connections)} соединений.")
        return "\n\n".join(lines) if lines else "Сетевые адаптеры и соединения не обнаружены."
    if key == "processes":
        if isinstance(value, dict):
            value = value.get("items", value.get("processes", []))
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
        if isinstance(value, dict):
            value = value.get("items", value.get("software", []))
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
        # KAI dark / gold visual system
        self.bg = "#090909"
        self.panel = "#151515"
        self.panel2 = "#202020"
        self.gold = "#D6B45A"
        self.gold_soft = "#806B3C"
        self.white = "#F0EEE8"
        self.muted = "#AAA69A"
        self.root.configure(bg=self.bg)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=self.bg, foreground=self.gold,
                        fieldbackground=self.panel, bordercolor=self.gold_soft,
                        lightcolor=self.gold_soft, darkcolor=self.bg,
                        font=("Segoe UI", 9))
        style.configure("TFrame", background=self.bg)
        style.configure("Panel.TFrame", background=self.panel)
        style.configure("TLabel", background=self.bg, foreground=self.white)
        style.configure("Muted.TLabel", background=self.bg, foreground=self.muted)
        style.configure("Header.TLabel", background=self.bg, foreground=self.gold,
                        font=("Segoe UI", 18, "bold"))
        style.configure("Section.TLabel", background=self.panel, foreground=self.gold,
                        font=("Segoe UI", 10, "bold"))
        style.configure("TButton", background=self.panel2, foreground=self.gold,
                        bordercolor=self.gold_soft, padding=(10, 6))
        style.map("TButton", background=[("active", "#34302A")],
                  foreground=[("active", "#F2D889")])
        style.configure("TNotebook", background=self.bg, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=self.panel2, foreground=self.white,
                        borderwidth=0, padding=(12, 7))
        style.map("TNotebook.Tab", background=[("selected", "#34302A")],
                  foreground=[("selected", "#F2D889")])
        style.configure("Treeview", background=self.panel, fieldbackground=self.panel,
                        foreground=self.white, rowheight=29, borderwidth=0)
        style.configure("Treeview.Heading", background=self.panel2, foreground=self.gold,
                        borderwidth=0, font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#514326")],
                  foreground=[("selected", "#FFFFFF")])
        style.configure("KAI.Vertical.TScrollbar", gripcount=0, background="#4B4028",
                        troughcolor=self.panel, bordercolor=self.panel,
                        arrowcolor=self.gold, relief="flat", width=12)
        style.layout("KAI.Vertical.TScrollbar", [
            ("Vertical.Scrollbar.trough", {"children": [
                ("Vertical.Scrollbar thumb", {"expand": "1", "sticky": "nswe"})
            ], "sticky": "ns"})
        ])

        header = ttk.Frame(self.root, padding=(16, 12))
        header.pack(fill="x")
        ttk.Label(header, text="KAI  /  REMOTE AUDIT", style="Header.TLabel").pack(side="left")
        ttk.Label(header, text="ЦЕНТР УПРАВЛЕНИЯ", style="Muted.TLabel").pack(side="left", padx=16)

        # Current state is visually separated from the event history.
        state_panel = ttk.Frame(self.root, style="Panel.TFrame", padding=(14, 9))
        state_panel.pack(fill="x", padx=12, pady=(0, 7))
        ttk.Label(state_panel, text="ТЕКУЩЕЕ СОСТОЯНИЕ", style="Section.TLabel").pack(anchor="w")
        self.status_label = tk.Label(state_panel, textvariable=self.status,
                                     bg=self.panel, fg=self.white, anchor="w",
                                     justify="left", font=("Segoe UI", 10, "bold"),
                                     wraplength=1100)
        self.status_label.pack(fill="x", pady=(5, 0))

        # Short, bounded event log instead of a long mixed status line.
        activity_panel = ttk.Frame(self.root, style="Panel.TFrame", padding=(14, 7))
        activity_panel.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Label(activity_panel, text="ЖУРНАЛ ДЕЙСТВИЙ", style="Section.TLabel").pack(anchor="w")
        self.activity = tk.Text(activity_panel, height=3, wrap="word",
                                font=("Segoe UI", 9), state="disabled",
                                background=self.panel, foreground=self.white,
                                insertbackground=self.gold, relief="flat",
                                highlightthickness=0)
        self.activity.pack(fill="x", pady=(4, 0))
        self.log_activity("Центр управления запускается. Проверяется доступность сетевых портов.")

        main = ttk.Panedwindow(self.root, orient="horizontal")
        main.pack(fill="both", expand=True, padx=12, pady=6)
        left = ttk.Frame(main, style="Panel.TFrame", padding=9)
        right = ttk.Frame(main, style="Panel.TFrame", padding=9)
        main.add(left, weight=1)
        main.add(right, weight=3)

        ttk.Label(left, text="КОМПЬЮТЕРЫ И ИСТОРИЯ", style="Section.TLabel").pack(anchor="w")
        search = ttk.Entry(left, textvariable=self.filter_text)
        search.pack(fill="x", pady=(8, 7))
        self.filter_text.trace_add("write", lambda *_: self.refresh_reports())
        cols = ("pc", "ip", "time")
        self.tree = ttk.Treeview(left, columns=cols, show="headings",
                                 selectmode="extended", height=22)
        for col, title, width in [("pc", "Компьютер", 150), ("ip", "IP-адрес", 110),
                                  ("time", "Получен", 125)]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=(0, 7))
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        actions = ttk.Frame(left)
        actions.pack(fill="x", pady=3)
        ttk.Button(actions, text="Обновить", command=self.refresh_reports).pack(side="left", padx=2)
        ttk.Button(actions, text="Экспорт", command=self.export_report).pack(side="left", padx=2)
        ttk.Button(actions, text="Папка отчётов", command=lambda: os.startfile(DATA)).pack(side="left", padx=2)
        ttk.Button(left, text="Сравнить два отчёта", command=self.compare_reports).pack(fill="x", pady=(5, 2))

        ttk.Label(right, text="АНАЛИТИКА И ДИАГНОСТИКА", style="Section.TLabel").pack(anchor="w", pady=(0, 7))
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)
        self.views = {}
        for key, title in [
            ("summary", "◈  Сводка"), ("hardware", "▦  Оборудование"),
            ("processes", "▤  Процессы"), ("network", "⌁  Сеть"),
            ("software", "▣  Программы"), ("events", "◷  События Windows"),
            ("raw", "⚙  Технические данные")
        ]:
            frame = ttk.Frame(self.notebook, padding=8, style="Panel.TFrame")
            self.notebook.add(frame, text=title)
            text = tk.Text(frame, wrap="word", font=("Segoe UI", 10),
                           state="disabled", background=self.panel,
                           foreground=self.white, insertbackground=self.gold,
                           selectbackground="#514326", selectforeground="#FFFFFF",
                           relief="flat", padx=12, pady=10,
                           highlightthickness=0)
            y = ttk.Scrollbar(frame, orient="vertical", style="KAI.Vertical.TScrollbar",
                              command=text.yview)
            text.configure(yscrollcommand=y.set)
            text.grid(row=0, column=0, sticky="nsew")
            y.grid(row=0, column=1, sticky="ns")
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            self.views[key] = text

        footer = ttk.Frame(self.root, padding=(14, 6))
        footer.pack(fill="x")
        ttk.Label(footer,
                  text="KAI  •  Локальный аудит  •  Отчёты сохраняются на этом компьютере",
                  style="Muted.TLabel").pack(anchor="w")

    def log_activity(self, value):
        if not hasattr(self, "activity"):
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        self.activity.configure(state="normal")
        self.activity.insert("end", f"{stamp} — {value}\n")
        line_count = int(self.activity.index("end-1c").split(".")[0])
        if line_count > 100:
            self.activity.delete("1.0", f"{line_count-100}.0")
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
        sections = {
            "summary": lambda: readable_value(summary),
            "hardware": lambda: format_section("hardware", report.get("hardware", {})),
            "processes": lambda: format_section("processes", report.get("processes", [])),
            "network": lambda: format_section("network", report.get("network", {})),
            "software": lambda: format_section("software", report.get("software", [])),
            "events": lambda: format_section("events", report.get("events", {})),
            "raw": lambda: json.dumps(report, ensure_ascii=False, indent=2, default=str),
        }
        for key, render in sections.items():
            try:
                value = render()
                self._put(key, value if value else "Для этого раздела в отчёте нет данных.")
            except Exception as exc:
                self._put(key, f"Не удалось отобразить раздел. Ошибка обработки данных: {exc}")
                self.log_activity(f"Ошибка отображения раздела «{key}»: {exc}")

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
        win.title("KAI — Сравнение отчётов")
        win.geometry("900x650")
        win.configure(bg="#090909")
        text = tk.Text(win, wrap="word", font=("Segoe UI", 10),
                       background="#151515", foreground="#F0EEE8",
                       insertbackground="#D6B45A", selectbackground="#514326",
                       relief="flat", padx=10, pady=8)
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
