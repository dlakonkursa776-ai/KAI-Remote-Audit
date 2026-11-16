import socket, ssl, json, threading, time, os, sys, hashlib
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import messagebox
from common import *

def app_dir():
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "KAI"

def log(msg):
    try:
        app_dir().mkdir(parents=True,exist_ok=True)
        with (app_dir()/"agent.log").open("a",encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {msg}\n")
    except Exception: pass

class Agent:
    def __init__(self, status):
        self.status=status; self.stop=False; self.last_report=None
    def discover(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); s.settimeout(4)
        try:
            s.sendto(b"KAI_DISCOVER_V1",("<broadcast>",DISCOVERY_PORT))
            data,addr=s.recvfrom(4096)
            msg=json.loads(data.decode("utf-8"))
            if msg.get("app")=="KAI_CONTROL_V1":
                msg["host"]=addr[0]; return msg
        except Exception as e: log(f"discovery: {e}")
        finally: s.close()
        return None
    def send_report(self, server, report):
        raw=json.dumps(report,ensure_ascii=False).encode("utf-8")
        # TLS certificate fingerprint is pinned from the local discovery beacon.
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with socket.create_connection((server["host"],int(server["port"])),timeout=10) as sock:
            with ctx.wrap_socket(sock,server_hostname=server["host"]) as tls:
                cert=tls.getpeercert(binary_form=True)
                fp=hashlib.sha256(cert).hexdigest()
                if fp.lower()!=server["fingerprint"].lower():
                    raise RuntimeError("Control Center certificate fingerprint mismatch")
                request={"type":"report","token":server["token"],"report":report}
                body=json.dumps(request,ensure_ascii=False).encode("utf-8")
                tls.sendall((f"POST /report HTTP/1.1\r\nHost: {server['host']}\r\n"
                             f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                             f"Connection: close\r\n\r\n").encode()+body)
                response=tls.recv(4096)
                if b"200" not in response.split(b"\r\n",1)[0]:
                    raise RuntimeError("Control Center rejected report")
        self.last_report=datetime.now().strftime("%H:%M:%S")
        log("report sent")
    def run(self):
        while not self.stop:
            self.status("Состояние: поиск управляющего компьютера в локальной сети.")
            log("Состояние: поиск управляющего компьютера")
            server=self.discover()
            if not server:
                self.status("Состояние: управляющий компьютер не найден. Повтор поиска через 10 секунд.")
                log("Состояние: управляющий компьютер не найден")
                time.sleep(10); continue
            try:
                self.status(f"Состояние: управляющий компьютер обнаружен ({server['host']}). Начинаю сбор данных.")
                log(f"Состояние: управляющий компьютер обнаружен ({server['host']})")
                self.status("Состояние: сбор системной информации, оборудования, процессов, сети, программ и событий Windows.")
                report = collect_all()
                report["agent_id"] = hostname()
                self.status("Состояние: отправка диагностического отчёта.")
                self.send_report(server, report)
                self.status(f"Состояние: отчёт принят управляющим компьютером ({self.last_report}). Следующая отправка через 5 минут.")
                time.sleep(300)
            except Exception as e:
                log(str(e)); self.status(f"Состояние: ошибка передачи отчёта — {e}. Повтор через 15 секунд.")
                time.sleep(15)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="KAI Remote Audit Agent")
    parser.add_argument("--headless", action="store_true",
                        help="Run without a window; stop KAI_Agent.exe from Windows Task Manager.")
    args = parser.parse_args()

    if args.headless:
        # Explicitly user-launched mode: no service, autorun, persistence, or command shell.
        agent = Agent(lambda message: log(message))
        log("Agent started in explicit headless mode")
        try:
            agent.run()
        except KeyboardInterrupt:
            agent.stop = True
            log("Agent stopped by user")
        return

    root = tk.Tk()
    root.title("KAI Agent")
    root.geometry("470x190")
    root.resizable(False, False)
    tk.Label(root, text="KAI Remote Audit", font=("Segoe UI", 16, "bold")).pack(pady=(18, 8))
    status = tk.StringVar(value="Запуск агента…")
    tk.Label(root, textvariable=status, wraplength=420, justify="center").pack(padx=18, pady=12)
    tk.Label(root, text="Закрытие окна останавливает агент. Фоновый режим запускается отдельно ключом --headless.",
             font=("Segoe UI", 8), fg="gray").pack(pady=4)
    agent = Agent(lambda x: root.after(0, status.set, x))
    th = threading.Thread(target=agent.run, daemon=True)
    th.start()

    def close():
        agent.stop = True
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close)
    root.mainloop()

if __name__ == "__main__":
    main()
