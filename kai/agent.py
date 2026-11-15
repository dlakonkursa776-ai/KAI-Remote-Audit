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
    def send_report(self, server):
        report=collect_all()
        report["agent_id"]=str(uuid.uuid4()) if False else hostname()
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
            self.status("Поиск KAI Control Center в локальной сети…")
            server=self.discover()
            if not server:
                self.status("Управляющий ПК не найден. Повтор через 10 секунд.")
                time.sleep(10); continue
            try:
                self.status(f"Найден управляющий ПК: {server['host']}. Сбор диагностики…")
                self.send_report(server)
                self.status(f"Отчёт передан успешно ({self.last_report}). Следующая проверка через 5 минут.")
                time.sleep(300)
            except Exception as e:
                log(str(e)); self.status(f"Ошибка передачи: {e}. Повтор через 15 секунд.")
                time.sleep(15)

def main():
    root=tk.Tk(); root.title("KAI Agent"); root.geometry("470x190"); root.resizable(False,False)
    tk.Label(root,text="KAI Remote Audit",font=("Segoe UI",16,"bold")).pack(pady=(18,8))
    status=tk.StringVar(value="Запуск агента…")
    tk.Label(root,textvariable=status,wraplength=420,justify="center").pack(padx=18,pady=12)
    tk.Label(root,text="Диагностика работает в видимом режиме. Закрытие окна останавливает агент.",
             font=("Segoe UI",8),fg="gray").pack(pady=4)
    agent=Agent(lambda x: root.after(0,status.set,x))
    th=threading.Thread(target=agent.run,daemon=True); th.start()
    def close():
        agent.stop=True; root.destroy()
    root.protocol("WM_DELETE_WINDOW",close)
    root.mainloop()
if __name__=="__main__": main()
