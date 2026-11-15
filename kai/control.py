import socket, ssl, json, threading, secrets, hashlib, os, tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from common import *

DATA=Path(os.environ.get("LOCALAPPDATA",str(Path.home())))/"KAI"/"reports"
DATA.mkdir(parents=True,exist_ok=True)

def make_cert():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"KAI-Control-Center")])
    now=datetime.utcnow()
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now)
          .not_valid_after(now.replace(year=now.year+5))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .sign(key,hashes.SHA256()))
    folder=DATA.parent; cp=folder/"control-cert.pem"; kp=folder/"control-key.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption()))
    fp=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return str(cp),str(kp),fp

class Server:
    def __init__(self, ui):
        self.ui=ui; self.token=secrets.token_urlsafe(32); self.cert,self.key,self.fp=make_cert()
        self.port=APP_PORT; self.running=True
        self.ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); self.ctx.load_cert_chain(self.cert,self.key)
        threading.Thread(target=self.discovery,daemon=True).start()
        threading.Thread(target=self.listen,daemon=True).start()
    def discovery(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("",DISCOVERY_PORT))
        while self.running:
            try:
                data,addr=s.recvfrom(2048)
                if data==b"KAI_DISCOVER_V1":
                    beacon=json.dumps({"app":"KAI_CONTROL_V1","port":self.port,
                      "token":self.token,"fingerprint":self.fp}).encode()
                    s.sendto(beacon,addr)
            except Exception: pass
    def listen(self):
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(("",self.port)); s.listen(8)
        while self.running:
            try:
                conn,addr=s.accept()
                threading.Thread(target=self.handle,args=(conn,addr),daemon=True).start()
            except Exception: pass
    def handle(self,raw,addr):
        try:
            with self.ctx.wrap_socket(raw,server_side=True) as c:
                data=b""
                while b"\r\n\r\n" not in data and len(data)<8192: data+=c.recv(4096)
                head,body=data.split(b"\r\n\r\n",1)
                length=0
                for line in head.decode("latin1").split("\r\n"):
                    if line.lower().startswith("content-length:"): length=int(line.split(":",1)[1])
                while len(body)<length: body+=c.recv(min(65536,length-len(body)))
                req=json.loads(body[:length].decode("utf-8"))
                if req.get("token")!=self.token: raise ValueError("Invalid pairing token")
                report=req.get("report",{})
                name=report.get("system",{}).get("computer_name","unknown")
                safe="".join(ch for ch in name if ch.isalnum() or ch in "-_")[:60] or "unknown"
                path=DATA/f"{safe}_{datetime.now():%Y%m%d_%H%M%S}.json"
                path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
                self.ui.after(0,self.ui.add_report,str(path),name,addr[0])
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        except Exception as e:
            try: raw.close()
            except Exception: pass
            self.ui.after(0,self.ui.set_status,f"Отклонено соединение {addr[0]}: {e}")

class Control:
    def __init__(self,root):
        self.root=root; root.title("KAI Control Center"); root.geometry("900x590")
        top=ttk.Frame(root,padding=12); top.pack(fill="x")
        ttk.Label(top,text="KAI Control Center",font=("Segoe UI",18,"bold")).pack(side="left")
        self.status=tk.StringVar(value="Запуск защищённого сервера…")
        ttk.Label(root,textvariable=self.status,padding=8).pack(fill="x")
        cols=("pc","ip","time","file")
        self.tree=ttk.Treeview(root,columns=cols,show="headings",height=14)
        for c,t,w in [("pc","Компьютер",220),("ip","IP-адрес",150),("time","Получен",180),("file","Файл отчёта",300)]:
            self.tree.heading(c,text=t); self.tree.column(c,width=w)
        self.tree.pack(fill="both",expand=True,padx=12,pady=8)
        bar=ttk.Frame(root,padding=12); bar.pack(fill="x")
        ttk.Button(bar,text="Открыть отчёт",command=self.open_report).pack(side="left",padx=4)
        ttk.Button(bar,text="Экспорт JSON",command=self.export_report).pack(side="left",padx=4)
        ttk.Button(bar,text="Папка отчётов",command=lambda:os.startfile(DATA)).pack(side="left",padx=4)
        ttk.Label(root,text="Агент должен быть запущен в той же локальной сети. Сопряжение ограничено локальной сетью и секретом текущего сеанса.",
                  foreground="gray",padding=8).pack()
        self.paths={}
        self.server=Server(self); self.set_status(f"Ожидание агентов. TCP {APP_PORT}, UDP discovery {DISCOVERY_PORT}.")
    def set_status(self,s): self.status.set(s)
    def add_report(self,path,name,ip):
        iid=self.tree.insert("",0,values=(name,ip,datetime.now().strftime("%Y-%m-%d %H:%M:%S"),Path(path).name))
        self.paths[iid]=path; self.set_status(f"Получен отчёт от {name} ({ip})")
    def selected(self):
        sel=self.tree.selection()
        return self.paths.get(sel[0]) if sel else None
    def open_report(self):
        p=self.selected()
        if not p: messagebox.showinfo("KAI","Выберите отчёт."); return
        os.startfile(p)
    def export_report(self):
        p=self.selected()
        if not p: messagebox.showinfo("KAI","Выберите отчёт."); return
        dest=filedialog.asksaveasfilename(defaultextension=".json",filetypes=[("JSON","*.json")])
        if dest: Path(dest).write_bytes(Path(p).read_bytes())
def main():
    root=tk.Tk(); Control(root); root.mainloop()
if __name__=="__main__": main()
