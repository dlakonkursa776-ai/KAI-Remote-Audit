import json, socket, uuid, platform, os, subprocess, time, hashlib
from datetime import datetime, timezone
import psutil

DISCOVERY_PORT = 39571
APP_PORT = 39572
APP_NAME = "KAI Remote Audit"

def hostname():
    return socket.gethostname()

def local_ips():
    found = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                found.add(a.address)
    return sorted(found)

def run_cmd(args, timeout=12):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return (p.stdout or p.stderr).strip()
    except Exception as e:
        return f"Unavailable: {e}"

def system_info():
    return {
        "computer_name": hostname(), "user": os.environ.get("USERNAME", ""),
        "os": platform.platform(), "windows_version": platform.version(),
        "architecture": platform.machine(), "ip_addresses": local_ips(),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
        "collected_at": datetime.now(timezone.utc).isoformat()
    }

def hardware_info():
    vm = psutil.virtual_memory()
    disks = []
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            disks.append({"device":p.device,"mount":p.mountpoint,"filesystem":p.fstype,
                          "total_gb":round(u.total/1e9,2),"used_gb":round(u.used/1e9,2),
                          "free_gb":round(u.free/1e9,2),"percent":u.percent})
        except Exception: pass
    return {"cpu": platform.processor() or platform.machine(),
            "logical_cores": psutil.cpu_count(), "physical_cores": psutil.cpu_count(logical=False),
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "ram_total_gb":round(vm.total/1e9,2),"ram_available_gb":round(vm.available/1e9,2),
            "ram_percent":vm.percent,"disks":disks}

def process_info():
    out=[]
    for p in psutil.process_iter(["pid","name","username","memory_info","cpu_percent","status"]):
        try:
            d=p.info; mi=d.get("memory_info")
            out.append({"pid":d.get("pid"),"name":d.get("name"),"user":d.get("username"),
                        "memory_mb":round(mi.rss/1048576,1) if mi else None,
                        "cpu_percent":d.get("cpu_percent"),"status":d.get("status")})
        except (psutil.NoSuchProcess, psutil.AccessDenied): pass
    return sorted(out,key=lambda x:x.get("memory_mb") or 0,reverse=True)

def network_info():
    adapters={}
    for name, addrs in psutil.net_if_addrs().items():
        adapters[name]=[{"family":str(a.family),"address":a.address,"netmask":a.netmask}
                        for a in addrs]
    conns=[]
    for c in psutil.net_connections(kind="inet"):
        try:
            conns.append({"family":str(c.family),"type":str(c.type),"local":str(c.laddr),
                          "remote":str(c.raddr),"status":c.status,"pid":c.pid})
        except Exception: pass
    return {"adapters":adapters,"connections":conns}

def software_info():
    if os.name != "nt": return []
    import winreg
    paths=[(winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
           (winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
           (winreg.HKEY_CURRENT_USER,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")]
    items={}
    for hive,path in paths:
        try: root=winreg.OpenKey(hive,path)
        except OSError: continue
        i=0
        while True:
            try: sub=winreg.EnumKey(root,i); i+=1
            except OSError: break
            try:
                k=winreg.OpenKey(root,sub)
                name,_=winreg.QueryValueEx(k,"DisplayName")
                try: ver,_=winreg.QueryValueEx(k,"DisplayVersion")
                except OSError: ver=""
                try: pub,_=winreg.QueryValueEx(k,"Publisher")
                except OSError: pub=""
                if name: items[name]={"name":name,"version":ver,"publisher":pub}
            except OSError: pass
    return sorted(items.values(),key=lambda x:x["name"].lower())

def event_info():
    if os.name != "nt": return {"error":"Windows only"}
    # Read recent System errors/warnings using the built-in Windows utility.
    text=run_cmd(["wevtutil","qe","System","/q:*[System[(Level=1 or Level=2 or Level=3)]]",
                  "/rd:true","/c:100","/f:text"],timeout=25)
    return {"source":"Windows System event log; latest 100 warning/error/critical events",
            "events_text":text}

def collect_all():
    return {"schema":"kai-report-v1","system":system_info(),"hardware":hardware_info(),
            "processes":process_info(),"network":network_info(),"software":software_info(),
            "events":event_info()}
