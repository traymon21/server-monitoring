from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import psutil
import platform
import time
import os
import json
import threading
import subprocess
from datetime import datetime, timedelta
from functools import wraps
import socket
from collections import deque
import urllib.request

# ============== LOAD CONFIG DARI FILE ==============
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

def load_config():
    default = {
        "password": "admin123",
        "secret_key": "ganti-dengan-kunci-rahasia-yang-panjang-dan-acak",
        "discord_webhook": "",
        "host": "0.0.0.0",
        "port": 5000,
        "thresholds": {
            "rx_mbps": 150.0,
            "pps": 5000,
            "syn_recv": 50,
            "conntrack_percent": 30.0,
            "duration_sec": 3
        },
        "alert_cooldown": 120,
        "external_targets": [
            {"name": "Server Sample", "host": "144.225.53.171", "port": 7019, "timeout": 3}
        ],
        "external_check_interval": 30
    }
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                default.update(data)
                if "thresholds" in data:
                    default["thresholds"].update(data["thresholds"])
    except Exception as e:
        print(f"[Config] Gagal load config.json: {e}")
    return default

config = load_config()

PASSWORD = config["password"]
DISCORD_WEBHOOK = config.get("discord_webhook", "")
THRESHOLDS = config["thresholds"]
ALERT_COOLDOWN = config.get("alert_cooldown", 120)
HOST = config.get("host", "0.0.0.0")
PORT = config.get("port", 5000)
EXTERNAL_TARGETS = config.get("external_targets", [])
EXTERNAL_INTERVAL = config.get("external_check_interval", 30)

app = Flask(__name__)
app.secret_key = config.get("secret_key", "ganti-dengan-kunci-rahasia")
# ==================================================

# External monitor state
ext_history = {}
ext_status = {}
ext_last_alert = {}
EXT_LOG = os.path.join(os.path.dirname(__file__), "external_history.json")

for t in EXTERNAL_TARGETS:
    key = f"{t['host']}:{t['port']}"
    ext_history[key] = deque(maxlen=300)
    ext_status[key] = {"online": None, "latency": None, "last_check": None, "name": t.get("name", key), "host": t["host"], "port": t["port"]}
    ext_last_alert[key] = 0

def load_ext_history():
    try:
        if os.path.exists(EXT_LOG):
            with open(EXT_LOG, "r") as f:
                data = json.load(f)
                for k, v in data.items():
                    if k in ext_history:
                        ext_history[k] = deque(v, maxlen=300)
    except Exception:
        pass

def save_ext_history():
    try:
        with open(EXT_LOG, "w") as f:
            json.dump({k: list(v) for k, v in ext_history.items()}, f)
    except Exception:
        pass

load_ext_history()

def check_port(host, port, timeout=3):
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        latency = round((time.time() - start) * 1000, 1)
        return (result == 0), (latency if result == 0 else None)
    except Exception:
        return False, None

def external_checker_loop():
    while True:
        for t in EXTERNAL_TARGETS:
            host, port = t["host"], t["port"]
            key = f"{host}:{port}"
            name = t.get("name", key)
            online, latency = check_port(host, port, t.get("timeout", 3))
            now = datetime.now().isoformat()
            entry = {"time": now, "time_str": datetime.now().strftime("%H:%M:%S"), "online": online, "latency": latency}
            if key in ext_history:
                ext_history[key].append(entry)
            prev = ext_status.get(key, {}).get("online")
            ext_status[key] = {"online": online, "latency": latency, "last_check": now, "name": name, "host": host, "port": port}
            # Alert on status change
            if prev is True and online is False and (time.time() - ext_last_alert.get(key, 0) > ALERT_COOLDOWN):
                send_discord(f"**🔴 Server Offline**\n**{name}**\n`{host}:{port}`\n{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                ext_last_alert[key] = time.time()
            elif prev is False and online is True and (time.time() - ext_last_alert.get(key, 0) > ALERT_COOLDOWN):
                send_discord(f"**🟢 Server Online Kembali**\n**{name}**\n`{host}:{port}`\nLatency: {latency} ms\n{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
                ext_last_alert[key] = time.time()
        save_ext_history()
        time.sleep(EXTERNAL_INTERVAL)

# Start external checker
if EXTERNAL_TARGETS:
    threading.Thread(target=external_checker_loop, daemon=True).start()

# History untuk chart
history = {
    "cpu": deque(maxlen=120),
    "ram": deque(maxlen=120),
    "net_sent": deque(maxlen=120),
    "net_recv": deque(maxlen=120),
    "pps": deque(maxlen=120),
    "timestamps": deque(maxlen=120),
}

# Peak values (tertinggi)
peaks = {
    "cpu": 0.0,
    "ram": 0.0,
    "rx_mbps": 0.0,
    "tx_mbps": 0.0,
    "pps": 0,
    "rx_mbps_time": None,
    "cpu_time": None,
    "ram_time": None,
}

# DDoS Log (simpan di memory + file)
ddos_logs = deque(maxlen=100)
LOG_FILE = os.path.join(os.path.dirname(__file__), "ddos_logs.json")

# State untuk deteksi
prev_net = psutil.net_io_counters()
prev_time = time.time()
prev_packets = prev_net.packets_recv
detection_start = None
last_alert_time = 0
current_attack = None

lock = threading.Lock()


def load_logs():
    global ddos_logs
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                data = json.load(f)
                ddos_logs = deque(data, maxlen=100)
    except Exception:
        pass


def save_logs():
    try:
        with open(LOG_FILE, "w") as f:
            json.dump(list(ddos_logs), f, indent=2)
    except Exception:
        pass


load_logs()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            # API → JSON 401, bukan HTML redirect
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Session habis, silakan login ulang"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_size(bytes_val):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(bytes_val) < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} PB"


def get_uptime():
    boot = datetime.fromtimestamp(psutil.boot_time())
    delta = datetime.now() - boot
    days = delta.days
    hours, rem = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    if days > 0:
        return f"{days} hari {hours} jam {minutes} menit"
    elif hours > 0:
        return f"{hours} jam {minutes} menit"
    return f"{minutes} menit {seconds} detik"


def get_syn_recv():
    """Coba ambil jumlah SYN_RECV (Linux only)"""
    try:
        out = subprocess.check_output(["ss", "-ant"], stderr=subprocess.DEVNULL, text=True, timeout=2)
        return out.count("SYN-RECV")
    except Exception:
        return 0


def get_conntrack():
    """Ambil conntrack count & max (Linux)"""
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
            count = int(f.read().strip())
        with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
            max_c = int(f.read().strip())
        return count, max_c, round(count / max_c * 100, 1) if max_c else 0
    except Exception:
        return 0, 0, 0.0


def send_discord(content: str, embed: dict = None):
    """Kirim pesan ke Discord webhook"""
    if not DISCORD_WEBHOOK:
        return False
    try:
        payload = {"content": content}
        if embed:
            payload["embeds"] = [embed]
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            DISCORD_WEBHOOK,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "ServerMonitor/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 204)
    except Exception as e:
        print(f"[Discord] Error: {e}")
        return False


def format_attack_message(attack: dict) -> str:
    """Format pesan mirip contoh user"""
    samples = attack.get("samples", [])
    sample_text = ""
    if samples:
        sample_text = "\nSumber paket teramati (bukan atribusi identitas):\n```\n"
        sample_text += f"Sampel: {attack.get('sample_count', 0)} paket dalam ≤{attack.get('duration', 0)} detik\n"
        for s in samples[:12]:
            sample_text += f"{s}\n"
        sample_text += "```"

    msg = (
        f"**Dugaan serangan DDoS real-time**\n"
        f"Traffic masuk: **{attack['rx_mbps']:.1f} Mbps** / **{attack['pps']} pps**\n"
        f"SYN_RECV: **{attack['syn_recv']}**  "
        f"Conntrack: **{attack['conntrack']}/{attack['conntrack_max']}** ({attack['conntrack_pct']}%)\n"
        f"Terdeteksi selama: **{attack['duration']} detik**\n"
        f"Pemicu: RX **{attack['rx_mbps']:.1f} Mbps** ≥ {THRESHOLDS['rx_mbps']}\n"
        f"{sample_text}\n"
        f"`{socket.gethostname()}` • sampling 1 detik • {attack['time']}"
    )
    return msg


def format_normal_message(attack: dict) -> str:
    msg = (
        f"**1. Trafik kembali normal**\n"
        f"Traffic masuk: **{attack.get('end_rx', 0):.1f} Mbps** / **{attack.get('end_pps', 0)} pps**\n"
        f"SYN_RECV: **{attack.get('end_syn', 0)}**  "
        f"Conntrack: **{attack.get('end_ct', 0)}/{attack.get('conntrack_max', 0)}** "
        f"({attack.get('end_ct_pct', 0)}%)\n"
        f"Normal stabil: **{attack.get('normal_duration', 30)} detik**\n"
        f"Peak serangan: **{attack['peak_rx']:.1f} Mbps** / **{attack['peak_pps']} pps**, "
        f"SYN {attack['peak_syn']}, conntrack {attack['peak_ct_pct']}%\n"
        f"`{socket.gethostname()}` • {datetime.now().strftime('%d/%m/%Y %H:%M')}"
    )
    return msg


def check_ddos(rx_mbps, pps, syn_recv, ct_count, ct_max, ct_pct):
    """Logika deteksi sederhana + kirim alert"""
    global detection_start, last_alert_time, current_attack

    is_suspicious = (
        rx_mbps >= THRESHOLDS["rx_mbps"]
        or pps >= THRESHOLDS["pps"]
        or syn_recv >= THRESHOLDS["syn_recv"]
        or ct_pct >= THRESHOLDS["conntrack_percent"]
    )

    now = time.time()

    with lock:
        if is_suspicious:
            if detection_start is None:
                detection_start = now
                current_attack = {
                    "start": now,
                    "peak_rx": rx_mbps,
                    "peak_pps": pps,
                    "peak_syn": syn_recv,
                    "peak_ct_pct": ct_pct,
                    "samples": [],
                    "sample_count": 0,
                }

            # update peak
            current_attack["peak_rx"] = max(current_attack["peak_rx"], rx_mbps)
            current_attack["peak_pps"] = max(current_attack["peak_pps"], pps)
            current_attack["peak_syn"] = max(current_attack["peak_syn"], syn_recv)
            current_attack["peak_ct_pct"] = max(current_attack["peak_ct_pct"], ct_pct)

            duration = int(now - detection_start)

            if duration >= THRESHOLDS["duration_sec"] and (now - last_alert_time) > ALERT_COOLDOWN:
                # Ambil sampel sederhana dari ss (bukan full packet capture)
                samples = []
                try:
                    out = subprocess.check_output(
                        ["ss", "-antup"], stderr=subprocess.DEVNULL, text=True, timeout=2
                    )
                    lines = [l for l in out.splitlines() if "ESTAB" in l or "SYN-RECV" in l][:15]
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 5:
                            samples.append(f"{parts[0]:8} | {parts[4]}")
                except Exception:
                    samples = ["(tidak bisa ambil sampel koneksi)"]

                attack_data = {
                    "rx_mbps": round(rx_mbps, 1),
                    "pps": pps,
                    "syn_recv": syn_recv,
                    "conntrack": ct_count,
                    "conntrack_max": ct_max,
                    "conntrack_pct": ct_pct,
                    "duration": duration,
                    "time": datetime.now().strftime("%d/%m/%Y %H:%M"),
                    "samples": samples,
                    "sample_count": len(samples),
                    "peak_rx": current_attack["peak_rx"],
                    "peak_pps": current_attack["peak_pps"],
                    "peak_syn": current_attack["peak_syn"],
                    "peak_ct_pct": current_attack["peak_ct_pct"],
                }

                # Simpan log
                log_entry = {
                    "type": "attack_detected",
                    "time": datetime.now().isoformat(),
                    "data": attack_data,
                }
                ddos_logs.appendleft(log_entry)
                save_logs()

                # Kirim Discord
                msg = format_attack_message(attack_data)
                send_discord(msg)
                last_alert_time = now

                current_attack["alerted"] = True

        else:
            # Trafik normal
            if detection_start is not None and current_attack:
                duration = int(now - detection_start)
                if duration >= THRESHOLDS["duration_sec"] and current_attack.get("alerted"):
                    # Kirim pesan "trafik kembali normal"
                    end_data = {
                        **current_attack,
                        "end_rx": round(rx_mbps, 1),
                        "end_pps": pps,
                        "end_syn": syn_recv,
                        "end_ct": ct_count,
                        "end_ct_pct": ct_pct,
                        "normal_duration": 30,
                        "conntrack_max": ct_max,
                    }
                    msg = format_normal_message(end_data)
                    send_discord(msg)

                    log_entry = {
                        "type": "attack_ended",
                        "time": datetime.now().isoformat(),
                        "data": end_data,
                    }
                    ddos_logs.appendleft(log_entry)
                    save_logs()

                detection_start = None
                current_attack = None


def get_network_speed():
    global prev_net, prev_time, prev_packets
    current = psutil.net_io_counters()
    now = time.time()
    elapsed = max(now - prev_time, 0.1)

    sent_speed = (current.bytes_sent - prev_net.bytes_sent) / elapsed
    recv_speed = (current.bytes_recv - prev_net.bytes_recv) / elapsed
    pps = int((current.packets_recv - prev_packets) / elapsed)

    prev_net = current
    prev_time = now
    prev_packets = current.packets_recv

    return {
        "bytes_sent": current.bytes_sent,
        "bytes_recv": current.bytes_recv,
        "sent_speed": sent_speed,
        "recv_speed": recv_speed,
        "sent_mbps": sent_speed * 8 / 1_000_000,
        "recv_mbps": recv_speed * 8 / 1_000_000,
        "pps": max(pps, 0),
        "packets_sent": current.packets_sent,
        "packets_recv": current.packets_recv,
    }


def get_system_info():
    uname = platform.uname()
    return {
        "hostname": socket.gethostname(),
        "os": f"{uname.system} {uname.release}",
        "architecture": uname.machine,
        "processor": uname.processor or platform.processor() or "N/A",
        "python": platform.python_version(),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": get_uptime(),
    }


def get_cpu_info():
    freq = psutil.cpu_freq()
    return {
        "percent": psutil.cpu_percent(interval=0.2),
        "count_physical": psutil.cpu_count(logical=False) or 1,
        "count_logical": psutil.cpu_count(logical=True) or 1,
        "freq_current": round(freq.current, 1) if freq else 0,
        "load_avg": [round(x, 2) for x in os.getloadavg()] if hasattr(os, "getloadavg") else [0, 0, 0],
    }


def get_memory_info():
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "percent": mem.percent,
        "total": mem.total,
        "used": mem.used,
        "total_human": get_size(mem.total),
        "used_human": get_size(mem.used),
        "swap_percent": swap.percent,
        "swap_total_human": get_size(swap.total),
        "swap_used_human": get_size(swap.used),
    }


def get_disk_info():
    partitions = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            partitions.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "percent": usage.percent,
                "total_human": get_size(usage.total),
                "used_human": get_size(usage.used),
                "free_human": get_size(usage.free),
            })
        except (PermissionError, OSError):
            continue
    return partitions


def get_top_processes(limit=12):
    processes = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "status"]):
        try:
            info = proc.info
            processes.append({
                "pid": info["pid"],
                "name": (info["name"] or "?")[:30],
                "username": info["username"] or "?",
                "cpu": round(info["cpu_percent"] or 0, 1),
                "memory": round(info["memory_percent"] or 0, 1),
                "status": info["status"],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    processes.sort(key=lambda x: (x["cpu"], x["memory"]), reverse=True)
    return processes[:limit]


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Password salah!"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html",
                           webhook_set=bool(DISCORD_WEBHOOK),
                           thresholds=THRESHOLDS)


@app.route("/api/stats")
@login_required
def api_stats():
    cpu = get_cpu_info()
    mem = get_memory_info()
    net = get_network_speed()
    disks = get_disk_info()
    processes = get_top_processes()
    sysinfo = get_system_info()
    syn = get_syn_recv()
    ct_count, ct_max, ct_pct = get_conntrack()

    # Update history
    now_str = datetime.now().strftime("%H:%M:%S")
    history["cpu"].append(cpu["percent"])
    history["ram"].append(mem["percent"])
    history["net_sent"].append(round(net["sent_mbps"], 2))
    history["net_recv"].append(round(net["recv_mbps"], 2))
    history["pps"].append(net["pps"])
    history["timestamps"].append(now_str)

    # Update peaks
    now_iso = datetime.now().isoformat()
    if cpu["percent"] > peaks["cpu"]:
        peaks["cpu"] = round(cpu["percent"], 1)
        peaks["cpu_time"] = now_iso
    if mem["percent"] > peaks["ram"]:
        peaks["ram"] = round(mem["percent"], 1)
        peaks["ram_time"] = now_iso
    if net["recv_mbps"] > peaks["rx_mbps"]:
        peaks["rx_mbps"] = round(net["recv_mbps"], 1)
        peaks["rx_mbps_time"] = now_iso
    if net["sent_mbps"] > peaks["tx_mbps"]:
        peaks["tx_mbps"] = round(net["sent_mbps"], 1)
    if net["pps"] > peaks["pps"]:
        peaks["pps"] = net["pps"]

    # Deteksi DDoS
    check_ddos(net["recv_mbps"], net["pps"], syn, ct_count, ct_max, ct_pct)

    return jsonify({
        "cpu": cpu,
        "memory": mem,
        "network": {
            **net,
            "sent_speed_human": get_size(net["sent_speed"]) + "/s",
            "recv_speed_human": get_size(net["recv_speed"]) + "/s",
            "bytes_sent_human": get_size(net["bytes_sent"]),
            "bytes_recv_human": get_size(net["bytes_recv"]),
        },
        "disks": disks,
        "processes": processes,
        "system": sysinfo,
        "syn_recv": syn,
        "conntrack": {"count": ct_count, "max": ct_max, "percent": ct_pct},
        "history": {
            "cpu": list(history["cpu"]),
            "ram": list(history["ram"]),
            "net_sent": list(history["net_sent"]),
            "net_recv": list(history["net_recv"]),
            "pps": list(history["pps"]),
            "timestamps": list(history["timestamps"]),
        },
        "peaks": peaks,
        "ddos_logs": list(ddos_logs)[:20],
        "detection_active": detection_start is not None,
        "thresholds": THRESHOLDS,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "external": [
            {
                **ext_status.get(k, {}),
                "key": k,
                "history": list(ext_history.get(k, []))[-40:],
                "uptime_percent": round(sum(1 for h in ext_history.get(k, []) if h.get("online")) / max(len(ext_history.get(k, [])), 1) * 100, 1) if ext_history.get(k) else None
            }
            for k in ext_status
        ],
    })


@app.route("/api/settings", methods=["POST"])
@login_required
def update_settings():
    global THRESHOLDS, DISCORD_WEBHOOK, config
    data = request.json or {}
    if "thresholds" in data:
        for k, v in data["thresholds"].items():
            if k in THRESHOLDS:
                try:
                    THRESHOLDS[k] = type(THRESHOLDS[k])(v)
                except Exception:
                    pass
    if "webhook" in data:
        DISCORD_WEBHOOK = data["webhook"].strip()
        config["discord_webhook"] = DISCORD_WEBHOOK

    # Simpan ke config.json
    try:
        config["thresholds"] = THRESHOLDS
        config["discord_webhook"] = DISCORD_WEBHOOK
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"[Config] Gagal simpan: {e}")

    return jsonify({"success": True, "thresholds": THRESHOLDS})


@app.route("/api/test-webhook", methods=["POST"])
@login_required
def test_webhook():
    if not DISCORD_WEBHOOK:
        return jsonify({"success": False, "message": "Webhook belum di-set"}), 400
    ok = send_discord("**Test notifikasi** dari Server Monitor Dashboard\nWebhook berhasil terhubung!")
    return jsonify({"success": ok, "message": "Terkirim!" if ok else "Gagal kirim"})


@app.route("/api/notify", methods=["POST"])
@login_required
def notify_discord():
    data = request.json or {}
    message = (data.get("message") or "").strip()
    use_embed = data.get("embed", False)
    title = (data.get("title") or "Notifikasi").strip()
    if not message:
        return jsonify({"success": False, "message": "Pesan kosong"}), 400
    if not DISCORD_WEBHOOK:
        return jsonify({"success": False, "message": "Webhook belum di-set"}), 400
    try:
        if use_embed:
            payload = {"embeds": [{"title": title, "description": message, "color": 3447003,
                                   "timestamp": datetime.utcnow().isoformat(), "footer": {"text": "Full Monitor"}}]}
        else:
            payload = {"content": message}
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(DISCORD_WEBHOOK, data=body,
                                     headers={"Content-Type": "application/json", "User-Agent": "FullMonitor/1.0"}, method="POST")
        with urllib.request.urlopen(req, timeout=8) as resp:
            ok = resp.status in (200, 204)
        return jsonify({"success": ok, "message": "Terkirim!" if ok else "Gagal"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/process/<int:pid>/kill", methods=["POST"])
@login_required
def kill_process(pid):
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        gone, alive = psutil.wait_procs([p], timeout=3)
        if alive:
            p.kill()
        return jsonify({"success": True, "message": f"Proses {name} (PID {pid}) dihentikan"})
    except psutil.NoSuchProcess:
        return jsonify({"success": False, "message": "Proses tidak ditemukan"}), 404
    except psutil.AccessDenied:
        return jsonify({"success": False, "message": "Akses ditolak"}), 403
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


if __name__ == "__main__":
    print("=" * 55)
    print("  Server Monitoring + DDoS Detection Dashboard")
    print(f"  Buka     : http://{HOST}:{PORT}")
    print(f"  Password : {PASSWORD}")
    print(f"  Webhook  : {'Sudah di-set' if DISCORD_WEBHOOK else 'BELUM (isi di config.json)'}")
    print(f"  Config   : {CONFIG_FILE}")
    print("=" * 55)
    app.run(host=HOST, port=PORT, debug=False)
