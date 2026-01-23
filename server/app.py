import os
import time
import hashlib
import re
import requests
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")

# ---------------- CONFIG ----------------
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")
MAX_DEVICES = int(os.environ.get("MAX_DEVICES", "5"))

GOOGLE_SCRIPT_URL = os.environ.get("GOOGLE_SCRIPT_URL", "").strip()
SHEET_NAME = os.environ.get("SHEET_NAME", "work_report").strip()

# ---------------- HELPERS ----------------
def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def hash_pw(pw: str):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def check_admin(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def get_ip():
    ip = request.headers.get("X-Forwarded-For", "")
    if ip:
        return ip.split(",")[0].strip()
    return request.remote_addr

YT_REGEX = re.compile(r'(https?://(?:www\.)?(?:youtube\.com|youtu\.be)/[^\s]+)', re.IGNORECASE)

def extract_youtube_links(items):
    links = []
    for x in items:
        if not isinstance(x, str):
            continue
        found = YT_REGEX.findall(x)
        for f in found:
            links.append(f.strip())

    unique = []
    for l in links:
        if l not in unique:
            unique.append(l)
    return unique

# ---------------- GOOGLE SHEET API ----------------
def sheet_post(payload: dict):
    if not GOOGLE_SCRIPT_URL:
        return {"ok": False, "error": "GOOGLE_SCRIPT_URL missing"}

    try:
        r = requests.post(GOOGLE_SCRIPT_URL, json=payload, timeout=12)
        return {"ok": r.status_code == 200, "status": r.status_code, "text": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def push_to_work_report(row: dict):
    payload = {
        "sheet": SHEET_NAME,
        "time": row.get("time", ""),
        "username": row.get("username", ""),
        "device_id": row.get("device_id", ""),
        "device_name": row.get("device_name", ""),
        "ip": row.get("ip", ""),
        "event": row.get("event", ""),
        "count": row.get("count", ""),
        "details": row.get("details", ""),
    }
    return sheet_post(payload)

def upsert_device_sheet(device: dict):
    payload = {
        "sheet": "devices",
        "device_id": device.get("device_id", ""),
        "device_name": device.get("device_name", ""),
        "ip": device.get("ip", ""),
        "created": device.get("created", ""),
        "last_seen": device.get("last_seen", ""),
        "status": device.get("status", "Active"),
        "disabled": str(device.get("disabled", False)).lower(),
        "username": device.get("username", "")
    }
    return sheet_post(payload)

# ---------------- IN-MEMORY CACHE (Optional) ----------------
# NOTE: Admin dashboard में list show करने के लिए
# हम temporary memory में रखते हैं, लेकिन source of truth Google Sheet है.
DEVICES_CACHE = {}
LOGS_CACHE = []

def add_log(device_id, name, status):
    global LOGS_CACHE
    LOGS_CACHE.insert(0, {
        "device_id": device_id,
        "name": name,
        "ip": get_ip(),
        "status": status,
        "time": now_str()
    })
    LOGS_CACHE = LOGS_CACHE[:50]

# ---------------- API: LOGIN ----------------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")
    device_id = data.get("device_id", "")
    device_name = data.get("device_name", "Unknown-PC")

    if not check_admin(username, password):
        add_log(device_id, device_name, "INVALID_CREDENTIALS")
        return jsonify({"ok": False, "error": "Invalid username or password"}), 401

    if not device_id:
        add_log(device_id, device_name, "NO_DEVICE_ID")
        return jsonify({"ok": False, "error": "Device ID missing"}), 400

    # Check cache for disabled
    existing = DEVICES_CACHE.get(device_id)

    if existing and existing.get("disabled", False):
        existing["last_seen"] = now_str()
        existing["ip"] = get_ip()
        existing["status"] = "Disabled"
        upsert_device_sheet(existing)
        add_log(device_id, device_name, "DEVICE_DISABLED")
        return jsonify({"ok": False, "error": "This device is disabled by admin"}), 403

    # If not exists, register (but limit MAX_DEVICES)
    if not existing:
        if len(DEVICES_CACHE) >= MAX_DEVICES:
            add_log(device_id, device_name, "MAX_DEVICES_REACHED")
            return jsonify({"ok": False, "error": "Max devices reached. Contact admin."}), 403

        new_device = {
            "id": int(time.time()),
            "device_id": device_id,
            "device_name": device_name,
            "ip": get_ip(),
            "created": now_str(),
            "last_seen": now_str(),
            "disabled": False,
            "status": "Active",
            "username": username
        }
        DEVICES_CACHE[device_id] = new_device
        upsert_device_sheet(new_device)
        add_log(device_id, device_name, "DEVICE_REGISTERED")

    else:
        existing["device_name"] = device_name
        existing["ip"] = get_ip()
        existing["last_seen"] = now_str()
        existing["status"] = "Active"
        existing["username"] = username
        upsert_device_sheet(existing)
        add_log(device_id, device_name, "LOGIN_OK")

    return jsonify({"ok": True, "max_devices": MAX_DEVICES})

@app.route("/api/ping", methods=["GET"])
def api_ping():
    return jsonify({"ok": True, "message": "pong", "time": now_str()}), 200

# ---------------- API: REPORTING ----------------
@app.route("/api/report/paste_links", methods=["POST"])
def report_paste_links():
    data = request.get_json(force=True) or {}

    items = data.get("items", [])
    yt_links = extract_youtube_links(items)

    row = {
        "time": now_str(),
        "username": data.get("username", ""),
        "device_id": data.get("device_id", ""),
        "device_name": data.get("device_name", ""),
        "ip": get_ip(),
        "event": "paste_links",
        "count": len(yt_links),
        "details": "\n".join(yt_links[:20])
    }

    result = push_to_work_report(row)
    return jsonify({"ok": True, "saved_links": len(yt_links), "sheet_result": result})

@app.route("/api/report/scrape_done", methods=["POST"])
def report_scrape_done():
    data = request.get_json(force=True) or {}

    row = {
        "time": now_str(),
        "username": data.get("username", ""),
        "device_id": data.get("device_id", ""),
        "device_name": data.get("device_name", ""),
        "ip": get_ip(),
        "event": "scrape_done",
        "count": int(data.get("count", 0)),
        "details": ""
    }

    result = push_to_work_report(row)
    return jsonify({"ok": True, "sheet_result": result})

@app.route("/api/report/download_done", methods=["POST"])
def report_download_done():
    data = request.get_json(force=True) or {}

    row = {
        "time": now_str(),
        "username": data.get("username", ""),
        "device_id": data.get("device_id", ""),
        "device_name": data.get("device_name", ""),
        "ip": get_ip(),
        "event": "download_done",
        "count": int(data.get("count", 0)),
        "details": ""
    }

    result = push_to_work_report(row)
    return jsonify({"ok": True, "sheet_result": result})

@app.route("/api/report/session", methods=["POST"])
def report_session():
    data = request.get_json(force=True) or {}

    row = {
        "time": now_str(),
        "username": data.get("username", ""),
        "device_id": data.get("device_id", ""),
        "device_name": data.get("device_name", ""),
        "ip": get_ip(),
        "event": "session",
        "count": int(data.get("seconds", 0)),
        "details": ""
    }

    result = push_to_work_report(row)
    return jsonify({"ok": True, "sheet_result": result})

# ---------------- ADMIN PANEL ----------------
@app.route("/")
def home():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    # Show cache devices + cache logs
    devices = list(DEVICES_CACHE.values())
    logs = LOGS_CACHE[:50]

    return render_template("dashboard.html", devices=devices, logs=logs, max_devices=MAX_DEVICES)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if check_admin(username, password):
            session["admin"] = True
            return redirect(url_for("home"))
        return render_template("login.html", error="Invalid Admin Login")
    return render_template("login.html", error=None)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin/device/remove/<device_id>", methods=["POST"])
def remove_device(device_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    if device_id in DEVICES_CACHE:
        DEVICES_CACHE.pop(device_id)

    # Mark removed in sheet (optional)
    upsert_device_sheet({
        "device_id": device_id,
        "device_name": "",
        "ip": "",
        "created": "",
        "last_seen": now_str(),
        "disabled": "true",
        "status": "Removed",
        "username": ""
    })

    return redirect(url_for("home"))

@app.route("/admin/device/disable/<device_id>", methods=["POST"])
def disable_device(device_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    d = DEVICES_CACHE.get(device_id)
    if d:
        d["disabled"] = True
        d["status"] = "Disabled"
        d["last_seen"] = now_str()
        upsert_device_sheet(d)

    return redirect(url_for("home"))

@app.route("/admin/device/enable/<device_id>", methods=["POST"])
def enable_device(device_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    d = DEVICES_CACHE.get(device_id)
    if d:
        d["disabled"] = False
        d["status"] = "Active"
        d["last_seen"] = now_str()
        upsert_device_sheet(d)

    return redirect(url_for("home"))

@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
