import os
import time
import re
import requests
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")

# ---------------- CONFIG ----------------
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")

GOOGLE_SCRIPT_URL = os.environ.get("GOOGLE_SCRIPT_URL", "").strip()
SHEET_NAME = os.environ.get("SHEET_NAME", "work_report").strip()

# STEP 1: TAB_NAME variable added
TAB_NAME = os.environ.get("TAB_NAME", "devices").strip()

# ---------------- HELPERS ----------------
def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

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

# ---------------- API HELPER ----------------
# STEP 2: sheet_post updated to return JSON correctly
def sheet_post(payload: dict):
    if not GOOGLE_SCRIPT_URL:
        return {"ok": False, "error": "GOOGLE_SCRIPT_URL missing"}
    try:
        r = requests.post(GOOGLE_SCRIPT_URL, json=payload, timeout=12)
        try:
            return r.json()
        except:
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

# ---------------- LOGIC FUNCTIONS ----------------
# STEP 3: register_or_update_device updated with correct payload (event="device_check")
def register_or_update_device(device_id, device_name, ip, username):
    payload = {
        "sheet": SHEET_NAME,      # spreadsheet name (work_report)
        "tab": TAB_NAME,          # devices
        "event": "device_check",  # Important: matches Script logic
        "device_id": device_id,
        "device_name": device_name,
        "ip": ip,
        "username": username,
        "time": now_str()
    }
    return sheet_post(payload)

# ---------------- ROUTES ----------------

@app.route("/login", methods=["POST"])
def login():
    try:
        body = request.get_json(force=True) or {}
        username = body.get("username", "")
        password = body.get("password", "")
        device_id = body.get("device_id", "")
        device_name = body.get("device_name", "")
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)

        if username != ADMIN_USER or password != ADMIN_PASS:
            return jsonify({"ok": False, "error": "Invalid credentials"}), 401

        if not device_id:
            return jsonify({"ok": False, "error": "Device ID missing"}), 400

        result = register_or_update_device(device_id, device_name, ip, username)

        # STEP 4: Login logic fixed to handle nested "data" in response
        if not result.get("ok"):
            return jsonify({"ok": False, "error": "Sheet API failed", "details": result}), 500

        data = result.get("data", {})
        
        # Fallback if script returns flat JSON (rare, but safety check)
        if not data:
            data = result

        if data.get("exists") is False:
            return jsonify({"ok": False, "error": "Device approval pending. Ask admin to set disabled=FALSE in sheet."}), 403

        if data.get("disabled") is True:
            return jsonify({"ok": False, "error": "Device disabled by admin."}), 403

        return jsonify({"ok": True, "status": data.get("status", "Active")})

    except Exception as e:
        return jsonify({"ok": False, "error": f"Server Error: {str(e)}"}), 500

@app.route("/api/login", methods=["POST"])
def api_login_old():
    return login()

@app.route("/api/ping", methods=["GET"])
def api_ping():
    return jsonify({"ok": True, "message": "pong", "time": now_str()}), 200

# --- REPORTING ROUTES ---
@app.route("/api/report/paste_links", methods=["POST"])
def report_paste_links():
    data = request.get_json(force=True) or {}
    items = data.get("items", [])
    yt_links = extract_youtube_links(items)
    row = {
        "time": now_str(), "username": data.get("username", ""), "device_id": data.get("device_id", ""),
        "device_name": data.get("device_name", ""), "ip": get_ip(), "event": "paste_links",
        "count": len(yt_links), "details": "\n".join(yt_links[:20])
    }
    return jsonify({"ok": True, "saved_links": len(yt_links), "sheet_result": push_to_work_report(row)})

@app.route("/api/report/scrape_done", methods=["POST"])
def report_scrape_done():
    data = request.get_json(force=True) or {}
    row = {
        "time": now_str(), "username": data.get("username", ""), "device_id": data.get("device_id", ""),
        "device_name": data.get("device_name", ""), "ip": get_ip(), "event": "scrape_done",
        "count": int(data.get("count", 0)), "details": ""
    }
    return jsonify({"ok": True, "sheet_result": push_to_work_report(row)})

@app.route("/api/report/download_done", methods=["POST"])
def report_download_done():
    data = request.get_json(force=True) or {}
    row = {
        "time": now_str(), "username": data.get("username", ""), "device_id": data.get("device_id", ""),
        "device_name": data.get("device_name", ""), "ip": get_ip(), "event": "download_done",
        "count": int(data.get("count", 0)), "details": ""
    }
    return jsonify({"ok": True, "sheet_result": push_to_work_report(row)})

@app.route("/api/report/session", methods=["POST"])
def report_session():
    data = request.get_json(force=True) or {}
    row = {
        "time": now_str(), "username": data.get("username", ""), "device_id": data.get("device_id", ""),
        "device_name": data.get("device_name", ""), "ip": get_ip(), "event": "session",
        "count": int(data.get("seconds", 0)), "details": ""
    }
    return jsonify({"ok": True, "sheet_result": push_to_work_report(row)})

# ---------------- ADMIN PANEL ----------------
@app.route("/")
def home():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    return "Admin Panel - Please use Google Sheet to manage devices."

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

@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
