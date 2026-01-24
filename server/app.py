import os
import time
import hashlib
import re
import requests
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, session

# --- NEW IMPORTS FOR DIRECT SHEET ACCESS ---
import gspread
from google.oauth2.service_account import Credentials

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")

# ---------------- CONFIG ----------------
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")
# REMOVED: MAX_DEVICES logic

GOOGLE_SCRIPT_URL = os.environ.get("GOOGLE_SCRIPT_URL", "").strip()
SHEET_NAME = os.environ.get("SHEET_NAME", "work_report").strip()
CREDENTIALS_FILE = os.environ.get("CREDENTIALS_FILE", "credentials.json")

# ---------------- SHEET API WRAPPER ----------------
# This class wraps gspread to match the function calls in your instructions
class SheetAPIWrapper:
    def __init__(self, creds_file):
        self.client = None
        if os.path.exists(creds_file):
            scope = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
            creds = Credentials.from_service_account_file(creds_file, scopes=scope)
            self.client = gspread.authorize(creds)
        else:
            print(f"WARNING: {creds_file} not found. Login logic will fail without it.")

    def get_sheet_rows(self, sheet_name, tab_name):
        if not self.client: raise Exception("Google Sheet Client not initialized")
        sh = self.client.open(sheet_name)
        wks = sh.worksheet(tab_name)
        return wks.get_all_values()

    def append_row(self, sheet_name, tab_name, row):
        if not self.client: raise Exception("Google Sheet Client not initialized")
        sh = self.client.open(sheet_name)
        wks = sh.worksheet(tab_name)
        wks.append_row(row)

    def update_row(self, sheet_name, tab_name, row_num, row_data):
        if not self.client: raise Exception("Google Sheet Client not initialized")
        sh = self.client.open(sheet_name)
        wks = sh.worksheet(tab_name)
        # Update the entire row range
        wks.update(range_name=f"A{row_num}", values=[row_data])

# Initialize the API
sheet_api = SheetAPIWrapper(CREDENTIALS_FILE)

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

# ---------------- NEW LOGIC FUNCTIONS (FROM INSTRUCTION) ----------------

def find_device_row(devices_rows, device_id):
    for i, row in enumerate(devices_rows):
        # Check if row has data and match device_id (Column A is usually index 0)
        if len(row) > 0 and str(row[0]).strip() == str(device_id).strip():
            return i
    return -1

def is_disabled(value):
    if value is None:
        return True
    v = str(value).strip().lower()
    return v in ["true", "1", "yes", "disabled"]

def register_or_update_device(sheet_api, sheet_name, device_id, device_name, ip, username):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    devices_tab = "devices"
    rows = sheet_api.get_sheet_rows(sheet_name, devices_tab)  # headers + data

    if not rows or len(rows) < 1:
        raise Exception("devices sheet empty or headers missing")

    headers = rows[0]
    data_rows = rows[1:]

    idx = find_device_row(data_rows, device_id)

    if idx == -1:
        # NEW DEVICE -> add pending (disabled TRUE)
        new_row = [
            device_id,            # device_id
            device_name,          # device_name
            ip,                   # ip
            now,                  # created
            now,                  # last_seen
            "Pending",            # status
            "TRUE",               # disabled
            username              # username
        ]
        sheet_api.append_row(sheet_name, devices_tab, new_row)
        return {"exists": False, "disabled": True, "status": "Pending"}

    # EXISTING -> update last_seen/ip/name/username
    row = data_rows[idx]

    # Column mapping based on your sheet:
    # A device_id, B device_name, C ip, D created, E last_seen, F status, G disabled, H username
    
    # Ensure row length to avoid index errors
    while len(row) < 8:
        row.append("")

    row[1] = device_name
    row[2] = ip
    row[4] = now
    row[7] = username

    disabled_val = row[6]
    disabled_flag = is_disabled(disabled_val)

    if disabled_flag:
        row[5] = "Disabled"
    else:
        row[5] = "Active"

    # write back updated row (1 header row + index + 1 for 1-based indexing)
    # The snippet said `idx + 2`. idx is from data_rows (starts at actual row 2).
    # If idx is 0, it is row 2 in Excel.
    sheet_row_number = idx + 2
    sheet_api.update_row(sheet_name, devices_tab, sheet_row_number, row)

    return {"exists": True, "disabled": disabled_flag, "status": row[5]}

# ---------------- OLD SHEET API (FOR REPORTING ONLY) ----------------
# We keep this for the reporting functions as they use the Webhook URL
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

# ---------------- UPDATED LOGIN ROUTE ----------------
@app.route("/login", methods=["POST"])
def login():
    try:
        body = request.get_json(force=True) or {}

        username = body.get("username", "")
        password = body.get("password", "")
        device_id = body.get("device_id", "")
        device_name = body.get("device_name", "")
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)

        # 1. Admin Auth
        if username != ADMIN_USER or password != ADMIN_PASS:
            return jsonify({"ok": False, "error": "Invalid credentials"}), 401

        if not device_id:
            return jsonify({"ok": False, "error": "Device ID missing"}), 400

        # 2. Register/Update device in sheet (Checks sheet directly)
        result = register_or_update_device(sheet_api, SHEET_NAME, device_id, device_name, ip, username)

        # 3. Handle Logic
        # New device -> Pending -> Reject
        if result["exists"] is False:
            return jsonify({
                "ok": False,
                "error": "Device approval pending. Ask admin to set disabled=FALSE in sheet."
            }), 403

        # Disabled -> Reject
        if result["disabled"] is True:
            return jsonify({
                "ok": False,
                "error": "Device disabled by admin."
            }), 403

        # Allow login
        return jsonify({"ok": True, "status": result["status"]})

    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({"ok": False, "error": f"Server Error: {str(e)}"}), 500

# Backward compatibility (optional, or remove if not needed)
@app.route("/api/login", methods=["POST"])
def api_login_old():
    return login()

@app.route("/api/ping", methods=["GET"])
def api_ping():
    return jsonify({"ok": True, "message": "pong", "time": now_str()}), 200

# ---------------- API: REPORTING (Unchanged) ----------------
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

# ---------------- SIMPLE ADMIN PANEL (Without Cache) ----------------
# Since we removed the memory cache, we can't easily show a live dashboard 
# without reading the sheet every time. For now, simple home.
@app.route("/")
def home():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    
    # Optional: You could read `sheet_api.get_sheet_rows` here to show devices
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
