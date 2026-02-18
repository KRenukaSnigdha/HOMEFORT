from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import os
import requests
from collections import Counter
import geoip2.database
from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default_secret_key_change_this")

# ------------------ BASE DIR ------------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# ------------------ GEOIP DB PATH ------------------
GEOIP_DB = os.path.join(BASE_DIR, "data", "GeoLite2-City.mmdb")

# ------------------ API KEYS ------------------
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

# ------------------ MONGODB ------------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("DB_NAME", "ids_db")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

packets_col = db["packets"]
alerts_col = db["alerts"]
users_col = db["users"]
devices_col = db["devices"]

# ------------------ LIMITS ------------------
MAX_ALERTS = 10
MAX_PACKETS = 50


# ------------------ LOGIN REQUIRED ------------------
def require_login():
    return "user_id" in session and "device_id" in session


# ------------------ READ PACKETS FROM MONGO ------------------
def read_latest_packets(user_id, device_id):
    packets = list(
        packets_col.find(
            {"user_id": user_id, "device_id": device_id},
            {"_id": 0}
        ).sort("timestamp", -1).limit(MAX_PACKETS)
    )

    packets.reverse()

    for pkt in packets:
        if isinstance(pkt.get("timestamp"), datetime):
            pkt["timestamp"] = pkt["timestamp"].isoformat()

    return packets


# ------------------ READ ALERTS FROM MONGO ------------------
def read_last_alerts(user_id, device_id):
    alerts = list(
        alerts_col.find(
            {"user_id": user_id, "device_id": device_id},
            {"_id": 0}
        ).sort("timestamp", -1).limit(MAX_ALERTS)
    )

    for alert in alerts:
        if isinstance(alert.get("timestamp"), datetime):
            alert["timestamp"] = alert["timestamp"].isoformat()

        if "packet" in alert and isinstance(alert["packet"].get("timestamp"), datetime):
            alert["packet"]["timestamp"] = alert["packet"]["timestamp"].isoformat()

    return alerts


# ------------------ TOTAL PACKETS COUNT ------------------
def get_total_packets(user_id, device_id):
    try:
        return packets_col.count_documents({"user_id": user_id, "device_id": device_id})
    except:
        return 0


# ------------------ GEOIP LOOKUP ------------------
def geoip_lookup(ip):
    if not os.path.exists(GEOIP_DB):
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None
        }

    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.city(ip)

            return {
                "ip": ip,
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }

    except:
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None
        }


# ------------------ ABUSEIPDB LOOKUP ------------------
def abuseipdb_lookup(ip):
    if not ABUSEIPDB_API_KEY:
        return {"enabled": False, "message": "AbuseIPDB API key not configured"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=5)
        data = r.json()

        if "data" not in data:
            return {"enabled": True, "error": "Invalid response"}

        d = data["data"]

        return {
            "enabled": True,
            "ip": ip,
            "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
            "countryCode": d.get("countryCode", "Unknown"),
            "usageType": d.get("usageType", "Unknown"),
            "domain": d.get("domain", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "totalReports": d.get("totalReports", 0)
        }

    except Exception as e:
        return {"enabled": True, "error": str(e)}


# ------------------ VIRUSTOTAL LOOKUP ------------------
def virustotal_lookup(ip):
    if not VIRUSTOTAL_API_KEY:
        return {"enabled": False, "message": "VirusTotal API key not configured"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=5)
        data = r.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "enabled": True,
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0)
        }

    except Exception as e:
        return {"enabled": True, "error": str(e)}


# ------------------ GEO THREAT REPORT ------------------
def generate_geo_threat_report(user_id, device_id):
    alerts = list(
        alerts_col.find(
            {"user_id": user_id, "device_id": device_id},
            {"_id": 0}
        ).sort("timestamp", -1).limit(50)
    )

    suspicious_ips = []
    for alert in alerts:
        pkt = alert.get("packet", {})
        src_ip = pkt.get("src_ip")
        if src_ip:
            suspicious_ips.append(src_ip)

    if not suspicious_ips:
        return []

    ip_counts = Counter(suspicious_ips)
    geo_results = []

    for ip, count in ip_counts.items():
        geo_data = geoip_lookup(ip)
        risk_score = min(100, count * 12)

        geo_results.append({
            "ip": ip,
            "country": geo_data["country"],
            "city": geo_data["city"],
            "latitude": geo_data["latitude"],
            "longitude": geo_data["longitude"],
            "risk_score": risk_score,
            "hits": count
        })

    geo_results.sort(key=lambda x: x["risk_score"], reverse=True)
    return geo_results


# ------------------ ROUTES ------------------
@app.route("/")
def home():
    return render_template("home.html")


# ------------------ REGISTER ------------------
@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html")

    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    if not name or not email or not password:
        return "All fields are required", 400

    if password != confirm_password:
        return "Passwords do not match", 400

    existing_user = users_col.find_one({"email": email})
    if existing_user:
        return "Email already registered. Please login.", 400

    users_col.insert_one({
        "name": name,
        "email": email,
        "password": password,  # later hash it
        "created_at": datetime.utcnow()
    })

    return redirect(url_for("login_page"))


# ------------------ LOGIN ------------------
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email")
    password = request.form.get("password")
    device_id = request.form.get("device_id")

    if not email or not password or not device_id:
        return "Email, Password and Device ID required", 400

    user = users_col.find_one({"email": email})

    if not user:
        return "User not found. Please register.", 400

    if user["password"] != password:
        return "Invalid password", 400

    devices_col.update_one(
        {"email": email, "device_id": device_id},
        {"$set": {"email": email, "device_id": device_id, "last_login": datetime.utcnow()}},
        upsert=True
    )

    session["user_id"] = email
    session["device_id"] = device_id

    return redirect(url_for("dashboard"))


# ------------------ LOGOUT ------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ------------------ DASHBOARD ------------------
@app.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect(url_for("login_page"))

    return render_template("dashboard.html", user=session["user_id"], device=session["device_id"])


# ------------------ API DATA ------------------
@app.route("/api/data")
def api_data():
    if not require_login():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session["user_id"]
    device_id = session["device_id"]

    packets = read_latest_packets(user_id, device_id)
    alerts = read_last_alerts(user_id, device_id)
    total_packets = get_total_packets(user_id, device_id)

    return jsonify({
        "packets": packets,
        "alerts": alerts,
        "total_packets": total_packets,
        "user_id": user_id,
        "device_id": device_id
    })


# ------------------ API GEO THREATS ------------------
@app.route("/api/geo-threats")
def api_geo_threats():
    if not require_login():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session["user_id"]
    device_id = session["device_id"]

    geo_report = generate_geo_threat_report(user_id, device_id)
    return jsonify(geo_report)


# ------------------ API THREAT INTEL ------------------
@app.route("/api/threat-intel", methods=["POST"])
def api_threat_intel():
    if not require_login():
        return jsonify({"error": "Not logged in"}), 401

    body = request.json
    ip = body.get("ip")

    if not ip:
        return jsonify({"error": "IP is required"}), 400

    geo_data = geoip_lookup(ip)
    abuse_data = abuseipdb_lookup(ip)
    vt_data = virustotal_lookup(ip)

    return jsonify({
        "ip": ip,
        "geo_location": geo_data,
        "abuseipdb": abuse_data,
        "virustotal": vt_data
    })


if __name__ == "__main__":
    app.run(debug=True)
