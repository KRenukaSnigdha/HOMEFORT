from flask import Flask, render_template, jsonify, request
import os
import re
import requests
from collections import deque, Counter
import geoip2.database

app = Flask(__name__)

CAPTURED_FILE = os.path.join("data", "captured_packets.csv")
ALERTS_FILE = os.path.join("data", "alerts.log")

# ------------------ GEOIP DB PATH ------------------
GEOIP_DB = os.path.join("data", "GeoLite2-City.mmdb")

MAX_ALERTS = 10
MAX_PACKETS = 50

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
# ------------------ API KEYS (PUT YOUR KEYS HERE) ------------------


# ------------------ CACHE FOR TOTAL PACKETS ------------------
packet_cache = {
    "last_size": 0,
    "total_packets": 0
}


def get_total_packets_fast():
    """Count packets only when file grows (cached)."""
    if not os.path.exists(CAPTURED_FILE):
        return 0

    size = os.path.getsize(CAPTURED_FILE)

    if size == packet_cache["last_size"]:
        return packet_cache["total_packets"]

    try:
        with open(CAPTURED_FILE, "r", encoding="utf-8") as f:
            total = sum(1 for _ in f)
    except:
        return packet_cache["total_packets"]

    packet_cache["last_size"] = size
    packet_cache["total_packets"] = total
    return total


# ------------------ ALERT READER ------------------
def read_last_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []

    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except:
        return []

    if lines and lines[-1].strip() == "":
        lines = lines[:-1]

    unique_alerts = []
    seen = set()

    for line in lines[::-1]:
        line = line.strip()
        if not line:
            continue

        decision = re.search(r"\[(SAFE|SUSPICIOUS|MALICIOUS)\]", line)
        final_score = re.search(r"FinalScore=([\d\.]+)", line)
        ml_score = re.search(r"MLScore=([\d\.]+)", line)
        rep_score = re.search(r"RepScore=([\d\.]+)", line)
        rule_score = re.search(r"RuleScore=([\d\.]+)", line)

        reason_match = re.search(r"Reason=(.+)$", line)

        blocked = True if "AUTO-BLOCKED" in line else False

        src_ip = re.search(r"'src_ip':\s*'([^']+)'", line)
        dst_ip = re.search(r"'dst_ip':\s*'([^']+)'", line)
        protocol = re.search(r"'protocol':\s*'([^']+)'", line)
        dst_port = re.search(r"'dst_port':\s*'([^']+)'", line)
        packet_length = re.search(r"'packet_length':\s*'([^']+)'", line)

        key = (
            src_ip.group(1) if src_ip else "",
            dst_ip.group(1) if dst_ip else "",
            protocol.group(1) if protocol else "",
            final_score.group(1) if final_score else ""
        )

        if key in seen:
            continue

        seen.add(key)

        unique_alerts.append({
            "raw": line,
            "decision": decision.group(1) if decision else "UNKNOWN",
            "final_score": float(final_score.group(1)) if final_score else None,
            "ml_score": float(ml_score.group(1)) if ml_score else None,
            "reputation_score": float(rep_score.group(1)) if rep_score else None,
            "rule_score": float(rule_score.group(1)) if rule_score else None,
            "blocked": blocked,
            "reason": reason_match.group(1).strip() if reason_match else "Hybrid detection triggered",
            "src_ip": src_ip.group(1) if src_ip else None,
            "dst_ip": dst_ip.group(1) if dst_ip else None,
            "dst_port": dst_port.group(1) if dst_port else None,
            "protocol": protocol.group(1) if protocol else None,
            "packet_length": packet_length.group(1) if packet_length else None
        })

        if len(unique_alerts) >= MAX_ALERTS:
            break

    return unique_alerts


# ------------------ READ LATEST PACKETS ------------------
def read_latest_packets():
    if not os.path.exists(CAPTURED_FILE):
        return []

    try:
        with open(CAPTURED_FILE, "r", encoding="utf-8") as f:
            last_lines = deque(f, maxlen=MAX_PACKETS)
    except:
        return []

    packets = []

    for line in last_lines:
        parts = line.strip().split(",")

        if len(parts) < 7:
            continue

        packets.append({
            "timestamp": parts[0],
            "src_ip": parts[1],
            "dst_ip": parts[2],
            "src_port": parts[3],
            "dst_port": parts[4],
            "protocol": parts[5],
            "packet_length": parts[6]
        })

    return packets


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
    if ABUSEIPDB_API_KEY == "" or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        return {
            "enabled": False,
            "message": "AbuseIPDB API key not configured"
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

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
    if VIRUSTOTAL_API_KEY == "" or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return {
            "enabled": False,
            "message": "VirusTotal API key not configured"
        }

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


# ------------------ THREAT SCORING ENGINE ------------------
def calculate_threat_score(abuse_score=0, total_reports=0, ml_score=0, rule_score=0):
    """
    Final Hybrid Score = ML + Rule + Reputation
    """

    rep_score = 0

    # Reputation scoring logic
    if abuse_score >= 80:
        rep_score = 5
    elif abuse_score >= 50:
        rep_score = 4
    elif abuse_score >= 30:
        rep_score = 3
    elif abuse_score >= 10:
        rep_score = 2
    else:
        rep_score = 1

    if total_reports > 50:
        rep_score += 2
    elif total_reports > 10:
        rep_score += 1

    final_score = (ml_score * 0.4) + (rule_score * 0.3) + (rep_score * 0.3)

    if final_score >= 4:
        decision = "MALICIOUS"
    elif final_score >= 2.5:
        decision = "SUSPICIOUS"
    else:
        decision = "SAFE"

    return final_score, decision, rep_score


# ------------------ EXTRACT SUSPICIOUS IPs ------------------
def extract_suspicious_ips():
    if not os.path.exists(ALERTS_FILE):
        return []

    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except:
        return []

    ips = []

    for line in lines[::-1]:
        src_ip = re.search(r"'src_ip':\s*'([^']+)'", line)
        if src_ip:
            ips.append(src_ip.group(1))

        if len(ips) >= 50:
            break

    return ips


# ------------------ GEO THREAT REPORT ------------------
def generate_geo_threat_report():
    suspicious_ips = extract_suspicious_ips()

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


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/data")
def api_data():
    packets = read_latest_packets()
    alerts = read_last_alerts()
    total_packets = get_total_packets_fast()

    return jsonify({
        "packets": packets,
        "alerts": alerts,
        "total_packets": total_packets
    })


# ------------------ GEO THREAT ENDPOINT ------------------
@app.route("/api/geo-threats")
def api_geo_threats():
    geo_report = generate_geo_threat_report()
    return jsonify(geo_report)


# ------------------ NEW THREAT INTELLIGENCE ENDPOINT ------------------
@app.route("/api/threat-intel", methods=["POST"])
def api_threat_intel():
    body = request.json
    ip = body.get("ip")

    if not ip:
        return jsonify({"error": "IP is required"}), 400

    geo_data = geoip_lookup(ip)
    abuse_data = abuseipdb_lookup(ip)
    vt_data = virustotal_lookup(ip)

    abuse_score = abuse_data.get("abuseConfidenceScore", 0)
    total_reports = abuse_data.get("totalReports", 0)

    # (Optional) You can connect this with your ML model score later
    ml_score = 0
    rule_score = 0

    final_score, decision, rep_score = calculate_threat_score(
        abuse_score=abuse_score,
        total_reports=total_reports,
        ml_score=ml_score,
        rule_score=rule_score
    )

    return jsonify({
        "ip": ip,
        "geo_location": geo_data,
        "abuseipdb": abuse_data,
        "virustotal": vt_data,
        "final_score": round(final_score, 2),
        "reputation_score": rep_score,
        "decision": decision
    })


if __name__ == "__main__":
    app.run(debug=True)

