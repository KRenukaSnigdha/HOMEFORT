from flask import Flask, render_template, jsonify
import os
import re
from collections import deque

app = Flask(__name__)

CAPTURED_FILE = os.path.join("data", "captured_packets.csv")
ALERTS_FILE = os.path.join("data", "alerts.log")

MAX_ALERTS = 10
MAX_PACKETS = 50

threat_info = {
    "ip": "89.222.98.34",
    "abuseConfidenceScore": 0,
    "countryCode": "CA",
    "usageType": "Data Center/Web Hosting/Transit",
    "domain": "datacamp.co.uk",
    "totalReports": 0
}

# --------- CACHE FOR TOTAL PACKETS ----------
packet_cache = {
    "last_size": 0,
    "total_packets": 0
}


def get_total_packets_fast():
    """Count packets only when file grows (cached)."""
    if not os.path.exists(CAPTURED_FILE):
        return 0

    size = os.path.getsize(CAPTURED_FILE)

    # If file size not changed, return cached value
    if size == packet_cache["last_size"]:
        return packet_cache["total_packets"]

    # If file changed, count once (still expensive but only when file grows)
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

    unique_alerts = []
    seen = set()

    for line in lines[::-1]:
        line = line.strip()

        src_ip = re.search(r"'src_ip':\s*'([^']+)'", line)
        dst_ip = re.search(r"'dst_ip':\s*'([^']+)'", line)
        src_port = re.search(r"'src_port':\s*([\d\.]+)", line)
        dst_port = re.search(r"'dst_port':\s*([\d\.]+)", line)
        protocol = re.search(r"'protocol':\s*'([^']+)'", line)
        label = re.search(r"Predicted label:\s*(\d+)", line)

        key = (
            src_ip.group(1) if src_ip else "",
            dst_ip.group(1) if dst_ip else "",
            src_port.group(1) if src_port else "",
            dst_port.group(1) if dst_port else "",
            protocol.group(1) if protocol else "",
            label.group(1) if label else ""
        )

        if key in seen:
            continue

        seen.add(key)
        unique_alerts.append({"raw": line})

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


# ------------------ ROUTES ------------------
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", threat_info=threat_info)


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


if __name__ == "__main__":
    app.run(debug=True)
