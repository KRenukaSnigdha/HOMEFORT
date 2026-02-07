import pandas as pd
import joblib
import os
from time import sleep
import subprocess
import sys

sys.path.append(os.path.join(os.path.dirname(__file__)))
from threat_intel import check_ip_abuse

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

clf = joblib.load(MODEL_PATH)
le_proto = joblib.load(PROTO_ENCODER_PATH)

blocked_ips = set()

# Map protocol string to NSL-KDD protocol_type
PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}


def preprocess_row(row):
    proto_type = PROTOCOL_MAP.get(str(row.get('protocol', '')).upper(), 'other')

    if proto_type in le_proto.classes_:
        row['protocol_type'] = le_proto.transform([proto_type])[0]
    else:
        row['protocol_type'] = 0

    row['src_bytes'] = int(row.get('packet_length', 0)) if pd.notnull(row.get('packet_length', 0)) else 0
    row['dst_bytes'] = 0
    return row


def block_ip(ip):
    if ip in blocked_ips:
        return

    try:
        cmd = f'netsh advfirewall firewall add rule name="IDS_Block_{ip}" dir=in action=block remoteip={ip} enable=yes'
        subprocess.run(cmd, shell=True, check=True)

        blocked_ips.add(ip)

        with open(LOG_PATH, 'a', encoding="utf-8") as f:
            f.write(f"AUTO-BLOCKED IP: {ip}\n")

        print(f"AUTO-BLOCKED IP: {ip}")

    except Exception as e:
        with open(LOG_PATH, 'a', encoding="utf-8") as f:
            f.write(f"Failed to block IP {ip}: {e}\n")

        print(f"Failed to block IP {ip}: {e}")


def main():
    print("Starting real-time detection with threat intelligence and auto-blocking...")

    file_pos = 0

    while True:
        if not os.path.exists(DATA_PATH):
            sleep(2)
            continue

        try:
            with open(DATA_PATH, "r", encoding="utf-8") as f:
                f.seek(file_pos)
                new_lines = f.readlines()
                file_pos = f.tell()

        except Exception as e:
            print("Error reading file:", e)
            sleep(2)
            continue

        if not new_lines:
            sleep(2)
            continue

        # Remove header line if it appears again
        new_lines = [line for line in new_lines if not line.startswith("timestamp")]

        for line in new_lines:
            line = line.strip()

            if not line:
                continue

            parts = line.split(",")

            # Must have 7 columns
            if len(parts) < 7:
                continue

            row = {
                "timestamp": parts[0],
                "src_ip": parts[1],
                "dst_ip": parts[2],
                "src_port": parts[3],
                "dst_port": parts[4],
                "protocol": parts[5].strip(),
                "packet_length": parts[6]
            }

            row = preprocess_row(row)

            X = pd.DataFrame([row])[['protocol_type', 'src_bytes', 'dst_bytes']]

            pred = clf.predict(X)[0]

            if pred != 0:
                src_ip = row["src_ip"]
                alert = f"ALERT: Suspicious activity detected: {row} | Predicted label: {pred}"

                print(alert)

                with open(LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(alert + "\n")

                # Threat intelligence check
                if ABUSEIPDB_API_KEY:
                    abuse_result = check_ip_abuse(src_ip, ABUSEIPDB_API_KEY)

                    with open(LOG_PATH, "a", encoding="utf-8") as f:
                        f.write(f"AbuseIPDB: {abuse_result}\n")

                    print(f"AbuseIPDB: {abuse_result}")

                    if abuse_result.get("abuseConfidenceScore", 0) >= 50:
                        block_ip(src_ip)

        sleep(2)


if __name__ == "__main__":
    main()
