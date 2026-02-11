import pandas as pd
import joblib
import os
from time import sleep
import subprocess
import sys
import json
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__)))

from threat_intel import check_ip_abuse
from rules_engine import rule_based_score

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')
REPUTATION_CACHE_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'reputation_cache.json')

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
print("🔥 UPDATED realtime_detect.py LOADED")
print("API KEY FOUND:", bool(ABUSEIPDB_API_KEY))
print("API KEY FOUND:", bool(VIRUSTOTAL_API_KEY))
clf = joblib.load(MODEL_PATH)

le_proto = joblib.load(PROTO_ENCODER_PATH)

blocked_ips = set()

# Map protocol string to NSL-KDD protocol_type
PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}


# ---------------- Reputation Cache ----------------
def load_reputation_cache():
    if not os.path.exists(REPUTATION_CACHE_PATH):
        return {}

    try:
        with open(REPUTATION_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}


def save_reputation_cache(cache):
    try:
        with open(REPUTATION_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=4)
    except:
        pass


reputation_cache = load_reputation_cache()


def get_reputation_score(ip):
    """
    Returns reputation score from AbuseIPDB.
    Uses caching to avoid API overuse.
    """
    if ip in reputation_cache:
        return reputation_cache[ip].get("abuseConfidenceScore", 0), reputation_cache[ip]

    if not ABUSEIPDB_API_KEY:
        return 0, None

    abuse_result = check_ip_abuse(ip, ABUSEIPDB_API_KEY)

    if "abuseConfidenceScore" in abuse_result:
        reputation_cache[ip] = abuse_result
        save_reputation_cache(reputation_cache)

    return abuse_result.get("abuseConfidenceScore", 0), abuse_result


# ---------------- Preprocessing ----------------
def preprocess_row(row):
    proto_type = PROTOCOL_MAP.get(str(row.get('protocol', '')).upper(), 'other')

    if proto_type in le_proto.classes_:
        row['protocol_type'] = le_proto.transform([proto_type])[0]
    else:
        row['protocol_type'] = 0

    try:
        row['src_bytes'] = int(row.get('packet_length', 0))
    except:
        row['src_bytes'] = 0

    row['dst_bytes'] = 0
    return row


# ---------------- Blocking ----------------
def block_ip(ip):
    if ip in blocked_ips:
        return

    try:
        cmd = f'netsh advfirewall firewall add rule name="IDS_Block_{ip}" dir=in action=block remoteip={ip} enable=yes'
        subprocess.run(cmd, shell=True, check=True)

        blocked_ips.add(ip)

        with open(LOG_PATH, 'a', encoding="utf-8") as f:
            f.write(f"[{datetime.now()}] AUTO-BLOCKED IP: {ip}\n")

        print(f"AUTO-BLOCKED IP: {ip}")

    except Exception as e:
        with open(LOG_PATH, 'a', encoding="utf-8") as f:
            f.write(f"[{datetime.now()}] Failed to block IP {ip}: {e}\n")

        print(f"Failed to block IP {ip}: {e}")


# ---------------- Hybrid Detection Logic ----------------
def hybrid_decision(attack_probability, rule_score, rep_score):
    """
    Hybrid Detection:
    Rules + ML + Reputation = Final Score
    """

    # ML score is probability in percentage
    ml_score = round(attack_probability * 100, 2)

    # Weighted final score
    final_score = (0.40 * ml_score) + (0.35 * rep_score) + (0.25 * rule_score)

    # Decision thresholds
    if final_score >= 65:
        decision = "MALICIOUS"
    elif final_score >= 35:
        decision = "SUSPICIOUS"
    else:
        decision = "SAFE"

    return decision, round(final_score, 2), ml_score


# ---------------- Main Loop ----------------
def main():
    print("Starting Hybrid IDS (Rules + ML + Reputation)...")

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

        # Remove header if it appears again
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

            # Preprocess for ML
            processed_row = preprocess_row(row.copy())

            X = pd.DataFrame([processed_row])[['protocol_type', 'src_bytes', 'dst_bytes']]

            # Predict probability
            proba = clf.predict_proba(X)[0]

            # If model has 2 classes: [normal, attack]
            if len(proba) == 2:
                attack_probability = proba[1]
            else:
                # fallback: max probability except normal
                attack_probability = max(proba)

            src_ip = row["src_ip"]

            # Rule-based score
            rules_score = rule_based_score(row)

            # Reputation score
            rep_score, abuse_result = get_reputation_score(src_ip)

            # Hybrid decision
            decision, final_score, ml_score = hybrid_decision(attack_probability, rules_score, rep_score)

            # Log only suspicious or malicious
            if decision != "SAFE":
                alert = (
                    f"[{decision}] FinalScore={final_score} | "
                    f"MLScore={ml_score} | RepScore={rep_score} | RuleScore={rules_score} | "
                    f"Data={row}"
                )

                print(alert)

                with open(LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(alert + "\n")

                    if abuse_result:
                        f.write(f"AbuseIPDB_Result={abuse_result}\n")

                # Auto-block only malicious
                if decision == "MALICIOUS":
                    block_ip(src_ip)

        sleep(2)


if __name__ == "__main__":
    main()

