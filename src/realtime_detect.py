import os
import time
import joblib
import numpy as np
import warnings
import json
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

from rules_engine import rule_based_score
from threat_intel import check_ip_abuse

warnings.filterwarnings("ignore", category=UserWarning)

# -------------------- LOAD ENV --------------------
load_dotenv()

MONGO_URI = os.environ.get("MONGO_URI")
DB_NAME = os.environ.get("DB_NAME", "ids_db")

USER_ID = os.environ.get("USER_ID", "demo_user")
DEVICE_ID = os.environ.get("DEVICE_ID", "demo_device")

MODEL_PATH = os.environ.get("MODEL_PATH", "models/rf_model.joblib")
PROTO_ENCODER_PATH = os.environ.get("PROTO_ENCODER_PATH", "models/proto_encoder.joblib")
LABEL_ENCODER_PATH = os.environ.get("LABEL_ENCODER_PATH", "models/label_encoder.joblib")

THRESHOLD_SCORE = float(os.environ.get("THRESHOLD_SCORE", 65))  # now in percentage
SCAN_INTERVAL = float(os.environ.get("SCAN_INTERVAL", 1.5))


REPUTATION_CACHE_PATH = os.environ.get("REPUTATION_CACHE_PATH", "data/reputation_cache.json")
print("🔥 UPDATED realtime_detect.py LOADED")

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
print("API KEY FOUND:", bool(ABUSEIPDB_API_KEY))
print("API KEY FOUND:", bool(VIRUSTOTAL_API_KEY))

# -------------------- MONGO --------------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

packets_col = db["packets"]
alerts_col = db["alerts"]


# -------------------- LOAD MODEL --------------------
print("[Detector] Loading model:", MODEL_PATH)
model = joblib.load(MODEL_PATH)

print("[Detector] Loading protocol encoder:", PROTO_ENCODER_PATH)
proto_encoder = joblib.load(PROTO_ENCODER_PATH)

print("[Detector] Loading label encoder:", LABEL_ENCODER_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)

print("[Detector] Model + encoders loaded successfully")


# -------------------- REPUTATION CACHE --------------------
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
        os.makedirs(os.path.dirname(REPUTATION_CACHE_PATH), exist_ok=True)
        with open(REPUTATION_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=4)
    except:
        pass


reputation_cache = load_reputation_cache()


def get_reputation_score(ip):
    """
    Returns AbuseIPDB reputation score (0-100)
    Uses cache to avoid API spam.
    """
    if not ip:
        return 0, None

    if ip in reputation_cache:
        cached = reputation_cache[ip]
        return cached.get("abuseConfidenceScore", 0), cached

    if not ABUSEIPDB_API_KEY:
        return 0, None

    abuse_result = check_ip_abuse(ip, ABUSEIPDB_API_KEY)

    if "abuseConfidenceScore" in abuse_result:
        reputation_cache[ip] = abuse_result
        save_reputation_cache(reputation_cache)

    return abuse_result.get("abuseConfidenceScore", 0), abuse_result


# -------------------- FETCH PACKETS --------------------
def fetch_latest_packets(limit=50):
    packets = list(
        packets_col.find(
            {"user_id": USER_ID, "device_id": DEVICE_ID},
            {
                "_id": 1,
                "timestamp": 1,
                "src_ip": 1,
                "dst_ip": 1,
                "src_port": 1,
                "dst_port": 1,
                "protocol": 1,
                "packet_length": 1
            }
        ).sort("_id", -1).limit(limit)
    )
    packets.reverse()
    return packets


# -------------------- ML DETECTION --------------------
def detect_packet(packet):
    proto = str(packet.get("protocol", "tcp")).lower()

    try:
        proto_enc = int(proto_encoder.transform([proto])[0])
    except:
        proto_enc = 0

    src_bytes = int(packet.get("packet_length", 0) or 0)
    dst_bytes = 0

    features = np.array([[proto_enc, src_bytes, dst_bytes]])

    pred_class = model.predict(features)[0]

    # probability based score
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(features)[0]

        class_names = label_encoder.inverse_transform(model.classes_)
        class_names = [str(c).lower() for c in class_names]

        if "normal" in class_names:
            normal_index = class_names.index("normal")
            normal_prob = float(probs[normal_index])
            attack_prob = 1.0 - normal_prob
        else:
            attack_prob = float(max(probs))
    else:
        attack_prob = float(pred_class)

    label_name = str(label_encoder.inverse_transform([pred_class])[0])

    ml_score = round(attack_prob * 100, 2)  # convert to percentage

    return label_name, ml_score


# -------------------- HYBRID SCORE --------------------
def hybrid_final_score(ml_score, rule_score, rep_score):
    """
    Weighted Hybrid Score:
    ML = 40%
    Reputation = 35%
    Rules = 25%
    """
    final_score = (0.40 * ml_score) + (0.35 * rep_score) + (0.25 * rule_score)

    if final_score >= 65:
        decision = "MALICIOUS"
    elif final_score >= 35:
        decision = "SUSPICIOUS"
    else:
        decision = "NORMAL"

    return decision, round(final_score, 2)


# -------------------- CREATE ALERT --------------------
def create_alert(packet, label_name, ml_score, rule_score, rep_score, final_score, decision, abuse_result=None):
    alert_doc = {
        "timestamp": datetime.utcnow(),
        "user_id": USER_ID,
        "device_id": DEVICE_ID,

        "decision": decision,
        "final_score": final_score,
        "ml_score": ml_score,
        "rule_score": rule_score,
        "rep_score": rep_score,

        "predicted_label": label_name,
        "reason": f"Hybrid detection triggered: ML={ml_score}, RULE={rule_score}, REP={rep_score}",

        "packet": {
            "timestamp": packet.get("timestamp"),
            "src_ip": packet.get("src_ip"),
            "dst_ip": packet.get("dst_ip"),
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "protocol": packet.get("protocol"),
            "packet_length": packet.get("packet_length")
        }
    }

    if abuse_result:
        alert_doc["abuseipdb_result"] = abuse_result

    alerts_col.insert_one(alert_doc)


# -------------------- MAIN LOOP --------------------
def start_realtime_detection():
    print(f"[Detector] Running for USER={USER_ID} DEVICE={DEVICE_ID}")
    print("[Detector] Real-time detection started...")

    last_seen_id = None

    while True:
        packets = fetch_latest_packets(limit=50)

        for pkt in packets:
            pkt_id = pkt["_id"]

            if last_seen_id is not None and pkt_id <= last_seen_id:
                continue

            # ---------------- ML SCORE ----------------
            label_name, ml_score = detect_packet(pkt)

            # ---------------- RULE SCORE ----------------
            rule_score = rule_based_score(pkt)

            # ---------------- REPUTATION SCORE ----------------
            rep_score, abuse_result = get_reputation_score(pkt.get("src_ip"))

            # ---------------- FINAL HYBRID SCORE ----------------
            decision, final_score = hybrid_final_score(ml_score, rule_score, rep_score)

            # Store only Suspicious/Malicious alerts
            if decision != "NORMAL":
                create_alert(
                    pkt,
                    label_name,
                    ml_score,
                    rule_score,
                    rep_score,
                    final_score,
                    decision,
                    abuse_result
                )

                print("\n================ ALERT ================")
                print(decision)
                print(f"Src: {pkt.get('src_ip')} | Dst: {pkt.get('dst_ip')} | Protocol: {pkt.get('protocol')} | Port: {pkt.get('dst_port')}")
                print(f"Final Score: {final_score}")
                print(f"ML Score: {ml_score} | Rule Score: {rule_score} | Reputation Score: {rep_score}")
                print("Timestamp:", datetime.utcnow().isoformat())
                print("======================================\n")

            last_seen_id = pkt_id

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    start_realtime_detection()
