import os
from datetime import datetime
from pymongo import MongoClient
from scapy.all import sniff, IP, TCP, UDP
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# -------------------- CONFIG --------------------
MONGO_URI = os.environ.get("MONGO_URI")
DB_NAME = os.environ.get("DB_NAME", "ids_db")

USER_ID = os.environ.get("USER_ID", "demo_user")
DEVICE_ID = os.environ.get("DEVICE_ID", "demo_device")

PACKET_LIMIT = int(os.environ.get("PACKET_LIMIT", 5000))

if not MONGO_URI:
    raise ValueError("MONGO_URI not found. Please set it in .env file.")

# -------------------- MONGO --------------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
packets_col = db["packets"]

print("[Sniffer] Connected to MongoDB:", DB_NAME)

# -------------------- PACKET EXTRACT --------------------
def extract_packet_features(packet):
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    proto = "OTHER"

    src_port = None
    dst_port = None

    if packet.haslayer(TCP):
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        proto = str(ip_layer.proto)

    pkt_data = {
        "timestamp": datetime.utcnow(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "packet_length": len(packet),
        "user_id": USER_ID,
        "device_id": DEVICE_ID
    }

    return pkt_data

# -------------------- PACKET SAVE --------------------
def save_packet(pkt_data):
    if pkt_data:
        packets_col.insert_one(pkt_data)

        count = packets_col.count_documents({"user_id": USER_ID, "device_id": DEVICE_ID})
        if count > PACKET_LIMIT:
            oldest = packets_col.find(
                {"user_id": USER_ID, "device_id": DEVICE_ID},
                {"_id": 1}
            ).sort("timestamp", 1).limit(200)

            oldest_ids = [doc["_id"] for doc in oldest]
            if oldest_ids:
                packets_col.delete_many({"_id": {"$in": oldest_ids}})

# -------------------- MAIN --------------------
def start_sniffer():
    print(f"[Sniffer] Running for USER={USER_ID} DEVICE={DEVICE_ID}")
    print("[Sniffer] Capturing packets... Press CTRL+C to stop.")

    def packet_callback(packet):
        pkt_data = extract_packet_features(packet)
        save_packet(pkt_data)

    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffer()
