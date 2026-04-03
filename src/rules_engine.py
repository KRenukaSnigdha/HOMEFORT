from collections import defaultdict
import time
import ipaddress

# Track packets per IP (for flood/burst detection)
ip_tracker = defaultdict(list)

# Track repeated port hits per src_ip (for UDP flood / scanning)
port_tracker = defaultdict(list)

# Common suspicious ports (can be adjusted)
SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    1433, 1521, 3306, 3389, 5900, 6667, 8080
}

# Optional static blacklist (example)
STATIC_BLACKLIST = {
    # "89.222.98.34",
    # "185.220.101.1"
}

# Known Cloud Provider IP ranges (basic examples)
CLOUD_RANGES = {
    "CLOUDFLARE": [
        "172.64.0.0/13",
        "104.16.0.0/12",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22"
    ],
    "GOOGLE": [
        "8.8.8.0/24",
        "8.34.208.0/20",
        "34.64.0.0/10"
    ],
    "MICROSOFT": [
        "13.64.0.0/11",
        "13.96.0.0/13",
        "40.64.0.0/10"
    ],
    "AMAZON_AWS": [
        "3.0.0.0/8",
        "13.32.0.0/15",
        "52.0.0.0/8"
    ]
}


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False


def get_cloud_provider(ip):
    """
    Returns provider name if IP belongs to known cloud/CDN ranges.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except:
        return None

    for provider, ranges in CLOUD_RANGES.items():
        for r in ranges:
            try:
                if ip_obj in ipaddress.ip_network(r):
                    return provider
            except:
                continue

    return None


def reputation_score(ip):
    """
    Reputation score (0 to 100)
    Current logic:
    - Private IP => 0
    - Static blacklist => 90
    - Cloud provider IP => 5
    - Unknown public IP => 0 (until AbuseIPDB is integrated)
    """

    if not ip:
        return 0

    if is_private_ip(ip):
        return 0

    if ip in STATIC_BLACKLIST:
        return 90

    provider = get_cloud_provider(ip)
    if provider:
        return 5

    return 0


def rule_based_score(row):
    """
    Returns a rule-based risk score from 0 to 100
    based on traffic behavior patterns.
    """

    score = 0
    src_ip = row.get("src_ip", "unknown")
    protocol = str(row.get("protocol", "")).upper()

    # Safe conversions
    try:
        pkt_len = int(row.get("packet_length", 0))
    except:
        pkt_len = 0

    try:
        dst_port = row.get("dst_port")
        dst_port = int(dst_port) if dst_port not in [None, "None", ""] else -1
    except:
        dst_port = -1

    now = time.time()

    # ---------------- RULES ----------------

    # Rule 1: Very large packets (possible flooding / data exfil)
    if pkt_len > 1200:
        score += 20

    if pkt_len > 2000:
        score += 20

    # Rule 2: Suspicious destination ports
    if dst_port in SUSPICIOUS_PORTS:
        score += 25

    # Rule 3: ICMP with high size (ICMP flood suspicion)
    if protocol == "ICMP" and pkt_len > 800:
        score += 30

    # Rule 4: UDP high port traffic (common in scanning/flood attacks)
    if protocol == "UDP" and dst_port > 50000:
        score += 15

    # ---------------- BURST DETECTION ----------------

    # Track IP traffic timestamps
    ip_tracker[src_ip].append(now)

    # Keep only last 10 seconds timestamps
    ip_tracker[src_ip] = [t for t in ip_tracker[src_ip] if now - t <= 10]

    # Rule 5: Packet burst detection (DoS / scanning)
    if len(ip_tracker[src_ip]) > 30:
        score += 20

    if len(ip_tracker[src_ip]) > 60:
        score += 30

    # Rule 6: UDP burst detection (strong indicator in your logs)
    if protocol == "UDP" and len(ip_tracker[src_ip]) > 20:
        score += 20

    if protocol == "UDP" and len(ip_tracker[src_ip]) > 50:
        score += 30

    # Rule 7: Very small packets repeatedly (port scanning pattern)
    if pkt_len < 80 and len(ip_tracker[src_ip]) > 40:
        score += 20

    # ---------------- SAME PORT REPETITION ----------------

    # Track same dst_port repetition for src_ip
    key = f"{src_ip}:{dst_port}"
    port_tracker[key].append(now)

    # Keep only last 10 sec for that src_ip:dst_port combo
    port_tracker[key] = [t for t in port_tracker[key] if now - t <= 10]

    # Rule 8: Same UDP port repeated too much (UDP flood / scanning)
    if protocol == "UDP" and len(port_tracker[key]) > 15:
        score += 25

    if protocol == "UDP" and len(port_tracker[key]) > 30:
        score += 35

    return min(score, 100)
