# 🛡️ HOMEFORT

## AI-Powered Intrusion Detection System (IDS) for Home Networks

A hybrid IDS combining Signature rules, Machine Learning, and Threat Intelligence to detect, analyze, and alert on suspicious network activity in real time via an intuitive Flask dashboard

<img width="1882" height="909" alt="image" src="https://github.com/user-attachments/assets/62bf5ed1-d77d-4526-8e2e-86e289c3fb3b" />

---

## 🚀 Project Highlights

- ✅ Real-time packet capture enhanced with GeoIP for enriched threat intelligence and location context
- ✅ Hybrid multi-layer IDS combining signature, ML, AbuseIPDB reputation data and Geo-Location Correlation
- ✅ Instant severity-tagged alerts with sound notifications and audit logging
- ✅ Exportable reports and clean, security-focused user interface
---

## 🧰 Features
### 🔍 Packet Monitoring:
- Live capture and display of network traffic, saved for analysis.
### ⚠️ Hybrid Threat Detection:
- Combines signature patterns, ML classification, and IP reputation scores into a weighted decision.
### 📊 GeoIP Visualization:
- Maps attack origins on an interactive world heatmap.
### 🧰Threat Intel Integration:
- AbuseIPDB and VirusTotal
### 🔔 Alerts System:
- Real-time alerts with sound notifications and severity tagging, logged for review.

---

## 🏗️ Architecture
```
+-----------------------+      +------------------------+      +---------------------------+
|    Packet Sniffer     | ---> |  Hybrid IDS Model      | ---> | Alert/Block/Log System    |
+-----------------------+      +------------------------+      +---------------------------+
        |                              |                                |
        v                              v                                v
[captured_packets.csv]      [Model: Signature + ML + Reputation]    [alerts.log, threat DB/cache]
        |                              |                                |
        +------------------------------+--------------------------------+
                                       |
                                       v
                             [Flask Web Dashboard & Visualization]

```

---

## 📊 Dashboard Modules
- **Live Traffic:** Real-time packet capture with filters and sorting.
- **AbuseIPDB:** IP reputation and abuse score lookup.
- **Geo Map:** Visual attacker locations via GeoLite2.
- **Alerts:** ML-powered, rule-based threat scoring.
- **CSV Export:** Download filtered traffic data instantly.

---

## 📦 Project Structure
```
ai-powered-ids-for-home-networks/
│
├── models/
│   ├── rf_model.joblib
│   ├── proto_encoder.joblib
│
├── src/
│   ├── dataset_prep.py
│   ├── train_model.py
│   ├── sniffer.py
│   ├── realtime_detect.py
│   ├── threat_intel.py
│   ├── rules_engine  .py
│
├── web/
│   ├── app.py
│   ├── templates/
│   │   ├── home.html
│   │   ├── dashboard.html
│   ├── static/
│   │   ├── css/style.css
│   │   ├── js/app.js
│   │   ├── images/logo.png
│
├── data/
│   ├── captured_packets.csv
│   ├── alerts.log
│   ├── geoip/GeoLite2-City.mmdb
│
├── requirements.txt
├── .gitignore
└── README.md

```

---

## 🏗️ Tech Stack
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **Backend:** Python Flask
- **ML:** Random Forest & signature-based detection
- **Threat Intel:** AbuseIPDB
- **Storage:** CSV logs, alert files, GeoLite2 DB

---

## ⚡ Quickstart (Local)

### 1. Clone the Repository
```sh
git clone <repo-url>
cd ai-powered-ids-for-home-networks
```

### 2. Set Up Python Environment
```sh
python -m venv venv
venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On Linux/Mac
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Prepare Dataset & Train Model
```sh
python src/dataset_prep.py      # Download and preprocess NSL-KDD
python src/train_model.py       # Train and save the ML model
```

### 4. Start Packet Capture
```sh
python src/sniffer.py           # Run in a separate terminal
```

### 5. (Optional) Set AbuseIPDB API Key
Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/).
```sh
$env:ABUSEIPDB_API_KEY="your_api_key_here"  # Windows
export ABUSEIPDB_API_KEY="your_api_key_here"  # Linux/Mac
```

### 6. Run Real-Time Detection
```sh
python src/realtime_detect.py   # Run in a separate terminal
```

### 7. Run the Web Dashboard
```sh
cd web
python app.py

```
Then open in browser:

http://127.0.0.1:5000/

---
## Screenshots

<img width="1887" height="904" alt="Screenshot 2026-02-08 222500" src="https://github.com/user-attachments/assets/4d61b057-e1e2-46a8-88fa-206a36351bc5" />

<img width="1900" height="906" alt="image" src="https://github.com/user-attachments/assets/2548f65a-c66e-461f-8bf2-61fe271d7b8d" />


---

## 🛡️ Security Use Case
- Protects home networks by:
- Detecting suspicious traffic
- Monitoring unknown IPs
- Spotting abnormal packet patterns
- Delivering real-time threat alerts

---

## 🙏 Acknowledgements
- [Scapy](https://scapy.net/)
- [scikit-learn](https://scikit-learn.org/)
- [Streamlit](https://streamlit.io/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html)

---
## ⭐ Support
- If you like this project, please ⭐ star the repository and share it.
