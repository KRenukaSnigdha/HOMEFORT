# 🛡️ HOMEFORT

## AI-Powered Intrusion Detection System (IDS) for Home Networks

An AI-driven Intrusion Detection System (IDS) designed to monitor home network traffic, detect suspicious activities, and generate real-time alerts using Machine Learning.
This project includes a Flask-based Web Dashboard for live packet monitoring, threat visualization, and alert management.

 <img width="1901" height="905" alt="image" src="https://github.com/user-attachments/assets/146ae9f1-b7f7-40a2-9f81-8700def838a0" />


---

## 🚀 Project Highlights

- ✅ Real-time packet capture and logging
- ✅ Machine Learning based intrusion classification
- ✅ Live dashboard with graphs and packet table
- ✅ Alerts generated and stored in alerts.log
- ✅ Export filtered packet logs as CSV
- ✅ Search + Sort + Pagination for smooth performance
- ✅ Clean UI with security-focused layout

---

## 🧰 Features
### 🔍 Packet Monitoring:
- Captures network packets in real time
- Stores packet logs in captured_packets.csv
- Displays latest packets in the dashboard
### ⚠️ Threat Detection:
- Uses a trained ML model to classify traffic
- Generates alerts automatically for suspicious packets
- Alerts stored in alerts.log
### 📊 Dashboard Analytics:
- Packet Length Graph
- Protocol Frequency
- Source IP Frequency
- Destination IP Frequency
- Traffic Volume Monitoring
### 🧰 Smart Filters:
- Search by Source/Destination IP
- Sort by packet length
- Pagination (Next/Prev) for lag-free performance
- Export filtered packets as CSV
### 🔔 Alerts System:
- Live alert badge count
- Alert sound notification (optional)
- Auto severity detection (High / Medium / Low)

---

## 🏗️ Architecture
```
+-------------------+      +-------------------+      +-------------------+
|  Packet Sniffer   | ---> |  ML Classifier    | ---> |  Alert/Block/Log  |
+-------------------+      +-------------------+      +-------------------+
        |                        |                           |
        v                        v                           v
   [captured_packets.csv]   [rf_model.joblib]         [alerts.log]
        |                        |                           |
        +------------------------+---------------------------+
                                 |
                                 v
                        [Flask Dashboard]
```

---

## 📊 Dashboard Modules
- Dashboard includes:
- Live packet table (latest captured traffic)
- Alerts panel with severity tags
- Live graphs updated automatically
- CSV export for filtered packet data

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
│   ├── sniffer.py
│   ├── realtime_detect.py
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
│
├── requirements.txt
├── .gitignore
└── README.md

```

---

## 🏗️ Tech Stack
### Frontend
- HTML5, CSS3, JavaScript
- Chart.js for live graphs
### Backend
- Python Flask
### Machine Learning
- Random Forest model (rf_model.joblib)
- Encoders (proto_encoder.joblib)
### Storage
- CSV-based packet logging
- Log file based alert system

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

<img width="1899" height="909" alt="image" src="https://github.com/user-attachments/assets/b18e9caf-9dd7-4c29-a03b-6f709b5d1e55" />

<img width="517" height="799" alt="image" src="https://github.com/user-attachments/assets/45932663-6e5e-4aa9-a140-55590238b632" />

<img width="585" height="896" alt="image" src="https://github.com/user-attachments/assets/a98330e1-cff9-4b54-86cb-7c8bf6967d56" />


---

## 🛡️ Security Use Case

- This IDS is useful for:
- Detecting suspicious traffic in home Wi-Fi
- Monitoring unknown IP activity
- Identifying abnormal packet patterns
- Generating real-time threat alerts

---

## 🙏 Acknowledgements
- [Scapy](https://scapy.net/)
- [scikit-learn](https://scikit-learn.org/)
- [Streamlit](https://streamlit.io/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html) 
