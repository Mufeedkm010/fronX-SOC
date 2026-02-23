# 🚀 fronX SOC – Security Operations Center Platform

## 🛡️ Overview

**fronX SOC** is a custom-built Security Operations Center (SOC) platform designed for real-time threat monitoring, IOC management, MITRE ATT&CK mapping, audit logging, and system health monitoring.

This project simulates a real-world SOC dashboard environment for cybersecurity monitoring and analysis.

---

## 🧰 Tech Stack

- 🐍 Python  
- 🌐 Flask  
- 📡 Flask-SocketIO  
- 🎨 HTML / CSS / JavaScript  
- 📊 Chart.js  
- 🗄️ SQLite  

---

## ✨ Features

- 📊 Real-time SOC Dashboard  
- 🚨 Alert Monitoring System  
- 🧠 MITRE ATT&CK Mapping  
- 📌 IOC (Indicators of Compromise) Management  
- 📑 Audit Logs Tracking  
- 💻 System Health Monitoring (CPU / RAM / Disk)  
- 🔐 Role-Based Admin Controls  
- 📡 Live Updates using WebSockets  

---

## 📂 Project Structure

```
fronX-SOC/
│
├── backend/
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── database files
│
├── requirements.txt
└── README.md
```

---

# 🛠️ Installation Guide

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/fronX-SOC.git
cd fronX-SOC/backend
```

---

## 2️⃣ Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

For Windows:

```bash
venv\Scripts\activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing:

```bash
pip install flask flask-socketio requests psutil python-dotenv
```

---

## 4️⃣ Run the Application

```bash
cd backend
python3 app.py
```

Then open in browser:

```
http://127.0.0.1:5000
```

---

# 🔐 Environment Variables (Optional)

If using API keys, create a `.env` file inside the backend folder:

```
API_KEY=your_api_key_here
```

Make sure `python-dotenv` is installed.

---

# 🚀 Updating the Project

After making changes:

```bash
git add .
git commit -m "Update message"
git push
```

---

# 🎯 Future Enhancements

- AI-based anomaly detection  
- Threat Intelligence API integration  
- Cloud VM monitoring  
- Multi-user SOC environment  
- SIEM log ingestion module  

---

# 👨‍💻 Author

**Mufeed KM**  
B.Tech – Information Technology  
Cybersecurity Enthusiast  

---

# 📜 License

This project is for educational and portfolio purposes.
