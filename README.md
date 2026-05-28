# Web Attack Detection SIEM

A mini SIEM (Security Information and Event Management) system developed using Python, Flask, SQLite, and Matplotlib to detect and monitor common web attacks in real time.

---

## 🚀 Features

- SQL Injection Detection
- XSS Attack Detection
- Brute Force Attack Detection
- Real-Time Security Alerts
- Attack Logging System
- Admin Dashboard
- Search Logs Feature
- SQLite Database Storage
- Pie Chart Analytics

---

## 🛠️ Technologies Used

- Python
- Flask
- SQLite
- HTML5
- CSS3
- Matplotlib

---

## 📌 Project Description

This project simulates a basic SIEM system capable of detecting common web attacks such as SQL Injection, XSS, and brute force login attempts.

Detected attacks are:
- logged into log files
- stored in SQLite database
- displayed on an admin dashboard
- visualized using charts

---

## 📂 Project Structure

```text
WebAttackSIEM/
│
├── app.py
├── database.py
│
├── database/
│   └── siem.db
│
├── logs/
│   └── access.log
│
├── static/
│   ├── style.css
│   └── chart.png
│
└── templates/
    ├── login.html
    ├── admin.html
    └── dashboard.html
```

---

## ▶️ How to Run

### Install Required Libraries

```bash
pip install flask matplotlib
```

### Create Database

```bash
python database.py
```

### Run Application

```bash
python app.py
```

Open browser:

```text
http://127.0.0.1:5000/
```

---

## 🔐 Admin Dashboard

```text
URL:
http://127.0.0.1:5000/admin

Username: admin
Password: admin123
```

---

## 👨‍💻 Developer

Aadarsh
