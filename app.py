"""
Project: Web Attack Detection SIEM
Developer: Aadarsh
Copyright © 2026
"""

import os
import sqlite3
from datetime import datetime

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for
)

app = Flask(__name__)

# --------------------------
# CREATE REQUIRED FOLDERS
# --------------------------

os.makedirs("logs", exist_ok=True)
os.makedirs("database", exist_ok=True)
os.makedirs("static", exist_ok=True)

# --------------------------
# CREATE LOG FILE
# --------------------------

if not os.path.exists("logs/access.log"):

    with open("logs/access.log", "w") as file:
        file.write("=== SIEM LOG FILE ===\n\n")

# --------------------------
# FAILED LOGIN STORAGE
# --------------------------

failed_attempts = {}

# --------------------------
# SQL INJECTION PATTERNS
# --------------------------

sql_patterns = [
    "' OR 1=1",
    "OR 1=1",
    "--",
    "UNION SELECT"
]

# --------------------------
# XSS PATTERNS
# --------------------------

xss_patterns = [
    "<script>",
    "</script>",
    "alert(",
    "javascript:"
]

# --------------------------
# WRITE LOG FUNCTION
# --------------------------

def write_log(message):

    with open("logs/access.log", "a") as file:
        file.write(message)

# --------------------------
# SAVE ALERT TO DATABASE
# --------------------------

def save_alert(time, ip, attack_type, severity, details):

    conn = sqlite3.connect('database/siem.db')

    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO alerts (
        time,
        ip,
        attack_type,
        severity,
        details
    )
    VALUES (?, ?, ?, ?, ?)
    ''', (time, ip, attack_type, severity, details))

    conn.commit()
    conn.close()

# --------------------------
# GENERATE PIE CHART
# --------------------------

def generate_chart(sql_count, xss_count, brute_force_count):

    labels = [
        'SQL Injection',
        'XSS',
        'Brute Force'
    ]

    sizes = [
        sql_count,
        xss_count,
        brute_force_count
    ]

    if sum(sizes) == 0:
        sizes = [1, 1, 1]

    plt.figure(figsize=(5, 5))

    plt.pie(
        sizes,
        labels=labels,
        autopct='%1.1f%%'
    )

    plt.title("Attack Analysis")

    plt.savefig("static/chart.png")

    plt.close()

# --------------------------
# USER LOGIN ROUTE
# --------------------------

@app.route('/', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        ip_address = request.remote_addr

        current_time = datetime.now()

        user_input = username + " " + password

        # --------------------------
        # DEMO LOGIN
        # --------------------------

        correct_username = "admin"
        correct_password = "1234"

        # --------------------------
        # SUCCESSFUL LOGIN
        # --------------------------

        if username == correct_username and password == correct_password:

            log_message = f"""
TIME: {current_time}
IP: {ip_address}
USERNAME: {username}
STATUS: Successful Login
-----------------------------------
"""

            write_log(log_message)

            return render_template(
                "success.html",
                username=username
            )

        # --------------------------
        # FAILED LOGIN
        # --------------------------

        if ip_address not in failed_attempts:

            failed_attempts[ip_address] = 0

        failed_attempts[ip_address] += 1

        log_message = f"""
TIME: {current_time}
IP: {ip_address}
USERNAME: {username}
STATUS: Failed Login
FAILED ATTEMPTS: {failed_attempts[ip_address]}
-----------------------------------
"""

        write_log(log_message)

        # --------------------------
        # SQL INJECTION DETECTION
        # --------------------------

        for pattern in sql_patterns:

            if pattern.lower() in user_input.lower():

                alert = f"""
TIME: {current_time}
IP: {ip_address}
SEVERITY: HIGH
ALERT: SQL Injection Detected
INPUT: {user_input}
-----------------------------------
"""

                write_log(alert)

                save_alert(
                    str(current_time),
                    ip_address,
                    "SQL Injection",
                    "HIGH",
                    user_input
                )

                return render_template("sql_alert.html")

        # --------------------------
        # XSS DETECTION
        # --------------------------

        for pattern in xss_patterns:

            if pattern.lower() in user_input.lower():

                alert = f"""
TIME: {current_time}
IP: {ip_address}
SEVERITY: HIGH
ALERT: XSS Attack Detected
INPUT: {user_input}
-----------------------------------
"""

                write_log(alert)

                save_alert(
                    str(current_time),
                    ip_address,
                    "XSS Attack",
                    "HIGH",
                    user_input
                )

                return render_template("xss_alert.html")

        # --------------------------
        # BRUTE FORCE DETECTION
        # --------------------------

        if failed_attempts[ip_address] >= 3:

            alert = f"""
TIME: {current_time}
IP: {ip_address}
SEVERITY: CRITICAL
ALERT: Brute Force Attack Detected
FAILED ATTEMPTS: {failed_attempts[ip_address]}
-----------------------------------
"""

            write_log(alert)

            save_alert(
                str(current_time),
                ip_address,
                "Brute Force",
                "CRITICAL",
                f"Failed Attempts: {failed_attempts[ip_address]}"
            )

            return render_template("bruteforce_alert.html")

        return render_template("invalid.html")

    return render_template('login.html')

# --------------------------
# ADMIN LOGIN ROUTE
# --------------------------

@app.route('/admin', methods=['GET', 'POST'])
def admin():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        ADMIN_USERNAME = "admin"
        ADMIN_PASSWORD = "admin123"

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:

            return redirect(url_for('dashboard'))

        return "Invalid Admin Credentials"

    return render_template('admin.html')

# --------------------------
# DASHBOARD ROUTE
# --------------------------

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():

    with open("logs/access.log", "r") as file:

        alerts = file.read()

    # --------------------------
    # SEARCH FEATURE
    # --------------------------

    search_query = ""

    if request.method == 'POST':

        search_query = request.form['search']

        filtered_logs = []

        lines = alerts.splitlines()

        for line in lines:

            if search_query.lower() in line.lower():

                filtered_logs.append(line)

        alerts = "\n".join(filtered_logs)

    # --------------------------
    # ATTACK COUNTS
    # --------------------------

    sql_count = alerts.count("SQL Injection Detected")

    xss_count = alerts.count("XSS Attack Detected")

    brute_force_count = alerts.count("Brute Force Attack Detected")

    total_attacks = (
        sql_count +
        xss_count +
        brute_force_count
    )

    # --------------------------
    # GENERATE PIE CHART
    # --------------------------

    generate_chart(
        sql_count,
        xss_count,
        brute_force_count
    )

    # --------------------------
    # LATEST ALERT
    # --------------------------

    latest_alert = "No Alerts"

    lines = alerts.splitlines()

    for line in reversed(lines):

        if "ALERT:" in line:

            latest_alert = line

            break

    # --------------------------
    # LOAD DASHBOARD
    # --------------------------

    return render_template(
        'dashboard.html',
        alerts=alerts,
        sql_count=sql_count,
        xss_count=xss_count,
        brute_force_count=brute_force_count,
        total_attacks=total_attacks,
        latest_alert=latest_alert,
        search_query=search_query
    )

# --------------------------
# RUN APPLICATION
# --------------------------

if __name__ == '__main__':

    app.run(debug=False)