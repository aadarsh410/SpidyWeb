import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import os
import sqlite3

from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)

# --------------------------
# SAVE ALERT INTO DATABASE
# --------------------------

def save_alert(time, ip, attack_type, severity, details):

    conn = sqlite3.connect('database/siem.db')

    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO alerts (time, ip, attack_type, severity, details)
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

    plt.figure(figsize=(5, 5))

    plt.pie(
        sizes,
        labels=labels,
        autopct='%1.1f%%'
    )

    plt.title("Attack Analysis")

    # Create static folder if not exists
    os.makedirs("static", exist_ok=True)

    # Save chart
    plt.savefig('static/chart.png')

    plt.close()


# --------------------------
# STORE FAILED LOGIN ATTEMPTS
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
# USER LOGIN ROUTE
# --------------------------

@app.route('/', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        # Get IP Address
        ip_address = request.remote_addr

        # Get Current Time
        current_time = datetime.now()

        # Combine Input
        user_input = username + " " + password

        # Demo Correct Login
        correct_username = "admin"
        correct_password = "1234"

        # --------------------------
        # SUCCESSFUL LOGIN
        # --------------------------

        if username == correct_username and password == correct_password:

            status = "Successful Login"

            log_message = f"""
TIME: {current_time}
IP: {ip_address}
USERNAME: {username}
STATUS: {status}
-----------------------------------
"""

            with open("logs/access.log", "a") as file:
                file.write(log_message)

            return f"Welcome {username}"

        # --------------------------
        # FAILED LOGIN
        # --------------------------

        else:

            if ip_address not in failed_attempts:
                failed_attempts[ip_address] = 0

            failed_attempts[ip_address] += 1

            status = "Failed Login"

            log_message = f"""
TIME: {current_time}
IP: {ip_address}
USERNAME: {username}
STATUS: {status}
FAILED ATTEMPTS: {failed_attempts[ip_address]}
-----------------------------------
"""

            with open("logs/access.log", "a") as file:
                file.write(log_message)

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

                with open("logs/access.log", "a") as file:
                    file.write(alert)

                save_alert(
                    str(current_time),
                    ip_address,
                    "SQL Injection",
                    "HIGH",
                    user_input
                )

                return "SQL Injection Attack Detected!"

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

                with open("logs/access.log", "a") as file:
                    file.write(alert)

                save_alert(
                    str(current_time),
                    ip_address,
                    "XSS Attack",
                    "HIGH",
                    user_input
                )

                return "XSS Attack Detected!"

        # --------------------------
        # BRUTE FORCE DETECTION
        # --------------------------

        if ip_address in failed_attempts and failed_attempts[ip_address] >= 3:

            alert = f"""
TIME: {current_time}
IP: {ip_address}
SEVERITY: CRITICAL
ALERT: Brute Force Attack Detected
FAILED ATTEMPTS: {failed_attempts[ip_address]}
-----------------------------------
"""

            with open("logs/access.log", "a") as file:
                file.write(alert)

            save_alert(
                str(current_time),
                ip_address,
                "Brute Force",
                "CRITICAL",
                f"Failed Attempts: {failed_attempts[ip_address]}"
            )

            return "Brute Force Attack Detected!"

        return "Invalid Username or Password"

    return render_template('login.html')


# --------------------------
# ADMIN LOGIN ROUTE
# --------------------------

@app.route('/admin', methods=['GET', 'POST'])
def admin():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        admin_username = "admin"
        admin_password = "admin123"

        if username == admin_username and password == admin_password:

            return dashboard()

        else:
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
    # REAL-TIME LATEST ALERT
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