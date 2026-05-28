import sqlite3
import os

# --------------------------
# CREATE DATABASE FOLDER
# --------------------------

os.makedirs("database", exist_ok=True)

# --------------------------
# CONNECT DATABASE
# --------------------------

conn = sqlite3.connect('database/siem.db')

# --------------------------
# CREATE CURSOR
# --------------------------

cursor = conn.cursor()

# --------------------------
# CREATE ALERTS TABLE
# --------------------------

cursor.execute('''
CREATE TABLE IF NOT EXISTS alerts (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    time TEXT,

    ip TEXT,

    attack_type TEXT,

    severity TEXT,

    details TEXT
)
''')

# --------------------------
# DELETE OLD DATA (OPTIONAL)
# --------------------------

cursor.execute("DELETE FROM alerts")

# --------------------------
# SAVE CHANGES
# --------------------------

conn.commit()

# --------------------------
# CLOSE CONNECTION
# --------------------------

conn.close()

print("Database created and old records deleted successfully!")