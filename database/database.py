import sqlite3
import os

# Create database folder if not exists
os.makedirs("database", exist_ok=True)

# Connect database
conn = sqlite3.connect('database/siem.db')

# Create cursor
cursor = conn.cursor()

# Create alerts table
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

# Save changes
conn.commit()

# Close connection
conn.close()

print("Database and table created successfully!")