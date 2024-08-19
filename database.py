import sqlite3
from sqlite3 import Error
import hashlib
from datetime import datetime

# Database connection
def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print("Connection established")
    except Error as e:
        print(e)
    return conn

# Create tables
def create_tables(conn):
    try:
        cursor = conn.cursor()

        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          username TEXT NOT NULL UNIQUE,
                          password TEXT NOT NULL
                          )''')

        # Create logs table
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          user_id INTEGER,
                          timestamp TEXT NOT NULL,
                          action TEXT NOT NULL,
                          status TEXT NOT NULL,
                          FOREIGN KEY (user_id) REFERENCES users (id)
                          )''')

        # Create captured_data table
        cursor.execute('''CREATE TABLE IF NOT EXISTS captured_data (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          packet_data TEXT,
                          timestamp TEXT NOT NULL,
                          status TEXT NOT NULL
                          )''')

        print("Tables created successfully")
    except Error as e:
        print(e)

# Hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Validate user credentials
def validate_user(conn, username, password):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                       (username, hash_password(password)))
        user = cursor.fetchone()
        if user:
            log_action(conn, user[0], "login", "success")
            print("User validated successfully")
            return user
        else:
            log_action(conn, None, "login", "failed")
            print("Invalid username or password")
            return None
    except Error as e:
        print(e)

# Create a new user
def create_user(conn, username, password):
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                       (username, hash_password(password)))
        conn.commit()
        log_action(conn, cursor.lastrowid, "create_user", "success")
        print("User created successfully")
    except Error as e:
        log_action(conn, None, "create_user", "failed")
        print(e)

# Update a user
def update_user(conn, user_id, new_username=None, new_password=None):
    try:
        cursor = conn.cursor()
        if new_username:
            cursor.execute("UPDATE users SET username = ? WHERE id = ?", 
                           (new_username, user_id))
        if new_password:
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", 
                           (hash_password(new_password), user_id))
        conn.commit()
        log_action(conn, user_id, "update_user", "success")
        print("User updated successfully")
    except Error as e:
        log_action(conn, user_id, "update_user", "failed")
        print(e)

# Delete a user
def delete_user(conn, user_id):
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        log_action(conn, user_id, "delete_user", "success")
        print("User deleted successfully")
    except Error as e:
        log_action(conn, user_id, "delete_user", "failed")
        print(e)

# Log an action (records both success and failure statuses)
def log_action(conn, user_id, action, status):
    try:
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO logs (user_id, timestamp, action, status) VALUES (?, ?, ?, ?)", 
                       (user_id, timestamp, action, status))
        conn.commit()
        print(f"Action '{action}' logged with status '{status}'")
    except Error as e:
        print(e)

# Store captured data (records both successful and failed captures)
def store_captured_data(conn, packet_data, status):
    try:
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO captured_data (packet_data, timestamp, status) VALUES (?, ?, ?)", 
                       (packet_data, timestamp, status))
        conn.commit()
        print(f"Packet data stored with status '{status}'")
    except Error as e:
        print(e)

# Update captured data
def update_captured_data(conn, data_id, new_packet_data, status):
    try:
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE captured_data SET packet_data = ?, timestamp = ?, status = ? WHERE id = ?", 
                       (new_packet_data, timestamp, status, data_id))
        conn.commit()
        log_action(conn, None, "update_captured_data", "success")
        print("Captured data updated successfully")
    except Error as e:
        log_action(conn, None, "update_captured_data", "failed")
        print(e)

# Delete captured data
def delete_captured_data(conn, data_id):
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM captured_data WHERE id = ?", (data_id,))
        conn.commit()
        log_action(conn, None, "delete_captured_data", "success")
        print("Captured data deleted successfully")
    except Error as e:
        log_action(conn, None, "delete_captured_data", "failed")
        print(e)
