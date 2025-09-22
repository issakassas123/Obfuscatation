import secrets
import sqlite3
import string
from flask import jsonify

def insert_token():
    try:

        characters = string.ascii_letters + string.digits

        token = "".join(secrets.choice(characters) for _ in range(40))

        print(f"Generated Key: {token}")

        conn = sqlite3.connect("db\vault.db")
        cursor = conn.cursor()

        cursor.execute("INSERT INTO tokens (token) VALUES (?)", (token,))

        conn.commit()

        conn.close()

        print(f"Token {token} inserted successfully")
        return token

    except sqlite3.Error as e:
        print("SQLite error:", e)


def create_table():
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect("db\vault.db")
        cursor = conn.cursor()
        
        # Create firewall_status table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='firewall_status'")
        status = cursor.fetchone()
        if not status:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS firewall_status (
                    id INTEGER PRIMARY KEY,
                    status BOOLEAN
                )
            ''')
            # Insert a default row if the table is empty
            cursor.execute('''
                INSERT OR IGNORE INTO firewall_status (id, status)
                VALUES (1, 0)
            ''')
            print("Created firewall_status table")

        # Create trusted_ip table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='trusted_ip'")
        ip_exist = cursor.fetchone()
        if not ip_exist:
            cursor.execute('''
                CREATE TABLE trusted_ip(
                    id INTEGER PRIMARY KEY,
                    ip TEXT NOT NULL
                )
            ''')

        # Create keys_management table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys_management'")
        keys_management_exists = cursor.fetchone()
        if not keys_management_exists:
            cursor.execute('''
                CREATE TABLE keys_management (
                    id INTEGER PRIMARY KEY,
                    key1 TEXT NOT NULL,
                    key2 TEXT NOT NULL,
                    value TEXT NOT NULL
                )
            ''')

        # Create users table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        users_exist = cursor.fetchone()
        if not users_exist:
            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    userName TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            ''')

        # Create tokens table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tokens'")
        tokens_exists = cursor.fetchone()
        if not tokens_exists:
            cursor.execute('''
                CREATE TABLE tokens (
                    id INTEGER PRIMARY KEY,
                    token TEXT NOT NULL,
                    isSend INTEGER NOT NULL DEFAULT 0
                )
            ''')

        conn.commit()
        conn.close()
        
        if tokens_exists and keys_management_exists:
            print("Tables already exist")
            return jsonify("Tables already exist")
        else:
            print("Tables created successfully")
            insert_token()

    except sqlite3.Error as e:
        print("SQLite error:", e)
