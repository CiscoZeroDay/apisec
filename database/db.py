# db/database.py
import sqlite3

class Database:
    def __init__(self, db_name="scan_results.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            type TEXT,
            severity TEXT,
            endpoint TEXT,
            payload TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT,
            url TEXT,
            status INTEGER,
            time REAL
        )
        """)

        self.conn.commit()

    def insert_scan(self, target):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO scans (target) VALUES (?)", (target,))
        self.conn.commit()
        return cursor.lastrowid