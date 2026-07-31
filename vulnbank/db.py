"""Tiny SQLite layer with seed data shared by several labs.

Passwords are stored twice on purpose so the crypto lab (A04) can contrast a
crackable MD5 hash with a proper bcrypt hash for the same account.
"""
import hashlib
import os
import sqlite3

import bcrypt

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnbank.sqlite")

SEED_USERS = [
    # id, username, plaintext (only used to derive the stored hashes), role, balance
    (1, "alice", "password123", "user", 500),
    (2, "bob", "hunter2", "user", 500),
    (3, "admin", "S3cretAdmin!", "admin", 999999),
]
SEED_INVOICES = [
    # id, owner_id, amount, memo
    (1001, 1, 42.00, "Alice — electricity"),
    (1002, 1, 88.50, "Alice — internet"),
    (2001, 2, 15.00, "Bob — coffee subscription"),
    (3001, 3, 0.00, "ADMIN — payroll export (confidential)"),
]


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init(force=False):
    if force and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    if os.path.exists(DB_PATH):
        return
    conn = connect()
    conn.executescript("""
        CREATE TABLE users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, md5 TEXT,
            bcrypt TEXT, role TEXT, balance REAL);
        CREATE TABLE invoices(
            id INTEGER PRIMARY KEY, owner_id INTEGER, amount REAL, memo TEXT);
    """)
    for uid, name, pw, role, bal in SEED_USERS:
        md5 = hashlib.md5(pw.encode()).hexdigest()
        bc = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=10)).decode()
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",
                     (uid, name, md5, bc, role, bal))
    conn.executemany("INSERT INTO invoices VALUES (?,?,?,?)", SEED_INVOICES)
    conn.commit()
    conn.close()
