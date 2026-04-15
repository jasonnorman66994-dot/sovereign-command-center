"""
Sovereign DB — Target Management
=================================
SQLite-backed store for pulse targets and per-target delivery counts.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "sovereign.db"


def _connect():
    return sqlite3.connect(str(DB_PATH))


def init_db():
    conn = _connect()
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS targets
           (id INTEGER PRIMARY KEY,
            email TEXT UNIQUE,
            pulses_received INTEGER DEFAULT 0)"""
    )
    c.execute(
        "INSERT OR IGNORE INTO targets (email) VALUES (?)",
        ("jasonnorman66994@gmail.com",),
    )
    conn.commit()
    conn.close()


def get_all_targets():
    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT email FROM targets")
    emails = [row[0] for row in c.fetchall()]
    conn.close()
    return emails


def get_targets_with_pulses() -> list[dict[str, int | str]]:
    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT email, pulses_received FROM targets")
    rows = c.fetchall()
    conn.close()
    return [{"email": row[0], "pulses": int(row[1])} for row in rows]


def increment_pulse(email: str):
    conn = _connect()
    c = conn.cursor()
    c.execute(
        "UPDATE targets SET pulses_received = pulses_received + 1 WHERE email = ?",
        (email,),
    )
    conn.commit()
    conn.close()


def add_target(email: str) -> bool:
    conn = _connect()
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO targets (email) VALUES (?)", (email,))
    created = c.rowcount > 0
    conn.commit()
    conn.close()
    return created


def remove_target(email: str) -> bool:
    conn = _connect()
    c = conn.cursor()
    c.execute("DELETE FROM targets WHERE email = ?", (email,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def purge_targets() -> None:
    conn = _connect()
    c = conn.cursor()
    c.execute("DELETE FROM targets")
    conn.commit()
    conn.close()


init_db()
