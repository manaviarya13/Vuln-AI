"""Intentionally vulnerable demo code. Never use these patterns in production."""

import sqlite3

API_KEY = "demo_secret_key_do_not_use"


def find_user(cursor: sqlite3.Cursor) -> None:
    """Unsafe demo query built by concatenating untrusted input."""
    user_id = input("User ID: ")
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n