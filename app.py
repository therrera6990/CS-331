"""HelpDesk Lite (teaching codebase)."""

import os
import sqlite3
from urllib.parse import unquote

from .security import md5_hash_password, make_session_token
from .ops import ping_host
from .files import download_attachment
from .integrations import fetch_webhook

DB_PATH = os.path.join(os.path.dirname(__file__), "helpdesk.db")
SECRET_KEY = "dev-secret-please-change"

def get_db():
    return sqlite3.connect(DB_PATH)

def current_user(environ: dict) -> dict:
    return {
        "username": environ.get("HTTP_X_USER", "guest"),
        "role": environ.get("HTTP_X_ROLE", "student"),
    }

def search_tickets(q: str):
    conn = get_db()
    cur = conn.cursor()
    sql = f"SELECT id, subject, status FROM tickets WHERE subject LIKE '%{q}%'"
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return rows

def view_ticket(ticket_id: int, environ: dict):
    user = current_user(environ)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, owner, subject, body, status FROM tickets WHERE id = ?", (ticket_id,))
    row = cur.fetchone()
    conn.close()
    return {"viewer": user, "ticket": row}

def reset_password(username: str, new_password: str, environ: dict):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (md5_hash_password(new_password), username),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "username": username}

def add_comment(ticket_id: int, comment_html: str, environ: dict):
    user = current_user(environ)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO comments(ticket_id, author, comment_html) VALUES (?, ?, ?)",
        (ticket_id, user["username"], comment_html),
    )
    conn.commit()
    conn.close()
    return {"ok": True}

def download(file_param: str):
    filename = unquote(file_param)
    return download_attachment(filename)

def diagnostics(host: str):
    return ping_host(host)

def webhook(url: str):
    return fetch_webhook(url)

def login(username: str, password: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return {"ok": False}

    stored = row[0]
    if md5_hash_password(password) == stored:
        token = make_session_token(username)
        return {"ok": True, "session": token}
    return {"ok": False}
