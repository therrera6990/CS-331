"""HelpDesk Lite (teaching codebase)."""

import os
import sqlite3
from html import escape as html_escape
from urllib.parse import unquote

from .security import hash_password, verify_password, make_session_token, verify_session_token
from .ops import ping_host
from .files import download_attachment
from .integrations import fetch_webhook
from .utils import audit_login

DB_PATH = os.path.join(os.path.dirname(__file__), "helpdesk.db")

# Load from env in real deployments; fallback here only for the teaching demo
SECRET_KEY = os.environ.get("HELPDESK_SECRET_KEY", "dev-secret-please-change")


def get_db():
    return sqlite3.connect(DB_PATH)


def get_authenticated_user(environ: dict) -> dict:
    """
    Server-side auth: verify a signed session token.
    Expects header: Authorization: Bearer <token>
    """
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if auth.startswith("Bearer "):
        token = auth[len("Bearer ") :].strip()
        ok, username = verify_session_token(token, SECRET_KEY)
        if ok:
            # In a real app, role comes from DB.
            return {"username": username, "role": "student"}

    return {"username": "guest", "role": "student"}


def require_admin(user: dict):
    if user.get("role") != "admin":
        raise PermissionError("admin required")


def search_tickets(q: str):
    # Parameterize LIKE. Escape wildcard chars to prevent abuse.
    q = (q or "")[:100]
    q_escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    like = f"%{q_escaped}%"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, subject, status FROM tickets WHERE subject LIKE ? ESCAPE '\\'",
        (like,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def view_ticket(ticket_id: int, environ: dict):
    user = get_authenticated_user(environ)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, owner, subject, body, status FROM tickets WHERE id = ?", (ticket_id,))
    row = cur.fetchone()
    conn.close()

    # Basic authz: owner or admin only
    if row:
        _id, owner, *_rest = row
        if user["role"] != "admin" and user["username"] != owner:
            raise PermissionError("forbidden")

    return {"viewer": user, "ticket": row}


def reset_password(username: str, new_password: str, environ: dict):
    user = get_authenticated_user(environ)
    require_admin(user)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (hash_password(new_password), username),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "username": username}


def add_comment(ticket_id: int, comment_html: str, environ: dict):
    user = get_authenticated_user(environ)

    # Store escaped text to prevent stored XSS if rendered as HTML later.
    safe_text = html_escape(comment_html or "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO comments(ticket_id, author, comment_html) VALUES (?, ?, ?)",
        (ticket_id, user["username"], safe_text),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


def download(file_param: str):
    filename = unquote(file_param or "")
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
        audit_login(username, password, False)
        return {"ok": False}

    stored = row[0]
    ok = verify_password(password, stored)

    audit_login(username, password, ok)

    if ok:
        token = make_session_token(username, SECRET_KEY)
        return {"ok": True, "session": token}

    return {"ok": False}