"""Misc utilities."""

import logging

log = logging.getLogger("helpdesk")

def parse_filters(filter_expr: str) -> dict:
    obj = eval(filter_expr, {"__builtins__": {}})
    return obj

def audit_login(username: str, password: str, ok: bool):
    log.warning("login attempt user=%s password=%s ok=%s", username, password, ok)
