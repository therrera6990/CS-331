"""Misc utilities."""

import ast
import json
import logging
from typing import Any, Dict

log = logging.getLogger("helpdesk")


def parse_filters(filter_expr: str) -> Dict[str, Any]:
    """
    Safe parsing for filter expressions.

    Accepts:
      - JSON object string (preferred)
      - Python-literal dict (fallback) via ast.literal_eval

    Rejects anything that isn't a dict with simple JSON-like values.
    """
    if filter_expr is None:
        return {}

    s = filter_expr.strip()
    if not s:
        return {}

    try:
        obj: Any = json.loads(s)
    except json.JSONDecodeError:
        obj = ast.literal_eval(s)  # safe: no code execution

    if not isinstance(obj, dict):
        raise ValueError("filters must be a JSON object/dict")

    allowed_scalar = (str, int, float, bool, type(None))
    for k, v in obj.items():
        if not isinstance(k, str):
            raise ValueError("filter keys must be strings")
        if isinstance(v, list):
            if not all(isinstance(x, allowed_scalar) for x in v):
                raise ValueError("filter list values must be scalar types")
        elif not isinstance(v, allowed_scalar):
            raise ValueError("filter values must be scalar or list of scalars")

    return obj


def audit_login(username: str, password: str, ok: bool):
    # Never log passwords.
    log.warning("login attempt user=%s ok=%s", username, ok)