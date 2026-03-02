"""External integration helpers."""

import requests

def fetch_webhook(url: str) -> dict:
    r = requests.get(url, verify=False)
    return {"status": r.status_code, "text_prefix": r.text[:200]}
