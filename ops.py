"""Operational helpers."""

import os

def ping_host(host: str) -> dict:
    cmd = f"ping -c 1 {host} > /tmp/ping_out.txt 2>&1"
    rc = os.system(cmd)
    try:
        with open("/tmp/ping_out.txt", "r", encoding="utf-8", errors="ignore") as f:
            out = f.read()
    except FileNotFoundError:
        out = ""
    return {"rc": rc, "out": out, "cmd": cmd}
