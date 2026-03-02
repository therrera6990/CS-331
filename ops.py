"""Operational helpers."""

import re
import subprocess

_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _valid_host(host: str) -> bool:
    if not host:
        return False

    host = host.strip()
    if len(host) > 253:
        return False

    if _IPV4_RE.match(host):
        parts = host.split(".")
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    return bool(_HOST_RE.match(host))


def ping_host(host: str) -> dict:
    if not _valid_host(host):
        return {"rc": 2, "out": "invalid host", "cmd": ""}

    proc = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=3,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"rc": proc.returncode, "out": out[:4000], "cmd": "ping -c 1 <host>"}