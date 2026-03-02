"""External integration helpers."""

import ipaddress
import socket
from urllib.parse import urlparse

import requests


def _is_private_host(hostname: str) -> bool:
    """
    Resolve hostname and block private/loopback/link-local/multicast/reserved/etc.
    Fail closed (block) if resolution fails.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True

    for _family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True

    return False


def fetch_webhook(url: str) -> dict:
    """
    Safer webhook fetch:
      - require https
      - block private/internal targets (basic SSRF protection)
      - TLS verify enabled
      - short timeout
      - do not follow redirects
    """
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        return {"status": 400, "text_prefix": "invalid url (https required)"}

    if _is_private_host(p.hostname):
        return {"status": 403, "text_prefix": "blocked (private host)"}

    r = requests.get(url, verify=True, timeout=3, allow_redirects=False)
    return {"status": r.status_code, "text_prefix": r.text[:200]}