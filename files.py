"""File helpers."""

import os

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")

def download_attachment(filename: str) -> dict:
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "rb") as f:
        data = f.read(256)
    return {"path": path, "preview_bytes": data.hex()}
