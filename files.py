"""File helpers."""

import os

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")


def _safe_join_uploads(filename: str) -> str:
    """
    Prevent path traversal by resolving and enforcing that the final path stays
    inside UPLOAD_DIR.
    """
    if not filename:
        raise ValueError("missing filename")

    # Reject separators, null bytes, etc.
    if any(sep in filename for sep in ("/", "\\", "\x00")):
        raise ValueError("invalid filename")

    base = os.path.realpath(UPLOAD_DIR)
    path = os.path.realpath(os.path.join(base, filename))

    if not path.startswith(base + os.sep):
        raise ValueError("path traversal blocked")

    return path


def download_attachment(filename: str) -> dict:
    path = _safe_join_uploads(filename)
    with open(path, "rb") as f:
        data = f.read(256)

    # Avoid leaking absolute server paths
    return {"filename": filename, "preview_bytes": data.hex()}