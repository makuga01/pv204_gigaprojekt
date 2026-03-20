from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from fastapi import Header, HTTPException


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_signature(payload: Any, timestamp: str, nonce: str, key: str) -> str:
    body = _canonical_json(payload)
    msg = b"|".join([timestamp.encode("utf-8"), nonce.encode("utf-8"), body])
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_signature(
    payload: Any,
    timestamp: str,
    nonce: str,
    signature: str,
    key: str,
    max_skew_seconds: int = 30,
) -> None:
    now = int(time.time())
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid peer timestamp") from exc

    if abs(now - ts) > max_skew_seconds:
        raise HTTPException(status_code=401, detail="Peer request expired")

    expected = make_signature(payload, timestamp, nonce, key)
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid peer signature")


async def require_peer_auth(
    x_peer_timestamp: str = Header(default=""),
    x_peer_nonce: str = Header(default=""),
    x_peer_signature: str = Header(default=""),
) -> tuple[str, str, str]:
    if not x_peer_timestamp or not x_peer_nonce or not x_peer_signature:
        raise HTTPException(status_code=401, detail="Missing peer auth headers")
    return x_peer_timestamp, x_peer_nonce, x_peer_signature
