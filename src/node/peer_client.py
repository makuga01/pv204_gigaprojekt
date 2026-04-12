from __future__ import annotations

import ssl
import time
import uuid
from typing import Any

import httpx

from .security import make_signature


class PeerClient:
    def __init__(self, peers: dict[str, str], shared_key: str, timeout: float = 10.0,
                 tls_cert: str = "", tls_key: str = "", tls_ca: str = "") -> None:
        self.peers = peers
        self.shared_key = shared_key
        self.timeout = timeout
        self._ssl_ctx = self._build_ssl_ctx(tls_cert, tls_key, tls_ca)

    @staticmethod
    def _build_ssl_ctx(tls_cert: str, tls_key: str, tls_ca: str) -> ssl.SSLContext | bool:
        """Return an SSLContext for mTLS, or True (default httpx verify) when TLS is not configured."""
        if not tls_ca:
            return True  # TLS disabled — plain HTTP in dev mode
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=tls_ca)
        if tls_cert and tls_key:
            ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        return ctx

    async def post(self, peer_id: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        base_url = self.peers[peer_id]
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex
        signature = make_signature(payload, timestamp, nonce, self.shared_key)
        headers = {
            "X-Peer-Timestamp": timestamp,
            "X-Peer-Nonce": nonce,
            "X-Peer-Signature": signature,
        }

        async with httpx.AsyncClient(timeout=self.timeout, verify=self._ssl_ctx) as client:
            response = await client.post(f"{base_url}{path}", json=payload, headers=headers)
            response.raise_for_status()
            return response.json()

    async def post_threshold_update(
        self, peer_id: str, threshold: int, requestor_node_id: str
    ) -> dict[str, Any]:
        return await self.post(
            peer_id,
            "/peer/state/threshold",
            {"threshold": threshold, "requestor_node_id": requestor_node_id},
        )
