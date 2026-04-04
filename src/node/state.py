from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pyfrost import Key, KeyGen, aggregate_nonce, aggregate_signatures, create_nonces


@dataclass
class DkgSession:
    dkg_id: str
    keygen: KeyGen


@dataclass
class SigningSession:
    session_id: str
    message_hash: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    nonces: dict[str, dict[str, int]] = field(default_factory=dict)
    shares: list[dict[str, Any]] = field(default_factory=list)
    private_nonce: dict[str, dict[int, int]] | None = None


class NodeState:
    def __init__(self, node_id: str, threshold: int, key_type: str) -> None:
        self.node_id = node_id
        self.threshold = threshold
        self.key_type = key_type
        self.dkg_sessions: dict[str, DkgSession] = {}
        self.signing_sessions: dict[str, SigningSession] = {}
        self.timestamp_records: dict[str, dict[str, Any]] = {}
        self.nonce_pool_public: list[dict[str, int]] = []
        self.nonce_pool_private: list[dict[str, dict[int, int]]] = []
        self.key: Key | None = None
        self.group_key_code: int | None = None

    def replenish_nonces(self, count: int = 10) -> None:
        public, private = create_nonces(int(self.node_id), count)
        self.nonce_pool_public.extend(public)
        self.nonce_pool_private.extend(private)

    def checkout_nonce(self) -> tuple[dict[str, int], dict[str, dict[int, int]]]:
        if not self.nonce_pool_public or not self.nonce_pool_private:
            self.replenish_nonces()
        return self.nonce_pool_public.pop(0), self.nonce_pool_private.pop(0)

    def remember_signature(self, session_id: str, signature_package: dict[str, Any]) -> None:
        self.timestamp_records[session_id] = {
            "hash": signature_package["message"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signature": signature_package,
        }

    def aggregate(self, message_hash: str, shares: list[dict[str, int]], nonces: dict[str, dict[str, int]]) -> dict[str, Any]:
        if self.group_key_code is None:
            raise RuntimeError("Group key is not initialized")
        agg_nonce = aggregate_nonce(message_hash, nonces)
        return aggregate_signatures(
            message_hash,
            shares,
            agg_nonce,
            self.group_key_code,
            self.key_type,
        )
