from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from ..frost import Key, KeyGen
from .peer_client import PeerClient
from .schemas import DkgInitRequest
from .state import DkgSession, NodeState, SigningSession

import hashlib
import random


class NodeService:
    def __init__(self, state: NodeState, peers: dict[str, str], peer_client: PeerClient) -> None:
        self.state = state
        self.peers = peers
        self.peer_client = peer_client

    @property
    def all_node_ids(self) -> list[str]:
        ids = sorted(set([self.state.node_id, *self.peers.keys()]), key=lambda x: int(x))
        return ids

    async def initiate_dkg(self, request: DkgInitRequest) -> dict[str, Any]:
        dkg_id = request.dkg_id
        threshold = request.threshold
        key_type = request.key_type

        partners = [node_id for node_id in self.all_node_ids if node_id != self.state.node_id]
        keygen = KeyGen(dkg_id, threshold, self.state.node_id, partners, key_type=key_type)
        self.state.dkg_sessions[dkg_id] = DkgSession(dkg_id=dkg_id, keygen=keygen)

        round1_broadcast = [keygen.round1()]
        for peer_id in partners:
            res = await self.peer_client.post(
                peer_id,
                "/peer/dkg/round1",
                {"dkg_id": dkg_id, "threshold": threshold, "key_type": key_type},
            )
            round1_broadcast.append(res["round1"])

        round2_messages = []
        round2_messages.extend(keygen.round2(round1_broadcast))
        for peer_id in partners:
            res = await self.peer_client.post(
                peer_id,
                "/peer/dkg/round2",
                {"dkg_id": dkg_id, "round1_broadcast": round1_broadcast},
            )
            round2_messages.extend(res["messages"])

        my_msgs = [m for m in round2_messages if m["receiver_id"] == self.state.node_id]
        local_round3 = keygen.round3(my_msgs)

        peer_round3 = {}
        for peer_id in partners:
            incoming = [m for m in round2_messages if m["receiver_id"] == peer_id]
            res = await self.peer_client.post(
                peer_id,
                "/peer/dkg/round3",
                {"dkg_id": dkg_id, "incoming_messages": incoming},
            )
            peer_round3[peer_id] = res

        if local_round3.get("status") != "SUCCESSFUL":
            raise HTTPException(status_code=400, detail="Local DKG failed")

        self.state.key = Key(
            {
                **local_round3["dkg_key_pair"],
                "key_type": key_type,
            },
            self.state.node_id,
        )
        self.state.group_key_code = local_round3["dkg_key_pair"]["dkg_public_key"]

        return {
            "dkg_id": dkg_id,
            "public_key": self.state.group_key_code,
            "local_status": local_round3["status"],
            "peers": peer_round3,
        }

    def issue_local_nonce(self, session_id: str) -> dict[str, int]:
        pub, priv = self.state.checkout_nonce()
        if session_id not in self.state.signing_sessions:
            self.state.signing_sessions[session_id] = SigningSession(session_id=session_id, message_hash="")
        self.state.signing_sessions[session_id].nonces[self.state.node_id] = pub
        self.state.signing_sessions[session_id].private_nonce = priv
        return pub

    def create_sign_share(self, session_id: str, message_hash: str, nonces_dict: dict[str, dict[str, int]], key_type: str) -> dict[str, Any]:
        if self.state.key is None:
            raise HTTPException(status_code=400, detail="Node key is not initialized")

        session = self.state.signing_sessions.get(session_id)
        if session is None or session.private_nonce is None:
            raise HTTPException(status_code=400, detail="Nonce not prepared for session")

        priv = session.private_nonce
        nonce_d = next(iter(priv["nonce_d_pair"].values()))
        nonce_e = next(iter(priv["nonce_e_pair"].values()))

        from ..frost import single_sign

        return single_sign(
            int(self.state.node_id),
            self.state.key.dkg_key_pair["share"],
            nonce_d,
            nonce_e,
            message_hash,
            nonces_dict,
            self.state.group_key_code,
            key_type,
        )

    async def issue_timestamp(self, document_hash: str, key_type: str) -> dict[str, Any]:
        if self.state.key is None:
            raise HTTPException(status_code=400, detail="DKG not completed")
        
        now = datetime.now(timezone.utc)
        ts_str = now.isoformat()
        
        raw_binding = f"{document_hash}|{ts_str}"
        
        signed_message = hashlib.sha256(raw_binding.encode()).hexdigest()

        session_id = uuid.uuid4().hex
        self.state.signing_sessions[session_id] = SigningSession(
            session_id=session_id,
            message_hash=signed_message
        )

        nonces_dict: dict[str, dict[str, int]] = {}
        nonces_dict[self.state.node_id] = self.issue_local_nonce(session_id)

        participant_ids = [self.state.node_id]
        
        available_peers = list(self.peers.keys())
        random.shuffle(available_peers)
        
        for peer_id in available_peers:
            
            if len(participant_ids) >= self.state.threshold:
                break
            res = await self.peer_client.post(peer_id, "/peer/sign/nonce", {"session_id": session_id})
            nonces_dict[peer_id] = {
                "id": int(res["id"]),
                "public_nonce_d": int(res["public_nonce_d"]),
                "public_nonce_e": int(res["public_nonce_e"]),
            }
            participant_ids.append(peer_id)

        if len(participant_ids) < self.state.threshold:
            raise HTTPException(status_code=400, detail="Insufficient participants for threshold")

        shares = []
        local_share = self.create_sign_share(session_id, signed_message, nonces_dict, key_type)
        shares.append(local_share)

        for peer_id in participant_ids:
            if peer_id == self.state.node_id:
                continue
            res = await self.peer_client.post(
                peer_id,
                "/peer/sign/share",
                {
                    "session_id": session_id,
                    "message": signed_message,
                    "nonces_dict": nonces_dict,
                    "key_type": key_type,
                },
            )
            shares.append(res)

        signature = self.state.aggregate(signed_message, shares, nonces_dict)
        self.state.remember_signature(session_id, signature)

        return {
            "session_id": session_id,
            "timestamp": ts_str,
            "document_hash": document_hash,
            "participants": participant_ids,
            "signature": signature,
        }
