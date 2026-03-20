from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from .config import Settings
from .peer_client import PeerClient
from .schemas import (
    DkgInitRequest,
    DkgRound2Request,
    DkgRound3Request,
    PeerSignShareRequest,
    TimestampRequest,
)
from .security import require_peer_auth, verify_signature
from .services import NodeService
from .state import DkgSession, NodeState
from ..frost import Key, KeyGen


def create_app() -> FastAPI:
    settings = Settings()
    peers = settings.parse_peers()
    peer_client = PeerClient(peers=peers, shared_key=settings.hmac_shared_key)
    state = NodeState(settings.node_id, settings.threshold, settings.key_type)
    service = NodeService(state=state, peers=peers, peer_client=peer_client)

    app = FastAPI(title="Threshold Timestamp Node", version="0.1.0")
    app.state.settings = settings
    app.state.state = state
    app.state.service = service

    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "node_id": settings.node_id,
            "threshold": settings.threshold,
            "key_initialized": state.key is not None,
        }

    @app.post("/public/dkg/init")
    async def public_dkg_init(request: DkgInitRequest) -> dict:
        return await service.initiate_dkg(request)

    @app.post("/public/timestamp")
    async def public_timestamp(request: TimestampRequest) -> dict:
        return await service.issue_timestamp(request.document_hash, request.key_type)

    @app.post("/peer/dkg/round1")
    async def peer_dkg_round1(body: DkgInitRequest, headers=Depends(require_peer_auth)) -> dict:
        ts, nonce, sig = headers
        verify_signature(body.model_dump(), ts, nonce, sig, settings.hmac_shared_key)

        partners = [node_id for node_id in service.all_node_ids if node_id != settings.node_id]
        keygen = KeyGen(body.dkg_id, body.threshold, settings.node_id, partners, key_type=body.key_type)
        state.dkg_sessions[body.dkg_id] = DkgSession(dkg_id=body.dkg_id, keygen=keygen)
        return {"round1": keygen.round1()}

    @app.post("/peer/dkg/round2")
    async def peer_dkg_round2(body: DkgRound2Request, headers=Depends(require_peer_auth)) -> dict:
        ts, nonce, sig = headers
        verify_signature(body.model_dump(), ts, nonce, sig, settings.hmac_shared_key)

        session = state.dkg_sessions.get(body.dkg_id)
        if session is None:
            return JSONResponse(status_code=404, content={"detail": "DKG session not found"})
        messages = session.keygen.round2(body.round1_broadcast)
        return {"messages": messages}

    @app.post("/peer/dkg/round3")
    async def peer_dkg_round3(body: DkgRound3Request, headers=Depends(require_peer_auth)) -> dict:
        ts, nonce, sig = headers
        verify_signature(body.model_dump(), ts, nonce, sig, settings.hmac_shared_key)

        session = state.dkg_sessions.get(body.dkg_id)
        if session is None:
            return JSONResponse(status_code=404, content={"detail": "DKG session not found"})
        result = session.keygen.round3(body.incoming_messages)
        if result.get("status") == "SUCCESSFUL":
            state.key = Key({**result["dkg_key_pair"], "key_type": session.keygen.key_type}, settings.node_id)
            state.group_key_code = result["dkg_key_pair"]["dkg_public_key"]
        return result

    @app.post("/peer/sign/nonce")
    async def peer_sign_nonce(request: Request, headers=Depends(require_peer_auth)) -> dict:
        payload = await request.json()
        ts, nonce, sig = headers
        verify_signature(payload, ts, nonce, sig, settings.hmac_shared_key)

        session_id = payload.get("session_id", "")
        nonce_public = service.issue_local_nonce(session_id)
        return nonce_public

    @app.post("/peer/sign/share")
    async def peer_sign_share(body: PeerSignShareRequest, headers=Depends(require_peer_auth)) -> dict:
        ts, nonce, sig = headers
        verify_signature(body.model_dump(), ts, nonce, sig, settings.hmac_shared_key)

        nonces_dict = {k: v.model_dump() for k, v in body.nonces_dict.items()}
        share = service.create_sign_share(body.session_id, body.message, nonces_dict, body.key_type)
        return share

    return app


app = create_app()
