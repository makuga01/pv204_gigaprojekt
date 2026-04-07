from datetime import datetime
from typing import Annotated
from typing import Literal

from pydantic import BaseModel, Field, StringConstraints


Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]


class TimestampRequest(BaseModel):
    document_hash: Hex64
    key_type: Literal["ETH", "BTC"] = "ETH"


class TimestampResponse(BaseModel):
    session_id: str
    timestamp: datetime
    document_hash: str
    message_signed: str
    signature: dict


class PeerNonceRequest(BaseModel):
    session_id: str


class PeerNonceResponse(BaseModel):
    id: int
    public_nonce_d: int
    public_nonce_e: int


class PeerSignShareRequest(BaseModel):
    session_id: str
    message: Hex64
    nonces_dict: dict[str, PeerNonceResponse]
    key_type: Literal["ETH", "BTC"] = "ETH"


class PeerSignShareResponse(BaseModel):
    id: int
    signature: int
    public_key: int
    aggregated_public_nonce: int
    key_type: Literal["ETH", "BTC"]


class DkgInitRequest(BaseModel):
    dkg_id: str
    threshold: int = Field(ge=2)
    key_type: Literal["ETH", "BTC"] = "ETH"


class DkgRound2Request(BaseModel):
    dkg_id: str
    round1_broadcast: list[dict]


class DkgRound3Request(BaseModel):
    dkg_id: str
    incoming_messages: list[dict]
