from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class NodePeer(BaseModel):
    id: str = Field(min_length=1)
    base_url: str = Field(min_length=1)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NODE_", extra="ignore")

    node_id: str = "1"
    host: str = "0.0.0.0"
    port: int = 8080
    threshold: int = 2
    key_type: str = "ETH"
    hmac_shared_key: str = "dev-shared-key"
    # Comma-separated origins for browser clients, e.g. "http://localhost:5173,http://127.0.0.1:5173"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    # Comma separated pairs: "1=http://127.0.0.1:8081,2=http://127.0.0.1:8082"
    peers: str = ""
    # mTLS — paths to this node's cert/key and the shared cluster CA cert.
    # Leave empty to disable TLS (plain HTTP, development only).
    tls_cert: str = ""
    tls_key: str = ""
    tls_ca: str = ""

    def parse_peers(self) -> dict[str, str]:
        result: dict[str, str] = {}
        if not self.peers.strip():
            return result
        for item in self.peers.split(","):
            part = item.strip()
            if not part:
                continue
            node_id, sep, url = part.partition("=")
            if not sep:
                continue
            result[node_id.strip()] = url.strip().rstrip("/")
        return result

    def parse_cors_origins(self) -> list[str]:
        if not self.cors_origins.strip():
            return []
        return [origin.strip().rstrip("/") for origin in self.cors_origins.split(",") if origin.strip()]
