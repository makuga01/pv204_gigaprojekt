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
    # Comma separated pairs: "1=http://127.0.0.1:8081,2=http://127.0.0.1:8082"
    peers: str = ""

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
