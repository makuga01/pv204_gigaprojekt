import requests
import pytest
import time
import ssl

# List of node URLs to test against
NODES = ["http://localhost:8080", "http://localhost:8081", "http://localhost:8082"]

# Caddy mTLS peer ports (host_port_start + 1000)
NODES_PEER_HTTPS = ["https://localhost:9080", "https://localhost:9081", "https://localhost:9082"]

def test_basic(): 
    assert 1 == 1

def test_node_connectivity():
    """Check if all nodes are up and responding to health checks."""
    for node_url in NODES:
        response = requests.get(f"{node_url}/health")
        assert response.status_code == 200

def test_peer_endpoint_rejects_without_client_cert():
    """Peer endpoints must reject connections that do not present a client certificate."""
    peer_url = NODES_PEER_HTTPS[0]
    rejected = False
    try:
        requests.post(
            f"{peer_url}/peer/dkg/round1",
            json={"dkg_id": "test_mtls", "threshold": 2, "key_type": "ETH"},
            verify=False,  # skip server cert check — we only care that mTLS rejects us
            timeout=5,
        )
    except requests.exceptions.SSLError:
        # TLS handshake failed because no client cert was presented — expected
        rejected = True
    except requests.exceptions.ConnectionError:
        # Connection refused / reset at the TLS layer — also acceptable
        rejected = True

    assert rejected, "Peer endpoint accepted a connection without a client certificate — mTLS not enforced"
