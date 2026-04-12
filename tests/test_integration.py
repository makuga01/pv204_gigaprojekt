import time

import ssl

import uuid

import pytest
import requests


NODES = ["http://localhost:8080", "http://localhost:8081", "http://localhost:8082"]
FRONTEND_URL = "http://localhost:5173"
REQUEST_TIMEOUT = 10


def _wait_for_http_200(url: str, timeout_seconds: int = 120, interval_seconds: float = 2.0) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                return
        except requests.RequestException as exc:
            last_error = exc
        time.sleep(interval_seconds)
    message = f"Timed out waiting for 200 response from {url}"
    if last_error is not None:
        message += f" (last error: {last_error})"
    raise AssertionError(message)


def _post_json(base_url: str, path: str, payload: dict) -> requests.Response:
    return requests.post(
        f"{base_url}{path}",
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )


@pytest.fixture(scope="module", autouse=True)
def wait_for_compose_stack_ready():
    for node_url in NODES:
        _wait_for_http_200(f"{node_url}/health")
    _wait_for_http_200(f"{FRONTEND_URL}/")


def test_nodes_health_and_identity():
    node_ids = set()
    for node_url in NODES:
        response = requests.get(f"{node_url}/health", timeout=REQUEST_TIMEOUT)
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert "threshold" in payload
        assert "key_initialized" in payload
        node_ids.add(int(payload["node_id"]))
    assert node_ids == {1, 2, 3}


def test_initial_threshold_is_from_ci_quickrun_config():
    for node_url in NODES:
        response = requests.get(f"{node_url}/health", timeout=REQUEST_TIMEOUT)
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

        assert response.json()["threshold"] == 2


def test_dkg_init_happy_path_on_node1():
    dkg_id = f"ci_dkg_{uuid.uuid4().hex}"
    response = _post_json(
        NODES[0],
        "/public/dkg/init",
        {"dkg_id": dkg_id, "threshold": 2, "key_type": "ETH"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["dkg_id"] == dkg_id
    assert "public_key" in payload


def test_timestamp_happy_path_after_dkg():
    dkg_id = f"ci_sign_{uuid.uuid4().hex}"
    dkg_response = _post_json(
        NODES[0],
        "/public/dkg/init",
        {"dkg_id": dkg_id, "threshold": 2, "key_type": "ETH"},
    )
    assert dkg_response.status_code == 200, dkg_response.text

    response = _post_json(
        NODES[0],
        "/public/timestamp",
        {
            "document_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "key_type": "ETH",
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["document_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert isinstance(payload.get("session_id"), str) and payload["session_id"]
    assert isinstance(payload.get("timestamp"), str) and payload["timestamp"]
    assert isinstance(payload.get("participants"), list)
    assert len(payload["participants"]) >= 2
    assert isinstance(payload.get("signature"), dict)


def test_threshold_update_endpoint_and_health_reflection():
    update_response = _post_json(NODES[0], "/public/state/threshold", {"threshold": 3})
    assert update_response.status_code == 200, update_response.text
    payload = update_response.json()
    assert payload["old_threshold"] == 2
    assert payload["new_threshold"] == 3

    node1_health = requests.get(f"{NODES[0]}/health", timeout=REQUEST_TIMEOUT)
    node2_health = requests.get(f"{NODES[1]}/health", timeout=REQUEST_TIMEOUT)
    node3_health = requests.get(f"{NODES[2]}/health", timeout=REQUEST_TIMEOUT)
    assert node1_health.status_code == 200
    assert node2_health.status_code == 200
    assert node3_health.status_code == 200
    assert node1_health.json()["threshold"] == 3
    assert node2_health.json()["threshold"] == 3
    assert node3_health.json()["threshold"] == 3

    reset_response = _post_json(NODES[0], "/public/state/threshold", {"threshold": 2})
    assert reset_response.status_code == 200, reset_response.text


def test_threshold_update_rejects_invalid_value():
    response = _post_json(NODES[0], "/public/state/threshold", {"threshold": 1})
    assert response.status_code == 422


def test_frontend_container_smoke():
    response = requests.get(f"{FRONTEND_URL}/", timeout=REQUEST_TIMEOUT)
    assert response.status_code == 200
    assert "GigaTimestamp" in response.text


def test_frontend_api_payload_compatibility_flow():
    dkg_response = _post_json(
        NODES[0],
        "/public/dkg/init",
        {
            "dkg_id": f"ci_ui_{uuid.uuid4().hex}",
            "threshold": 2,
            "key_type": "ETH",
        },
    )
    assert dkg_response.status_code == 200, dkg_response.text

    threshold_sync_response = _post_json(NODES[0], "/public/state/threshold", {"threshold": 2})
    assert threshold_sync_response.status_code == 200, threshold_sync_response.text

    timestamp_response = _post_json(
        NODES[0],
        "/public/timestamp",
        {
            "document_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "key_type": "ETH",
        },
    )
    assert timestamp_response.status_code == 200, timestamp_response.text

