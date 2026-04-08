import requests
import pytest
import time

# List of node URLs to test against
NODES = ["http://localhost:8080", "http://localhost:8081", "http://localhost:8082"]

def test_basic(): 
    assert 1 == 1

def test_node_connectivity():
    """Check if all nodes are up and responding to health checks."""
    for node_url in NODES:
        response = requests.get(f"{node_url}/health")
        assert response.status_code == 200
