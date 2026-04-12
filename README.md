#  PV204_GigaTimestamp: Trusted Threshold Signing Server

Project for **Security Technologies (PV204)** at Faculty of Informatics, Masaryk University.

GigaTimestamp is a decentralized trusted timestamping system. It replaces a single central authority with a cluster of nodes using **FROST (Flexible Round-Optimized Schnorr Threshold signatures)** to ensure that no single node can forge a timestamp.

More detail architecture, initial draft for workflow and more can be seen at [Inital Design](design/DESIGN.md)

## Project Phases
- [x] **Phase I**: Team formation, topic selection.
- [x] **Phase II**: Project design, prototype implementation.
- [x] **Phase III**: Final implementation, integration of Web UI, DKG logic.
- [ ] **Phase IV**: Analysis of other projects, project presentation.
- [ ] **Phase V**: Final discussion and evaluation.

---

## Design & Architecture

The system is built on a decentralized k-of-n threshold architecture. A valid timestamp is only generated if a minimum number of nodes ($t$) cooperate to sign the document hash combined with a current timestamp.

### Key Design Principles
* **Decentralized Trust**: No single point of failure. The private key exists only in shards across multiple nodes.
* **Cryptographic Binding**: The signature covers both the document hash and the ISO-8601 timestamp, preventing backdating.
* **FROST Protocol**: High-performance Schnorr threshold signatures with optimized communication rounds.
* **Zero-Trust Frontend**: Verification is performed entirely client-side in the browser using `@noble/curves`.

### Technology Stack
- **Backend**: Python 3.11, FastAPI, Uvicorn.
- **Cryptography**: `pyfrost` (FROST implementation), `secp256k1`.
- **Frontend**: React, Vite, Tailwind-style CSS.
- **Deployment**: Docker, Docker Compose.

---

## Implementation Details

1.  **Distributed Key Generation (DKG)**: Nodes perform a Pedersen DKG to establish a group public key and individual secret shares without ever assembling the full private key.
2.  **Two-Round Signing**:
    - **Round 1**: Nodes exchange public nonces.
    - **Round 2**: Nodes submit partial signature shares.
3.  **Ethereum Compatibility**: The system supports deriving an Ethereum address from the signature nonce.
4.  **HMAC Authentication and mTLS layer**: Inter-node communication is secured via shared HMAC keys to prevent unauthorized peer interference.

---

## Quick Start (Local Development)

### Prerequisites
- Python 3.10+
- Node.js 20+ (for Web UI)

### Backend Setup
```bash
git clone https://github.com/makuga01/pv204_gigaprojekt.git
cd pv204_gigaprojekt
python3 -m venv .venv
source .venv/bin/activate
(.venv) pip install -r requirements.txt
```

### Running Nodes Manually
To run a manual network (e.g., 3 nodes), open 3 terminals:

**Terminal 1 (Node 1):**
```bash
export NODE_NODE_ID="1" && export NODE_PORT=8080
export NODE_PEERS="2=http://127.0.0.1:8081,3=http://127.0.0.1:8082"
(.venv) python -m src.node.run
```

**Terminal 2 (Node 2):**
```bash
export NODE_NODE_ID="2" && export NODE_PORT=8081
export NODE_PEERS="1=http://127.0.0.1:8080,3=http://127.0.0.1:8082"
(.venv) python -m src.node.run
```

---

## Docker Quick Run (Recommended)

The easiest way to deploy a k-of-n cluster is using the `quickrun.py` script. It generates a custom Docker Compose file with all peers auto-configured.

```bash
# Generate a cluster of 3 nodes with threshold 2
python quickrun.py 3 --threshold 2 --key-type ETH

# Build and start the cluster
docker compose -f docker-compose.quickrun.yml up --build
```

### Accessing the System
- **Node 1 API**: `http://localhost:8080`
- **Node 2 API**: `http://localhost:8081`
- **Node 3 API**: `http://localhost:8082`
- **Web Dashboard**: `http://localhost:5173`

> **Note on Key-type:** If you use `--key-type BTC`, in the following setup, user will only be able to get BTC-key signed timestamps and as well for the `--key-type ETH` is goes the same.

> **Note on Ports:** If you use `--host-port-start`, ensure your Web UI "Base URL" matches the first node's port. The frontend is automatically configured with the port used during the `quickrun` generation.


The command above generates `docker-compose.quickrun.yml` with services `node1..nodeN` as described above,
auto-configured `NODE_PEERS`, shared `NODE_HMAC_SHARED_KEY`, and port mapping
from `8080` upward. It also includes a `gigatimestamp` frontend service
published on `http://localhost:5173`.

Other useful options:

```bash
python quickrun.py 5 --threshold 3 --key-type BTC --host-port-start 9000 --output docker-compose.5n.yml
python quickrun.py 4 --threshold 3 --frontend-port 8088
```

---

## Web Dashboard (GigaTimestamp UI)

The React dashboard allows you to manage the entire lifecycle:
1.  **Connection**: Verify node health.
2.  **DKG**: Initialize a new distributed key generation session.
3.  **Configuration**: Dynamically update the threshold in node memory.
4.  **Timestamp**: Upload files to hash them and request a multi-node signature.
5.  **Verify**: Perform **local cryptographic verification** of the resulting signature.

To run the UI outside of Docker:
```bash
cd web
npm install
npm run dev
```
Then open the URL shown by Vite (typically `http://localhost:5173`) and set Base URL to your coordinator node (for example `http://localhost:8080`).

---

## API Usage Examples

**Initialize DKG:**
```bash
curl -X POST http://127.0.0.1:8080/public/dkg/init \
     -H "Content-Type: application/json" \
     -d '{"dkg_id": "session_01", "threshold": 2, "key_type": "ETH"}'
```

**Request Timestamp:**
```bash
curl -X POST http://127.0.0.1:8080/public/timestamp \
     -H "Content-Type: application/json" \
     -d '{"document_hash": "e3b0c4...", "key_type": "ETH"}'
```

**Update Threshold (In-Memory):**
```bash
curl -X POST http://127.0.0.1:8080/public/state/threshold \
     -H "Content-Type: application/json" \
     -d '{"threshold": 2}'
```

**Also a status check for nodes is available:**
```bash
curl -X GET http://127.0.0.1:8080/health
```


---

## Current Status

### Done
- [x] Multi-node DKG implementation.
- [x] FROST-based two-round signing process.
- [x] Dockerized environment with dynamic scaling script.
- [x] React Dashboard for DKG, Signing, and **Client-side Verification**.
- [x] Ethereum-compatible address derivation.

### TODO / Improvements
- [ ] Integration with hardware security modules (HSM) simulation.
- [ ] Support for persistent storage of key shares (currently in-memory).
- [ ] Enhanced certificate-based identity proof for signing entities.

---

## AI/LLM/Coding Agents usage
During the development of this project, Large Language Models (LLMs) and AI coding agents were utilized as accelerators for generating boilerplate code, helping designing complex configurations, and debugging integrations between Python and React. This approach enabled faster prototyping iterations, and the generation of technical documentation, while the core architectural decisions and the security logic of usage of the FROST protocol remained entirely under the control of the human developer.

---

## License
MIT - PV204 Team Project.