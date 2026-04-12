#!/usr/bin/env python3
"""Generate a docker-compose file for N timestamping nodes on one network."""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def generate_certs(node_count: int, certs_dir: Path) -> None:
    """Generate a throwaway cluster CA and one cert/key pair per node.

    Writes to *certs_dir*:
      ca.crt
      node{i}.crt   node{i}.key   for i in 1..node_count
    """
    certs_dir.mkdir(parents=True, exist_ok=True)

    # --- Cluster CA ---
    ca_key = _new_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "timestamp-cluster-ca")])
    now = _utc_now()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (certs_dir / "ca.crt").write_bytes(
        ca_cert.public_bytes(serialization.Encoding.PEM)
    )

    # --- Per-node certs ---
    for node_id in range(1, node_count + 1):
        node_key = _new_key()
        node_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"node{node_id}")])
        node_cert = (
            x509.CertificateBuilder()
            .subject_name(node_name)
            .issuer_name(ca_name)
            .public_key(node_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(f"caddy{node_id}"),
                    x509.DNSName(f"node{node_id}"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (certs_dir / f"node{node_id}.crt").write_bytes(
            node_cert.public_bytes(serialization.Encoding.PEM)
        )
        (certs_dir / f"node{node_id}.key").write_bytes(
            node_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        # Keys must not be world-readable
        os.chmod(certs_dir / f"node{node_id}.key", 0o600)

    print(f"Generated CA + {node_count} node certificates in {certs_dir}/")


def generate_caddyfile(node_id: int, internal_port: int, certs_dir: Path, peer_port: int = 8443) -> None:
    """Write a Caddyfile for node *node_id* into *certs_dir*."""
    content = f"""\
{{
  admin off
}}

:{peer_port} {{
  tls /certs/node{node_id}.crt /certs/node{node_id}.key {{
    client_auth {{
      mode             require_and_verify
      trusted_ca_cert_file /certs/ca.crt
    }}
  }}

  reverse_proxy localhost:{internal_port}
}}
"""
    (certs_dir / f"Caddyfile.node{node_id}").write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Compose generation
# ---------------------------------------------------------------------------

def build_peers(node_id: int, node_count: int, peer_port: int = 8443) -> str:
    peers: list[str] = []
    for peer_id in range(1, node_count + 1):
        if peer_id == node_id:
            continue
        # Peer traffic goes through Caddy (mTLS) on peer_port in the shared network namespace
        peers.append(f"{peer_id}=https://node{peer_id}:{peer_port}")
    return ",".join(peers)


def build_compose(
    node_count: int,
    threshold: int,
    key_type: str,
    host_port_start: int,
    internal_port: int,
    shared_key: str,
    frontend_port: int,
    peer_port: int = 8443,
) -> str:
    lines: list[str] = []
    lines.append('version: "3.9"')
    lines.append("services:")

    for node_id in range(1, node_count + 1):
        host_port = host_port_start + node_id - 1
        # Host peer port is offset by 1000 to avoid collisions (e.g. 9080, 9081, ...)
        host_peer_port = host_port_start + 1000 + node_id - 1
        peers = build_peers(node_id=node_id, node_count=node_count, peer_port=peer_port)
        cors_origins = (
            f"http://localhost:{frontend_port},"
            f"http://127.0.0.1:{frontend_port},"
            f"http://host.docker.internal:{frontend_port}"
        )

        # FastAPI node — public API and Caddy peer port both exposed here.
        # Caddy shares this container's network namespace so its port (peer_port)
        # must be published from this service, not from the sidecar.
        lines.extend(
            [
                f"  node{node_id}:",
                "    build:",
                "      context: .",
                "      dockerfile: Dockerfile",
                f"    container_name: timestamp-node-{node_id}",
                "    environment:",
                f"      NODE_NODE_ID: \"{node_id}\"",
                "      NODE_HOST: \"0.0.0.0\"",
                f"      NODE_PORT: \"{internal_port}\"",
                f"      NODE_THRESHOLD: \"{threshold}\"",
                f"      NODE_KEY_TYPE: \"{key_type}\"",
                f"      NODE_HMAC_SHARED_KEY: \"{shared_key}\"",
                f"      NODE_CORS_ORIGINS: \"{cors_origins}\"",
                f"      NODE_PEERS: \"{peers}\"",
                f"      NODE_TLS_CERT: \"/certs/node{node_id}.crt\"",
                f"      NODE_TLS_KEY: \"/certs/node{node_id}.key\"",
                "      NODE_TLS_CA: \"/certs/ca.crt\"",
                "      PYTHONPATH: \"/app\"",
                "    command: [\"python\", \"-m\", \"src.node.run\"]",
                "    volumes:",
                "      - ./certs:/certs:ro",
                "    ports:",
                f"      - \"{host_port}:{internal_port}\"",
                f"      - \"{host_peer_port}:{peer_port}\"",
                "    networks:",
                "      - timestamp_net",
            ]
        )

        # Caddy sidecar — mTLS termination for peer traffic.
        # Shares node's network namespace (no ports here — published on node service above).
        lines.extend(
            [
                f"  caddy{node_id}:",
                "    image: caddy:2-alpine",
                f"    container_name: timestamp-caddy-{node_id}",
                "    volumes:",
                "      - ./certs:/certs:ro",
                f"      - ./certs/Caddyfile.node{node_id}:/etc/caddy/Caddyfile:ro",
                f"    network_mode: \"service:node{node_id}\"",
                "    depends_on:",
                f"      - node{node_id}",
            ]
        )

    lines.extend(
        [
            "  gigatimestamp:",
            "    build:",
            "      context: ./web",
            "      dockerfile: Dockerfile",
            "      args:", 
            f"        - VITE_DEFAULT_API_URL=http://localhost:{host_port_start}",
            f"        - VITE_DEFAULT_THRESHOLD={threshold}",
            f"        - VITE_DEFAULT_KEY_TYPE={key_type}",
            "    container_name: gigatimestamp-ui",
            "    depends_on:",
            "      - node1",
            "    ports:",
            f"      - \"{frontend_port}:80\"",
            "    networks:",
            "      - timestamp_net",
        ]
    )

    lines.extend(
        [
            "networks:",
            "  timestamp_net:",
            "    name: timestamp_net",
            "    driver: bridge",
        ]
    )

    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate docker-compose for N threshold-signing nodes.",
    )
    parser.add_argument("n", type=int, help="Number of nodes to generate.")
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Signing threshold k. Default: min(2, n).",
    )
    parser.add_argument(
        "--key-type",
        choices=("ETH", "BTC"),
        default="ETH",
        help="Key type used by nodes.",
    )
    parser.add_argument(
        "--host-port-start",
        type=int,
        default=8080,
        help="First host port. Nodes map to consecutive ports.",
    )
    parser.add_argument(
        "--internal-port",
        type=int,
        default=8080,
        help="Container port each node listens on.",
    )
    parser.add_argument(
        "--shared-key",
        default="dev-shared-key",
        help="Shared HMAC key for peer auth.",
    )
    parser.add_argument(
        "--output",
        default="docker-compose.quickrun.yml",
        help="Output compose file path.",
    )
    parser.add_argument(
        "--frontend-port",
        type=int,
        default=5173,
        help="Host port used for GigaTimestamp frontend.",
    )
    parser.add_argument(
        "--certs-dir",
        default="certs",
        help="Directory where generated certificates and Caddyfiles are written.",
    )
    parser.add_argument(
        "--peer-port",
        type=int,
        default=8443,
        help="Internal port Caddy listens on for mTLS peer traffic.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.n < 2:
        raise SystemExit("n must be >= 2")

    threshold = args.threshold if args.threshold is not None else min(2, args.n)
    if threshold < 2:
        raise SystemExit("threshold must be >= 2")
    if threshold > args.n:
        raise SystemExit("threshold must be <= n")

    certs_dir = Path(args.certs_dir)
    generate_certs(node_count=args.n, certs_dir=certs_dir)
    for node_id in range(1, args.n + 1):
        generate_caddyfile(node_id=node_id, internal_port=args.internal_port, certs_dir=certs_dir, peer_port=args.peer_port)

    compose_text = build_compose(
        node_count=args.n,
        threshold=threshold,
        key_type=args.key_type,
        host_port_start=args.host_port_start,
        internal_port=args.internal_port,
        shared_key=args.shared_key,
        frontend_port=args.frontend_port,
        peer_port=args.peer_port,
    )

    output_path = Path(args.output)
    output_path.write_text(compose_text, encoding="utf-8")
    print(f"Generated {output_path} for {args.n} nodes (threshold={threshold}, key_type={args.key_type}).")
    print(f"Run: docker compose -f {output_path} up --build")


if __name__ == "__main__":
    main()
