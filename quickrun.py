#!/usr/bin/env python3
"""Generate a docker-compose file for N timestamping nodes on one network."""

from __future__ import annotations

import argparse
from pathlib import Path


def build_peers(node_id: int, node_count: int, internal_port: int) -> str:
    peers: list[str] = []
    for peer_id in range(1, node_count + 1):
        if peer_id == node_id:
            continue
        peers.append(f"{peer_id}=http://node{peer_id}:{internal_port}")
    return ",".join(peers)


def build_compose(
    node_count: int,
    threshold: int,
    key_type: str,
    host_port_start: int,
    internal_port: int,
    shared_key: str,
    frontend_port: int,
) -> str:
    lines: list[str] = []
    lines.append('version: "3.9"')
    lines.append("services:")

    for node_id in range(1, node_count + 1):
        host_port = host_port_start + node_id - 1
        peers = build_peers(node_id=node_id, node_count=node_count, internal_port=internal_port)
        cors_origins = (
            f"http://localhost:{frontend_port},"
            f"http://127.0.0.1:{frontend_port},"
            f"http://host.docker.internal:{frontend_port}"
        )

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
                "      PYTHONPATH: \"/app\"",
                "    command: [\"python\", \"-m\", \"src.node.run\"]",
                "    ports:",
                f"      - \"{host_port}:{internal_port}\"",
                "    networks:",
                "      - timestamp_net",
            ]
        )

    lines.extend(
        [
            "  gigatimestamp:",
            "    build:",
            "      context: ./web",
            "      dockerfile: Dockerfile",
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

    compose_text = build_compose(
        node_count=args.n,
        threshold=threshold,
        key_type=args.key_type,
        host_port_start=args.host_port_start,
        internal_port=args.internal_port,
        shared_key=args.shared_key,
        frontend_port=args.frontend_port,
    )

    output_path = Path(args.output)
    output_path.write_text(compose_text, encoding="utf-8")
    print(f"Generated {output_path} for {args.n} nodes (threshold={threshold}, key_type={args.key_type}).")
    print(f"Run: docker compose -f {output_path} up --build")


if __name__ == "__main__":
    main()
