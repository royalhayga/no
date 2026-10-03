from __future__ import annotations

import asyncio
import os
import random
import socket
import ssl
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text

INPUT_DIR = ROOT_DIR / "output" / "dns"
OUTPUT_DIR = ROOT_DIR / "output" / "socket"


def build_quic_initial_packet() -> bytes:
    """
    Construct 1200-byte RFC 9000 QUIC Initial packet with reserved version 0x1a2a3a4a.
    Any compliant QUIC/Hysteria/TUIC server MUST respond with Version Negotiation.
    """
    dcid = os.urandom(8)
    head = bytearray()
    head.append(0xc0)  # Long Header + Fixed bit
    head.extend((0x1a2a3a4a).to_bytes(4, "big"))  # Reserved Version -> Triggers Version Negotiation
    head.append(len(dcid))
    head.extend(dcid)
    head.append(0)  # SCID length
    head.append(0)  # Token length

    payload_len = 1200 - len(head) - 2 - 1
    head.extend((0x4000 | payload_len).to_bytes(2, "big"))

    packet = bytearray(1200)
    packet[0:len(head)] = head
    return bytes(packet)


async def probe_tcp_endpoint(host: str, port: int, use_tls: bool = False, sni: str = "", timeout: float = 3.0) -> bool:
    """Probe TCP connection and optional TLS handshake."""
    try:
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

            conn = asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=sni or host)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        else:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
    except Exception:
        # If TLS handshake failed, fall back to pure TCP connect check
        if use_tls:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                pass
        return False


async def probe_quic_endpoint(host: str, port: int, timeout: float = 3.0) -> bool:
    """Probe UDP QUIC port by sending Initial packet and waiting for response."""
    loop = asyncio.get_event_loop()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        packet = build_quic_initial_packet()

        await loop.sock_sendto(sock, packet, (host, port))

        recv_task = loop.sock_recv(sock, 2048)
        data = await asyncio.wait_for(recv_task, timeout=timeout)
        sock.close()
        return len(data) > 0
    except Exception:
        return False


async def probe_endpoint(node: Dict[str, Any], timeout: float = 3.0) -> bool:
    """Probe single node endpoint."""
    host = node.get("server")
    port = node.get("port")
    ntype = node.get("type")

    if not host or not port:
        return False

    if ntype in ["hysteria2", "hy2", "tuic"]:
        return await probe_quic_endpoint(host, port, timeout)
    else:
        use_tls = bool(node.get("tls")) or ntype == "trojan"
        sni = node.get("sni") or node.get("host") or ""
        return await probe_tcp_endpoint(host, port, use_tls=use_tls, sni=sni, timeout=timeout)


async def batch_probe_nodes(nodes: List[Dict[str, Any]], concurrency: int = 128, timeout: float = 3.0) -> List[Dict[str, Any]]:
    """Probe all endpoints with deduplicated endpoint cache."""
    endpoint_results: Dict[str, bool] = {}

    unique_endpoints = {}
    for n in nodes:
        key = f"{n.get('server')}:{n.get('port')}:{n.get('type')}:{n.get('tls')}"
        if key not in unique_endpoints:
            unique_endpoints[key] = n

    semaphore = asyncio.Semaphore(concurrency)

    async def sem_probe(key: str, node: Dict[str, Any]):
        async with semaphore:
            res = await probe_endpoint(node, timeout=timeout)
            endpoint_results[key] = res

    print(f"Probing {len(unique_endpoints)} unique endpoints with concurrency={concurrency}, timeout={timeout}s...")
    tasks = [sem_probe(k, n) for k, n in unique_endpoints.items()]
    await asyncio.gather(*tasks)

    alive_nodes = []
    for n in nodes:
        key = f"{n.get('server')}:{n.get('port')}:{n.get('type')}:{n.get('tls')}"
        if endpoint_results.get(key, False):
            alive_nodes.append(n)

    print(f"Stage 4 Socket Probe Completed: Retained {len(alive_nodes)} online nodes out of {len(nodes)} total.")
    return alive_nodes


def main() -> int:
    print("=== Stage 4: High-Concurrency Socket TCP / TLS / QUIC Handshake Probe ===")
    nodes_file = INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        print(f"Error: Input file {nodes_file} not found. Run Stage 3 (scripts/dns_check.py) first.")
        return 1

    content = nodes_file.read_text(encoding="utf-8")
    nodes = extract_node_links_from_text(content)
    print(f"Loaded {len(nodes)} nodes from Stage 3.")

    alive_nodes = asyncio.run(batch_probe_nodes(nodes, concurrency=128, timeout=3.0))

    # Export all 5 standard format files to output/socket/
    export_stage_files(
        output_dir=OUTPUT_DIR,
        nodes=alive_nodes,
        stage_title="Stage 4 - Socket TCP/TLS/QUIC Handshake Probe"
    )

    print(f"Successfully exported Stage 4 output to {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
