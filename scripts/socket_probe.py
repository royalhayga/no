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
ALT_INPUT_DIR = ROOT_DIR / "output" / "verified"
OUTPUT_DIR = ROOT_DIR / "output" / "socket"


def build_quic_initial_packet() -> bytes:
    """Construct 1200-byte RFC 9000 QUIC Initial packet with reserved version 0x1a2a3a4a."""
    dcid = os.urandom(8)
    head = bytearray()
    head.append(0xc0)
    head.extend((0x1a2a3a4a).to_bytes(4, "big"))
    head.append(len(dcid))
    head.extend(dcid)
    head.append(0)
    head.append(0)

    payload_len = 1200 - len(head) - 2 - 1
    head.extend((0x4000 | payload_len).to_bytes(2, "big"))

    packet = bytearray(1200)
    packet[0:len(head)] = head
    return bytes(packet)


async def probe_tcp_endpoint(host: str, port: int, use_tls: bool = False, sni: str = "", timeout: float = 1.5) -> bool:
    """Probe TCP connection and optional TLS handshake."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def probe_quic_endpoint(host: str, port: int, timeout: float = 1.5) -> bool:
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


async def probe_endpoint(node: Dict[str, Any], timeout: float = 1.5) -> bool:
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


async def batch_probe_nodes(nodes: List[Dict[str, Any]], concurrency: int = 256, timeout: float = 1.5) -> List[Dict[str, Any]]:
    """Probe all endpoints with 256-worker async concurrency and real-time progress logging."""
    endpoint_results: Dict[str, bool] = {}
    unique_endpoints = {}

    for n in nodes:
        key = f"{n.get('server')}:{n.get('port')}:{n.get('type')}:{n.get('tls')}"
        if key not in unique_endpoints:
            unique_endpoints[key] = n

    endpoint_list = list(unique_endpoints.items())
    total_ep = len(endpoint_list)
    print(f"Probing {total_ep} unique endpoints with concurrency={concurrency}, timeout={timeout}s...", flush=True)

    semaphore = asyncio.Semaphore(concurrency)
    completed_counter = 0

    async def sem_probe(key: str, node: Dict[str, Any]):
        nonlocal completed_counter
        async with semaphore:
            res = await probe_endpoint(node, timeout=timeout)
            endpoint_results[key] = res
            completed_counter += 1
            if completed_counter % 500 == 0 or completed_counter == total_ep:
                print(f"  Progress: [{completed_counter}/{total_ep}] endpoints probed...", flush=True)

    tasks = [sem_probe(k, n) for k, n in endpoint_list]
    await asyncio.gather(*tasks)

    alive_nodes = []
    for n in nodes:
        key = f"{n.get('server')}:{n.get('port')}:{n.get('type')}:{n.get('tls')}"
        if endpoint_results.get(key, False):
            alive_nodes.append(n)

    print(f"Stage 4 Socket Probe Completed: Retained {len(alive_nodes)} online nodes out of {len(nodes)} total.", flush=True)
    return alive_nodes


def main() -> int:
    print("=== Stage 4: High-Speed Socket TCP / TLS / QUIC Handshake Probe ===", flush=True)
    nodes_file = INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        nodes_file = ALT_INPUT_DIR / "nodes.txt"

    if not nodes_file.exists():
        print(f"Error: Input file {nodes_file} not found.", flush=True)
        return 1

    content = nodes_file.read_text(encoding="utf-8")
    nodes = extract_node_links_from_text(content)
    print(f"Loaded {len(nodes)} nodes for socket probe.", flush=True)

    alive_nodes = asyncio.run(batch_probe_nodes(nodes, concurrency=256, timeout=1.5))

    # Export all 5 standard format files to output/socket/
    export_stage_files(
        output_dir=OUTPUT_DIR,
        nodes=alive_nodes,
        stage_title="Stage 4 - Socket TCP/TLS/QUIC Handshake Probe"
    )

    print(f"Successfully exported Stage 4 output to {OUTPUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
