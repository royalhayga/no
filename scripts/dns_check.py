from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import dns.asyncresolver
import dns.resolver

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text

INPUT_DIR = ROOT_DIR / "output" / "deduped"
OUTPUT_DIR = ROOT_DIR / "output" / "dns"

DOMESTIC_DNS = ["223.5.5.5", "119.29.29.29"]
FOREIGN_DNS = ["1.1.1.1", "8.8.8.8"]

# Known GFW blackhole / fake poisoned IP addresses and bogon ranges
GFW_POISON_IPS = {
    "127.0.0.1", "0.0.0.0", "198.105.244.228", "198.105.254.228",
    "59.24.3.173", "243.185.187.39", "37.61.54.158", "93.46.8.89",
    "203.98.7.65", "8.7.198.45", "78.16.49.15", "159.106.121.75",
    "46.82.174.68", "202.106.199.34", "211.98.71.195"
}


def is_gfw_poisoned_ip(ip: str) -> bool:
    """Check if resolved IP is a known GFW poison/blackhole IP or private address."""
    if ip in GFW_POISON_IPS:
        return True
    if ip.startswith(("10.", "192.168.", "127.", "0.")):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except Exception:
            pass
    return False


async def query_dns(domain: str, nameservers: List[str], timeout: float = 3.0) -> Set[str]:
    """Asynchronously resolve domain using specific nameservers."""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = nameservers
    resolver.lifetime = timeout
    resolver.timeout = timeout

    ips = set()
    try:
        answers = await resolver.resolve(domain, "A")
        for rdata in answers:
            ips.add(str(rdata))
    except Exception:
        pass
    return ips


async def check_domain_dns_health(domain: str) -> Tuple[bool, str]:
    """
    Check domain health across Domestic DNS (AliDNS/DNSPod) vs Foreign DNS (Cloudflare/Google).
    Returns (is_healthy, reason).
    """
    if domain.replace(".", "").isdigit():
        if is_gfw_poisoned_ip(domain):
            return False, "Bogon/Poisoned IP"
        return True, "Direct IP"

    domestic_ips = await query_dns(domain, DOMESTIC_DNS)
    foreign_ips = await query_dns(domain, FOREIGN_DNS)

    if not domestic_ips and foreign_ips:
        return False, "Domestic DNS Failed (Blocked in China)"

    for ip in domestic_ips:
        if is_gfw_poisoned_ip(ip):
            return False, f"Domestic DNS Poisoned ({ip})"

    if domestic_ips:
        return True, "Valid Resolution"

    if not foreign_ips:
        return False, "Unresolvable Globally"

    return True, "Passed DNS Check"


async def filter_dns_nodes(nodes: List[Dict[str, Any]], concurrency: int = 100) -> List[Dict[str, Any]]:
    """Filter nodes with 100-way concurrent async DNS resolution."""
    valid_nodes = []
    domain_status: Dict[str, Tuple[bool, str]] = {}
    unique_domains = list({n.get("server", "") for n in nodes if n.get("server")})

    print(f"Resolving {len(unique_domains)} unique domains with {concurrency}-worker async concurrency...")
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_check(domain: str):
        async with semaphore:
            res = await check_domain_dns_health(domain)
            domain_status[domain] = res

    tasks = [sem_check(d) for d in unique_domains]
    await asyncio.gather(*tasks)

    filtered_count = 0
    for n in nodes:
        server = n.get("server", "")
        is_healthy, reason = domain_status.get(server, (True, "OK"))
        if is_healthy:
            valid_nodes.append(n)
        else:
            filtered_count += 1

    print(f"Stage 3 DNS Check Completed: Retained {len(valid_nodes)} valid nodes, filtered out {filtered_count} poisoned/blocked nodes.")
    return valid_nodes


def main() -> int:
    print("=== Stage 3: High-Concurrency Multi-DNS GFW Pollution & Blocking Filter ===")
    nodes_file = INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        print(f"Error: Input file {nodes_file} not found. Run Stage 2 (scripts/dedupe.py) first.")
        return 1

    content = nodes_file.read_text(encoding="utf-8")
    nodes = extract_node_links_from_text(content)
    print(f"Loaded {len(nodes)} nodes from Stage 2.")

    valid_nodes = asyncio.run(filter_dns_nodes(nodes, concurrency=100))

    # Export all 5 standard format files to output/dns/
    export_stage_files(
        output_dir=OUTPUT_DIR,
        nodes=valid_nodes,
        stage_title="Stage 3 - DNS Health & GFW Pollution Filter"
    )

    print(f"Successfully exported Stage 3 output to {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
