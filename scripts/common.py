from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]


def sanitize_node(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Sanitize and disinfect node data ("去毒"与安全净化):
    1. Strip HTML tags, control chars, and malicious script injection from node name/remark.
    2. Filter out invalid, empty, or internal/bogon server addresses (127.0.0.1, 10.x, 192.168.x, 0.0.0.0, etc.).
    3. Validate port numbers (1-65535).
    """
    if not isinstance(node, dict):
        return None

    server = str(node.get("server", "")).strip().rstrip(".")
    if not server or server.lower() in ["localhost", "0.0.0.0", "127.0.0.1"]:
        return None

    # Internal BOGON IP check
    if server.startswith(("10.", "192.168.", "169.254.")):
        return None
    if server.startswith("172."):
        try:
            second_octet = int(server.split(".")[1])
            if 16 <= second_octet <= 31:
                return None
        except Exception:
            pass

    try:
        port = int(node.get("port", 0))
        if not (1 <= port <= 65535):
            return None
        node["port"] = port
    except Exception:
        return None

    # Sanitize node name / remark (remove HTML tags and control chars)
    raw_name = str(node.get("name", "Node")).strip()
    clean_name = re.sub(r"<[^>]+>", "", raw_name)  # Remove HTML tags
    clean_name = re.sub(r"[\r\n\t\x00-\x1f]", " ", clean_name).strip()  # Remove control chars
    node["name"] = clean_name or "Node"
    node["server"] = server

    return node


def safe_base64_decode(data: str) -> str:
    """Safely decode standard and URL-safe Base64 strings with auto padding."""
    if not data:
        return ""
    data = data.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    # Add missing Base64 padding
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    try:
        return base64.b64decode(data, validate=False).decode("utf-8", errors="ignore")
    except Exception:
        try:
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
        except Exception:
            return ""


def safe_base64_encode(data: str) -> str:
    """Encode a string to Base64."""
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")


def parse_vmess(link: str) -> Optional[Dict[str, Any]]:
    """Parse vmess:// B64JSON link."""
    try:
        b64_str = link[8:]
        decoded = safe_base64_decode(b64_str)
        if not decoded:
            return None
        data = json.loads(decoded)
        if not isinstance(data, dict):
            return None
        server = data.get("add") or data.get("host")
        port = int(data.get("port", 0))
        uuid = data.get("id")
        if not server or not port or not uuid:
            return None

        tls = data.get("tls") in ["tls", True, "true"]
        net = data.get("net") or "tcp"

        return {
            "type": "vmess",
            "name": str(data.get("ps", "VMess")).strip(),
            "server": str(server).strip(),
            "port": port,
            "uuid": str(uuid).strip(),
            "alterId": int(data.get("aid", 0)),
            "cipher": str(data.get("scy", "auto")).strip(),
            "network": str(net).strip(),
            "path": str(data.get("path", "")).strip(),
            "host": str(data.get("host", "")).strip(),
            "tls": tls,
            "sni": str(data.get("sni", data.get("host", ""))).strip(),
            "raw_link": link
        }
    except Exception:
        return None


def parse_vless(link: str) -> Optional[Dict[str, Any]]:
    """Parse vless://uuid@server:port?params#remark link."""
    try:
        parsed = urllib.parse.urlparse(link)
        if not parsed.netloc or "@" not in parsed.netloc:
            return None
        uuid, netloc = parsed.netloc.split("@", 1)
        if ":" in netloc:
            server, port_str = netloc.split(":", 1)
            port = int(port_str)
        else:
            server = netloc
            port = 443

        params = urllib.parse.parse_qs(parsed.query)
        remark = urllib.parse.unquote(parsed.fragment) or "VLESS"

        security = params.get("security", ["none"])[0]
        tls = security in ["tls", "reality"]

        return {
            "type": "vless",
            "name": remark.strip(),
            "server": server.strip(),
            "port": port,
            "uuid": uuid.strip(),
            "cipher": "auto",
            "network": params.get("type", ["tcp"])[0],
            "path": params.get("path", [""])[0],
            "host": params.get("host", [""])[0],
            "tls": tls,
            "security": security,
            "sni": params.get("sni", [params.get("host", [""])[0]])[0],
            "flow": params.get("flow", [""])[0],
            "public_key": params.get("pbk", [""])[0],
            "short_id": params.get("sid", [""])[0],
            "raw_link": link
        }
    except Exception:
        return None


def parse_ss(link: str) -> Optional[Dict[str, Any]]:
    """Parse ss:// SIP002 / Legacy link."""
    try:
        url_part = link[5:]
        remark = ""
        if "#" in url_part:
            url_part, remark = url_part.split("#", 1)
            remark = urllib.parse.unquote(remark)

        if "@" in url_part:
            userinfo, server_part = url_part.split("@", 1)
            decoded_userinfo = safe_base64_decode(userinfo) or userinfo
            if ":" in decoded_userinfo:
                cipher, password = decoded_userinfo.split(":", 1)
            else:
                cipher, password = "aes-256-gcm", decoded_userinfo
        else:
            decoded_all = safe_base64_decode(url_part)
            if "@" in decoded_all:
                userinfo, server_part = decoded_all.split("@", 1)
                cipher, password = userinfo.split(":", 1)
            else:
                return None

        if ":" in server_part:
            server, port_str = server_part.split(":", 1)
            port = int(port_str.split("?")[0].split("/")[0])
        else:
            return None

        return {
            "type": "ss",
            "name": remark.strip() or "Shadowsocks",
            "server": server.strip(),
            "port": port,
            "cipher": cipher.strip(),
            "password": password.strip(),
            "raw_link": link
        }
    except Exception:
        return None


def parse_trojan(link: str) -> Optional[Dict[str, Any]]:
    """Parse trojan://password@server:port?params#remark link."""
    try:
        parsed = urllib.parse.urlparse(link)
        if not parsed.netloc or "@" not in parsed.netloc:
            return None
        password, netloc = parsed.netloc.split("@", 1)
        if ":" in netloc:
            server, port_str = netloc.split(":", 1)
            port = int(port_str)
        else:
            server = netloc
            port = 443

        params = urllib.parse.parse_qs(parsed.query)
        remark = urllib.parse.unquote(parsed.fragment) or "Trojan"

        return {
            "type": "trojan",
            "name": remark.strip(),
            "server": server.strip(),
            "port": port,
            "password": password.strip(),
            "tls": True,
            "sni": params.get("sni", [params.get("peer", [""])[0]])[0],
            "network": params.get("type", ["tcp"])[0],
            "path": params.get("path", [""])[0],
            "host": params.get("host", [""])[0],
            "raw_link": link
        }
    except Exception:
        return None


def parse_hysteria2(link: str) -> Optional[Dict[str, Any]]:
    """Parse hysteria2:// or hy2:// auth@server:port?params#remark link."""
    try:
        prefix_len = 12 if link.startswith("hysteria2://") else 6
        parsed = urllib.parse.urlparse(link)
        netloc = parsed.netloc
        auth = ""
        if "@" in netloc:
            auth, netloc = netloc.split("@", 1)

        if ":" in netloc:
            server, port_str = netloc.split(":", 1)
            port = int(port_str)
        else:
            server = netloc
            port = 443

        params = urllib.parse.parse_qs(parsed.query)
        remark = urllib.parse.unquote(parsed.fragment) or "Hysteria2"

        return {
            "type": "hysteria2",
            "name": remark.strip(),
            "server": server.strip(),
            "port": port,
            "auth": auth.strip(),
            "password": auth.strip(),
            "tls": True,
            "sni": params.get("sni", [""])[0],
            "obfs": params.get("obfs", [""])[0],
            "obfs_password": params.get("obfs-password", [""])[0],
            "raw_link": link
        }
    except Exception:
        return None


def extract_node_links_from_text(text: str) -> List[Dict[str, Any]]:
    """Extract node links from raw text (including Base64 decoded text)."""
    nodes = []
    # If text looks like a Base64 blob, decode it first
    if not any(proto in text for proto in ["vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://", "tuic://"]):
        decoded = safe_base64_decode(text)
        if decoded:
            text = decoded

    patterns = [
        r"vmess://[a-zA-Z0-9+/=_-]+",
        r"vless://[^\s\"']+",
        r"ss://[^\s\"']+",
        r"trojan://[^\s\"']+",
        r"hysteria2://[^\s\"']+",
        r"hy2://[^\s\"']+",
        r"tuic://[^\s\"']+"
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            link = match.group(0).strip()
            parsed_node = None
            if link.startswith("vmess://"):
                parsed_node = parse_vmess(link)
            elif link.startswith("vless://"):
                parsed_node = parse_vless(link)
            elif link.startswith("ss://"):
                parsed_node = parse_ss(link)
            elif link.startswith("trojan://"):
                parsed_node = parse_trojan(link)
            elif link.startswith("hysteria2://") or link.startswith("hy2://"):
                parsed_node = parse_hysteria2(link)

            if parsed_node:
                sanitized = sanitize_node(parsed_node)
                if sanitized:
                    nodes.append(sanitized)
    return nodes


def get_node_fingerprint(node: Dict[str, Any]) -> str:
    """
    Calculate unique SHA256 fingerprint hash based purely on core endpoint & credentials.
    EXCLUDES node name / remark / label so renamed duplicate nodes share the exact same hash!
    """
    proto = str(node.get("type", "")).lower()
    server = str(node.get("server", "")).lower().strip()
    port = str(node.get("port", ""))
    uuid_pwd = str(node.get("uuid") or node.get("password") or node.get("auth") or "").strip()
    sni_host = str(node.get("sni") or node.get("host") or "").lower().strip()
    path = str(node.get("path", "")).strip()
    pbk = str(node.get("public_key", "")).strip()

    raw_str = f"{proto}|{server}|{port}|{uuid_pwd}|{sni_host}|{path}|{pbk}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


def reconstruct_node_link(node: Dict[str, Any]) -> str:
    """Reconstruct standard node URL string from node dictionary."""
    if node.get("raw_link"):
        return node["raw_link"]

    ntype = node.get("type")
    server = node.get("server")
    port = node.get("port")
    name = urllib.parse.quote(node.get("name", "Node"))

    if ntype == "ss":
        cipher = node.get("cipher", "aes-256-gcm")
        pwd = node.get("password", "")
        userinfo = safe_base64_encode(f"{cipher}:{pwd}")
        return f"ss://{userinfo}@{server}:{port}#{name}"
    elif ntype == "trojan":
        pwd = node.get("password", "")
        sni = node.get("sni", "")
        return f"trojan://{pwd}@{server}:{port}?sni={sni}#{name}"
    elif ntype == "vless":
        uuid = node.get("uuid", "")
        sni = node.get("sni", "")
        security = node.get("security", "none")
        return f"vless://{uuid}@{server}:{port}?security={security}&sni={sni}#{name}"
    elif ntype == "vmess":
        vdict = {
            "v": "2", "ps": node.get("name", "VMess"), "add": server, "port": str(port),
            "id": node.get("uuid", ""), "aid": "0", "scy": "auto", "net": node.get("network", "tcp"),
            "type": "none", "host": node.get("host", ""), "path": node.get("path", ""),
            "tls": "tls" if node.get("tls") else ""
        }
        b64 = safe_base64_encode(json.dumps(vdict, ensure_ascii=False))
        return f"vmess://{b64}"
    elif ntype in ["hysteria2", "hy2"]:
        auth = node.get("auth") or node.get("password", "")
        sni = node.get("sni", "")
        return f"hysteria2://{auth}@{server}:{port}?sni={sni}#{name}"

    return f"{ntype}://{server}:{port}#{name}"


def export_stage_files(output_dir: Path, nodes: List[Dict[str, Any]], stage_title: str, extra_data: Dict[str, Any] = None) -> None:
    """
    Export all 5 standard formats to output_dir:
    1. nodes.txt (Plaintext links)
    2. sub.txt (Base64 subscription)
    3. clash.yaml (Clash / Mihomo configuration)
    4. singbox.json (Sing-box configuration)
    5. summary.json (Metadata & statistics)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Plaintext node links
    raw_links = [reconstruct_node_link(n) for n in nodes]
    nodes_txt_content = "\n".join(raw_links)
    (output_dir / "nodes.txt").write_text(nodes_txt_content, encoding="utf-8")

    # 2. Base64 subscription
    sub_txt_content = safe_base64_encode(nodes_txt_content)
    (output_dir / "sub.txt").write_text(sub_txt_content, encoding="utf-8")

    # 3. Clash YAML configuration
    clash_proxies = []
    for idx, n in enumerate(nodes):
        proxy = {
            "name": n.get("name") or f"Node-{idx+1}",
            "type": n.get("type", "ss"),
            "server": n.get("server"),
            "port": n.get("port")
        }
        if n.get("type") == "vmess":
            proxy.update({
                "uuid": n.get("uuid"),
                "alterId": n.get("alterId", 0),
                "cipher": n.get("cipher", "auto"),
                "tls": bool(n.get("tls")),
                "network": n.get("network", "tcp")
            })
        elif n.get("type") == "vless":
            proxy.update({
                "uuid": n.get("uuid"),
                "cipher": "auto",
                "tls": bool(n.get("tls")),
                "servername": n.get("sni", "")
            })
        elif n.get("type") == "ss":
            proxy.update({
                "cipher": n.get("cipher", "aes-256-gcm"),
                "password": n.get("password", "")
            })
        elif n.get("type") == "trojan":
            proxy.update({
                "password": n.get("password", ""),
                "sni": n.get("sni", "")
            })
        elif n.get("type") in ["hysteria2", "hy2"]:
            proxy.update({
                "auth": n.get("auth") or n.get("password", ""),
                "sni": n.get("sni", "")
            })
        clash_proxies.append(proxy)

    proxy_names = [p["name"] for p in clash_proxies]
    clash_config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "AUTO", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": proxy_names if proxy_names else ["DIRECT"]},
            {"name": "PROXY", "type": "select", "proxies": ["AUTO", "DIRECT"] + (proxy_names if proxy_names else [])}
        ],
        "rules": ["MATCH,PROXY"]
    }
    clash_yaml_str = f"# Generated by {stage_title} at {datetime.now(timezone.utc).isoformat()}\n" + yaml.safe_dump(clash_config, allow_unicode=True, sort_keys=False)
    (output_dir / "clash.yaml").write_text(clash_yaml_str, encoding="utf-8")

    # 4. Sing-box JSON configuration
    singbox_outbounds = []
    for idx, n in enumerate(nodes):
        outbound = {
            "tag": n.get("name") or f"Node-{idx+1}",
            "type": n.get("type", "shadowsocks"),
            "server": n.get("server"),
            "server_port": n.get("port")
        }
        if n.get("type") == "ss":
            outbound["type"] = "shadowsocks"
            outbound["method"] = n.get("cipher", "aes-256-gcm")
            outbound["password"] = n.get("password", "")
        elif n.get("type") == "vmess":
            outbound["uuid"] = n.get("uuid")
            outbound["security"] = n.get("cipher", "auto")
        elif n.get("type") == "vless":
            outbound["uuid"] = n.get("uuid")
        elif n.get("type") == "trojan":
            outbound["password"] = n.get("password", "")

        singbox_outbounds.append(outbound)

    singbox_config = {
        "outbounds": singbox_outbounds
    }
    (output_dir / "singbox.json").write_text(json.dumps(singbox_config, ensure_ascii=False, indent=2), encoding="utf-8")

    # 5. Summary statistics
    protocol_counts = {}
    for n in nodes:
        ptype = n.get("type", "other")
        protocol_counts[ptype] = protocol_counts.get(ptype, 0) + 1

    summary = {
        "stage": stage_title,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_nodes": len(nodes),
        "protocol_breakdown": protocol_counts
    }
    if extra_data:
        summary["extra"] = extra_data

    (output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
