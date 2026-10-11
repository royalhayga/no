from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# Ensure unbuffered real-time stdout logging for GitHub Actions
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parents[1]

VALID_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "chacha20-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "chacha20", "chacha20-ietf", "xchacha20-ietf-poly1305",
    "none"
}

HEX_ESCAPE_RE = re.compile(r'\\x[0-9a-fA-F]{2}')


def strict_clean_str(val: Any) -> str:
    """根本性白名单净化字符串：物理剥离 ASCII 0-31 所有控制字符、字面量 \\x.. 转义序列及 HTML 标签"""
    if not val:
        return ""
    s = str(val)
    # 彻底清理 HTML 标签与字面量 \x.. 转义序列
    s = re.sub(r'<[^>]+>', '', s)
    s = HEX_ESCAPE_RE.sub('', s)
    # 物理过滤 ASCII < 32 (含 \r, \n, \t, \x00, \x1e) 与 DEL 127
    s = ''.join(c for c in s if 32 <= ord(c) <= 126 or ord(c) > 127).strip()
    # 规整连续空格
    return re.sub(r'\s+', ' ', s).strip()


def sanitize_node(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    100% 根本性构造净化节点数据：
    1. 彻底白名单重构字段，拒绝任何非 Mihomo 规范字段渗入。
    2. 校验 IP、端口、密码/UUID 的绝对合法性，拒绝任何带反斜杠或损坏凭据。
    """
    if not isinstance(node, dict):
        return None

    ntype = strict_clean_str(node.get("type")).lower()
    server = strict_clean_str(node.get("server")).rstrip(".")

    if not server or server.lower() in ["localhost", "0.0.0.0", "127.0.0.1"] or "\\" in server:
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
    except Exception:
        return None

    name = strict_clean_str(node.get("name")) or "Node"

    # 根据节点类型，精准纯净白名单构造字典，绝不保留多余的污染字段 (如 VLESS 带有 password)
    if ntype == "ss":
        cipher = strict_clean_str(node.get("cipher")).lower()
        pwd = strict_clean_str(node.get("password"))
        if not pwd or not cipher or cipher not in VALID_SS_CIPHERS or "\\" in pwd:
            return None
        if not re.match(r"^[a-z0-9_-]+$", cipher):
            return None
        return {
            "type": "ss",
            "name": name,
            "server": server,
            "port": port,
            "cipher": cipher,
            "password": pwd
        }
    elif ntype in ["vmess", "vless"]:
        uuid = strict_clean_str(node.get("uuid"))
        if not uuid or "\\" in uuid or len(uuid) < 8 or any(ord(c) > 126 for c in uuid):
            return None
        clean_node = {
            "type": ntype,
            "name": name,
            "server": server,
            "port": port,
            "uuid": uuid,
            "cipher": "auto",
            "tls": bool(node.get("tls")),
            "network": strict_clean_str(node.get("network")) or "tcp"
        }
        if node.get("sni"):
            clean_node["sni"] = strict_clean_str(node.get("sni"))
        if node.get("host"):
            clean_node["host"] = strict_clean_str(node.get("host"))
        if node.get("path"):
            clean_node["path"] = strict_clean_str(node.get("path"))
        return clean_node
    elif ntype == "trojan":
        pwd = strict_clean_str(node.get("password"))
        if not pwd or "\\" in pwd:
            return None
        clean_node = {
            "type": "trojan",
            "name": name,
            "server": server,
            "port": port,
            "password": pwd
        }
        if node.get("sni"):
            clean_node["sni"] = strict_clean_str(node.get("sni"))
        return clean_node
    elif ntype in ["hysteria2", "hy2"]:
        auth = strict_clean_str(node.get("auth") or node.get("password"))
        if not auth or "\\" in auth:
            return None
        clean_node = {
            "type": "hysteria2",
            "name": name,
            "server": server,
            "port": port,
            "auth": auth,
            "password": auth,
            "tls": True
        }
        if node.get("sni"):
            clean_node["sni"] = strict_clean_str(node.get("sni"))
        return clean_node

    return None


def safe_base64_decode(data: str) -> str:
    """Safely decode standard and URL-safe Base64 strings with auto padding."""
    if not data:
        return ""
    data = data.strip().replace("\r", "").replace("\n", "").replace(" ", "")
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
    """Safely encode UTF-8 string to Base64."""
    if not data:
        return ""
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")


def parse_vmess(link: str) -> Optional[Dict[str, Any]]:
    """Parse vmess:// B64 / JSON link."""
    try:
        b64_str = link[8:]
        decoded_json_str = safe_base64_decode(b64_str)
        if not decoded_json_str:
            return None
        vdict = json.loads(decoded_json_str)
        if not isinstance(vdict, dict):
            return None

        server = strict_clean_str(vdict.get("add"))
        port = int(vdict.get("port", 0))
        uuid = strict_clean_str(vdict.get("id"))
        name = strict_clean_str(vdict.get("ps")) or "VMess"
        tls_val = str(vdict.get("tls", "")).lower().strip()

        return sanitize_node({
            "type": "vmess",
            "name": name,
            "server": server,
            "port": port,
            "uuid": uuid,
            "alterId": int(vdict.get("aid", 0)),
            "cipher": str(vdict.get("scy", "auto")).lower().strip() or "auto",
            "tls": tls_val in ["tls", "true", "1"],
            "network": str(vdict.get("net", "tcp")).lower().strip() or "tcp",
            "host": str(vdict.get("host", "")).strip(),
            "path": str(vdict.get("path", "")).strip()
        })
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
        remark = urllib.parse.unquote(parsed.fragment) or "VLess"

        return sanitize_node({
            "type": "vless",
            "name": remark,
            "server": server,
            "port": port,
            "uuid": uuid,
            "cipher": "auto",
            "tls": params.get("security", [""])[0] in ["tls", "reality"],
            "sni": params.get("sni", [""])[0]
        })
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

        return sanitize_node({
            "type": "ss",
            "name": remark or "Shadowsocks",
            "server": server,
            "port": port,
            "cipher": cipher,
            "password": password
        })
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

        return sanitize_node({
            "type": "trojan",
            "name": remark,
            "server": server,
            "port": port,
            "password": password,
            "sni": params.get("sni", [""])[0]
        })
    except Exception:
        return None


def parse_hysteria2(link: str) -> Optional[Dict[str, Any]]:
    """Parse hysteria2://auth@server:port?params#remark link."""
    try:
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

        return sanitize_node({
            "type": "hysteria2",
            "name": remark,
            "server": server,
            "port": port,
            "auth": auth,
            "password": auth,
            "tls": True,
            "sni": params.get("sni", [""])[0]
        })
    except Exception:
        return None


def extract_node_links_from_text(text: str) -> List[Dict[str, Any]]:
    """Extract node links from raw text (including Base64 decoded text)."""
    nodes = []
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
                nodes.append(parsed_node)
    return nodes


def get_node_fingerprint(node: Dict[str, Any]) -> str:
    """
    Calculate unique SHA256 fingerprint hash based purely on core endpoint & credentials.
    EXCLUDES node name / remark / label so renamed duplicate nodes share the exact same hash!
    """
    proto = strict_clean_str(node.get("type")).lower()
    server = strict_clean_str(node.get("server")).lower()
    port = str(node.get("port", ""))
    uuid_pwd = strict_clean_str(node.get("uuid") or node.get("password") or node.get("auth"))
    sni_host = strict_clean_str(node.get("sni") or node.get("host")).lower()
    path = strict_clean_str(node.get("path"))

    raw_str = f"{proto}|{server}|{port}|{uuid_pwd}|{sni_host}|{path}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


def reconstruct_node_link(node: Dict[str, Any]) -> str:
    """Reconstruct standard node URL string from node dictionary."""
    ntype = node.get("type")
    server = strict_clean_str(node.get("server"))
    port = node.get("port")
    name = urllib.parse.quote(strict_clean_str(node.get("name", "Node")))

    if ntype == "ss":
        cipher = node.get("cipher", "aes-256-gcm")
        pwd = strict_clean_str(node.get("password", ""))
        userinfo = safe_base64_encode(f"{cipher}:{pwd}")
        return f"ss://{userinfo}@{server}:{port}#{name}"
    elif ntype == "trojan":
        pwd = strict_clean_str(node.get("password", ""))
        sni = strict_clean_str(node.get("sni", ""))
        return f"trojan://{pwd}@{server}:{port}?sni={sni}#{name}"
    elif ntype == "vless":
        uuid = strict_clean_str(node.get("uuid", ""))
        sni = strict_clean_str(node.get("sni", ""))
        return f"vless://{uuid}@{server}:{port}?security=none&sni={sni}#{name}"
    elif ntype == "vmess":
        vdict = {
            "v": "2", "ps": strict_clean_str(node.get("name", "VMess")), "add": server, "port": str(port),
            "id": strict_clean_str(node.get("uuid", "")), "aid": "0", "scy": "auto", "net": node.get("network", "tcp"),
            "type": "none", "host": strict_clean_str(node.get("host", "")), "path": strict_clean_str(node.get("path", "")),
            "tls": "tls" if node.get("tls") else ""
        }
        b64 = safe_base64_encode(json.dumps(vdict, ensure_ascii=False))
        return f"vmess://{b64}"
    elif ntype in ["hysteria2", "hy2"]:
        auth = strict_clean_str(node.get("auth") or node.get("password", ""))
        sni = strict_clean_str(node.get("sni", ""))
        return f"hysteria2://{auth}@{server}:{port}?sni={sni}#{name}"

    return f"{ntype}://{server}:{port}#{name}"


def ensure_unique_node_names(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ensure every node in the list has a 100% unique name to prevent Mihomo duplicate proxy name errors."""
    seen_names: Set[str] = set()
    unique_nodes = []

    for n in nodes:
        n_copy = dict(n)
        base_name = strict_clean_str(n_copy.get("name") or "Node")
        candidate_name = base_name
        idx = 2
        while candidate_name in seen_names:
            candidate_name = f"{base_name} #{idx}"
            idx += 1
        seen_names.add(candidate_name)
        n_copy["name"] = candidate_name
        unique_nodes.append(n_copy)

    return unique_nodes


def export_stage_files(output_dir: Path, nodes: List[Dict[str, Any]], stage_title: str, extra_data: Dict[str, Any] = None, max_nodes_per_file: int = 50000) -> None:
    """
    100% 根本性白名单构造导出，绝对杜绝字段渗漏与非打印控制字符！
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    clean_nodes = []
    for n in nodes:
        sanitized = sanitize_node(n)
        if sanitized:
            clean_nodes.append(sanitized)

    capped_nodes = ensure_unique_node_names(clean_nodes[:max_nodes_per_file] if len(clean_nodes) > max_nodes_per_file else clean_nodes)

    # 1. Plaintext node links
    raw_links = [reconstruct_node_link(n) for n in capped_nodes]
    nodes_txt_content = "\n".join(raw_links)
    (output_dir / "nodes.txt").write_text(nodes_txt_content, encoding="utf-8")

    # 2. Base64 subscription
    sub_txt_content = safe_base64_encode(nodes_txt_content)
    (output_dir / "sub.txt").write_text(sub_txt_content, encoding="utf-8")

    # 3. Clash YAML configuration (白名单纯净字段重构)
    clash_proxies = []
    for n in capped_nodes:
        sanitized_proxy = sanitize_node(n)
        if sanitized_proxy:
            clash_proxies.append(sanitized_proxy)

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
    for n in capped_nodes:
        ntype = n.get("type")
        outbound = {
            "tag": strict_clean_str(n.get("name")),
            "type": "shadowsocks" if ntype == "ss" else ntype,
            "server": strict_clean_str(n.get("server")),
            "server_port": n.get("port")
        }
        if ntype == "ss":
            outbound["method"] = strict_clean_str(n.get("cipher"))
            outbound["password"] = strict_clean_str(n.get("password"))
        elif ntype in ["vmess", "vless"]:
            outbound["uuid"] = strict_clean_str(n.get("uuid"))
        elif ntype == "trojan":
            outbound["password"] = strict_clean_str(n.get("password"))

        singbox_outbounds.append(outbound)

    singbox_config = {"outbounds": singbox_outbounds}
    (output_dir / "singbox.json").write_text(json.dumps(singbox_config, ensure_ascii=False, indent=2), encoding="utf-8")

    # 5. Summary statistics
    protocol_counts = {}
    for n in clean_nodes:
        ptype = n.get("type", "other")
        protocol_counts[ptype] = protocol_counts.get(ptype, 0) + 1

    summary = {
        "stage": stage_title,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_nodes": len(clean_nodes),
        "protocol_breakdown": protocol_counts
    }
    if extra_data:
        summary["extra"] = extra_data

    (output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
