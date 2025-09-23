import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

# --- Constants ---
VALID_SS_METHODS = {
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "aes-256-cfb", "aes-128-cfb",
    "camellia-256-cfb", "camellia-128-cfb", "rc4-md5"
}
VALID_V_TRANSPORTS = {"tcp", "ws", "grpc", "kcp", "http", "xhttp"}
PROTOCOLS = {
    "vless": "vless://", "vmess": "vmess://", "trojan": "trojan://",
    "ss": "ss://", "ssr": "ssr://", "tuic": "tuic://", "hy2": "hy2://"
}

# --- Dataclass for Standardized Proxy Representation ---
@dataclass
class Proxy:
    """A standardized representation of a proxy configuration."""
    protocol: str
    original_line: str
    host: str
    port: int
    name: Optional[str]

    # Protocol-specific fields
    uuid: Optional[str] = None
    password: Optional[str] = None
    method: Optional[str] = None
    
    # Transport & Security
    transport: str = "tcp"
    security: str = "none"
    
    # VLESS specific
    flow: Optional[str] = None
    
    # VMess specific
    alterId: int = 0
    vmess_cipher: str = "auto"
    vmess_data: Dict[str, Any] = field(default_factory=lambda: {})

    # Network settings
    sni: Optional[str] = None
    ws_path: Optional[str] = None
    ws_host: Optional[str] = None
    grpc_service_name: Optional[str] = None
    
    # REALITY settings
    fingerprint: Optional[str] = None
    publicKey: Optional[str] = None
    shortId: Optional[str] = None

    @property
    def unique_key(self):
        """Generates a unique key for deduplication purposes."""
        if self.protocol == "vmess":
            return ("vmess", self.host.lower(), self.port, self.uuid, self.transport, self.ws_path, self.ws_host, self.security)
        elif self.protocol in ["vless", "trojan"]:
            return (self.protocol, self.host.lower(), self.port, self.uuid, self.transport, self.security, self.ws_path, self.sni)
        elif self.protocol == "ss":
            return ("ss", self.host.lower(), self.port, self.method, self.password)
        else: # tuic, hy2
            return (self.protocol, self.host.lower(), self.port, self.uuid)

# --- Main Parser Function ---
def parse_proxy(line: str) -> Optional[Proxy]:
    """
    Parses a proxy configuration link and returns a standardized Proxy object.
    Returns None if the link is invalid or unsupported.
    """
    line = line.strip()
    if not line:
        return None

    protocol_name = next((name for name, prefix in PROTOCOLS.items() if line.startswith(prefix)), None)
    if not protocol_name:
        return None

    try:
        if protocol_name == "vmess":
            return _parse_vmess(line)
        elif protocol_name in ["vless", "trojan"]:
            return _parse_vless_trojan(line, protocol_name)
        elif protocol_name == "ss":
            return _parse_ss(line)
        elif protocol_name in ["tuic", "hy2"]:
            return _parse_tuic_hy2(line, protocol_name)
    except Exception:
        return None
    
    return None

# --- Protocol-Specific Parsers ---
def _parse_vmess(line: str) -> Optional[Proxy]:
    vmess_json_str = base64.b64decode(line[len("vmess://"):]).decode('utf-8')
    vmess_data: Dict[str, Any] = json.loads(vmess_json_str)
    
    host = vmess_data.get("add")
    port = int(vmess_data.get("port", 0))
    uuid = vmess_data.get("id")
    transport = vmess_data.get("net", "tcp")

    if not host or not port or not uuid or transport not in VALID_V_TRANSPORTS:
        return None

    return Proxy(
        protocol="vmess", original_line=line, host=host, port=port,
        name=vmess_data.get("ps"), uuid=uuid, alterId=int(vmess_data.get("aid", 0)),
        vmess_cipher=vmess_data.get("scy", "auto"), transport=transport,
        security="tls" if vmess_data.get("tls") in ["tls", True] else "none",
        sni=vmess_data.get("host", host),
        ws_path=vmess_data.get("path"), ws_host=vmess_data.get("host"),
        vmess_data=vmess_data
    )

def _parse_vless_trojan(line: str, protocol: str) -> Optional[Proxy]:
    parsed_url = urlparse(line)
    host, port, uuid = parsed_url.hostname, parsed_url.port, parsed_url.username
    
    if not host or not port or not uuid:
        return None
        
    qs = parse_qs(parsed_url.query)
    transport = qs.get("type", ["tcp"])[0]
    security = qs.get("security", ["none"])[0]

    if transport not in VALID_V_TRANSPORTS:
        return None

    return Proxy(
        protocol=protocol, original_line=line, host=host, port=port,
        name=unquote(parsed_url.fragment) if parsed_url.fragment else None, uuid=uuid, transport=transport,
        security=security, flow=qs.get("flow", [None])[0],
        sni=qs.get("sni", [None])[0],
        fingerprint=qs.get("fp", [None])[0],
        publicKey=qs.get("pbk", [None])[0],
        shortId=qs.get("sid", [None])[0],
        ws_path=qs.get("path", [None])[0],
        ws_host=qs.get("host", [None])[0],
        grpc_service_name=qs.get("serviceName", [None])[0]
    )

def _parse_ss(line: str) -> Optional[Proxy]:
    parsed_url = urlparse(line)
    host, port = parsed_url.hostname, parsed_url.port

    if not host or not port or not parsed_url.username:
        return None

    try:
        userinfo = base64.b64decode(parsed_url.username + "==").decode('utf-8')
    except Exception:
        userinfo = unquote(parsed_url.username)
        
    method, password = userinfo.split(':', 1)
    if method not in VALID_SS_METHODS:
        return None

    return Proxy(
        protocol="ss", original_line=line, host=host, port=port,
        name=unquote(parsed_url.fragment) if parsed_url.fragment else None, method=method, password=password
    )

def _parse_tuic_hy2(line: str, protocol: str) -> Optional[Proxy]:
    parsed_url = urlparse(line)
    host, port, uuid = parsed_url.hostname, parsed_url.port, parsed_url.username

    if not host or not port or not uuid:
        return None

    qs = parse_qs(parsed_url.query)
    return Proxy(
        protocol=protocol, original_line=line, host=host, port=port,
        name=unquote(parsed_url.fragment) if parsed_url.fragment else None, uuid=uuid, transport="udp",
        sni=qs.get("sni", [None])[0]
    )

# --- Conversion Functions ---
def to_clash_dict(proxy: Proxy) -> Dict[str, Any]:
    """Converts a Proxy object to a Clash-compatible dictionary."""
    clash_proxy: Dict[str, Any] = {
        "name": proxy.name,
        "type": proxy.protocol,
        "server": proxy.host,
        "port": proxy.port,
    }

    if proxy.protocol in ["vless", "trojan", "vmess"]:
        clash_proxy["uuid"] = proxy.uuid
        clash_proxy["network"] = proxy.transport
        clash_proxy["tls"] = proxy.security in ["tls", "reality"]
        clash_proxy["servername"] = proxy.sni if proxy.sni else proxy.host

        if proxy.transport == "ws":
            clash_proxy["ws-opts"] = {"path": proxy.ws_path or "/", "headers": {"Host": proxy.ws_host or proxy.host}}
        
        if proxy.protocol == "vless":
            if proxy.flow:
                clash_proxy["flow"] = proxy.flow
    
    if proxy.protocol == "vmess":
        clash_proxy["alterId"] = proxy.alterId
        clash_proxy["cipher"] = proxy.vmess_cipher

    if proxy.protocol == "ss":
        clash_proxy["cipher"] = proxy.method
        clash_proxy["password"] = proxy.password

    return clash_proxy