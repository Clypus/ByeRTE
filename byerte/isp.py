"""Ağ ve operatör tespiti: WAN arayüzü, genel IP, ASN → strateji önerisi.

ASN, genel IP'nin Team Cymru'ya TXT sorgusuyla (zehirlenmemiş DoH yolundan)
sorulmasıyla bulunur. Hepsi best-effort; başarısız olursa kullanıcı operatörü
elle seçer.
"""

from __future__ import annotations

import socket
import ssl
import subprocess

from . import strategies
from .dns import DohResolver, parse_txt

# Genel IP için CDN-arkası uç (meşhur IP'ler engelli olabilir; cloudflare.com
# CDN aralığında, erişilebilir). SNI cloudflare.com ile doğrulanır.
_TRACE_HOST = "www.cloudflare.com"
_TRACE_IPS = ["104.16.123.96", "104.16.124.96"]
_TRACE_PATH = "/cdn-cgi/trace"


def detect_wan_iface() -> str | None:
    """Varsayılan rota arayüzü (ör. wlan0, enp3s0)."""
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:  # noqa: BLE001
        pass
    return None


def detect_wan_ip() -> str | None:
    """Yerel WAN kaynak IP'si (default rota üzerinden)."""
    try:
        out = subprocess.run(["ip", "route", "get", "1.1.1.1"],
                             capture_output=True, text=True, timeout=5).stdout
        parts = out.split()
        if "src" in parts:
            return parts[parts.index("src") + 1]
    except Exception:  # noqa: BLE001
        pass
    return None


def get_public_ip() -> str | None:
    """Genel IP'yi CDN-arkası Cloudflare trace ucundan al."""
    import http.client

    ctx = ssl.create_default_context()
    for ip in _TRACE_IPS:
        try:
            sock = ctx.wrap_socket(
                socket.create_connection((ip, 443), timeout=5),
                server_hostname=_TRACE_HOST)
            conn = http.client.HTTPSConnection(_TRACE_HOST, 443, context=ctx, timeout=5)
            conn.sock = sock
            conn.request("GET", _TRACE_PATH, headers={"User-Agent": "byerte/1.0"})
            body = conn.getresponse().read().decode("latin1")
            conn.close()
            for line in body.splitlines():
                if line.startswith("ip="):
                    return line[3:].strip()
        except Exception:  # noqa: BLE001
            continue
    return None


def _reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def detect_asn(resolver: DohResolver | None = None, public_ip: str | None = None) -> int | None:
    """Genel IP'den ASN'i bul (Team Cymru TXT, DoH üzerinden)."""
    resolver = resolver or DohResolver()
    public_ip = public_ip or get_public_ip()
    if not public_ip or ":" in public_ip:  # yalnızca IPv4
        return None
    name = f"{_reverse_ip(public_ip)}.origin.asn.cymru.com"
    resp = resolver.query(name, qtype=16)  # TXT
    if not resp:
        return None
    for txt in parse_txt(resp):
        # biçim: "9121 | 78.160.0.0/12 | TR | ripencc | ..."
        first = txt.split("|")[0].strip().split()
        if first and first[0].isdigit():
            return int(first[0])
    return None


def suggest_strategy(resolver: DohResolver | None = None) -> tuple[str, dict]:
    """Operatörü otomatik tespit edip strateji öner. (strateji_adı, bilgi)."""
    info: dict = {
        "wan_iface": detect_wan_iface(),
        "public_ip": None,
        "asn": None,
        "auto": True,
    }
    resolver = resolver or DohResolver()
    info["public_ip"] = get_public_ip()
    asn = detect_asn(resolver, info["public_ip"])
    info["asn"] = asn
    if asn and asn in strategies.ASN_TO_STRATEGY:
        return strategies.ASN_TO_STRATEGY[asn], info
    return strategies.DEFAULT_STRATEGY, info
