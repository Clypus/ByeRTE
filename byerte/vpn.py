"""VPN (TUN tüneli) algılama. ByeRTE, bir VPN aktifken yakalamayı otomatik duraklatır.

Mantık: internete giden VARSAYILAN rota bir tünel arayüzünden geçiyorsa VPN aktiftir.
Çalışan bir VPN zaten DPI'yı aştığından, o sırada ByeRTE'nin devrede olması hem
gereksiz hem zararlıdır — DNS'i ele geçirip tüneli bozar, VPN'in kill-switch'i
ByeRTE'nin DoH bağlantısını engelleyip Discord/Roblox DNS'ini düşürebilir. Bu yüzden
VPN görülünce yakalama durur, VPN kapanınca kaldığı yerden sürer.

Fail-open: durum belirlenemezse (komut yok, zaman aşımı, ayrıştırma hatası) False
döner — VPN'siz yaygın durumu bozmamak için güvenli varsayılan.
"""

from __future__ import annotations

import subprocess

from . import paths

# Tünel/VPN işaretleri: Linux arayüz adı (tun0, wg0, proton0...) ve Windows adapter
# adı/açıklaması (WireGuard Tunnel, TAP-Windows, ProtonVPN, WAN Miniport...) için.
# Fiziksel NIC adları (eth*, en*, wl*, Realtek, Intel Ethernet/Wi-Fi) bunları içermez.
_VPN_MARKERS = (
    "tun", "tap", "wg", "wireguard", "ppp", "ipsec", "l2tp", "pptp",
    "openvpn", "proton", "nordlynx", "nordvpn", "mullvad", "expressvpn",
    "surfshark", "windscribe", "cyberghost", "wan miniport", "tailscale",
    "zerotier", "softether", "hamachi", "anyconnect", "forticlient",
    "pulse secure", "openconnect", "wintun", "utun", "nebula", "vpn",
)


def is_tunnel_iface(name: str | None) -> bool:
    """Arayüz adı / açıklaması bir VPN tüneline mi benziyor?"""
    n = (name or "").strip().lower()
    return bool(n) and any(m in n for m in _VPN_MARKERS)


def _linux_active() -> bool:
    """Linux: `ip route get <genel IP>` çıktısındaki çıkış arayüzü tünel mi?"""
    for dest in ("1.1.1.1", "8.8.8.8"):
        try:
            out = subprocess.run(
                ["ip", "route", "get", dest],
                capture_output=True, text=True, timeout=3,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return False
        toks = out.split()
        if "dev" in toks:
            try:
                return is_tunnel_iface(toks[toks.index("dev") + 1])
            except IndexError:
                return False
    return False


# En düşük metrikli varsayılan rotanın (0.0.0.0/0) arayüzünü bul, tipini+adını yaz.
# Çıktı: "<iftype>|<ad>|<açıklama>" (ör. "131|ProtonVPN|WireGuard Tunnel").
_PS_ROUTE = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' |"
    " Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1;"
    "if($r){$a=Get-NetAdapter -InterfaceIndex $r.ifIndex;"
    "Write-Output ([string]$a.InterfaceType+'|'+[string]$a.Name+'|'+"
    "[string]$a.InterfaceDescription)}"
)


def _windows_active() -> bool:
    """Windows: varsayılan rotayı taşıyan adapter tünel tipinde mi / VPN adlı mı?"""
    flags = 0
    try:
        from .win import winutil
        flags = winutil.CREATE_NO_WINDOW
    except Exception:  # noqa: BLE001
        pass
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_ROUTE],
            capture_output=True, text=True, timeout=6, creationflags=flags,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    if not out:
        return False
    parts = out.splitlines()[-1].split("|")
    iftype = parts[0].strip() if parts else ""
    name = parts[1] if len(parts) > 1 else ""
    desc = parts[2] if len(parts) > 2 else ""
    # IANA ifType: 131=tunnel, 23=ppp. Ad/açıklama VPN işareti içeriyorsa da VPN say.
    if iftype in ("131", "23"):
        return True
    return is_tunnel_iface(name) or is_tunnel_iface(desc)


def vpn_active() -> bool:
    """İnternete giden varsayılan rota bir VPN tünelinden mi geçiyor? Hata → False."""
    try:
        return _windows_active() if paths.IS_WINDOWS else _linux_active()
    except Exception:  # noqa: BLE001
        return False
