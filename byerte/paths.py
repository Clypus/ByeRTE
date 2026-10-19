"""Yol ve sabit çözümü: hem geliştirme (repo içinden) hem kurulu (/usr/lib) çalışır."""

from __future__ import annotations

import os
import platform
from pathlib import Path

# --- Sabitler (tüm bileşenler buradan okur) ---------------------------------

NFT_TABLE = "byerte"              # tek nftables tablosu; kapatma = bu tabloyu sil
NFT_FAMILY = "inet"
FWMARK = 0x40000000               # nfqws2 varsayılanı; döngü önleme
QUEUE_NUM = 4242                  # NFQUEUE numarası (upstream zapret 200'den uzak)
DNS_BRIDGE_ADDR = "127.0.0.1"
DNS_BRIDGE_PORT = 5355            # yerel DoH köprüsü; 53 buraya yönlenir
PORTS_TCP = "80,443"
PORTS_UDP = "443"                 # QUIC; Roblox oyun UDP'si (49152+) TR'de engelli değil
MAX_PKT = 15                      # akış başına kuyruğa alınan ilk paket sayısı

# nfqws2'nin ayrıcalık düşürdüğü hesap (hostlist-auto yazabilsin diye gerçek olmalı)
DROP_USER = "nobody"

# Yüklenmesi gereken çekirdek modülleri (nft -f atomik olduğundan önce yüklenir)
KERNEL_MODULES = [
    "nfnetlink_queue", "nft_queue",
    "nf_conntrack", "nft_ct",
    "nf_nat", "nft_nat",
    "nft_reject_inet",
]

# DoH yukarı akışları (sıra = yedekleme önceliği).
# IP'ler sabit (pinned): köprü açıkken :53 köprüye yönlendiği için DoH host adını
# DNS ile çözmeye kalkarsak sonsuz döngü olur. IP ile bağlanıp SNI/sertifikayı
# host adıyla doğruluyoruz.
#
# ÖNEMLİ: Meşhur resolver IP'leri (1.1.1.1, 8.8.8.8, 9.9.9.9) Türkiye'de 443'te
# aktif engelli ("no route to host"). Bu yüzden CDN-arkası DoH uçları kullanıyoruz:
# bunlar genel CDN IP aralıklarında olduğundan IP ile engellenemiyor (Firefox'un
# mozilla.cloudflare-dns.com'u kullanmasının sebebi de bu). Canlı test edildi.
DOH_UPSTREAMS = [
    {"host": "mozilla.cloudflare-dns.com", "path": "/dns-query",
     "ips": ["104.16.248.249", "104.16.249.249"]},
    {"host": "dns.nextdns.io", "path": "/dns-query",
     "ips": ["45.90.28.0", "45.90.30.0"]},
    {"host": "freedns.controld.com", "path": "/p0",
     "ips": ["76.76.2.0", "76.76.10.0"]},
]

# Sağlık kontrolü ve probe için kullanılan hedefler
TEST_DOMAINS = ["discord.com", "www.roblox.com"]


# --- Dizinler ----------------------------------------------------------------

def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _installed() -> bool:
    """Sistem geneli kurulu mu (paket /usr veya /opt altında)?"""
    p = str(Path(__file__).resolve())
    return p.startswith("/usr/") or p.startswith("/opt/")


def data_dir() -> Path:
    """Gömülü veri (nfqws2, lua, bloblar). Dev'de repo/data, kuruluda /usr/lib."""
    if not _installed():
        return _repo_root() / "data"
    for cand in ("/usr/lib/byerte/data", "/usr/local/lib/byerte/data", "/opt/byerte/data"):
        p = Path(cand)
        if p.is_dir():
            return p
    return Path("/usr/lib/byerte/data")


def config_dir() -> Path:
    if _installed():
        d = Path("/etc/byerte")
    else:
        d = _repo_root() / ".runtime" / "etc"
    d.mkdir(parents=True, exist_ok=True)
    return d


def runtime_dir() -> Path:
    """Çalışma anı durumu (durum, autohostlist).

    DEV'de bile /run/byerte kullanılır: nfqws2 `nobody`'ye düştüğünde autohostlist
    dosyasına erişebilmeli; /home altındaki yollar nobody için gezilemez. /run/byerte
    kök tarafından 0755 oluşturulur (bkz. engine.prepare_runtime). mkdir best-effort:
    kök değilsek sadece yolu döndürürüz (okuyucular için).
    """
    d = Path("/run/byerte")
    try:
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o755)
    except (PermissionError, OSError):
        pass
    return d


def config_file() -> Path:
    return config_dir() / "byerte.conf"


def state_file() -> Path:
    return runtime_dir() / "state.json"


# --- Mimariye göre nfqws2 ----------------------------------------------------

def _arch_tag() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "linux-x86_64"
    if m in ("aarch64", "arm64"):
        return "linux-arm64"
    raise RuntimeError(f"desteklenmeyen mimari: {m} (x86_64 / arm64 gerekli)")


def nfqws2_bin() -> Path:
    return data_dir() / "nfqws2" / _arch_tag() / "nfqws2"


def lua_dir() -> Path:
    return data_dir() / "lua"


def fake_dir() -> Path:
    return data_dir() / "fake"


def hostlist_file() -> Path:
    """Kaynak hostlist (salt-okunur şablon, data/ içinde)."""
    return data_dir() / "hostlist.txt"


def active_hostlist_file() -> Path:
    """Çalışma anındaki hostlist (/run/byerte). nfqws2 nobody'ye düştükten sonra
    listeyi yeniden açtığı için herkesin okuyabileceği bir yerde olmalı; data/
    /home altındaysa nobody oraya erişemez. engine başlangıçta kaynaktan kopyalar."""
    return runtime_dir() / "hostlist.txt"


def autohostlist_file() -> Path:
    """nfqws2'nin öğrendiği engelli alan adlarını yazdığı dosya (yazılabilir olmalı)."""
    return runtime_dir() / "autohostlist.txt"


LUA_FILES = ["zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"]


def active_lua_dir() -> Path:
    """Çalışma anı lua kopyası (/run/byerte/lua). nfqws2 Lua'yı root olarak
    çalıştırmaz; yetki düşürdükten sonra yükler — dosyalar nobody'ce okunabilir
    olmalı. engine.prepare_runtime kaynaktan kopyalar."""
    return runtime_dir() / "lua"


def lua_init_args() -> list[str]:
    """nfqws2 için lua kütüphanelerini doğru sırada yükleyen argümanlar."""
    d = active_lua_dir()
    return [f"--lua-init=@{d / f}" for f in LUA_FILES]
