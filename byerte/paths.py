"""Yol ve sabit çözümü: hem geliştirme (repo içinden) hem kurulu çalışır.

Linux: /usr/lib/byerte, /etc/byerte, /run/byerte.
Windows: kurulum dizini (repo düzeniyle aynı ya da donmuş exe), %ProgramData%\\ByeRTE.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

# --- Sabitler (tüm bileşenler buradan okur) ---------------------------------

NFT_TABLE = "byerte"              # tek nftables tablosu; kapatma = bu tabloyu sil
NFT_FAMILY = "inet"
FWMARK = 0x40000000               # nfqws2 varsayılanı; döngü önleme
QUEUE_NUM = 4242                  # NFQUEUE numarası (upstream zapret 200'den uzak)
DNS_BRIDGE_ADDR = "127.0.0.1"
# Yerel DoH köprüsü. Linux'ta 53 buraya yönlenir. Windows'ta 5353/5355'i DNS Client
# servisi (mDNS/LLMNR) tutar; orada köprü yalnızca sağlık kontrolü/teşhis içindir,
# asıl yönlendirmeyi WinDivert yapar (bkz. byerte.win.dnsdivert).
DNS_BRIDGE_PORT = 15353 if IS_WINDOWS else 5355
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

# Windows servis adı (SCM). Linux'taki byerte.service'in karşılığı.
WIN_SERVICE_NAME = "ByeRTE"


# --- Dizinler ----------------------------------------------------------------

def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _frozen() -> bool:
    """PyInstaller ile paketlenmiş (donmuş) exe içinden mi çalışıyoruz?"""
    return bool(getattr(sys, "frozen", False))


def _installed() -> bool:
    """Sistem geneli kurulu mu? Linux: /usr veya /opt altında. Windows: donmuş exe
    ya da %ProgramFiles% altında."""
    if IS_WINDOWS:
        if _frozen():
            return True
        pf = os.environ.get("ProgramFiles", r"C:\Program Files").rstrip("\\") + "\\"
        return str(Path(__file__).resolve()).lower().startswith(pf.lower())
    p = str(Path(__file__).resolve())
    return p.startswith("/usr/") or p.startswith("/opt/")


def _programdata() -> Path:
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ByeRTE"


def data_dir() -> Path:
    """Gömülü veri (nfqws2/winws2, lua, bloblar). Dev'de repo/data, kuruluda /usr/lib.
    Windows'ta kurulu düzen repo ile aynıdır (kurulum dizini/data); donmuş exe'de
    PyInstaller'ın açtığı dizin."""
    if IS_WINDOWS:
        if _frozen():
            return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "data"
        return _repo_root() / "data"
    if not _installed():
        return _repo_root() / "data"
    for cand in ("/usr/lib/byerte/data", "/usr/local/lib/byerte/data", "/opt/byerte/data"):
        p = Path(cand)
        if p.is_dir():
            return p
    return Path("/usr/lib/byerte/data")


def config_dir() -> Path:
    if IS_WINDOWS and _installed():
        d = _programdata()
    elif _installed():
        d = Path("/etc/byerte")
    else:
        d = _repo_root() / ".runtime" / "etc"
    # best-effort: yetkisiz `durum` çağrısında (henüz dizin yokken) çökmesin;
    # okuyucular zaten FileNotFoundError'ı varsayılanlara düşürerek karşılar.
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


def runtime_dir() -> Path:
    """Çalışma anı durumu (durum, autohostlist).

    DEV'de bile /run/byerte kullanılır: nfqws2 `nobody`'ye düştüğünde autohostlist
    dosyasına erişebilmeli; /home altındaki yollar nobody için gezilemez. /run/byerte
    kök tarafından 0755 oluşturulur (bkz. engine.prepare_runtime). mkdir best-effort:
    kök değilsek sadece yolu döndürürüz (okuyucular için).

    Windows'ta (dev dahil) %ProgramData%\\ByeRTE\\run: servis (SYSTEM) ile yetkili
    CLI aynı yeri görür, yetkisiz `durum` da okuyabilir.
    """
    if IS_WINDOWS:
        d = _programdata() / "run"
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        return d
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


# --- Mimariye göre nfqws2 / winws2 -------------------------------------------

def _arch_tag() -> str:
    m = platform.machine().lower()
    if IS_WINDOWS:
        # WinDivert'in imzalı sürücüsü yalnızca x86_64 için var (ARM64'te test
        # imzası gerekir); zapret2 de Windows'ta yalnızca x86/x86_64 derler.
        if m in ("amd64", "x86_64"):
            return "windows-x86_64"
        raise RuntimeError(f"desteklenmeyen mimari: {m} (Windows'ta x86_64 gerekli)")
    if m in ("x86_64", "amd64"):
        return "linux-x86_64"
    if m in ("aarch64", "arm64"):
        return "linux-arm64"
    raise RuntimeError(f"desteklenmeyen mimari: {m} (x86_64 / arm64 gerekli)")


def nfqws2_bin() -> Path:
    return data_dir() / "nfqws2" / _arch_tag() / "nfqws2"


def winws2_dir() -> Path:
    """winws2.exe + cygwin1.dll + WinDivert.dll + WinDivert64.sys (aynı dizinde olmalı)."""
    return data_dir() / "winws2" / _arch_tag()


def winws2_bin() -> Path:
    return winws2_dir() / "winws2.exe"


def windivert_dll() -> Path:
    """DNS yönlendirmesi winws2 ile AYNI WinDivert.dll/sürücüsünü kullanır."""
    return winws2_dir() / "WinDivert.dll"


def engine_bin() -> Path:
    """Bu platformun DPI motoru: Linux'ta nfqws2, Windows'ta winws2.exe."""
    return winws2_bin() if IS_WINDOWS else nfqws2_bin()


def arg_path(p: Path) -> str:
    """Motor argümanı için yol dizesi. winws2 cygwin programıdır: C:/... biçimini
    sorunsuz açar; ters eğik çizgi kaçış derdi olmasın diye Windows'ta / kullanılır."""
    return p.as_posix() if IS_WINDOWS else str(p)


def lua_dir() -> Path:
    return data_dir() / "lua"


def fake_dir() -> Path:
    return data_dir() / "fake"


def hostlist_file() -> Path:
    """Kaynak hostlist (salt-okunur şablon, data/ içinde). İlk açılışta kullanıcı
    kopyası (user_hostlist_file) bundan tohumlanır."""
    return data_dir() / "hostlist.txt"


def user_hostlist_file() -> Path:
    """Kullanıcının düzenleyebildiği hostlist (config dizininde). Buraya başka
    engelli siteler eklenebilir; alt alan adları otomatik kapsanır. İlk açılışta
    gömülü şablondan (discord/roblox) tohumlanır. DPI desync BU listedeki alanlara
    uygulanır (DNS zaten tüm sitelerde DoH'tan gider)."""
    return config_dir() / "hostlist.txt"


def denylist_file() -> Path:
    """Kullanıcının düzenleyebildiği HARİÇ-TUTMA listesi (config dizininde). Buradaki
    alanlara ByeRTE hiç dokunmaz: DPI uygulanmaz (--hostlist-exclude) ve DNS normal
    çözümleyiciden gider (Windows). Hata veren üçüncü-parti API'ler için."""
    return config_dir() / "denylist.txt"


def active_hostlist_file() -> Path:
    """Çalışma anındaki hostlist (/run/byerte). nfqws2 nobody'ye düştükten sonra
    listeyi yeniden açtığı için herkesin okuyabileceği bir yerde olmalı; config
    dizini erişilemezse engine kullanıcı kopyasından buraya kopyalar."""
    return runtime_dir() / "hostlist.txt"


def active_denylist_file() -> Path:
    """Çalışma anındaki denylist kopyası (/run/byerte)."""
    return runtime_dir() / "denylist.txt"


def autohostlist_file() -> Path:
    """nfqws2'nin öğrendiği engelli alan adlarını yazdığı dosya (yazılabilir olmalı)."""
    return runtime_dir() / "autohostlist.txt"


# Düzenlenebilir listelerin başına yazılan açıklama (zapret2 '#' satırlarını atlar).
HOSTLIST_HEADER = (
    "# ByeRTE — DPI atlatma UYGULANACAK siteler (satır başına bir alan adı).\n"
    "# Alt alan adları otomatik kapsanır (roblox.com → www.roblox.com, apis.roblox.com).\n"
    "# Başka engelli siteler ekleyebilirsiniz; gerekirse CDN alan adlarını da ekleyin.\n"
    "# '#', ';' veya '/' ile başlayan satırlar yorumdur. Değişiklikten sonra:\n"
    "#   byerte kapat && byerte aç\n"
    "#\n"
    "# TÜM SİTELER modu: aşağıya tek başına 'ALL=1' yazarsanız DPI atlatma yalnız\n"
    "# bu listeyle sınırlı kalmaz, TÜM sitelere uygulanır (denylist yine hariç tutar).\n"
    "# Daha çok CPU harcar ve engelsiz bazı siteleri bozabilir — dikkatli kullanın.\n"
)
DENYLIST_HEADER = (
    "# ByeRTE — tamamen HARİÇ tutulacak siteler (satır başına bir alan adı).\n"
    "# Buradaki alanlara dokunulmaz: DPI uygulanmaz, DNS normal çözümleyiciden gider\n"
    "# (bozulan üçüncü-parti API'ler için). Alt alan adları otomatik kapsanır.\n"
    "# '#', ';' veya '/' ile başlayan satırlar yorumdur. Örnek:\n"
    "#   ornek-api.com\n"
)


def load_list(path: Path) -> list[str]:
    """Bir liste dosyasını oku: yorum (#/;//) ve boş satırları atla, küçük harfe
    indir, baştaki/sondaki boşlukları kırp. Dosya yoksa boş liste."""
    out: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s[0] in "#;/":
                continue
            out.append(s.split()[0].lower())
    except (FileNotFoundError, OSError, ValueError):
        pass
    return out


def denylist_active() -> bool:
    """Çalışma anı denylist'inde en az bir alan var mı? (motor --hostlist-exclude'u
    yalnızca o zaman ekler; boşken davranış birebir eskisi gibi kalır)."""
    return bool(load_list(active_denylist_file()))


# hostlist'te bu belirteçlerden biri varsa "TÜM SİTELER" modu: DPI desync hostlist
# ile sınırlanmaz, tüm TLS/QUIC akışlarına uygulanır (denylist yine hariç tutar).
ALL_SITES_TOKENS = {"all", "all=1", "*"}


def all_sites_active() -> bool:
    """hostlist'te ALL=1 / all / * belirteci var mı? (tüm sitelere DPI uygula)."""
    return any(x in ALL_SITES_TOKENS for x in load_list(active_hostlist_file()))


def seed_user_lists() -> None:
    """Düzenlenebilir kullanıcı listelerini ilk açılışta oluştur. hostlist, gömülü
    şablondan (discord/roblox) + açıklama başlığıyla tohumlanır; denylist boş (yalnız
    başlık). Mevcut dosyaların ÜZERİNE YAZILMAZ (kullanıcı düzenlemeleri korunur)."""
    uh = user_hostlist_file()
    uh.parent.mkdir(parents=True, exist_ok=True)
    if not uh.exists():
        try:
            tmpl = hostlist_file().read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            tmpl = ""
        uh.write_text(HOSTLIST_HEADER + tmpl, encoding="utf-8")
    dl = denylist_file()
    if not dl.exists():
        dl.write_text(DENYLIST_HEADER, encoding="utf-8")


LUA_FILES = ["zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"]


def active_lua_dir() -> Path:
    """Çalışma anı lua kopyası (/run/byerte/lua). nfqws2 Lua'yı root olarak
    çalıştırmaz; yetki düşürdükten sonra yükler — dosyalar nobody'ce okunabilir
    olmalı. engine.prepare_runtime kaynaktan kopyalar."""
    return runtime_dir() / "lua"


def lua_init_args() -> list[str]:
    """nfqws2/winws2 için lua kütüphanelerini doğru sırada yükleyen argümanlar."""
    d = active_lua_dir()
    return [f"--lua-init=@{arg_path(d / f)}" for f in LUA_FILES]
