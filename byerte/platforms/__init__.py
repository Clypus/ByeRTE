"""Platform arka ucu: CLI / GUI / tarama'nın işletim sistemine özel işleri.

cli.py ve probe.py yalnızca bu arayüzü kullanır; Linux davranışı platforms/linux.py,
Windows davranışı platforms/windows.py içindedir. Her arka uç modülü şunları sağlar:

    NAME: str                         # "linux" | "windows"
    ENGINE_LABEL: str                 # "nftables + nfqws2" | "WinDivert + winws2"
    RESIDUAL_WARNING: str             # kapat sonrası artık kalırsa basılan uyarı

    setup_console() -> bool           # renk (ANSI) kullanılabilir mi; Windows'ta VT + UTF-8 çıktı
    is_admin() -> bool
    ensure_admin(argv: list[str]) -> None
        # Yetkili değilsek yetkili olarak yeniden çalıştır (Linux: sudo exec,
        # Windows: UAC). Yeniden çalıştırma olursa bu çağrı DÖNMEZ (süreç, yetkili
        # kopyanın çıkış koduyla biter).

    service_installed() -> bool       # systemd birimi / Windows servisi kurulu mu
    service_active() -> bool          # motor çalışıyor mu (servis ya da dev arka plan süreci)
    service_start() -> None
    service_stop() -> None            # durdur + her hâlükârda backstop temizlik
    engine_present() -> bool          # Linux: nft tablosu var; Windows: winws2 çalışıyor
    force_cleanup() -> None           # artığı zorla temizle (nft delete / winws2 kill)

    autostart_enabled() -> bool | None   # None = servis kurulu değil
    set_autostart(on: bool) -> None
    service_missing_hint() -> str     # servis kurulu değilken basılan açıklama

    follow_log() -> int               # günlüğü izle (journalctl/tail ya da Windows eşleniği)
    log_hint() -> str                 # "  ayrıntı:  ..." satırı
    status_rows() -> list[tuple[str, str, bool]]
        # `durum` için ek satırlar: (etiket, değer, iyi_mi). Yetki gerekiyorsa ve
        # yoksa boş liste (yanıltıcı bilgi gösterme).

    class ProbeEnv:                   # `tara` için bağlam yöneticisi
        settle: float                 # motor başlatıldıktan sonra beklenecek sn
        def __enter__(self) -> "ProbeEnv"   # yakalama + DoH köprüsü kurulur
        def spawn(self, strategy: str) -> subprocess.Popen   # stratejiyle motoru başlat
        def kill(self, proc) -> None        # motoru durdur (terminate → bekle → kill)
        def __exit__(...)                   # her şey tam olarak geri alınır
"""

from __future__ import annotations

import sys


def current():
    """Bu platformun arka uç modülü (tembel import: Windows'ta Linux'a özgü
    modüller, Linux'ta ctypes.windll yüklenmez)."""
    if sys.platform == "win32":
        from . import windows as mod
    else:
        from . import linux as mod
    return mod
