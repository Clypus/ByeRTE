"""Windows motoru: winws2.exe + WinDivert DNS yönlendirmesi + DoH köprüsü yaşam döngüsü.

Linux engine.Engine'in karşılığı. Tasarım ilkeleri aynı kalır:
- Kalıcı sistem durumu DEĞİŞMEZ. Tüm yakalama handle tabanlıdır (WinDivert): süreç
  nasıl biterse bitsin (normal, çökme, taskkill /F) handle kapanır ve yakalama
  anında durur → internet/DNS normale döner. Linux'taki "nft tablo sızıntısı"nın
  karşılığı Windows'ta YOKTUR.
- winws2, engine'in ÇOCUK sürecidir. Düzgün durdurmada teardown onu öldürür; sert
  öldürmede servis/CLI `taskkill /T` ile süreç AĞACINI öldürür (winws2 dahil).
- DNS yönlendirmesi (:53) ile winws2 aynı süreçte yaşar; biri giderse ikisi de gider.

root/SYSTEM olarak çalışır: WinDivert sürücüsü ve winws2 manifesti yönetici ister.
winws2 başlatıldıktan sonra kendini Low integrity + job sandbox'a indirir.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time

from .. import config, paths, strategies, vpn
from ..dns import DnsBridge, DohResolver
from . import winutil

log = logging.getLogger("byerte.engine")
VPN_POLL = 3.0  # saniye: VPN durumunu bu aralıkla yokla (varsa yakalamayı duraklat)


# --- Çalışma anı hazırlığı ---------------------------------------------------

def prepare_runtime() -> None:
    """hostlist + denylist + lua dosyalarını çalışma dizinine (%ProgramData%\\ByeRTE\\run)
    kopyala. Kullanıcı listeleri (config dizini) ilk açılışta tohumlanır.

    Linux'tan farkı: nobody'ye chown YOK. winws2 autohostlist dosyasına Low integrity
    etiketi kendisi koyar (ensure_file_access), böylece sandbox'a indikten sonra da
    yazabilir. Dosyaların admin-yazılabilir bir yerde olması yeter."""
    d = paths.runtime_dir()
    d.mkdir(parents=True, exist_ok=True)
    paths.seed_user_lists()
    # Listeler %ProgramData%'da; yükseltilmiş motor oluşturursa SYSTEM/admin'e ait olur.
    # Normal kullanıcının (GUI/notepad) düzenleyebilmesi için Users'a değiştirme izni ver.
    for f in (paths.user_hostlist_file(), paths.denylist_file()):
        try:
            subprocess.run(["icacls", str(f), "/grant", "*S-1-5-32-545:(M)"],
                           capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
        except OSError:
            pass

    # Kullanıcı hostlist'ini runtime'a kopyala (motor buradan okur)
    paths.active_hostlist_file().write_text(
        paths.user_hostlist_file().read_text(encoding="utf-8"), encoding="utf-8")
    paths.active_denylist_file().write_text(
        paths.denylist_file().read_text(encoding="utf-8"), encoding="utf-8")

    lua_dst = paths.active_lua_dir()
    lua_dst.mkdir(exist_ok=True)
    for name in paths.LUA_FILES:
        (lua_dst / name).write_bytes((paths.lua_dir() / name).read_bytes())

    f = paths.autohostlist_file()
    if not f.exists():
        f.write_text("", encoding="utf-8")


def flush_dns() -> None:
    """Windows DNS Client önbelleğini temizle (ipconfig /flushdns).

    KRİTİK: Bypass açılmadan ÖNCE cache'lenmiş zehirli kayıtlar (ör. TT'de
    apis.roblox.com → sinkhole 195.175.254.2) aksi halde TTL dolana dek kalır;
    çözümleyici bunları önbellekten döndürdüğü için WinDivert :53 yakalaması ve
    DoH köprüsü devreye hiç girmez → 'Experiences failed to load'. Açarken (yeni
    sorgular temiz gelsin) ve kapatırken (eski kayıtlar kalmasın) temizliyoruz.
    Tarayıcıların KENDİ iç önbelleği ayrıdır — sayfayı yeniden yükleyin."""
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                       creationflags=winutil.CREATE_NO_WINDOW)
    except Exception:  # noqa: BLE001
        pass


# --- winws2 süreci -----------------------------------------------------------

class WinEngine:
    def __init__(self, strategy: str, wan_iface: str | None = None,
                 stop_event: threading.Event | None = None):
        self.strategy = strategies.resolve_strategy(strategy)
        self.wan_iface = wan_iface  # Windows'ta kullanılmaz (WinDivert tüm arayüzler)
        self.proc: subprocess.Popen | None = None
        self.bridge: DnsBridge | None = None
        self.divert = None  # byerte.win.dnsdivert.DnsDivert (tembel import)
        self._resolver: DohResolver | None = None
        self._started = 0
        self._vpn_flag = False                  # VPN monitör thread'i günceller
        self._vpn_thread: threading.Thread | None = None
        self._stop = stop_event or threading.Event()

    def stop(self) -> None:
        """Dışarıdan düzgün durdurma (servis kontrol handler'ı çağırır)."""
        self._stop.set()

    def _start_winws(self) -> None:
        argv = strategies.build_argv(self.strategy, with_exclude=paths.denylist_active(),
                                     all_sites=paths.all_sites_active())
        with open(paths.runtime_dir() / "winws2.log", "ab") as logf:  # çocuk kendi kopyasını alır
            self.proc = subprocess.Popen(
                argv, stdout=logf, stderr=logf,
                creationflags=winutil.CREATE_NO_WINDOW,
                cwd=str(paths.winws2_dir()),  # cygwin1.dll ve WinDivert.dll yanında
            )

    # --- VPN duraklatma: yakalamayı tekrar tekrar aç/kapat (köprü hep ayakta) ---

    def _start_capture(self) -> None:
        """DNS yönlendirmesi (:53) + winws2'yi (yeniden) kur; cache'i temizle."""
        from .dnsdivert import DnsDivert  # tembel: WinDivert yalnızca gerekince yüklensin
        self.divert = DnsDivert(self._resolver)
        self.divert.start()
        self._start_winws()
        flush_dns()  # bypass öncesi cache'lenmiş zehirli kayıtları at → temiz çözüm

    def _stop_capture(self) -> None:
        """Yakalamayı durdur: winws2 + :53 yönlendirmesi → DNS/trafik normale (VPN serbest)."""
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    winutil.taskkill(self.proc.pid)
                except Exception:  # noqa: BLE001
                    pass
        self.proc = None
        if self.divert is not None:
            try:
                self.divert.stop()
            except Exception:  # noqa: BLE001
                pass
            self.divert = None
        flush_dns()  # duraklatınca eski (DoH'tan gelen) kayıtlar kalmasın

    def _write_running_state(self, paused: bool) -> None:
        config.write_state({
            "running": True,
            "pid": os.getpid(),
            "engine_pid": self.proc.pid if self.proc else None,
            "strategy": self.strategy,
            "platform": "windows",
            "started": self._started,
            "paused_for_vpn": paused,
        })

    def _vpn_monitor(self) -> None:
        """Arka planda VPN durumunu yoklar. Algılama (PowerShell) ~2 sn sürebilir;
        ana döngüyü bloke etmesin diye ayrı thread. run() bu bayrağı okur."""
        while not self._stop.is_set():
            if self._stop.wait(VPN_POLL):
                break
            try:
                self._vpn_flag = vpn.vpn_active()
            except Exception:  # noqa: BLE001
                pass

    def _teardown(self) -> None:
        # Sıra: önce winws2 (DPI bypass'ı durdur), sonra divert (DNS normale), sonra köprü.
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    winutil.taskkill(self.proc.pid)
                except Exception:  # noqa: BLE001
                    pass
        if self.divert is not None:
            try:
                self.divert.stop()
            except Exception:  # noqa: BLE001
                pass
        if self.bridge is not None:
            try:
                self.bridge.stop()
            except Exception:  # noqa: BLE001
                pass
        flush_dns()  # kapatınca eski (DoH'tan gelen) kayıtlar kalmasın

    def run(self) -> int:
        """Her şeyi kur, bloke ol, çıkışta GARANTİ teardown. Dönüş = çıkış kodu."""
        prepare_runtime()

        def _sig(_signum, _frame):
            self._stop.set()
        # Dev konsolunda Ctrl+C / Ctrl+Break düzgün kapatsın (servis kendi event'ini kullanır)
        for sig in (signal.SIGINT, getattr(signal, "SIGBREAK", None), signal.SIGTERM):
            if sig is not None:
                try:
                    signal.signal(sig, _sig)
                except (ValueError, OSError):
                    pass

        try:
            self._started = int(time.time())
            self._resolver = DohResolver()
            self.bridge = DnsBridge()           # 127.0.0.1:15353 — yalnızca sağlık kontrolü
            self.bridge.resolver = self._resolver
            self.bridge.start()
            # VPN açıksa yakalamayı başlatma: çalışan VPN zaten DPI'yı aşar; devrede
            # olursak VPN'in DNS'ini kaçırırız ve kill-switch DoH'u engelleyince her
            # şey tıkanır. VPN kapanınca monitör aşağıda yakalamayı başlatır.
            self._vpn_flag = vpn.vpn_active()       # başlangıç durumu (bir kerelik, ~2 sn)
            paused = self._vpn_flag
            if paused:
                log.info("VPN algılandı; ByeRTE duraklatıldı (yakalama kapalı)")
            else:
                self._start_capture()
            self._write_running_state(paused)
            self._vpn_thread = threading.Thread(target=self._vpn_monitor,
                                                 name="byerte-vpnmon", daemon=True)
            self._vpn_thread.start()

            # İkinci temizlik: yönlendirme açılmadan HEMEN önce ISS'ye giden bir sorgunun
            # (zehirli) cevabı, ilk flush'tan SONRA gelip önbelleğe yazılabilir (TT'de TTL
            # ~1 saat → ör. Discord güncelleme ekranında takılır). Birkaç sn sonra bir kez
            # daha temizleyerek bu yarış penceresini kapatırız.
            reflush_at = 0.0 if paused else time.monotonic() + 5.0
            while not self._stop.is_set():
                now = time.monotonic()
                active = self._vpn_flag             # monitör thread'inin yayımladığı bayrak
                if active and not paused:
                    log.info("VPN algılandı; ByeRTE duraklatılıyor")
                    self._stop_capture()
                    paused = True
                    reflush_at = 0.0
                    self._write_running_state(True)
                elif not active and paused:
                    log.info("VPN kapandı; ByeRTE sürdürülüyor")
                    self._start_capture()
                    paused = False
                    reflush_at = now + 5.0
                    self._write_running_state(False)
                # winws2 çöktü → çık (yalnızca etkinken anlamlı). Servis yeniden başlatır.
                if not paused and self.proc and self.proc.poll() is not None:
                    log.error("winws2 beklenmedik şekilde çıktı (kod %s)", self.proc.returncode)
                    return 1
                if reflush_at and now >= reflush_at:
                    flush_dns()
                    reflush_at = 0.0
                time.sleep(0.5)
            return 0
        finally:
            self._teardown()
            config.write_state({"running": False})


def run_service(strategy: str | None = None, wan_iface: str | None = None,
                stop_event: threading.Event | None = None) -> int:
    """Motoru çalıştır. Argüman verilmezse yapılandırmadan okur."""
    cfg = config.load()
    strategy = strategy or cfg.get("strategy") or strategies.DEFAULT_STRATEGY
    return WinEngine(strategy, wan_iface, stop_event).run()


def _setup_logging() -> None:
    """Ayrık motor sürecinin günlüğü UTF-8 olsun (aksi halde Windows konsolunda/engine.log'da
    Türkçe karakterler bozulur — fork A'nın notu)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(name)s %(message)s")


if __name__ == "__main__":
    # Dahili: `python -m byerte.win.engine [strateji]` (dev arka plan süreci)
    _setup_logging()
    strat = sys.argv[1] if len(sys.argv) > 1 else None
    raise SystemExit(run_service(strat))
