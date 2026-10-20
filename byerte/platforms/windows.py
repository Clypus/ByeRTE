"""Windows arka ucu: UAC + WinDivert + winws2, ayrık süreç + Görev Zamanlayıcı.

Neden SCM servisi değil? (1) pywin32 bağımlılığı olmadan düzgün bir servis
yazmak ağır ve test edilemez; (2) asıl önemlisi: WinDivert yakalaması süreç
ölünce otomatik durur — Linux'taki "kapatınca nft tablosunu sil" garantisine
Windows'ta gerek yoktur. Motor sert öldürülse (taskkill /F) bile tüm WinDivert
handle'ları işletim sistemince kapatılır → DNS ve DPI yakalaması anında biter,
internet normale döner. Açılışta başlatma için Görev Zamanlayıcı (schtasks)
kullanılır: en yüksek ayrıcalıkla, oturum açılışında, UAC istemi olmadan.
"""

from __future__ import annotations

import subprocess
import sys
import time

from .. import config, paths, strategies
from ..win import winutil

NAME = "windows"
ENGINE_LABEL = "WinDivert + winws2"
RESIDUAL_WARNING = "uyarı: winws2 hâlâ çalışıyor, sonlandırılıyor..."

TASK_NAME = "ByeRTE"
_NOWIN = {"creationflags": winutil.CREATE_NO_WINDOW}


# --- Konsol / yetki ----------------------------------------------------------

def setup_console() -> bool:
    return winutil.setup_console()


def is_admin() -> bool:
    return winutil.is_admin()


def ensure_admin(argv: list[str]) -> None:
    winutil.ensure_admin(argv)


# --- Süreç yardımcıları ------------------------------------------------------

def _pidfile():
    return paths.runtime_dir() / "byerte.pid"


def _engine_spawn_cmd() -> list[str]:
    """Arka plan motorunu başlatan komut. Donmuş exe'de kardeş byerte.exe'nin gizli
    `_engine` alt komutu, dev'de `python -m byerte.win.engine`."""
    if getattr(sys, "frozen", False):
        import pathlib
        cli = pathlib.Path(sys.executable).with_name("byerte.exe")
        return [str(cli) if cli.exists() else sys.executable, "_engine"]
    return [sys.executable, "-m", "byerte.win.engine"]


def service_installed() -> bool:
    # Windows'ta açılış mekanizması (schtasks) her zaman kullanılabilir; "servis"
    # satırı motor sürecini temsil eder.
    return True


def service_active() -> bool:
    """Motor (byerte.win.engine) süreci canlı mı?"""
    try:
        pid = int(_pidfile().read_text())
    except (FileNotFoundError, ValueError):
        return False
    return winutil.pid_alive(pid)


def service_start() -> None:
    """Motoru ayrık, penceresiz arka plan sürecinde başlat. (ensure_admin zaten
    çalıştığından buradayken yöneticiyiz; ikinci UAC gerekmez.)"""
    force_cleanup()  # olası artık winws2/motor süreçlerini temizle (dup-check çakışması olmasın)
    with open(paths.runtime_dir() / "engine.log", "ab") as logf:  # çocuk kendi kopyasını alır
        p = subprocess.Popen(
            _engine_spawn_cmd(),
            stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
            creationflags=(winutil.DETACHED_PROCESS | winutil.CREATE_NEW_PROCESS_GROUP
                           | winutil.CREATE_NO_WINDOW),
            close_fds=True,
        )
    _pidfile().write_text(str(p.pid))


def service_stop() -> None:
    """Motor süreç AĞACINI öldür (winws2 çocuğu dahil) → tüm WinDivert handle'ları
    kapanır → sistem normale döner."""
    try:
        pid = int(_pidfile().read_text())
        winutil.taskkill(pid)       # /T: ağaç → winws2 de ölür
        for _ in range(20):
            if not winutil.pid_alive(pid):
                break
            time.sleep(0.2)
    except (FileNotFoundError, ValueError):
        pass
    _pidfile().unlink(missing_ok=True)
    force_cleanup()                 # backstop: artık winws2 kalmasın
    config.write_state({"running": False})


def engine_present() -> bool:
    """winws2.exe çalışıyor mu? (nft_present'in karşılığı: 'bypass gerçekten açık mı')."""
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq winws2.exe", "/NH"],
                       capture_output=True, text=True, **_NOWIN)
    return "winws2.exe" in (r.stdout or "")


def force_cleanup() -> None:
    """Artık süreçleri zorla temizle. İdempotent (bir şey yoksa sessiz geçer)."""
    subprocess.run(["taskkill", "/IM", "winws2.exe", "/T", "/F"],
                   capture_output=True, **_NOWIN)
    try:
        pid = int(_pidfile().read_text())
        if winutil.pid_alive(pid):
            winutil.taskkill(pid)
    except (FileNotFoundError, ValueError):
        pass


# --- Açılışta başlatma (Görev Zamanlayıcı) -----------------------------------

def _task_tr() -> str:
    """schtasks /TR için komut dizesi: oturum açılışında `byerte aç` çalıştırır."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" aç'
    import byerte, os  # noqa: E401
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(byerte.__file__)))
    # dev: PYTHONPATH'i taşıyarak python -m byerte aç
    return f'cmd /c "set "PYTHONPATH={pkg_parent}" && "{sys.executable}" -m byerte aç"'


def autostart_enabled() -> bool | None:
    r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                       capture_output=True, **_NOWIN)
    return r.returncode == 0


def set_autostart(on: bool) -> None:
    if on:
        subprocess.run(["schtasks", "/Create", "/TN", TASK_NAME, "/SC", "ONLOGON",
                        "/RL", "HIGHEST", "/F", "/TR", _task_tr()],
                       check=True, capture_output=True, **_NOWIN)
    else:
        subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                       capture_output=True, **_NOWIN)


def service_missing_hint() -> str:
    return "açılış görevi oluşturulamadı (yönetici gerekir)."


# --- Günlük / durum ----------------------------------------------------------

def follow_log() -> int:
    """Günlüğü izle. Windows'ta journalctl yok; winws2.log + engine.log'u izleriz."""
    logs = [paths.runtime_dir() / "winws2.log", paths.runtime_dir() / "engine.log"]
    logs = [p for p in logs if p.exists()]
    if not logs:
        print("günlük yok.")
        return 1
    target = max(logs, key=lambda p: p.stat().st_mtime)
    print(f"--- {target} (çıkmak için Ctrl+C) ---")
    with open(target, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
        for line in lines[-50:]:
            sys.stdout.write(line)
        try:
            while True:
                where = f.tell()
                line = f.readline()
                if line:
                    sys.stdout.write(line)
                else:
                    time.sleep(0.5)
                    f.seek(where)
        except KeyboardInterrupt:
            return 0


def log_hint() -> str:
    return f"  ayrıntı:  type \"{paths.runtime_dir() / 'winws2.log'}\""


def status_rows() -> list[tuple[str, str, bool]]:
    # tasklist yetkisiz çalışır; yanıltıcı değil.
    present = engine_present()
    return [("winws2", "çalışıyor" if present else "yok", present)]


# --- Tarama ortamı -----------------------------------------------------------

class ProbeEnv:
    """`byerte tara` için: WinDivert DNS yönlendirmesi + DoH köprüsü BİR KEZ kurulur,
    her strateji için yalnızca winws2 değiştirilir. Çıkışta tam geri alınır. (Yönetici
    gerekir; cmd_tara ensure_admin ile sağlar.)"""

    settle = 1.5  # winws2 + WinDivert biraz daha yavaş bağlanır

    def __enter__(self) -> "ProbeEnv":
        from ..dns import DnsBridge, DohResolver
        from ..win.dnsdivert import DnsDivert
        from ..win.engine import prepare_runtime
        force_cleanup()
        prepare_runtime()
        resolver = DohResolver()
        self._bridge = DnsBridge()
        self._bridge.resolver = resolver
        self._bridge.start()
        self._divert = DnsDivert(resolver)
        self._divert.start()
        return self

    def spawn(self, strategy: str) -> subprocess.Popen:
        argv = strategies.build_argv(strategy, with_exclude=paths.denylist_active(),
                                     all_sites=paths.all_sites_active())
        # Çocuk süreç handle'ın kendi kopyasını alır; ebeveynin kopyası hemen kapanır
        # (aksi halde her strateji denemesinde bir dosya handle'ı sızar).
        with open(paths.runtime_dir() / "winws2.log", "ab") as logf:
            return subprocess.Popen(argv, stdout=logf, stderr=logf,
                                    creationflags=winutil.CREATE_NO_WINDOW,
                                    cwd=str(paths.winws2_dir()))

    def kill(self, proc: subprocess.Popen) -> None:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=4)
            except Exception:  # noqa: BLE001
                try:
                    winutil.taskkill(proc.pid)
                except Exception:  # noqa: BLE001
                    pass

    def __exit__(self, *exc) -> None:
        try:
            self._divert.stop()
        finally:
            self._bridge.stop()
