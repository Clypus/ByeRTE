"""Linux arka ucu: systemd/sudo + nftables. Davranış, taşımadan önceki cli.py ile
BİREBİR aynıdır (yalnızca başka bir modüle taşındı).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from .. import engine, paths, strategies
from ..dns import DnsBridge

NAME = "linux"
ENGINE_LABEL = "nftables + nfqws2"
RESIDUAL_WARNING = "uyarı: nftables tablosu hâlâ var, siliniyor..."

UNIT = "byerte.service"


# --- Konsol ------------------------------------------------------------------

def setup_console() -> bool:
    return sys.stdout.isatty()


# --- Yetki -------------------------------------------------------------------

def is_admin() -> bool:
    return os.geteuid() == 0


def ensure_admin(argv: list[str]) -> None:
    """Kök değilsek sudo ile yeniden çalıştır (paket yolunu koruyarak)."""
    if os.geteuid() == 0:
        return
    print("yetki gerekiyor, sudo ile yeniden çalıştırılıyor...")
    import byerte
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(byerte.__file__)))
    os.execvp("sudo", ["sudo", "env", f"PYTHONPATH={pkg_parent}",
                        sys.executable, "-m", "byerte", *argv])


# --- Servis ------------------------------------------------------------------

def _pidfile():
    return paths.runtime_dir() / "byerte.pid"


def service_installed() -> bool:
    if os.path.exists(f"/etc/systemd/system/{UNIT}"):
        return True
    r = subprocess.run(["systemctl", "cat", UNIT], capture_output=True)
    return r.returncode == 0


def service_active() -> bool:
    if service_installed():
        r = subprocess.run(["systemctl", "is-active", "--quiet", UNIT])
        return r.returncode == 0
    # dev: pidfile + canlı süreç
    try:
        pid = int(_pidfile().read_text())
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return False


def service_start() -> None:
    if service_installed():
        subprocess.run(["systemctl", "start", UNIT], check=True)
        return
    # dev: motoru ayrık arka plan sürecinde başlat
    logf = open(paths.runtime_dir() / "engine.log", "ab")
    p = subprocess.Popen(
        [sys.executable, "-m", "byerte.engine"],
        stdout=logf, stderr=logf, start_new_session=True,
    )
    _pidfile().write_text(str(p.pid))


def service_stop() -> None:
    if service_installed():
        subprocess.run(["systemctl", "stop", UNIT])
    else:
        try:
            pid = int(_pidfile().read_text())
            os.kill(pid, 15)  # SIGTERM → engine finally teardown
            for _ in range(20):
                try:
                    os.kill(pid, 0); time.sleep(0.2)
                except ProcessLookupError:
                    break
        except (FileNotFoundError, ValueError, ProcessLookupError):
            pass
        _pidfile().unlink(missing_ok=True)
    engine.nft_delete()  # her hâlükârda backstop: tablo gitsin


def engine_present() -> bool:
    return engine.nft_present()


def force_cleanup() -> None:
    engine.nft_delete()


# --- Açılışta başlatma -------------------------------------------------------

def autostart_enabled() -> bool | None:
    if not service_installed():
        return None
    return subprocess.run(["systemctl", "is-enabled", "--quiet", UNIT]).returncode == 0


def set_autostart(on: bool) -> None:
    if on:
        subprocess.run(["systemctl", "enable", UNIT], check=True)
    else:
        subprocess.run(["systemctl", "disable", UNIT])


def service_missing_hint() -> str:
    return "systemd birimi kurulu değil (install.sh ile kurun)."


# --- Günlük / durum ----------------------------------------------------------

def follow_log() -> int:
    if service_installed():
        os.execvp("journalctl", ["journalctl", "-u", UNIT, "-n", "50", "-f"])
    else:
        log = paths.runtime_dir() / "engine.log"
        if log.exists():
            os.execvp("tail", ["tail", "-n", "50", "-f", str(log)])
        print("günlük yok.")
        return 1
    return 0


def log_hint() -> str:
    if service_installed():
        return "  ayrıntı:  journalctl -u byerte -n 30"
    return f"  ayrıntı:  cat {paths.runtime_dir() / 'engine.log'}"


def status_rows() -> list[tuple[str, str, bool]]:
    """nft/nfqws yalnızca root okuyabilir; köksüzken yanıltıcı göstermeyelim."""
    if os.geteuid() != 0:
        return []
    nfqws = subprocess.run(["pgrep", "-x", "nfqws2"], capture_output=True).returncode == 0
    return [
        ("nftables", "yüklü" if engine.nft_present() else "yok", engine.nft_present()),
        ("nfqws2", "çalışıyor" if nfqws else "yok", nfqws),
    ]


# --- Tarama ortamı -----------------------------------------------------------

class ProbeEnv:
    """`byerte tara` için: nftables tablosu + DoH köprüsü BİR KEZ kurulur, her
    strateji için yalnızca nfqws2 değiştirilir. Çıkışta tam geri alınır."""

    settle = 1.2  # nfqws2 kuyruğa bağlansın

    def __enter__(self) -> "ProbeEnv":
        from .. import isp
        wan = isp.detect_wan_iface()
        engine.load_modules()
        engine.prepare_runtime()
        self._bridge = DnsBridge()
        self._bridge.start()
        engine.nft_apply(wan)
        return self

    def spawn(self, strategy: str) -> subprocess.Popen:
        argv = strategies.build_argv(strategy, with_exclude=paths.denylist_active(),
                                     all_sites=paths.all_sites_active())
        return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def kill(self, proc: subprocess.Popen) -> None:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()

    def __exit__(self, *exc) -> None:
        engine.nft_delete()
        self._bridge.stop()
