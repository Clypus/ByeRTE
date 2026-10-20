"""Windows yardımcıları: yönetici kontrolü, UAC ile yeniden başlatma, konsol kurulumu.

Bu modül yalnızca Windows'ta içe aktarılır. Linux'taki `os.geteuid()==0` + `sudo
execvp` mantığının karşılığıdır (bkz. byerte.platforms.linux._ensure_root).
"""

from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys
from ctypes import wintypes

log = logging.getLogger("byerte.win")

ERROR_CANCELLED = 1223  # kullanıcı UAC istemini reddetti
SW_HIDE = 0
SW_SHOWNORMAL = 1
SEE_MASK_NOCLOSEPROCESS = 0x00000040
# Ayrık arka plan süreci (dev motoru): kendi süreç grubu, konsol bağı yok.
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000


# --- Yönetici (admin) --------------------------------------------------------

def is_admin() -> bool:
    """Süreç yükseltilmiş (elevated) mi? Linux'taki euid==0 karşılığı."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def self_argv(args: list[str]) -> tuple[str, list[str]]:
    """byerte CLI'ını yeniden çağırmak için (exe, argümanlar). Donmuş (PyInstaller)
    derlemede HER ZAMAN kardeş konsol exe'si byerte.exe; dev'de `python -m byerte`.

    Kardeş çözümü kritik: GUI (byerte-gui.exe) bir eylemi yetkiyle çalıştırırken
    sys.executable kendisidir; onu çalıştırmak 'aç' yerine GUI'yi açardı. Hep
    byerte.exe'ye yönlendiririz."""
    if getattr(sys, "frozen", False):
        import pathlib
        cli = pathlib.Path(sys.executable).with_name("byerte.exe")
        exe = str(cli) if cli.exists() else sys.executable  # tek-exe/portable yedeği
        return exe, list(args)
    # PYTHONPATH'i koru ki yükseltilmiş süreç de byerte paketini bulsun
    import byerte
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(byerte.__file__)))
    os.environ["PYTHONPATH"] = pkg_parent + os.pathsep + os.environ.get("PYTHONPATH", "")
    return sys.executable, ["-m", "byerte", *args]


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", ctypes.c_ulong),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def _shell_execute_runas(exe: str, params: str, show: int) -> int | None:
    """ShellExecuteEx "runas" ile yükseltilmiş süreç başlat. Süreç handle'ı döndürür
    (SEE_MASK_NOCLOSEPROCESS). Reddedilir/başarısız olursa None."""
    sei = _SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = exe
    sei.lpParameters = params
    sei.nShow = show
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        if err == ERROR_CANCELLED:
            log.info("UAC istemi reddedildi")
        else:
            log.error("ShellExecuteEx(runas) başarısız: %s", err)
        return None
    return sei.hProcess


def run_byerte_elevated(args: list[str], show_window: bool = False) -> int:
    """byerte'yi verilen argümanlarla yükseltilmiş (UAC) çalıştır, bitmesini bekle,
    çıkış kodunu döndür. UAC reddedilir/başarısız olursa 126 (pkexec iptal kodu).

    show_window: True ise yükseltilmiş sürecin konsolu görünür (CLI). False ise gizli
    (GUI eylemleri; GUI durumu kendi yoklamasıyla günceller)."""
    exe, argv = self_argv(args)
    params = subprocess.list2cmdline(argv)
    h = _shell_execute_runas(exe, params, SW_SHOWNORMAL if show_window else SW_HIDE)
    if h is None:
        return 126
    try:
        ctypes.windll.kernel32.WaitForSingleObject(h, 0xFFFFFFFF)
        code = wintypes.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        return int(code.value)
    finally:
        ctypes.windll.kernel32.CloseHandle(h)


PAUSE_FLAG = "--_pause"  # gizli: yükseltilmiş konsol çıkışta Enter beklesin


def relaunch_elevated_wait(args: list[str]) -> int:
    """CLI kendini yükseltirken kullanır: yükseltilmiş kopyanın konsolu görünür
    (Windows'ta UAC her zaman AYRI bir konsol açar; çıktı o pencerede akar).
    PAUSE_FLAG eklenir: aksi halde o pencere iş biter bitmez kapanır ve çıktı
    (ör. `tara` sonuçları) okunamadan kaybolur. GUI'nin gizli yolu bunu EKLEMEZ."""
    return run_byerte_elevated([*args, PAUSE_FLAG], show_window=True)


def ensure_admin(args: list[str]) -> None:
    """Yükseltilmiş değilsek, komutu UAC ile yeniden çalıştır ve o kopyanın çıkış
    koduyla SON VER (bu fonksiyon o durumda DÖNMEZ). Linux _ensure_root ile aynı
    sözleşme: döndüyse artık yöneticiyiz."""
    if is_admin():
        return
    print("yetki gerekiyor, Yönetici olarak yeniden çalıştırılıyor (UAC)...")
    raise SystemExit(relaunch_elevated_wait(args))


# --- Konsol (ANSI renk + UTF-8) ---------------------------------------------

def setup_console() -> bool:
    """Windows konsolunda ANSI (VT) işleme ve UTF-8 çıktısını aç. Renk kullanılabilir
    mi onu döndürür. Yönlendirilmiş (pipe) çıktı ya da desteklenmeyen konsol → False."""
    ok = False
    try:
        k = ctypes.windll.kernel32
        for handle_id in (-11, -12):  # STDOUT, STDERR
            h = k.GetStdHandle(handle_id)
            if h and h != wintypes.HANDLE(-1).value:
                mode = wintypes.DWORD()
                if k.GetConsoleMode(h, ctypes.byref(mode)):
                    # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4
                    k.SetConsoleMode(h, mode.value | 0x4)
                    ok = True
        k.SetConsoleOutputCP(65001)
    except Exception:  # noqa: BLE001
        ok = False
    # Python akışlarını UTF-8'e al (✓/✗ ve Türkçe karakterler için)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass
    return ok and sys.stdout.isatty()


# --- Süreç yardımcıları ------------------------------------------------------

def pid_alive(pid: int) -> bool:
    """PID canlı mı? (OpenProcess + çıkış kodu STILL_ACTIVE)."""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k = ctypes.windll.kernel32
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = wintypes.DWORD()
        if k.GetExitCodeProcess(h, ctypes.byref(code)):
            return code.value == 259  # STILL_ACTIVE
        return False
    finally:
        k.CloseHandle(h)


def taskkill(pid: int) -> None:
    """PID'i ağaç olarak sonlandır (taskkill /T). İdempotent."""
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)
