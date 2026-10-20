#!/usr/bin/env python3
"""ByeRTE Windows derleyici. Çalıştır:  python packaging/windows/build.py [--out DİZİN]

Önce gömülü winws2/WinDivert/lua ikililerini SHA-256 ile doğrular (data/SHA256SUMS),
sonra PyInstaller'ı spec ile çağırır. Çıktı: dist/ByeRTE/ (byerte.exe + byerte-gui.exe
+ data/). Kurulum için packaging/windows/install.ps1, taşınabilir için klasörü
olduğu gibi kopyalayıp byerte-gui.exe'yi çalıştırın.

--out DİZİN: çıktıyı DİZİN/ByeRTE'ye yazar. dist/ByeRTE'den ByeRTE çalışıyorsa
(exe + WinDivert sürücüsü kilitli) onu durdurmadan ayrı bir release derlemesi için.

PyInstaller yoksa:  pip install pyinstaller
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DATA = REPO / "data"
SPEC = REPO / "packaging" / "windows" / "byerte.spec"
DIST_ROOT = REPO / "dist"
if "--out" in sys.argv[1:-1]:  # ayrı çıktı dizini (bkz. modül belgesi)
    DIST_ROOT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
DIST = DIST_ROOT / "ByeRTE"
_NOWIN = 0x08000000  # CREATE_NO_WINDOW


def _locked(p: Path) -> bool:
    """Dosya başka bir süreç/sürücü tarafından kilitli mi (üzerine yazılamaz mı)?"""
    if not p.exists():
        return False
    try:
        fd = os.open(str(p), os.O_RDWR)
        os.close(fd)
        return False
    except OSError:
        return True


def release_locks() -> None:
    """Yeniden derlemeden önce kilitleri aç: çalışan motoru + winws2'yi durdur,
    WinDivert sürücüsünü indir. winws2 çalışırken byerte.exe'yi, sürücü yüklüyken
    WinDivert64.sys'i kimse (admin dahil) üzerine yazamaz — çünkü bunlar
    'izin' değil 'kullanımda' kilitleridir."""
    import subprocess
    # çalışan motor (byerte.exe _engine / python -m byerte.win.engine) + winws2
    pid = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ByeRTE" / "run" / "byerte.pid"
    try:
        subprocess.run(["taskkill", "/PID", pid.read_text().strip(), "/T", "/F"],
                       capture_output=True, creationflags=_NOWIN)
    except (FileNotFoundError, ValueError, OSError):
        pass
    subprocess.run(["taskkill", "/IM", "winws2.exe", "/T", "/F"],
                   capture_output=True, creationflags=_NOWIN)
    # WinDivert sürücüsünü indir (.sys kilidini açar) — yönetici gerekir
    subprocess.run(["sc", "stop", "WinDivert"], capture_output=True, creationflags=_NOWIN)


def verify_hashes() -> None:
    """data/SHA256SUMS'taki Windows + lua satırlarını doğrula (Linux nfqws2'yi atla)."""
    sums = (DATA / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    checked = 0
    for line in sums:
        line = line.strip()
        if not line or "  " not in line:
            continue
        want, rel = line.split("  ", 1)
        if rel.startswith("nfqws2/"):
            continue  # Linux ikilisi; Windows derlemesine girmez
        f = DATA / rel
        if not f.exists():
            sys.exit(f"HATA: gömülü dosya yok: {rel}")
        got = hashlib.sha256(f.read_bytes()).hexdigest()
        if got != want:
            sys.exit(f"HATA: sha256 uyuşmadı: {rel}\n  beklenen {want}\n  bulunan  {got}")
        checked += 1
    print(f"==> bütünlük doğrulandı ({checked} dosya)")


def main() -> int:
    if sys.platform != "win32":
        sys.exit("HATA: bu derleyici yalnızca Windows'ta çalışır.")
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit("HATA: PyInstaller yok. Kur:  pip install pyinstaller")

    verify_hashes()
    gui = REPO / "gui" / "byerte_gui_win.py"
    if not gui.exists():
        sys.exit(f"HATA: GUI dosyası yok: {gui}")

    # Önceki derleme çalışıyor/yüklüyse dosyaları kilitler → önce kilitleri aç.
    locks = [DIST / "byerte.exe",
             DIST / "_internal" / "data" / "winws2" / "windows-x86_64" / "WinDivert64.sys"]
    if any(_locked(p) for p in locks):
        print("==> çalışan motor/sürücü durduruluyor (dosya kilitleri açılıyor)")
        release_locks()
        import time as _t; _t.sleep(1.5)
    still = [p for p in locks if _locked(p)]
    if still:
        sys.exit(
            "HATA: şu dosya hâlâ kilitli:\n  " + "\n  ".join(str(p) for p in still) +
            "\n\nByeRTE çalışıyor ya da WinDivert sürücüsü yüklü. YÖNETİCİ PowerShell'de:\n"
            "  .\\dist\\ByeRTE\\byerte.exe kapat\n"
            "  sc.exe stop WinDivert\n"
            "sonra bu betiği yeniden çalıştırın. (Gerekirse bir kez yeniden başlatın.)")

    print("==> PyInstaller çalışıyor (onedir)")
    cmd = [sys.executable, "-m", "PyInstaller", str(SPEC), "--noconfirm",
           "--distpath", str(DIST_ROOT), "--workpath", str(REPO / "build")]
    r = subprocess.run(cmd, cwd=str(REPO))
    if r.returncode != 0:
        return r.returncode

    out = DIST
    print()
    print(f"OK  Derleme tamam: {out}")
    print("  byerte.exe      - konsol (byerte ac / kapat / durum / tara)")
    print("  byerte-gui.exe  - grafik arayuz")
    print()
    print("  Kurulum (Yonetici PowerShell):  packaging\\windows\\install.ps1")
    print("  Tasinabilir: bu klasoru kopyalayin, byerte-gui.exe'yi calistirin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
