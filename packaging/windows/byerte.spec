# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: ByeRTE Windows derlemesi (onedir).

İki exe üretir — byerte.exe (konsol CLI) ve byerte-gui.exe (penceresiz GUI) — ve
ikisini TEK bir dist klasörüne (dist/ByeRTE) toplar. winws2.exe + WinDivert + lua
veri olarak gömülür; paths.data_dir() donmuş modda bunları bulur.

onedir (onefile DEĞİL) bilinçli: WinDivert sürücüsü (.sys) kararlı bir yoldan
yüklenmeli. onefile her çalıştırmada farklı bir geçici dizine açılır; sürücü
servisi eski yolu arayıp bozulabilir. Kurulu dizin (Program Files\\ByeRTE) sabittir.

Derleme:  python packaging/windows/build.py
Elle:     pyinstaller packaging/windows/byerte.spec --noconfirm
"""

import os

# SPECPATH, PyInstaller tarafından spec DOSYASININ BULUNDUĞU DİZİNE ayarlanır
# (yani zaten packaging/windows). Bir kez daha dirname ALMA.
SPEC_DIR = os.path.abspath(SPECPATH)  # noqa: F821  -> ...\byert\packaging\windows
REPO = os.path.abspath(os.path.join(SPEC_DIR, "..", ".."))  # -> ...\byert
WIN = os.path.join(REPO, "data", "winws2", "windows-x86_64")

datas = [
    (os.path.join(WIN, "winws2.exe"), "data/winws2/windows-x86_64"),
    (os.path.join(WIN, "cygwin1.dll"), "data/winws2/windows-x86_64"),
    (os.path.join(WIN, "WinDivert.dll"), "data/winws2/windows-x86_64"),
    (os.path.join(WIN, "WinDivert64.sys"), "data/winws2/windows-x86_64"),
    (os.path.join(REPO, "data", "hostlist.txt"), "data"),
    (os.path.join(REPO, "data", "SHA256SUMS"), "data"),
    (os.path.join(REPO, "data", "lua", "zapret-lib.lua"), "data/lua"),
    (os.path.join(REPO, "data", "lua", "zapret-antidpi.lua"), "data/lua"),
    (os.path.join(REPO, "data", "lua", "zapret-auto.lua"), "data/lua"),
]

# Tembel/koşullu importlar statik analizde kaçabilir — elle ekle.
hidden = [
    "byerte.cli", "byerte.config", "byerte.dns", "byerte.isp",
    "byerte.paths", "byerte.probe", "byerte.strategies",
    "byerte.platforms", "byerte.platforms.windows",
    "byerte.win.engine", "byerte.win.dnsdivert",
    "byerte.win.windivert", "byerte.win.winutil",
]

block_cipher = None

a_cli = Analysis(
    [os.path.join(SPEC_DIR, "byerte-cli.py")],
    pathex=[REPO], binaries=[], datas=datas, hiddenimports=hidden,
    hookspath=[], runtime_hooks=[], excludes=["tkinter"],  # CLI'da tkinter gerekmez
    win_no_prefer_redirects=False, win_private_assemblies=False,
    cipher=block_cipher, noarchive=False,
)
a_gui = Analysis(
    [os.path.join(REPO, "gui", "byerte_gui_win.py")],
    pathex=[REPO], binaries=[], datas=datas, hiddenimports=hidden,
    hookspath=[], runtime_hooks=[], excludes=[],
    win_no_prefer_redirects=False, win_private_assemblies=False,
    cipher=block_cipher, noarchive=False,
)

# İki exe TEK klasöre toplanır; COLLECT aynı hedef adlı dosyaları (ortak Python
# çalışma zamanı, DLL'ler) kendiliğinden tekilleştirir. MERGE'in göreli-yol
# varsayımlarına gerek yok — birleşik tek-klasör derlemede bu daha güvenilir.
pyz_cli = PYZ(a_cli.pure, a_cli.zipped_data, cipher=block_cipher)
pyz_gui = PYZ(a_gui.pure, a_gui.zipped_data, cipher=block_cipher)

exe_cli = EXE(
    pyz_cli, a_cli.scripts, [], exclude_binaries=True,
    name="byerte", console=True, icon=None,
    uac_admin=False,  # asInvoker: `durum` UAC'siz çalışır; `aç` kendi UAC'ını çıkarır
    disable_windowed_traceback=False,
)
exe_gui = EXE(
    pyz_gui, a_gui.scripts, [], exclude_binaries=True,
    name="byerte-gui", console=False, icon=None,
    uac_admin=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe_cli, a_cli.binaries, a_cli.zipfiles, a_cli.datas,
    exe_gui, a_gui.binaries, a_gui.zipfiles, a_gui.datas,
    strip=False, upx=False, name="ByeRTE",
)
