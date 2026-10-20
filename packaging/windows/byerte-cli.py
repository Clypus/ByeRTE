"""Donmuş (PyInstaller) byerte.exe giriş noktası — konsol CLI.

`python -m byerte` ile aynı; gizli `_engine` alt komutu da buradan çalışır
(motor arka plan sürecini donmuş exe bu şekilde kendi kendine başlatır).
"""
import sys

from byerte.cli import main

if __name__ == "__main__":
    sys.exit(main())
