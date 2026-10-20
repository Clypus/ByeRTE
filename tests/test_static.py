"""Statik güvence: hiçbir modülde tanımsız isim (eksik import vb.) olmamalı.

Tembel/koşullu kod yolları (ör. yalnızca `tara`da çalışan ProbeEnv.spawn) birim
testlerden kaçabilir; pyflakes bunları kod çalışmadan yakalar. pyflakes kurulu
değilse test atlanır (çalışma zamanı bağımlılığı değildir).
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [ROOT / "byerte", ROOT / "gui" / "byerte_gui_win.py",
           ROOT / "packaging" / "windows" / "byerte-cli.py",
           ROOT / "packaging" / "windows" / "build.py"]

try:
    from pyflakes import api as _api, messages as _msgs
    from pyflakes import reporter as _rep
except ImportError:  # pragma: no cover
    _api = None


class _Collect(_rep.Reporter if _api else object):
    def __init__(self):
        self.found = []

    def unexpectedError(self, filename, msg):  # noqa: N802
        self.found.append(f"{filename}: {msg}")

    def syntaxError(self, filename, msg, lineno, offset, text):  # noqa: N802
        self.found.append(f"{filename}:{lineno}: sözdizimi: {msg}")

    def flake(self, message):
        bad = (_msgs.UndefinedName, _msgs.UndefinedExport, _msgs.UndefinedLocal)
        if isinstance(message, bad):
            self.found.append(str(message))


@unittest.skipIf(_api is None, "pyflakes kurulu değil")
class NoUndefinedNamesTest(unittest.TestCase):
    def test_no_undefined_names(self):
        rep = _Collect()
        files = []
        for t in TARGETS:
            files += sorted(t.rglob("*.py")) if t.is_dir() else [t]
        for f in files:
            _api.checkPath(str(f), rep)
        self.assertEqual(rep.found, [], "\n".join(rep.found))


if __name__ == "__main__":
    unittest.main()
