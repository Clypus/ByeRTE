"""`byerte tara` yolunun regresyon testi: ProbeEnv.spawn GERÇEKTEN çalıştırılır.

Neden: Windows ProbeEnv.spawn'da `strategies` importu eksikti (NameError) ve yalnızca
canlı `byerte.exe tara`da ortaya çıktı; diğer testler build_argv'ı doğrudan çağırdığı
için yakalamamıştı. Burada motor süreci yerine subprocess.Popen sahtelenir; yönetici,
WinDivert, ağ gerekmez.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))

from byerte import paths  # noqa: E402


class _Layout:
    """Geçici dizinlere yönlendirilmiş Windows/Linux yol düzeni."""

    def __init__(self, tmp: Path, windows: bool):
        self.patches = [
            mock.patch.object(paths, "IS_WINDOWS", windows),
            mock.patch.object(paths, "data_dir", lambda: tmp / "data"),
            mock.patch.object(paths, "runtime_dir", lambda: tmp / "run"),
            mock.patch.object(paths, "config_dir", lambda: tmp / "cfg"),
            mock.patch.object(paths, "_arch_tag",
                              lambda: "windows-x86_64" if windows else "linux-x86_64"),
        ]
        (tmp / "run").mkdir()

    def __enter__(self):
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        mock.patch.stopall()


class WindowsProbeEnvSpawnTest(unittest.TestCase):
    def test_spawn_builds_argv_and_launches(self):
        from byerte.platforms import windows as win
        with tempfile.TemporaryDirectory() as d, _Layout(Path(d), windows=True):
            env = win.ProbeEnv()  # __enter__ (WinDivert) ÇAĞRILMAZ; yalnızca spawn
            with mock.patch.object(subprocess, "Popen") as popen:
                env.spawn("turk-telekom")
        popen.assert_called_once()
        argv = popen.call_args.args[0]
        self.assertTrue(argv[0].endswith("winws2.exe"), argv[0])
        self.assertIn("--wf-tcp-out=80,443", argv)
        self.assertTrue(any(a.startswith("--lua-desync=") for a in argv))
        self.assertEqual(popen.call_args.kwargs.get("creationflags"),
                         win.winutil.CREATE_NO_WINDOW)

    def test_spawn_respects_all_sites_and_denylist(self):
        from byerte.platforms import windows as win
        with tempfile.TemporaryDirectory() as d, _Layout(Path(d), windows=True):
            (Path(d) / "run" / "hostlist.txt").write_text("ALL=1\n", encoding="utf-8")
            (Path(d) / "run" / "denylist.txt").write_text("ornek-api.com\n", encoding="utf-8")
            env = win.ProbeEnv()
            with mock.patch.object(subprocess, "Popen") as popen:
                env.spawn("turk-telekom")
        argv = popen.call_args.args[0]
        self.assertFalse(any(a.startswith("--hostlist=") for a in argv))     # ALL=1
        self.assertTrue(any(a.startswith("--hostlist-exclude=") for a in argv))


class LinuxProbeEnvSpawnTest(unittest.TestCase):
    def test_spawn_builds_argv_and_launches(self):
        from byerte.platforms import linux as lin
        with tempfile.TemporaryDirectory() as d, _Layout(Path(d), windows=False):
            env = lin.ProbeEnv()  # __enter__ (nft/modprobe) ÇAĞRILMAZ; yalnızca spawn
            with mock.patch.object(subprocess, "Popen") as popen:
                env.spawn("turk-telekom")
        popen.assert_called_once()
        argv = popen.call_args.args[0]
        self.assertTrue(argv[0].endswith("nfqws2"), argv[0])
        self.assertIn("--qnum=4242", argv)
        self.assertEqual(popen.call_args.kwargs.get("stdout"), subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
