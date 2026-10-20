"""UAC ile açılan görünür konsolun çıkışta beklemesi (--_pause) testleri.

Kritik değişmez: GUI'nin GİZLİ yolu (run_byerte_elevated, show_window=False) bayrağı
ASLA eklememeli — eklerse görünmez pencere sonsuza kadar Enter bekler ve GUI eylemi
asılı kalır. Yalnızca CLI'nin görünür yükseltme yolu ekler.
"""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))

from byerte import cli  # noqa: E402


class MainPauseTest(unittest.TestCase):
    def test_pause_flag_stripped_and_waits(self):
        seen = {}

        def fake_durum(args):
            seen["called"] = True
            return 0
        with mock.patch.object(cli, "cmd_durum", fake_durum), \
             mock.patch("builtins.input") as inp:
            rc = cli.main(["durum", cli.PAUSE_FLAG])
        self.assertEqual(rc, 0)
        self.assertTrue(seen.get("called"))   # argparse bayrağa takılmadı
        inp.assert_called_once()              # çıkışta bekledi

    def test_no_pause_without_flag(self):
        with mock.patch.object(cli, "cmd_durum", lambda a: 0), \
             mock.patch("builtins.input") as inp:
            cli.main(["durum"])
        inp.assert_not_called()

    def test_pause_even_on_error(self):
        def boom(args):
            raise KeyboardInterrupt
        with mock.patch.object(cli, "cmd_durum", boom), \
             mock.patch("builtins.input") as inp:
            rc = cli.main(["durum", cli.PAUSE_FLAG])
        self.assertEqual(rc, 130)
        inp.assert_called_once()              # hata olsa da pencere kapanmadan bekler


@unittest.skipUnless(sys.platform == "win32", "Windows'a özel")
class ElevationFlagTest(unittest.TestCase):
    def test_cli_visible_path_adds_flag(self):
        from byerte.win import winutil
        with mock.patch.object(winutil, "run_byerte_elevated", return_value=0) as rbe:
            winutil.relaunch_elevated_wait(["tara"])
        args, kwargs = rbe.call_args
        self.assertEqual(args[0], ["tara", winutil.PAUSE_FLAG])
        self.assertTrue(kwargs.get("show_window"))

    def test_gui_hidden_path_never_adds_flag(self):
        from byerte.win import winutil
        with mock.patch.object(winutil, "_shell_execute_runas", return_value=None) as sh:
            rc = winutil.run_byerte_elevated(["aç", "--operator", "auto"], show_window=False)
        self.assertEqual(rc, 126)                       # runas reddi → 126
        params = sh.call_args.args[1]
        self.assertNotIn(winutil.PAUSE_FLAG, params)    # gizli pencere ASLA beklememeli
        self.assertEqual(sh.call_args.args[2], winutil.SW_HIDE)


if __name__ == "__main__":
    unittest.main()
