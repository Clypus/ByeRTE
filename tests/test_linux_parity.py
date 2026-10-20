"""Linux davranışı kilidi: refactor öncesi (pristine) kodun ürettiği nfqws2 argv'leri
ve nftables ruleset'i tests/golden/linux_golden.json'da donduruldu. Kod Linux
modunda çalıştırıldığında çıktı BİREBİR aynı olmalı (Linux bu makinede canlı test
edilemediği için tek güvence bu).

Her platformda çalışır: Windows'ta paths.IS_WINDOWS geçici olarak False yapılır.
"""

from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))  # Windows'ta engine.py importu için

from byerte import engine, paths, strategies  # noqa: E402

GOLDEN = json.loads((ROOT / "tests" / "golden" / "linux_golden.json").read_text(encoding="utf-8"))


def _linux_layout():
    """Golden üretilirken kullanılan Linux kurulu düzeni (bkz. golden üreteci)."""
    return [
        mock.patch.object(paths, "IS_WINDOWS", False),
        # import anında platforma göre seçilen sabit; gerçek Linux'ta 5355
        mock.patch.object(paths, "DNS_BRIDGE_PORT", 5355),
        mock.patch.object(paths, "data_dir", lambda: PurePosixPath("/usr/lib/byerte/data")),
        mock.patch.object(paths, "runtime_dir", lambda: PurePosixPath("/run/byerte")),
        mock.patch.object(paths, "config_dir", lambda: PurePosixPath("/etc/byerte")),
        mock.patch.object(paths, "_arch_tag", lambda: "linux-x86_64"),
    ]


class LinuxParityTest(unittest.TestCase):
    def setUp(self):
        self._patches = _linux_layout()
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    def test_argv_identical(self):
        self.assertEqual(len(GOLDEN["argv"]), len(strategies.STRATEGIES) * 4)
        for key, expected in GOLDEN["argv"].items():
            name, q, a = key.split("|")
            got = strategies.build_argv(name, with_quic=q.endswith("1"),
                                        autohostlist=a.endswith("1"))
            self.assertEqual(got, expected, key)

    def test_ruleset_identical(self):
        for wan, expected in GOLDEN["ruleset"].items():
            got = engine.build_ruleset(None if wan == "None" else wan)
            self.assertEqual(got, expected, wan)

    def test_resolve_identical(self):
        for name, expected in GOLDEN["resolve"].items():
            self.assertEqual(strategies.resolve_strategy(name), expected, name)

    def test_bridge_port_unchanged(self):
        # Modül seviyesi sabit; Linux'ta 5355 olmalı (Windows'ta 15353).
        if sys.platform != "win32":
            self.assertEqual(paths.DNS_BRIDGE_PORT, 5355)


class WindowsArgvTest(unittest.TestCase):
    """Windows başlığı: --wf-* filtreleri, Linux'a özgü bayraklar YOK, profiller aynı."""

    def setUp(self):
        base = Path(r"C:\Program Files\ByeRTE\data")
        run = Path(r"C:\ProgramData\ByeRTE\run")
        self._patches = [
            mock.patch.object(paths, "IS_WINDOWS", True),
            mock.patch.object(paths, "data_dir", lambda: base),
            mock.patch.object(paths, "runtime_dir", lambda: run),
            mock.patch.object(paths, "_arch_tag", lambda: "windows-x86_64"),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    def test_header_and_profiles(self):
        for name in strategies.STRATEGIES:
            for q in (True, False):
                for a in (True, False):
                    win = strategies.build_argv(name, with_quic=q, autohostlist=a)
                    self.assertTrue(win[0].endswith("winws2.exe"), win[0])
                    self.assertEqual(win[1], "--wf-tcp-out=80,443")
                    self.assertEqual("--wf-udp-out=443" in win, q)
                    for flag in ("--qnum=", "--fwmark=", "--user="):
                        self.assertFalse(any(x.startswith(flag) for x in win), flag)
                    # profil kısmı Linux golden'ıyla aynı (yollar hariç)
                    lin = GOLDEN["argv"][f"{name}|quic={int(q)}|auto={int(a)}"]
                    strip = lambda v: [x for x in v if not x.startswith(  # noqa: E731
                        ("--lua-init=", "--hostlist=", "--hostlist-auto="))]
                    self.assertEqual(strip(win[2 if not q else 3:]), strip(lin[4:]), name)

    def test_paths_are_forward_slash(self):
        win = strategies.build_argv("turk-telekom")
        for x in win[1:]:
            if x.startswith(("--lua-init=@", "--hostlist=", "--hostlist-auto=")):
                self.assertNotIn("\\", x, x)
                self.assertIn("C:/ProgramData/ByeRTE/run/", x)


if __name__ == "__main__":
    unittest.main()
