"""Denylist (hariç tutma) + düzenlenebilir hostlist özelliği testleri.

Ağ/yönetici/WinDivert gerektirmez. dnsdivert'in hariç-tutma kapısı, gerçek bir
IPv4+UDP+DNS paketi kurulup WinDivert AÇILMADAN sınanır.
"""

from __future__ import annotations

import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))

from byerte import dns, paths, strategies  # noqa: E402


def _win_layout(tmp: Path):
    base = tmp / "data"
    return [
        mock.patch.object(paths, "IS_WINDOWS", True),
        mock.patch.object(paths, "data_dir", lambda: base),
        mock.patch.object(paths, "runtime_dir", lambda: tmp / "run"),
        mock.patch.object(paths, "config_dir", lambda: tmp / "cfg"),
        mock.patch.object(paths, "_arch_tag", lambda: "windows-x86_64"),
    ]


class HelpersTest(unittest.TestCase):
    def test_qname_of(self):
        self.assertEqual(dns.qname_of(dns.make_query("apis.roblox.com")), "apis.roblox.com")
        self.assertEqual(dns.qname_of(dns.make_query("WWW.Roblox.COM")), "www.roblox.com")

    def test_suffix_match(self):
        dl = ["roblox.com", "ornek-api.com"]
        self.assertTrue(dns.domain_suffix_match("apis.roblox.com", dl))
        self.assertTrue(dns.domain_suffix_match("roblox.com", dl))
        self.assertTrue(dns.domain_suffix_match("a.b.ornek-api.com", dl))
        self.assertFalse(dns.domain_suffix_match("notroblox.com", dl))
        self.assertFalse(dns.domain_suffix_match("roblox.com.evil.com", dl))  # son-ek sahteciliği
        self.assertFalse(dns.domain_suffix_match("", dl))

    def test_load_list(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "l.txt"
            p.write_text("# yorum\n; başka\n/ü\nRoblox.com\n\n  discord.gg  \n", encoding="utf-8")
            self.assertEqual(paths.load_list(p), ["roblox.com", "discord.gg"])
        self.assertEqual(paths.load_list(Path(d) / "yok.txt"), [])  # eksik dosya → boş


class BuildArgvExcludeTest(unittest.TestCase):
    def test_exclude_flag_toggles(self):
        with tempfile.TemporaryDirectory() as d:
            for p in _win_layout(Path(d)):
                p.start()
            try:
                on = strategies.build_argv("turk-telekom", with_exclude=True)
                off = strategies.build_argv("turk-telekom", with_exclude=False)
            finally:
                mock.patch.stopall()
        ex = [x for x in on if x.startswith("--hostlist-exclude=")]
        self.assertEqual(len(ex), 2, "TLS + QUIC profilleri")
        self.assertTrue(ex[0].endswith("denylist.txt"))
        self.assertFalse(any(x.startswith("--hostlist-exclude") for x in off))
        # exclude kapalıyken çıktı, exclude satırları çıkarılmış haliyle aynı olmalı
        self.assertEqual([x for x in on if not x.startswith("--hostlist-exclude=")], off)


class SeedListsTest(unittest.TestCase):
    def test_seed_and_preserve(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "data").mkdir()
            (tmp / "data" / "hostlist.txt").write_text("roblox.com\ndiscord.com\n", encoding="utf-8")
            for p in _win_layout(tmp):
                p.start()
            try:
                paths.seed_user_lists()
                uh = paths.user_hostlist_file().read_text(encoding="utf-8")
                dl = paths.denylist_file().read_text(encoding="utf-8")
                self.assertIn("roblox.com", uh)
                self.assertIn("# ByeRTE", uh)               # başlık eklendi
                self.assertIn("# ByeRTE", dl)
                self.assertEqual(paths.load_list(paths.denylist_file()), [])  # denylist boş
                # kullanıcı düzenlemesi korunur (ikinci çağrı ÜZERİNE YAZMAZ)
                paths.denylist_file().write_text("ornek-api.com\n", encoding="utf-8")
                paths.seed_user_lists()
                self.assertEqual(paths.load_list(paths.denylist_file()), ["ornek-api.com"])
            finally:
                mock.patch.stopall()


def _udp_query_packet(name: str) -> bytes:
    """apis.roblox.com için giden IPv4+UDP+DNS sorgu paketi (parse_query_packet'in
    kabul edeceği biçimde)."""
    d = dns.make_query(name)
    udp = struct.pack("!HHHH", 50000, 53, 8 + len(d), 0)
    total = 20 + 8 + len(d)
    ip = (struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, 17, 0)
          + bytes([192, 168, 1, 2]) + bytes([8, 8, 8, 8]))
    return ip + udp + d


class DivertDenylistGateTest(unittest.TestCase):
    """dnsdivert._handle: denylist'teki alan DoH'a gitmeden _pass edilmeli."""

    def setUp(self):
        self._patches = [mock.patch.object(paths, "IS_WINDOWS", True)]
        for p in self._patches:
            p.start()
        from byerte.win import dnsdivert, windivert
        self.dnsdivert = dnsdivert
        self.addr = windivert.Address()

    def tearDown(self):
        mock.patch.stopall()

    def _make(self, denylist):
        # protected=[]: makinedeki gerçek hostlist dosyası okunmasın (deterministik)
        d = self.dnsdivert.DnsDivert(denylist=denylist, protected=[])
        d._pass = mock.Mock()
        d._pool = mock.Mock()
        return d

    def test_denylisted_passes_without_doh(self):
        d = self._make(["roblox.com"])
        d._handle(_udp_query_packet("apis.roblox.com"), self.addr)
        d._pass.assert_called_once()
        d._pool.submit.assert_not_called()

    def test_non_denylisted_goes_to_doh(self):
        d = self._make(["roblox.com"])
        d._handle(_udp_query_packet("discord.com"), self.addr)
        d._pass.assert_not_called()
        d._pool.submit.assert_called_once()

    def test_empty_denylist_goes_to_doh(self):
        d = self._make([])
        d._handle(_udp_query_packet("apis.roblox.com"), self.addr)
        d._pass.assert_not_called()
        d._pool.submit.assert_called_once()


class AllSitesTest(unittest.TestCase):
    def test_build_argv_all_sites(self):
        with tempfile.TemporaryDirectory() as d:
            for p in _win_layout(Path(d)):
                p.start()
            try:
                allm = strategies.build_argv("turk-telekom", all_sites=True)
                norm = strategies.build_argv("turk-telekom", all_sites=False)
            finally:
                mock.patch.stopall()
        self.assertFalse(any(x.startswith("--hostlist=") for x in allm))
        self.assertFalse(any(x.startswith("--hostlist-auto") for x in allm))
        self.assertTrue(any(x.startswith("--hostlist=") for x in norm))

    def test_all_sites_active_token(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "h.txt"
            with mock.patch.object(paths, "active_hostlist_file", lambda: p):
                p.write_text("ALL=1\npornhub.com\n", encoding="utf-8")
                self.assertTrue(paths.all_sites_active())
                p.write_text("roblox.com\n", encoding="utf-8")
                self.assertFalse(paths.all_sites_active())
                p.write_text("*\n", encoding="utf-8")
                self.assertTrue(paths.all_sites_active())


class ProbeTargetsTest(unittest.TestCase):
    def test_custom_targets_merged(self):
        from byerte import probe
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "h.txt"
            p.write_text("ALL=1\ndiscord.com\nroblox.com\npornhub.com\nphncdn.com\n",
                         encoding="utf-8")
            with mock.patch.object(paths, "active_hostlist_file", lambda: p):
                t = probe._probe_targets()
        self.assertEqual(t[:3], probe.PROBE_TARGETS)           # sabitler önce
        self.assertIn("pornhub.com", t)                        # özel site eklendi
        self.assertIn("phncdn.com", t)
        self.assertNotIn("ALL=1", t)                           # belirteç elendi
        self.assertNotIn("discord.com", t[3:])                 # gömülü tekrar eklenmedi


if __name__ == "__main__":
    unittest.main()
