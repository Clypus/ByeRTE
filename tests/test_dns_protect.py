"""Korumalı alan (hostlist) politikası: ISS'nin zehirli cevabına ASLA düşülmez.

Gerçek olay (2026-10-20): motor açılışında DoH bir an yetişemedi, dnsdivert
updates.discord.com sorgusunu ISS'ye bıraktı; TT sinkhole IP'yi (195.175.254.2)
~1 saat TTL ile verdi, Windows önbelleğe aldı ve Discord 'Checking for updates'ta
takıldı. Artık hostlist'teki alanlar için DoH başarısızsa sorgu düşürülür (istemci
yeniden sorar), korumasız alanlar ise eskisi gibi fail-open kalır.

WinDivert açılmaz; yönetici/ağ gerekmez.
"""

from __future__ import annotations

import struct
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))

from byerte import dns, paths  # noqa: E402


def _pkt(name: str) -> bytes:
    d = dns.make_query(name)
    udp = struct.pack("!HHHH", 50000, 53, 8 + len(d), 0)
    ip = (struct.pack("!BBHHHBBH", 0x45, 0, 28 + len(d), 0, 0x4000, 64, 17, 0)
          + bytes([192, 168, 1, 2]) + bytes([192, 168, 1, 1]))
    return ip + udp + d


def _nxdomain(query: bytes) -> bytes:
    r = bytearray(query)
    r[2] |= 0x80                         # QR=1 (yanıt)
    r[3] = (r[3] & 0xF0) | 3             # RCODE=NXDOMAIN
    return bytes(r)


@unittest.skipUnless(sys.platform == "win32", "WinDivert.dll yalnızca Windows'ta")
class ProtectedDomainTest(unittest.TestCase):
    def setUp(self):
        self._p = mock.patch.object(paths, "IS_WINDOWS", True)
        self._p.start()
        from byerte.win import dnsdivert, windivert
        self.dd, self.wd = dnsdivert, windivert

    def tearDown(self):
        mock.patch.stopall()

    def _make(self, protected=("discord.com", "roblox.com"), denylist=()):
        d = self.dd.DnsDivert(protected=list(protected), denylist=list(denylist))
        d._pass = mock.Mock()
        d._answer = mock.Mock()
        d._pool = mock.Mock()
        return d

    def _resolve_with(self, d, name, doh_answer):
        """name için bekleyen bir sorgu kur ve _resolve'u DoH cevabı sahteleyerek çalıştır."""
        pkt = _pkt(name)
        q = self.dd.parse_query_packet(pkt)
        key = self.dd.question_key(q.dns)
        d._inflight[key] = [(pkt, self.wd.Address(), q)]
        d.resolver = mock.Mock()
        d.resolver.resolve.return_value = (doh_answer(q.dns) if callable(doh_answer)
                                           else doh_answer)
        d._resolve(key, q.dns)

    # --- DoH başarısız ---------------------------------------------------------

    def test_protected_doh_failure_dropped_not_passed(self):
        d = self._make()
        self._resolve_with(d, "updates.discord.com", None)       # zaman aşımı
        d._pass.assert_not_called()                              # ISS'ye ASLA
        d._answer.assert_not_called()
        self.assertEqual(d.stats["dropped"], 1)

    def test_unprotected_doh_failure_still_fails_open(self):
        d = self._make()
        self._resolve_with(d, "router.lan", None)
        d._pass.assert_called_once()                             # yerel adlar çalışsın
        self.assertEqual(d.stats["dropped"], 0)

    # --- DoH NOERROR dışı --------------------------------------------------------

    def test_protected_nxdomain_answered_from_doh(self):
        d = self._make()
        self._resolve_with(d, "yok.roblox.com", _nxdomain)
        d._pass.assert_not_called()
        d._answer.assert_called_once()                           # DoH'un doğru NXDOMAIN'i

    def test_unprotected_nxdomain_passed(self):
        d = self._make()
        self._resolve_with(d, "printer.home", _nxdomain)
        d._pass.assert_called_once()

    # --- devre kesici ----------------------------------------------------------------

    def test_breaker_protected_dropped(self):
        # Gerçek hostlist discord.gg içerir → gateway.discord.gg korumalıdır.
        d = self._make(protected=("discord.gg",))
        d._bypass_until = time.monotonic() + 60
        d._handle(_pkt("gateway.discord.gg"), self.wd.Address())
        d._pass.assert_not_called()                              # ISS'ye ASLA
        d._pool.submit.assert_not_called()                       # devre kesici: DoH denenmez
        self.assertEqual(d.stats["dropped"], 1)

    def test_breaker_unprotected_passed(self):
        d = self._make()
        d._bypass_until = time.monotonic() + 60
        d._handle(_pkt("example.org"), self.wd.Address())
        d._pass.assert_called_once()

    # --- denylist önceliği / enjeksiyon hatası ---------------------------------------

    def test_denylist_wins_over_protected(self):
        d = self._make(protected=("roblox.com",), denylist=("apis.roblox.com",))
        d._handle(_pkt("apis.roblox.com"), self.wd.Address())
        d._pass.assert_called_once()
        d._pool.submit.assert_not_called()

    def test_inject_failure_protected_dropped(self):
        d = self.dd.DnsDivert(protected=["discord.com"], denylist=[])
        d._pass = mock.Mock()
        d._wd = mock.Mock()
        pkt = _pkt("discord.com")
        q = self.dd.parse_query_packet(pkt)
        ans = bytearray(q.dns); ans[2] |= 0x80
        with mock.patch.object(self.dd.windivert, "calc_checksums",
                               side_effect=RuntimeError("enjekte edilemedi")):
            d._answer(pkt, self.wd.Address(), q, bytes(ans), "answered")
        d._pass.assert_not_called()
        self.assertEqual(d.stats["dropped"], 1)

    def test_default_protected_from_hostlist_ignores_all_token(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            h = Path(t) / "hostlist.txt"
            h.write_text("ALL=1\ndiscord.com\n# yorum\nroblox.com\n", encoding="utf-8")
            with mock.patch.object(paths, "active_hostlist_file", lambda: h), \
                 mock.patch.object(paths, "active_denylist_file", lambda: Path(t) / "yok"):
                d = self.dd.DnsDivert()
        self.assertEqual(d._protected, ["discord.com", "roblox.com"])


if __name__ == "__main__":
    unittest.main()
