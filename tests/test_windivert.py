"""byerte.win.windivert: ctypes bağlaması. Sürücü YÜKLENMEZ (WinDivertOpen çağrılmaz);
yalnızca yönetici gerektirmeyen DLL yardımcıları ve sahte DLL ile handle mantığı."""

from __future__ import annotations

import ctypes
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from byerte.win import windivert as wd  # noqa: E402

IS_WIN = sys.platform == "win32"
DLL = ROOT / "data" / "winws2" / "windows-x86_64" / "WinDivert.dll"
needs_dll = unittest.skipUnless(IS_WIN and DLL.is_file(), "WinDivert.dll yalnızca Windows'ta")


def ones_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def udp4(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    ulen = 8 + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + ulen, 0x1111, 0, 128, 17, 0) + src + dst
    return ip + struct.pack("!HHHH", sport, dport, ulen, 0) + payload


def udp6(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    ulen = 8 + len(payload)
    ip = struct.pack("!IHBB", 6 << 28, ulen, 17, 64) + src + dst
    return ip + struct.pack("!HHHH", sport, dport, ulen, 0) + payload


def verify_udp4(pkt: bytes) -> bool:
    if ones_sum(pkt[:20]) != 0xFFFF:
        return False
    ulen = struct.unpack_from("!H", pkt, 24)[0]
    pseudo = pkt[12:20] + struct.pack("!BBH", 0, 17, ulen)
    return ones_sum(pseudo + pkt[20:20 + ulen]) == 0xFFFF


def verify_udp6(pkt: bytes) -> bool:
    ulen = struct.unpack_from("!H", pkt, 44)[0]
    pseudo = pkt[8:40] + struct.pack("!IxxxB", ulen, 17)
    return ones_sum(pseudo + pkt[40:40 + ulen]) == 0xFFFF


class AddressLayoutTest(unittest.TestCase):
    def test_size_and_alignment(self):
        self.assertEqual(ctypes.sizeof(wd.Address), 80)
        self.assertEqual(ctypes.alignment(wd.Address), 8)

    @unittest.skipUnless(IS_WIN, "MSVC bit alanı düzeni yalnızca Windows'ta garanti")
    def test_bitfields_match_header(self):
        cases = {"Outbound": 17, "Loopback": 18, "Impostor": 19, "IPv6": 20,
                 "IPChecksum": 21, "TCPChecksum": 22, "UDPChecksum": 23, "Sniffed": 16}
        for name, bit in cases.items():
            a = wd.Address()
            setattr(a, name, 1)
            self.assertEqual(struct.unpack_from("<I", bytes(a), 8)[0], 1 << bit, name)
        a = wd.Address()
        a.Layer, a.Event = 0xAB, 0xCD
        self.assertEqual(struct.unpack_from("<I", bytes(a), 8)[0], 0xCDAB)

    def test_network_data_offsets(self):
        a = wd.Address()
        a.IfIdx, a.SubIfIdx = 0x11223344, 7
        self.assertEqual(bytes(a)[16:24], struct.pack("<II", 0x11223344, 7))

    def test_copy_is_independent(self):
        a = wd.Address()
        a.Outbound, a.IfIdx = 1, 9
        b = a.copy()
        b.Outbound = 0
        self.assertEqual((a.Outbound, b.Outbound, b.IfIdx), (1, 0, 9))


@needs_dll
class HelperTest(unittest.TestCase):
    """Yönetici gerektirmeyen gerçek DLL yardımcıları."""

    def test_compile_filter(self):
        from byerte.win.dnsdivert import DIVERT_FILTER
        self.assertEqual(wd.compile_filter(DIVERT_FILTER, dll_path=DLL), (True, None))
        ok, err = wd.compile_filter("outbound and udp.DstPortX == 53", dll_path=DLL)
        self.assertFalse(ok)
        self.assertTrue(err)

    def test_calc_checksums_ipv4(self):
        pkt = udp4(bytes([192, 168, 1, 1]), bytes([192, 168, 1, 86]), 53, 51234, b"x" * 33)
        a = wd.Address()
        out = wd.calc_checksums(pkt, a, dll_path=DLL)
        self.assertEqual(len(out), len(pkt))
        self.assertTrue(verify_udp4(out))
        self.assertEqual((a.IPChecksum, a.UDPChecksum), (1, 1))

    def test_calc_checksums_ipv6(self):
        src = bytes.fromhex("fe800000000000000000000000000001")
        dst = bytes.fromhex("fe80000000000000aabbccfffe001122")
        out = wd.calc_checksums(udp6(src, dst, 53, 40000, b"hello dns"), dll_path=DLL)
        self.assertTrue(verify_udp6(out))

    def test_eval_filter_matches_only_outbound_dns(self):
        from byerte.win.dnsdivert import DIVERT_FILTER
        pkt = udp4(bytes([192, 168, 1, 86]), bytes([192, 168, 1, 1]), 51234, 53, b"q" * 20)
        pkt = wd.calc_checksums(pkt, dll_path=DLL)

        def addr(**kw):
            a = wd.Address()
            a.Outbound = 1
            for k, v in kw.items():
                setattr(a, k, v)
            return a

        ev = lambda p, a: wd.eval_filter(DIVERT_FILTER, p, a, dll_path=DLL)  # noqa: E731
        self.assertTrue(ev(pkt, addr()))
        self.assertFalse(ev(pkt, addr(Outbound=0)))          # enjekte ettiğimiz yanıt yönü
        self.assertFalse(ev(pkt, addr(Loopback=1)))          # yerel DNS vekili
        self.assertFalse(ev(pkt, addr(Impostor=1)))          # başka sürücünün enjeksiyonu
        other = wd.calc_checksums(udp4(pkt[12:16], pkt[16:20], 51234, 5353, b"q" * 20), dll_path=DLL)
        self.assertFalse(ev(other, addr()))                  # mDNS vb. 53 dışı


class FakeDll:
    """WinDivertOpen'ı ASLA gerçekten çağırmamak için sahte DLL."""

    def __init__(self):
        self.closed = []
        self.sent = []
        self.recv_fail = None

    def WinDivertOpen(self, flt, layer, prio, flags):
        return 0x1234

    def WinDivertClose(self, h):
        self.closed.append(h)
        return 1

    def WinDivertShutdown(self, h, how):
        return 1

    def WinDivertSend(self, h, buf, n, pn, pa):
        self.sent.append((h, bytes(buf.raw[:n])))
        return 1

    def WinDivertRecv(self, h, buf, n, pn, pa):
        return 0


class HandleLogicTest(unittest.TestCase):
    def _open(self):
        fake = FakeDll()
        with mock.patch.object(wd, "load_dll", return_value=fake):
            h = wd.WinDivert("udp").open()
        return h, fake

    def test_open_send_close_idempotent(self):
        h, fake = self._open()
        self.assertTrue(h.is_open)
        h.send(b"abc", wd.Address())
        self.assertEqual(fake.sent, [(0x1234, b"abc")])
        h.close()
        h.close()
        self.assertEqual(fake.closed, [0x1234])
        with self.assertRaises(wd.WinDivertError):
            h.send(b"x", wd.Address())

    def test_recv_after_shutdown_returns_none(self):
        h, _fake = self._open()
        h.shutdown(wd.SHUTDOWN_RECV)
        with mock.patch.object(ctypes, "get_last_error", create=True, return_value=wd.ERROR_NO_DATA):
            self.assertIsNone(h.recv())

    def test_open_failure_maps_hint(self):
        fake = FakeDll()
        fake.WinDivertOpen = lambda *a: ctypes.c_void_p(-1).value
        with mock.patch.object(wd, "load_dll", return_value=fake), \
                mock.patch.object(ctypes, "get_last_error", create=True,
                                  return_value=wd.ERROR_ACCESS_DENIED):
            with self.assertRaises(wd.WinDivertError) as cm:
                wd.WinDivert("udp").open()
        self.assertIn("yönetici", str(cm.exception))
        self.assertEqual(cm.exception.winerror if IS_WIN else wd.ERROR_ACCESS_DENIED,
                         wd.ERROR_ACCESS_DENIED)

    def test_bad_priority(self):
        with self.assertRaises(ValueError):
            wd.WinDivert("udp", priority=40000).open()


if __name__ == "__main__":
    unittest.main()
