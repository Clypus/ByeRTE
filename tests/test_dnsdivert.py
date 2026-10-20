"""byerte.win.dnsdivert: paket ayrıştırma/kurma, DNS uydurma ve yönlendirme mantığı.

Sürücü yüklenmez: DnsDivert sahte bir WinDivert ve sahte bir çözücüyle sürülür.
Sağlama toplamı testleri gerçek WinDivert.dll yardımcısını kullanır (yönetici gerekmez).
"""

from __future__ import annotations

import logging
import struct
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from byerte.win import dnsdivert as dd  # noqa: E402
from byerte.win import windivert as wd  # noqa: E402

IS_WIN = sys.platform == "win32"
# test çıktısı temiz kalsın (motor normalde kendi handler'ını kurar)
logging.getLogger("byerte").addHandler(logging.NullHandler())
DLL = ROOT / "data" / "winws2" / "windows-x86_64" / "WinDivert.dll"

CLIENT4, SERVER4 = bytes([192, 168, 1, 86]), bytes([192, 168, 1, 1])
CLIENT6 = bytes.fromhex("2a020000000000000000000000000086")
SERVER6 = bytes.fromhex("fe800000000000000000000000000001")


# --- DNS mesajı kurucuları ------------------------------------------------------

def qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def opt_rr(size: int = 1232, do: bool = False) -> bytes:
    return b"\x00" + struct.pack("!HHIH", 41, size, 0x8000 if do else 0, 0)


def dns_query(name="discord.com", qtype=1, qid=0x1234, edns=None, do=False, flags=0x0100,
              qd=1):
    m = struct.pack("!HHHHHH", qid, flags, qd, 0, 0, 1 if edns else 0)
    m += (qname(name) + struct.pack("!HH", qtype, 1)) * qd
    if edns:
        m += opt_rr(edns, do)
    return m


def dns_answer(query: bytes, ips=("162.159.128.233",), ttl=300, rc=0, ns_names=0,
               ar_a=0, opt=False, qid=None):
    qend = 12 + len(query[12:]) - (11 if query[11] else 0)  # OPT'yi soru bölümünden ayır
    qsec = query[12:qend]
    an = b""
    for ip in ips:
        an += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes(int(x) for x in ip.split("."))
    ns = b""
    for i in range(ns_names):
        target = qname(f"ns{i}.cloudflare-long-nameserver-label.net")
        ns += b"\xc0\x0c" + struct.pack("!HHIH", 2, 1, 86400, len(target)) + target
    ar = b""
    for i in range(ar_a):
        ar += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([10, 0, 0, i])
    if opt:
        ar += opt_rr(1232)
    head = struct.pack("!HHHHHH", qid if qid is not None else struct.unpack("!H", query[:2])[0],
                       0x8180 | rc, 1, len(ips), ns_names, ar_a + (1 if opt else 0))
    return head + qsec + an + ns + ar


def ipv4_pkt(dns: bytes, sport=51234, dport=53, frag=0) -> bytes:
    ulen = 8 + len(dns)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + ulen, 7, frag, 128, 17, 0) + CLIENT4 + SERVER4
    return ip + struct.pack("!HHHH", sport, dport, ulen, 0) + dns


def ipv6_pkt(dns: bytes, sport=40000, nh=17) -> bytes:
    ulen = 8 + len(dns)
    ip = struct.pack("!IHBB", 6 << 28, ulen, nh, 64) + CLIENT6 + SERVER6
    return ip + struct.pack("!HHHH", sport, 53, ulen, 0) + dns


# --- saf fonksiyonlar ------------------------------------------------------------

class ParseTest(unittest.TestCase):
    def test_ipv4(self):
        q = dd.parse_query_packet(ipv4_pkt(dns_query()))
        self.assertEqual((q.ipv6, q.src, q.dst, q.sport, q.dport), (False, CLIENT4, SERVER4, 51234, 53))
        self.assertEqual(q.dns, dns_query())

    def test_ipv6(self):
        q = dd.parse_query_packet(ipv6_pkt(dns_query(qtype=28)))
        self.assertEqual((q.ipv6, q.src, q.dst, q.sport), (True, CLIENT6, SERVER6, 40000))

    def test_rejects(self):
        self.assertIsNone(dd.parse_query_packet(ipv4_pkt(dns_query(), frag=0x2000)))  # MF
        self.assertIsNone(dd.parse_query_packet(ipv4_pkt(dns_query(), frag=0x0010)))  # ofset
        self.assertIsNone(dd.parse_query_packet(ipv6_pkt(dns_query(), nh=0)))         # uzantı başlığı
        self.assertIsNone(dd.parse_query_packet(ipv4_pkt(dns_query())[:30]))         # kesik
        self.assertIsNone(dd.parse_query_packet(b"\x00" * 40))

    def test_standard_query(self):
        self.assertTrue(dd.is_standard_query(dns_query()))
        self.assertTrue(dd.is_standard_query(dns_query(edns=1232, do=True)))
        self.assertFalse(dd.is_standard_query(dns_answer(dns_query())))        # QR=1
        self.assertFalse(dd.is_standard_query(dns_query(flags=0x2900)))        # opcode UPDATE
        self.assertFalse(dd.is_standard_query(dns_query(qd=2)))
        self.assertFalse(dd.is_standard_query(b"\x12\x34" + b"\x00" * 8))


class DnsHelpersTest(unittest.TestCase):
    def test_client_udp_limit(self):
        self.assertEqual(dd.client_udp_limit(dns_query()), 512)
        self.assertEqual(dd.client_udp_limit(dns_query(edns=1232)), 1232)
        self.assertEqual(dd.client_udp_limit(dns_query(edns=100)), 512)
        self.assertEqual(dd.client_udp_limit(b"garbage"), 512)

    def test_question_key(self):
        k = dd.question_key(dns_query("discord.com", qid=1))
        self.assertEqual(k, dd.question_key(dns_query("DISCORD.com", qid=2)))
        self.assertNotEqual(k, dd.question_key(dns_query("discord.com", qtype=28)))
        self.assertNotEqual(k, dd.question_key(dns_query("discord.com", edns=1232)))
        self.assertNotEqual(dd.question_key(dns_query(edns=1232)),
                            dd.question_key(dns_query(edns=1232, do=True)))

    def test_fit_small_patches_id_only(self):
        q = dns_query(qid=0xBEEF)
        a = dns_answer(q, qid=0)          # DoH sunucusu kimliği 0 döndürebilir
        out = dd.fit_response(q, a, 512)
        self.assertEqual(out[:2], b"\xbe\xef")
        self.assertEqual(out[2:], a[2:])

    def test_fit_minimizes_then_truncates(self):
        q = dns_query(edns=1232)
        big = dns_answer(q, ns_names=12, ar_a=12, opt=True)
        self.assertGreater(len(big), 512)
        mini = dd.fit_response(q, big, 512)
        self.assertLessEqual(len(mini), 512)
        _id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", mini)
        self.assertEqual((qd, an, ns, ar), (1, 1, 0, 1))      # yalnız cevap + OPT
        self.assertFalse(flags & dd.TC_BIT)
        self.assertEqual(dd.client_udp_limit(mini), 1232)     # OPT korunur

        many = dns_answer(q, ips=tuple(f"10.0.{i // 250}.{i % 250}" for i in range(80)))
        tr = dd.fit_response(q, many, 512)
        self.assertLessEqual(len(tr), 512)
        _id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", tr)
        self.assertTrue(flags & dd.TC_BIT)
        self.assertEqual((qd, an, ns), (1, 0, 0))
        self.assertEqual(tr[12:12 + len(qname("discord.com")) + 4], q[12:12 + len(qname("discord.com")) + 4])

    def test_patch_question_case(self):
        q1, q2 = dns_query("discord.com"), dns_query("DiScOrD.com")
        a = dns_answer(q1)
        patched = dd._patch_question(a, q2)
        self.assertEqual(patched[12:12 + 13], q2[12:12 + 13])
        self.assertEqual(len(patched), len(a))
        self.assertIs(dd._patch_question(a, dns_query("roblox.com")), a)  # farklı soru: dokunma

    def test_min_ttl_and_rcode(self):
        q = dns_query()
        self.assertEqual(dd.min_ttl(dns_answer(q, ttl=42)), 42)
        self.assertEqual(dd.min_ttl(dns_answer(q, ips=())), None)
        self.assertEqual(dd.rcode(dns_answer(q, rc=3)), 3)


class ResponsePacketTest(unittest.TestCase):
    def test_ipv4_swap(self):
        q = dd.parse_query_packet(ipv4_pkt(dns_query()))
        msg = dns_answer(q.dns)
        pkt = dd.build_response_packet(q, msg)
        self.assertEqual(len(pkt), 20 + 8 + len(msg))
        r = dd.parse_query_packet(pkt)     # ayrıştırıcı her UDP paketini okur
        self.assertEqual((r.src, r.dst, r.sport, r.dport, r.dns), (SERVER4, CLIENT4, 53, 51234, msg))
        self.assertEqual(struct.unpack_from("!H", pkt, 6)[0], 0x4000)   # DF

    def test_ipv6_swap(self):
        q = dd.parse_query_packet(ipv6_pkt(dns_query(qtype=28)))
        r = dd.parse_query_packet(dd.build_response_packet(q, b"x" * 40))
        self.assertEqual((r.ipv6, r.src, r.dst, r.sport, r.dport), (True, SERVER6, CLIENT6, 53, 40000))

    @unittest.skipUnless(IS_WIN and DLL.is_file(), "WinDivert.dll yalnızca Windows'ta")
    def test_checksums_valid(self):
        from tests.test_windivert import verify_udp4, verify_udp6
        q4 = dd.parse_query_packet(ipv4_pkt(dns_query()))
        a = wd.Address()
        out = wd.calc_checksums(dd.build_response_packet(q4, dns_answer(q4.dns)), a, dll_path=DLL)
        self.assertTrue(verify_udp4(out))
        q6 = dd.parse_query_packet(ipv6_pkt(dns_query(qtype=28)))
        out6 = wd.calc_checksums(dd.build_response_packet(q6, dns_answer(q6.dns)), dll_path=DLL)
        self.assertTrue(verify_udp6(out6))


# --- yönlendirme mantığı (sahte sürücü) ------------------------------------------

class FakeWD:
    def __init__(self):
        self.sent: list[tuple[bytes, wd.Address]] = []
        self.lock = threading.Lock()

    def send(self, pkt, addr):
        with self.lock:
            self.sent.append((bytes(pkt), addr.copy()))
        return len(pkt)

    def shutdown(self, how):
        pass

    def close(self):
        pass


class SyncPool:
    def submit(self, fn, *a):
        fn(*a)

    def shutdown(self, wait=True, cancel_futures=False):
        pass


class FakeResolver:
    def __init__(self, fn):
        self.fn = fn
        self.calls = 0

    def resolve(self, wire, deadline=None):
        self.calls += 1
        return self.fn(wire)


def out_addr(ifidx=12):
    a = wd.Address()
    a.Outbound, a.IfIdx, a.SubIfIdx = 1, ifidx, 0
    return a


def make(resolver, pool=None, **kw):
    # Makineden bağımsız: varsayılan olarak çalışma anı hostlist/denylist DOSYALARI
    # okunmasın (yoksa sonuç bu makinedeki %ProgramData% içeriğine bağlı olur).
    # Korumalı-alan politikası tests/test_dns_protect.py'de ayrıca sınanır.
    kw.setdefault("protected", [])
    kw.setdefault("denylist", [])
    d = dd.DnsDivert(resolver, **kw)
    d._wd = FakeWD()
    d._pool = pool or SyncPool()
    return d


@mock.patch.object(dd.windivert, "calc_checksums", lambda pkt, addr=None, flags=0, dll_path=None: pkt)
class DivertLogicTest(unittest.TestCase):
    def test_answers_inbound_with_swapped_addresses(self):
        res = FakeResolver(lambda w: dns_answer(w))
        d = make(res)
        pkt = ipv4_pkt(dns_query(qid=0x4242))
        d._handle(pkt, out_addr(ifidx=12))
        (sent, addr), = d._wd.sent
        self.assertEqual((addr.Outbound, addr.IfIdx), (0, 12))
        r = dd.parse_query_packet(sent)
        self.assertEqual((r.src, r.dst, r.sport, r.dport), (SERVER4, CLIENT4, 53, 51234))
        self.assertEqual(r.dns[:2], b"\x42\x42")
        self.assertEqual(d.stats["answered"], 1)

    def test_doh_failure_passes_original(self):
        d = make(FakeResolver(lambda w: None))
        pkt = ipv4_pkt(dns_query())
        d._handle(pkt, out_addr())
        (sent, addr), = d._wd.sent
        self.assertEqual((sent, addr.Outbound), (pkt, 1))
        self.assertEqual(d.stats["passed"], 1)

    def test_non_noerror_passes_original(self):
        for rc in (2, 3, 5):
            d = make(FakeResolver(lambda w, rc=rc: dns_answer(w, ips=(), rc=rc)))
            pkt = ipv4_pkt(dns_query("router.home"))
            d._handle(pkt, out_addr())
            self.assertEqual(d._wd.sent[0][0], pkt, rc)

    def test_not_a_query_passes(self):
        d = make(FakeResolver(lambda w: self.fail("çözücü çağrılmamalı")))
        resp = ipv4_pkt(dns_answer(dns_query()))
        d._handle(resp, out_addr())
        self.assertEqual(d._wd.sent[0][0], resp)

    def test_cache_hit_skips_resolver_and_patches_id_and_case(self):
        res = FakeResolver(lambda w: dns_answer(w))
        d = make(res)
        d._handle(ipv4_pkt(dns_query("discord.com", qid=1)), out_addr())
        d._handle(ipv4_pkt(dns_query("DISCORD.com", qid=2), sport=6000), out_addr())
        self.assertEqual(res.calls, 1)
        r = dd.parse_query_packet(d._wd.sent[1][0])
        self.assertEqual((r.dns[:2], r.dport), (b"\x00\x02", 6000))
        self.assertEqual(r.dns[12:25], qname("DISCORD.com"))
        self.assertEqual(d.stats["cached"], 1)

    def test_zero_ttl_not_cached(self):
        res = FakeResolver(lambda w: dns_answer(w, ttl=0))
        d = make(res)
        d._handle(ipv4_pkt(dns_query(qid=1)), out_addr())
        d._handle(ipv4_pkt(dns_query(qid=2)), out_addr())
        self.assertEqual(res.calls, 2)

    def test_inflight_coalescing(self):
        gate = threading.Event()

        def slow(w):
            gate.wait(5)
            return dns_answer(w)

        res = FakeResolver(slow)
        pool = ThreadPoolExecutor(max_workers=4)
        d = make(res, pool=pool)
        d._handle(ipv4_pkt(dns_query(qid=1), sport=1001), out_addr(ifidx=1))
        d._handle(ipv4_pkt(dns_query(qid=2), sport=1002), out_addr(ifidx=2))  # ör. SMHNR ikinci arayüz
        gate.set()
        pool.shutdown(wait=True)
        self.assertEqual(res.calls, 1)
        got = sorted((dd.parse_query_packet(p).dport, a.IfIdx, dd.parse_query_packet(p).dns[:2])
                     for p, a in d._wd.sent)
        self.assertEqual(got, [(1001, 1, b"\x00\x01"), (1002, 2, b"\x00\x02")])

    def test_circuit_breaker(self):
        res = FakeResolver(lambda w: None)
        d = make(res, fail_threshold=3, bypass_secs=30)
        for i in range(3):
            d._handle(ipv4_pkt(dns_query(f"a{i}.com")), out_addr())
        self.assertTrue(d.bypassing)
        d._handle(ipv4_pkt(dns_query("b.com")), out_addr())
        self.assertEqual(res.calls, 3)                     # devre açıkken DoH denenmez
        self.assertEqual(d.stats["passed"], 4)
        d._bypass_until = time.monotonic() - 1             # süre doldu: yarı açık
        res.fn = lambda w: dns_answer(w)
        d._handle(ipv4_pkt(dns_query("c.com")), out_addr())
        self.assertEqual((res.calls, d._fail_streak, d.bypassing), (4, 0, False))

    def test_ipv6_response(self):
        d = make(FakeResolver(lambda w: dns_answer(w)))
        d._handle(ipv6_pkt(dns_query(qtype=28)), out_addr())
        (sent, addr), = d._wd.sent
        r = dd.parse_query_packet(sent)
        self.assertEqual((r.ipv6, r.src, r.dst, addr.Outbound), (True, SERVER6, CLIENT6, 0))

    def test_oversized_answer_truncated_for_classic_client(self):
        many = tuple(f"10.1.{i // 250}.{i % 250}" for i in range(60))
        d = make(FakeResolver(lambda w: dns_answer(w, ips=many)))
        d._handle(ipv4_pkt(dns_query()), out_addr())
        r = dd.parse_query_packet(d._wd.sent[0][0])
        self.assertLessEqual(len(r.dns), 512)
        self.assertTrue(struct.unpack_from("!H", r.dns, 2)[0] & dd.TC_BIT)

    def test_stop_is_idempotent_and_silences(self):
        d = make(FakeResolver(lambda w: dns_answer(w)))
        d._thread = threading.Thread(target=lambda: None)
        d._thread.start()
        d.stop()
        d.stop()
        self.assertFalse(d.alive)
        d._pass(ipv4_pkt(dns_query()), out_addr())         # durunca hiçbir şey gönderilmez
        self.assertIsNone(d._wd)

    def test_default_resolver(self):
        d = dd.DnsDivert()
        from byerte.dns import DohResolver
        self.assertIsInstance(d.resolver, DohResolver)


if __name__ == "__main__":
    unittest.main()
