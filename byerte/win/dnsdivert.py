"""Windows'ta yerel DNS yönlendirmesi: WinDivert ↔ DoH.

Linux'taki nftables `dnsnat` kuralının (53 → 127.0.0.1:5355) Windows karşılığı.
Giden UDP/53 sorguları WinDivert ile yakalanır, ortak DohResolver ile çözülür ve
yanıt, sanki sorgulanan DNS sunucusundan gelmiş gibi GELEN yöne enjekte edilir
(adresler/portlar yer değiştirir, aynı arayüz). Orijinal sorgu ağa çıkmaz.

Hiçbir kalıcı ayar değişmez: adaptör DNS'i, NRPT, hosts dosyası... dokunulmaz.

Fail-open:
- Süreç ölürse WinDivert handle'ı kapanır → sorgular normal yoluna (ISS DNS) döner.
- DoH bir sorgu için başarısız olursa / NOERROR dışı yanıt verirse (NXDOMAIN,
  SERVFAIL ...) orijinal paket aynen ağa bırakılır (yerel ağ adları da çalışır).
- DoH art arda başarısız olursa bir süre tüm sorgular doğrudan geçer (devre kesici;
  ör. giriş sayfalı otel Wi-Fi'ında her sorgu süre aşımı beklemesin).

TCP/53 dokunulmadan geçer. Yanıt UDP'ye sığmazsa önce yetki/ek bölümleri atılır,
yine sığmazsa TC bayrağıyla kesilir; istemci TCP'ye düşer ve o sorgu ISS DNS'ine
gider (bilinen sınırlama — Discord/Roblox A/AAAA yanıtları rahatça sığar).
"""

from __future__ import annotations

import logging
import os
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from ..dns import DohResolver, domain_suffix_match, qname_of
from . import windivert

log = logging.getLogger("byerte.dns")

# Döngü yok: yanıtlarımız gelen yönde, DoH 443'te; loopback (yerel DNS vekili)
# Linux'taki `ip daddr != 127.0.0.0/8` gibi hariç.
DIVERT_FILTER = "outbound and !loopback and !impostor and udp.DstPort == 53"

DNS_HEADER = 12
QR_BIT = 0x8000
TC_BIT = 0x0200
OPCODE_MASK = 0x7800
TYPE_OPT = 41
DO_BIT = 0x8000                 # OPT TTL alanındaki DNSSEC OK biti

# Parçalanmadan sığan en büyük UDP yükü (1500 MTU): IPv4 1500-20-8, IPv6 1500-40-8.
IPV4_UDP_CAP = 1472
IPV6_UDP_CAP = 1452
CLASSIC_UDP_LIMIT = 512

_CACHE_MAX = 1024


# --- IP/UDP ayrıştırma ve yanıt paketi -----------------------------------------

@dataclass(frozen=True)
class QueryPacket:
    """Yakalanan bir UDP/53 paketinin ihtiyacımız olan alanları."""
    ipv6: bool
    src: bytes          # istemci IP (4 / 16 bayt)
    dst: bytes          # DNS sunucusu IP
    sport: int          # istemci portu
    dport: int          # 53
    dns: bytes          # UDP yükü (DNS mesajı)


def parse_query_packet(pkt: bytes) -> QueryPacket | None:
    """IPv4/IPv6 + UDP paketini ayrıştır. Anlamadığımız her şey (parça, IPv6 uzantı
    başlığı, bozuk uzunluk) için None → çağıran paketi dokunmadan geçirir."""
    if len(pkt) < 28:
        return None
    ver = pkt[0] >> 4
    if ver == 4:
        ihl = (pkt[0] & 0x0F) * 4
        if ihl < 20 or len(pkt) < ihl + 8:
            return None
        total = struct.unpack_from("!H", pkt, 2)[0]
        frag = struct.unpack_from("!H", pkt, 6)[0]
        if frag & 0x3FFF:                       # MF ya da parça ofseti: parça
            return None
        if pkt[9] != 17 or total < ihl + 8 or total > len(pkt):
            return None
        src, dst = pkt[12:16], pkt[16:20]
        l4, end = ihl, total
        v6 = False
    elif ver == 6:
        if len(pkt) < 48 or pkt[6] != 17:       # uzantı başlıklarını işlemiyoruz
            return None
        plen = struct.unpack_from("!H", pkt, 4)[0]
        if plen < 8 or 40 + plen > len(pkt):
            return None
        src, dst = pkt[8:24], pkt[24:40]
        l4, end = 40, 40 + plen
        v6 = True
    else:
        return None
    sport, dport, ulen = struct.unpack_from("!HHH", pkt, l4)
    if ulen < 8 or l4 + ulen > end:
        return None
    return QueryPacket(v6, bytes(src), bytes(dst), sport, dport, bytes(pkt[l4 + 8:l4 + ulen]))


def build_response_packet(q: QueryPacket, dns_msg: bytes) -> bytes:
    """Sorgunun tersine (sunucu:53 → istemci:port) bir IP+UDP paketi kur.
    Sağlama toplamları 0 bırakılır (windivert.calc_checksums doldurur)."""
    ulen = 8 + len(dns_msg)
    udp = struct.pack("!HHHH", q.dport, q.sport, ulen, 0)
    if q.ipv6:
        ip = struct.pack("!IHBB", 6 << 28, ulen, 17, 64) + q.dst + q.src
    else:
        ident = struct.unpack("!H", os.urandom(2))[0]
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + ulen, ident, 0x4000, 64, 17, 0) + q.dst + q.src
    return ip + udp + dns_msg


# --- DNS mesajı yardımcıları --------------------------------------------------

def _counts(msg: bytes) -> tuple[int, int, int, int]:
    return struct.unpack_from("!HHHH", msg, 4)


def _skip_name(msg: bytes, off: int) -> int:
    """Alan adını atla (sıkıştırma işaretçisi dahil); sınır dışında ValueError."""
    n = len(msg)
    while True:
        if off >= n:
            raise ValueError("ad taşması")
        length = msg[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            if off + 2 > n:
                raise ValueError("işaretçi taşması")
            return off + 2
        if length & 0xC0:
            raise ValueError("geçersiz etiket")
        off += 1 + length


def _skip_rr(msg: bytes, off: int) -> tuple[int, int, int, int]:
    """Bir kaynak kaydını atla → (tip, sınıf, ttl, sonraki_ofset)."""
    off = _skip_name(msg, off)
    if off + 10 > len(msg):
        raise ValueError("RR başlığı taşması")
    rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
    end = off + 10 + rdlen
    if end > len(msg):
        raise ValueError("RR verisi taşması")
    return rtype, rclass, ttl, end


def _question_end(msg: bytes, qdcount: int) -> int:
    off = DNS_HEADER
    for _ in range(qdcount):
        off = _skip_name(msg, off) + 4
        if off > len(msg):
            raise ValueError("soru taşması")
    return off


def _find_opt(msg: bytes) -> tuple[int, int, int] | None:
    """Ek bölümdeki OPT kaydı → (udp_boyutu, ttl_alanı, kayıt_uzunluğu); yoksa None.
    OPT'de SINIF alanı UDP boyutunu, TTL alanı EDNS bayraklarını (DO) taşır."""
    span = _opt_span(msg)
    if span is None:
        return None
    start, end = span
    off = _skip_name(msg, start)
    _rtype, size, ttl, _ = struct.unpack_from("!HHIH", msg, off)
    return size, ttl, end - start


def _opt_span(msg: bytes) -> tuple[int, int] | None:
    qd, an, ns, ar = _counts(msg)
    off = _question_end(msg, qd)
    for _ in range(an + ns):
        off = _skip_rr(msg, off)[3]
    for _ in range(ar):
        start = off
        rtype, _cls, _ttl, off = _skip_rr(msg, off)
        if rtype == TYPE_OPT:
            return start, off
    return None


def is_standard_query(dns_msg: bytes) -> bool:
    """Tek sorulu, standart (opcode 0) bir sorgu mu? Değilse dokunmayız."""
    if len(dns_msg) < DNS_HEADER + 5:
        return False
    flags = struct.unpack_from("!H", dns_msg, 2)[0]
    if flags & QR_BIT or flags & OPCODE_MASK:
        return False
    qd, an, ns, _ar = _counts(dns_msg)
    if qd != 1 or an or ns:
        return False
    try:
        return _question_end(dns_msg, 1) <= len(dns_msg)
    except ValueError:
        return False


def rcode(dns_msg: bytes) -> int:
    return dns_msg[3] & 0x0F if len(dns_msg) >= 4 else -1


def client_udp_limit(query: bytes) -> int:
    """İstemcinin kabul ettiği en büyük UDP yanıtı: EDNS OPT varsa onun boyutu
    (en az 512), yoksa klasik 512."""
    try:
        opt = _find_opt(query)
    except (ValueError, struct.error):
        return CLASSIC_UDP_LIMIT
    if opt is None:
        return CLASSIC_UDP_LIMIT
    return max(CLASSIC_UDP_LIMIT, opt[0])


def question_key(query: bytes) -> bytes | None:
    """Önbellek/birleştirme anahtarı: küçük harf soru (ad+tip+sınıf) + EDNS/DO.
    Farklı EDNS istekleri farklı yanıt biçimi bekler; ayrı tutulur."""
    try:
        qend = _question_end(query, 1)
        opt = _find_opt(query)
    except (ValueError, struct.error):
        return None
    edns = b"\x00" if opt is None else (b"\x02" if opt[1] & DO_BIT else b"\x01")
    return query[DNS_HEADER:qend].lower() + edns


def _patch_question(answer: bytes, query: bytes) -> bytes:
    """Yanıttaki soru bölümünü bu sorgununkiyle (harf büyüklüğü dahil) eşitle;
    önbellekten/birleştirilmiş yanıtta istemci kendi sorusunu görsün."""
    try:
        qend = _question_end(query, 1)
    except ValueError:
        return answer
    qsec = query[DNS_HEADER:qend]
    asec = answer[DNS_HEADER:qend]
    if asec == qsec or asec.lower() != qsec.lower():
        return answer
    return answer[:DNS_HEADER] + qsec + answer[qend:]


def fit_response(query: bytes, answer: bytes, max_len: int) -> bytes:
    """Yanıtı istemciye uydur: işlem kimliğini sorgununkiyle değiştir, sığmıyorsa
    önce yetki + ek bölümleri at (OPT hariç), yine sığmıyorsa TC ile kes."""
    if len(answer) < DNS_HEADER or len(query) < 2:
        raise ValueError("kısa DNS mesajı")
    msg = query[:2] + answer[2:]
    if len(msg) <= max_len:
        return msg
    flags = struct.unpack_from("!H", msg, 2)[0]
    qd, an, _ns, _ar = _counts(msg)
    try:
        qend = _question_end(msg, qd)
        off = qend
        for _ in range(an):
            off = _skip_rr(msg, off)[3]
        span = _opt_span(msg)
        opt = msg[span[0]:span[1]] if span else b""
        mini = (struct.pack("!HHHHHH", struct.unpack_from("!H", msg, 0)[0], flags,
                            qd, an, 0, 1 if opt else 0)
                + msg[DNS_HEADER:off] + opt)
        if len(mini) <= max_len:
            return mini
        qsec = msg[DNS_HEADER:qend]
    except (ValueError, struct.error):
        opt = b""
        try:
            qsec = query[DNS_HEADER:_question_end(query, 1)]
            qd = 1
        except ValueError:
            qsec, qd = b"", 0
    trunc = struct.pack("!HHHHHH", struct.unpack_from("!H", msg, 0)[0], flags | TC_BIT,
                        qd, 0, 0, 1 if opt else 0) + qsec + opt
    if len(trunc) > max_len and opt:
        trunc = struct.pack("!HHHHHH", struct.unpack_from("!H", msg, 0)[0], flags | TC_BIT,
                            qd, 0, 0, 0) + qsec
    return trunc


def min_ttl(answer: bytes) -> int | None:
    """Yanıt + yetki bölümündeki en küçük TTL (OPT hariç); kayıt yoksa None."""
    try:
        qd, an, ns, _ar = _counts(answer)
        off = _question_end(answer, qd)
        best = None
        for _ in range(an + ns):
            rtype, _cls, ttl, off = _skip_rr(answer, off)
            if rtype != TYPE_OPT:
                best = ttl if best is None else min(best, ttl)
        return best
    except (ValueError, struct.error):
        return None


# --- Yönlendirici ---------------------------------------------------------------

class DnsDivert:
    """Giden UDP/53 sorgularını DoH ile yanıtlayan WinDivert döngüsü.

    start() yönetici ister (WinDivertOpen) ve bloke etmez; açılamazsa
    windivert.WinDivertError (OSError) yükselir. stop() idempotent; döndüğünde
    yakalama bitmiştir ve DNS anında normal yoluna döner.
    """

    def __init__(self, resolver: DohResolver | None = None, *, dll_path: Path | None = None,
                 workers: int = 16, deadline: float = 3.0, cache_ttl: float = 10.0,
                 fail_threshold: int = 3, bypass_secs: float = 30.0,
                 filter: str = DIVERT_FILTER, denylist: list[str] | None = None,
                 protected: list[str] | None = None):
        self.resolver = resolver or DohResolver()
        # Hariç tutulan alanlar: DoH yerine olduğu gibi geçer (normal/ISS DNS'ine gider).
        # Verilmezse çalışma anı denylist dosyasından okunur.
        self._denylist = denylist if denylist is not None else paths.load_list(
            paths.active_denylist_file())
        # Korumalı alanlar = hostlist (discord/roblox + kullanıcı eklemeleri). Bunlar için
        # ISS cevabına ASLA düşülmez: ISS zehirli IP'yi ~1 saat TTL ile verir, Windows onu
        # önbelleğe alır ve uygulama takılır (ör. updates.discord.com → 195.175.254.2 →
        # Discord 'Checking for updates'ta kalır). DoH başarısızsa sorgu DÜŞÜRÜLÜR; istemci
        # ~1 sn sonra yeniden sorar (Linux köprüsünün davranışıyla aynı). ALL=1 belirteci
        # sayılmaz: yerel ağ adları için korumasız alanlar fail-open kalır.
        if protected is None:
            protected = [d for d in paths.load_list(paths.active_hostlist_file())
                         if d not in paths.ALL_SITES_TOKENS]
        self._protected = protected
        self._dll_path = dll_path
        self._workers = workers
        self._deadline = deadline
        self._cache_ttl = cache_ttl
        self._fail_threshold = fail_threshold
        self._bypass_secs = bypass_secs
        self._filter = filter

        self._wd: windivert.WinDivert | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

        self._lock = threading.Lock()           # önbellek, bekleyenler, sayaçlar
        self._cache: dict[bytes, tuple[float, bytes]] = {}
        self._inflight: dict[bytes, list[tuple[bytes, windivert.Address, QueryPacket]]] = {}
        self._fail_streak = 0
        self._bypass_until = 0.0
        self.stats = {"answered": 0, "cached": 0, "passed": 0, "dropped": 0, "errors": 0}

    # --- yaşam döngüsü ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stopping.clear()
        wd = windivert.WinDivert(self._filter, dll_path=self._dll_path)
        wd.open()  # yetki/sürücü hatası burada yükselir (WinDivertError)
        self._wd = wd
        self._pool = ThreadPoolExecutor(max_workers=self._workers,
                                        thread_name_prefix="byerte-doh")
        self._thread = threading.Thread(target=self._recv_loop, name="byerte-dnsdivert",
                                        daemon=True)
        self._thread.start()
        log.info("DNS yönlendirmesi açık (WinDivert: %s)", self._filter)

    def stop(self) -> None:
        if self._thread is None and self._wd is None:
            return
        self._stopping.set()
        wd, pool, thread = self._wd, self._pool, self._thread
        if wd is not None:
            wd.shutdown(windivert.SHUTDOWN_RECV)
        if thread is not None:
            thread.join(timeout=2.0)
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        if wd is not None:
            wd.close()  # bekleyen yanıtlar artık gönderilemez; istemci yeniden sorar
        with self._lock:
            self._inflight.clear()
            self._cache.clear()
        self._wd = self._pool = self._thread = None
        log.info("DNS yönlendirmesi kapandı (%s)", self.stats)

    @property
    def alive(self) -> bool:
        t = self._thread
        return t is not None and t.is_alive() and not self._stopping.is_set()

    @property
    def bypassing(self) -> bool:
        """Devre kesici açık mı (DoH ulaşılamıyor, sorgular doğrudan geçiyor)?"""
        return time.monotonic() < self._bypass_until

    # --- paket döngüsü ---------------------------------------------------------

    def _recv_loop(self) -> None:
        errors = 0
        while not self._stopping.is_set():
            try:
                got = self._wd.recv()
            except windivert.WinDivertError as e:
                if self._stopping.is_set():
                    break
                errors += 1
                self._count("errors")
                log.warning("WinDivert recv hatası: %s", e)
                if errors >= 50:  # kalıcı arıza: döngüyü bırak (alive=False)
                    log.error("DNS yönlendirme döngüsü durdu: art arda recv hatası")
                    break
                time.sleep(0.05)
                continue
            if got is None:
                break
            errors = 0
            try:
                self._handle(*got)
            except Exception:  # noqa: BLE001 — tek paket döngüyü düşürmesin
                self._count("errors")
                log.exception("DNS paketi işlenemedi")
                self._pass(*got)

    def _is_protected(self, q: QueryPacket) -> bool:
        """Sorgu, hostlist'teki (engelli, ISS'nin zehirlediği) bir alan için mi?"""
        if not self._protected:
            return False
        name = qname_of(q.dns)
        return bool(name) and domain_suffix_match(name, self._protected)

    def _fallback(self, pkt: bytes, addr: windivert.Address, q: QueryPacket,
                  ans: bytes | None) -> None:
        """DoH kullanılabilir (NOERROR) bir yanıt vermedi.
        - Korumasız alan → orijinali ISS'ye bırak (fail-open; yerel ağ adları çalışır).
        - Korumalı alan → ISS'nin zehirli cevabını ASLA alma: DoH NXDOMAIN dediyse o
          doğrudur, ilet; aksi halde (zaman aşımı/SERVFAIL) düşür, istemci yeniden sorar."""
        if not self._is_protected(q):
            self._pass(pkt, addr)
            return
        if ans is not None and len(ans) >= DNS_HEADER and rcode(ans) == 3:
            self._answer(pkt, addr, q, ans, "answered")
            return
        self._count("dropped")

    def _handle(self, pkt: bytes, addr: windivert.Address) -> None:
        q = parse_query_packet(pkt)
        key = question_key(q.dns) if q is not None and is_standard_query(q.dns) else None
        if key is None:
            self._pass(pkt, addr)
            return
        # Hariç-tutma: bu alan denylist'teyse DoH'a sorma, orijinali olduğu gibi bırak
        # → normal/ISS çözümleyicisinden gider (bozulan API'ler için). Hostlist'te de
        # olsa denylist kazanır (zapret --hostlist-exclude anlamıyla aynı).
        if self._denylist:
            name = qname_of(q.dns)
            if name and domain_suffix_match(name, self._denylist):
                self._pass(pkt, addr)
                return
        if self.bypassing:                        # devre kesici: DoH ulaşılamıyor
            self._fallback(pkt, addr, q, None)    # korumalı alan ISS'ye düşmez
            return
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None and hit[0] <= now:
                del self._cache[key]
                hit = None
            if hit is None:
                waiters = self._inflight.get(key)
                if waiters is not None:          # aynı soru zaten çözülüyor
                    waiters.append((pkt, addr, q))
                    return
                self._inflight[key] = [(pkt, addr, q)]
        if hit is not None:
            self._answer(pkt, addr, q, hit[1], "cached")
            return
        try:
            self._pool.submit(self._resolve, key, q.dns)
        except RuntimeError:                     # havuz kapanıyor
            with self._lock:
                waiters = self._inflight.pop(key, [])
            for w in waiters:
                self._pass(w[0], w[1])

    def _resolve(self, key: bytes, wire: bytes) -> None:
        try:
            ans = self.resolver.resolve(wire, deadline=time.monotonic() + self._deadline)
        except Exception:  # noqa: BLE001
            ans = None
        ok = ans is not None and len(ans) >= DNS_HEADER and rcode(ans) == 0
        now = time.monotonic()
        with self._lock:
            waiters = self._inflight.pop(key, [])
            if ans is None:
                self._fail_streak += 1
                if self._fail_streak >= self._fail_threshold and now >= self._bypass_until:
                    self._bypass_until = now + self._bypass_secs
                    log.warning("DoH ulaşılamıyor; %.0f sn boyunca DNS sorguları doğrudan "
                                "geçiyor", self._bypass_secs)
            else:
                self._fail_streak = 0
            if ok and not struct.unpack_from("!H", ans, 2)[0] & TC_BIT:
                self._cache_put(key, ans, now)
        for pkt, addr, q in waiters:
            if ok:
                self._answer(pkt, addr, q, ans, "answered")
            else:
                self._fallback(pkt, addr, q, ans)

    def _cache_put(self, key: bytes, ans: bytes, now: float) -> None:
        ttl = min_ttl(ans)
        life = self._cache_ttl if ttl is None else min(self._cache_ttl, ttl)
        if life <= 0:
            return
        if len(self._cache) >= _CACHE_MAX:
            for k in [k for k, v in self._cache.items() if v[0] <= now]:
                del self._cache[k]
            while len(self._cache) >= _CACHE_MAX:
                del self._cache[next(iter(self._cache))]
        self._cache[key] = (now + life, ans)

    # --- enjeksiyon ------------------------------------------------------------

    def _answer(self, pkt: bytes, addr: windivert.Address, q: QueryPacket,
                ans: bytes, stat: str) -> None:
        try:
            cap = IPV6_UDP_CAP if q.ipv6 else IPV4_UDP_CAP
            msg = fit_response(q.dns, _patch_question(ans, q.dns),
                               min(client_udp_limit(q.dns), cap))
            raddr = addr.copy()
            raddr.Outbound = 0               # gelen yön: sanki sunucudan geldi
            raddr.Loopback = 0
            raddr.Impostor = 0
            out = windivert.calc_checksums(build_response_packet(q, msg), raddr,
                                           dll_path=self._dll_path)
            self._wd.send(out, raddr)
            self._count(stat)
        except Exception as e:  # noqa: BLE001 — yanıt veremezsek orijinal geçsin
            if not self._stopping.is_set():
                self._count("errors")
                if self._is_protected(q):           # zehirli ISS cevabına düşme
                    log.debug("DNS yanıtı enjekte edilemedi (%s); korumalı sorgu düşürüldü", e)
                    self._count("dropped")
                else:
                    log.debug("DNS yanıtı enjekte edilemedi (%s); sorgu geçiriliyor", e)
                    self._pass(pkt, addr)

    def _pass(self, pkt: bytes, addr: windivert.Address) -> None:
        """Orijinal sorguyu dokunmadan ağa bırak (fail-open)."""
        wd = self._wd
        if wd is None or self._stopping.is_set():
            return
        try:
            wd.send(pkt, addr)
            self._count("passed")
        except Exception as e:  # noqa: BLE001
            self._count("errors")
            log.debug("sorgu geçirilemedi: %s", e)

    def _count(self, name: str) -> None:
        with self._lock:
            self.stats[name] += 1
