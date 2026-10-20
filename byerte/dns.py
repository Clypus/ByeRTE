"""Yerel DoH köprüsü: 127.0.0.1:5355 (UDP+TCP) ↔ DoH (HTTPS).

ISS'nin DNS zehirlemesini aşar. Sadece stdlib. DoH sunucularına IP ile bağlanır
(SNI/sertifika host adıyla doğrulanır) — böylece köprü açıkken ortaya çıkacak
DNS döngüsü olmaz.

Not: bu köprü root GEREKTİRMEZ; yüksek portta (5355) dinler. nftables 53'ü buraya
yönlendirir. Köprü düşerse yalnızca DNS bozulur — servis bir bütün olduğundan
systemd süreci durdurur ve ExecStopPost nftables tablosunu siler.

Windows'ta köprü 15353'te yalnızca sağlık kontrolü için dinler; 53 trafiğini
byerte.win.dnsdivert WinDivert ile yakalayıp aynı DohResolver'a sorar.
"""

from __future__ import annotations

import http.client
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time

from . import paths


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Belirli bir IP'ye bağlanır ama TLS SNI + sertifika doğrulamasını host adıyla yapar."""

    def __init__(self, host: str, ip: str, context: ssl.SSLContext, timeout: float = 2.5):
        super().__init__(host, 443, context=context, timeout=timeout)
        self._ip = ip

    def connect(self):  # noqa: D102
        sock = socket.create_connection((self._ip, 443), timeout=self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def make_query(name: str, qtype: int = 1) -> bytes:
    """Minimal DNS sorgusu (wire) üret. qtype: 1=A, 16=TXT, 28=AAAA."""
    qid = 0x1234
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(struct.pack("B", len(p)) + p for p in name.encode().split(b".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def answer_count(resp: bytes) -> int:
    return struct.unpack("!H", resp[6:8])[0] if len(resp) >= 8 else 0


def _skip_name(resp: bytes, off: int) -> int:
    """DNS adını atla (sıkıştırma işaretçisi dahil), yeni ofseti döndür."""
    while off < len(resp):
        length = resp[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:  # sıkıştırma işaretçisi (2 bayt)
            return off + 2
        off += 1 + length
    return off


def qname_of(msg: bytes) -> str | None:
    """DNS mesajının ilk sorusundaki alan adını noktalı küçük-harf dizeye çöz
    (ör. b'...\\x03www\\x06roblox\\x03com\\x00...' → 'www.roblox.com'). Ayrıştıramazsa None.
    Sıkıştırma işaretçisi soru adında olmaz; basit okuma yeterli."""
    try:
        labels = []
        off = 12
        n = len(msg)
        while off < n:
            length = msg[off]
            if length == 0:
                break
            if length & 0xC0:          # soru adında işaretçi/uzun etiket beklenmez
                return None
            off += 1
            if off + length > n:
                return None
            labels.append(msg[off:off + length].decode("latin1").lower())
            off += length
        return ".".join(labels) if labels else None
    except (IndexError, ValueError):
        return None


def domain_suffix_match(qname: str, entries) -> bool:
    """qname, entries'teki bir alanla aynı mı ya da onun alt alan adı mı?
    (roblox.com, 'apis.roblox.com' → True). entries küçük harf olmalı."""
    if not qname:
        return False
    qname = qname.rstrip(".").lower()
    for e in entries:
        if qname == e or qname.endswith("." + e):
            return True
    return False


def parse_txt(resp: bytes) -> list[str]:
    """TXT yanıtındaki metinleri çıkar (Team Cymru ASN sorgusu için)."""
    out: list[str] = []
    try:
        qd = struct.unpack("!H", resp[4:6])[0]
        an = answer_count(resp)
        off = 12
        for _ in range(qd):  # soru bölümünü atla
            off = _skip_name(resp, off) + 4
        for _ in range(an):
            off = _skip_name(resp, off)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", resp[off:off + 10])
            off += 10
            rdata = resp[off:off + rdlen]
            off += rdlen
            if rtype == 16 and rdata:  # TXT: ilk bayt uzunluk
                tlen = rdata[0]
                out.append(rdata[1:1 + tlen].decode("latin1"))
    except Exception:  # noqa: BLE001
        pass
    return out


class DohResolver:
    """DoH yukarı akışlarına yük devretmeli (failover) DNS-wire → DNS-wire çözücü."""

    def __init__(self, upstreams=None):
        self._upstreams = upstreams or paths.DOH_UPSTREAMS
        self._ctx = ssl.create_default_context()
        self._lock = threading.Lock()
        self._good = 0  # son çalışan yukarı akışın indeksi (sticky)
        self.queries = 0
        self.errors = 0

    def _try_one(self, up: dict, ip: str, wire: bytes) -> bytes:
        conn = _PinnedHTTPSConnection(up["host"], ip, self._ctx)
        try:
            conn.request(
                "POST", up["path"], body=wire,
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                    "Content-Length": str(len(wire)),
                    "User-Agent": "byerte-doh/1.0",
                },
            )
            resp = conn.getresponse()
            data = resp.read()
            if resp.status != 200 or not data:
                raise OSError(f"DoH HTTP {resp.status}")
            return data
        finally:
            conn.close()

    def resolve(self, wire: bytes, deadline: float | None = None) -> bytes | None:
        """Ham DNS sorgusunu çöz. Başarısız olursa None.

        deadline: time.monotonic() cinsinden son an; geçildiyse yeni deneme
        başlatılmaz (Windows'ta tutulan sorgu zamanında ISS'ye bırakılabilsin)."""
        with self._lock:
            start = self._good
        n = len(self._upstreams)
        for off in range(n):
            idx = (start + off) % n
            up = self._upstreams[idx]
            for ip in up["ips"]:
                if deadline is not None and time.monotonic() >= deadline:
                    with self._lock:
                        self.errors += 1
                    return None
                try:
                    data = self._try_one(up, ip, wire)
                    with self._lock:
                        self._good = idx
                        self.queries += 1
                    return data
                except Exception:
                    continue
        with self._lock:
            self.errors += 1
        return None

    def active_upstream(self) -> str:
        with self._lock:
            return self._upstreams[self._good]["host"]

    def query(self, name: str, qtype: int = 1) -> bytes | None:
        """Ada göre sorgu yap, ham yanıtı döndür."""
        return self.resolve(make_query(name, qtype))


# --- UDP sunucu --------------------------------------------------------------

class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if len(data) < 12:
            return
        resolver: DohResolver = self.server.resolver  # type: ignore[attr-defined]
        answer = resolver.resolve(data)
        if answer:
            try:
                sock.sendto(answer, self.client_address)
            except OSError:
                pass


class _ExclusiveBindMixin:
    """Windows'ta SO_REUSEADDR başka bir soketin aynı portu ele geçirmesine izin
    verir; orada portu SO_EXCLUSIVEADDRUSE ile tek başımıza tutarız."""

    def server_bind(self):
        if paths.IS_WINDOWS and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class _ThreadingUDPServer(_ExclusiveBindMixin, socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = not paths.IS_WINDOWS
    max_packet_size = 4096


# --- TCP sunucu (2 baytlık uzunluk öneki) ------------------------------------

class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5.0)
        try:
            hdr = self._recv_exact(2)
            if not hdr:
                return
            (length,) = struct.unpack("!H", hdr)
            query = self._recv_exact(length)
            if not query:
                return
        except OSError:
            return
        resolver: DohResolver = self.server.resolver  # type: ignore[attr-defined]
        answer = resolver.resolve(query)
        if answer:
            try:
                self.request.sendall(struct.pack("!H", len(answer)) + answer)
            except OSError:
                pass

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf


class _ThreadingTCPServer(_ExclusiveBindMixin, socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = not paths.IS_WINDOWS


class DnsBridge:
    """UDP+TCP DoH köprüsünü birlikte yönetir."""

    def __init__(self, addr: str = paths.DNS_BRIDGE_ADDR, port: int = paths.DNS_BRIDGE_PORT):
        self.addr = addr
        self.port = port
        self.resolver = DohResolver()
        self._udp: _ThreadingUDPServer | None = None
        self._tcp: _ThreadingTCPServer | None = None
        self._threads: list[threading.Thread] = []

    def start(self):
        self._udp = _ThreadingUDPServer((self.addr, self.port), _UDPHandler)
        self._udp.resolver = self.resolver  # type: ignore[attr-defined]
        self._tcp = _ThreadingTCPServer((self.addr, self.port), _TCPHandler)
        self._tcp.resolver = self.resolver  # type: ignore[attr-defined]
        for srv in (self._udp, self._tcp):
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        for srv in (self._udp, self._tcp):
            if srv is not None:
                srv.shutdown()
                srv.server_close()

    def serve_forever(self):
        self.start()
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            self.stop()


def _selftest() -> int:
    """Köprüyü aç, 127.0.0.1:5355'ten discord.com'u çöz (dış DNS'e dokunmadan)."""
    import struct as _s

    bridge = DnsBridge(addr="127.0.0.1", port=paths.DNS_BRIDGE_PORT)
    try:
        bridge.start()
    except OSError as e:
        print(f"köprü başlatılamadı (port meşgul olabilir): {e}", file=sys.stderr)
        return 2
    try:
        # minimal DNS sorgusu: discord.com A
        qname = b"".join(_s.pack("B", len(p)) + p for p in b"discord.com".split(b".")) + b"\x00"
        query = _s.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + _s.pack("!HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # bir ölü upstream'den kurtulacak kadar süre (3 upstream × 2 IP × 2.5s < 16s)
        s.settimeout(16)
        s.sendto(query, ("127.0.0.1", paths.DNS_BRIDGE_PORT))
        resp, _ = s.recvfrom(4096)
        ancount = _s.unpack("!H", resp[6:8])[0]
        print(f"DoH köprüsü OK — {bridge.resolver.active_upstream()} üzerinden "
              f"{ancount} yanıt kaydı alındı (discord.com)")
        return 0 if ancount > 0 else 1
    except Exception as e:
        print(f"köprü self-test başarısız: {e}", file=sys.stderr)
        return 1
    finally:
        bridge.stop()


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    DnsBridge().serve_forever()
