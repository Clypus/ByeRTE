"""Çekirdek motor: nftables tablosu + nfqws2 + DoH köprüsü yaşam döngüsü.

Tasarım ilkeleri:
- Tek `inet byerte` tablosu. Queue kuralları `bypass` → nfqws2 ölse paketler
  dokunulmadan geçer (fail-open, internet kesilmez).
- DNS redirect ile köprünün ömrü AYNI: tablo varsa köprü de vardır. Süreç her
  çıkışında tablo silinir (finally). Köprü dead iken redirect DNS'i bozacağından
  bu değişmez bir kural; systemd tarafında ExecStopPost ayrıca garanti eder.
- Hiçbir kalıcı sistem durumu değişmez (resolv.conf/sysctl/systemd-resolved'e
  dokunulmaz). Reboot = tertemiz.

root olarak çalışır (nft + NFQUEUE için). nfqws2 kendi --user=nobody ile yetki düşürür.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time

from . import config, paths, strategies
from .dns import DnsBridge

try:
    import pwd
except ImportError:  # Windows: bu modül yalnızca Linux'ta çalışır (bkz. byerte.win.engine)
    pwd = None  # type: ignore[assignment]


# --- Çekirdek modülleri ------------------------------------------------------

def load_modules() -> None:
    for mod in paths.KERNEL_MODULES:
        subprocess.run(["modprobe", mod], capture_output=True)


# --- nftables ----------------------------------------------------------------

def _nft(script: str) -> None:
    r = subprocess.run(["nft", "-f", "-"], input=script, text=True,
                       capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"nft başarısız: {r.stderr.strip()}")


def nft_present() -> bool:
    r = subprocess.run(["nft", "list", "table", paths.NFT_FAMILY, paths.NFT_TABLE],
                       capture_output=True)
    return r.returncode == 0


def nft_delete() -> None:
    """Tabloyu sil (idempotent). Kapatma = tam geri dönüş."""
    if nft_present():
        subprocess.run(["nft", "delete", "table", paths.NFT_FAMILY, paths.NFT_TABLE],
                       capture_output=True)


def build_ruleset(wan_iface: str | None) -> str:
    """nftables script'ini üret. wan_iface None ise tüm arayüzler eşlenir."""
    fw = f"0x{paths.FWMARK:08X}"
    q = paths.QUEUE_NUM
    tcp = paths.PORTS_TCP
    udp = paths.PORTS_UDP
    mx = paths.MAX_PKT
    oif = f'oifname "{wan_iface}" ' if wan_iface else ""
    iif = f'iifname "{wan_iface}" ' if wan_iface else ""
    bridge = f"{paths.DNS_BRIDGE_ADDR}:{paths.DNS_BRIDGE_PORT}"

    return f"""\
table {paths.NFT_FAMILY} {paths.NFT_TABLE} {{
  chain postnat {{
    type filter hook postrouting priority srcnat + 1; policy accept;
    {oif}meta mark and {fw} == 0 udp dport {{ {udp} }} ct original packets 1-{mx} queue num {q} bypass
    {oif}meta mark and {fw} == 0 tcp dport {{ {tcp} }} ct original packets 1-{mx} queue num {q} bypass
    {oif}meta mark and {fw} == 0 tcp dport {{ {tcp} }} tcp flags fin,rst queue num {q} bypass
  }}
  chain pre {{
    type filter hook prerouting priority filter; policy accept;
    {iif}udp sport {{ {udp} }} ct reply packets 1-{mx} queue num {q} bypass
    {iif}tcp sport {{ {tcp} }} ct reply packets 1-{mx} queue num {q} bypass
    {iif}tcp sport {{ {tcp} }} tcp flags & (syn | ack) == (syn | ack) queue num {q} bypass
  }}
  chain predefrag {{
    type filter hook output priority -401; policy accept;
    meta mark and {fw} != 0 notrack
  }}
  chain dnsnat {{
    type nat hook output priority -100; policy accept;
    meta l4proto {{ tcp, udp }} th dport 53 ip daddr != 127.0.0.0/8 redirect to :{paths.DNS_BRIDGE_PORT}
  }}
}}
"""


def nft_apply(wan_iface: str | None) -> None:
    nft_delete()  # idempotent: önce eski tabloyu temizle
    _nft(build_ruleset(wan_iface))


# --- autohostlist (nfqws2 nobody'ye düşünce yazabilsin) ----------------------

def prepare_runtime() -> None:
    """/run/byerte'yi nobody'nin gezebileceği (0755) şekilde hazırla ve
    autohostlist dosyasını nobody'ye devret (nfqws2 yetki düşürünce yazabilsin)."""
    d = paths.runtime_dir()
    try:
        d.chmod(0o755)
    except OSError:
        pass
    # nfqws2 yetki düşürdükten SONRA hostlist + lua dosyalarını açar; hepsini
    # herkesin okuyabileceği /run/byerte altına kopyala (kaynak /home'da olabilir).
    # Kullanıcı listelerini (hostlist/denylist) ilk açılışta tohumla, sonra kopyala.
    paths.seed_user_lists()
    dst = paths.active_hostlist_file()
    dst.write_text(paths.user_hostlist_file().read_text())
    os.chmod(dst, 0o644)

    deny = paths.active_denylist_file()
    deny.write_text(paths.denylist_file().read_text())
    os.chmod(deny, 0o644)

    lua_dst = paths.active_lua_dir()
    lua_dst.mkdir(exist_ok=True)
    os.chmod(lua_dst, 0o755)
    for name in paths.LUA_FILES:
        target = lua_dst / name
        target.write_bytes((paths.lua_dir() / name).read_bytes())
        os.chmod(target, 0o644)

    f = paths.autohostlist_file()
    if not f.exists():
        f.write_text("")
    try:
        nobody = pwd.getpwnam(paths.DROP_USER)
        os.chown(f, nobody.pw_uid, nobody.pw_gid)
        os.chmod(f, 0o644)
    except (KeyError, PermissionError):
        pass


# --- nfqws2 süreci -----------------------------------------------------------

class Engine:
    def __init__(self, strategy: str, wan_iface: str | None):
        self.strategy = strategies.resolve_strategy(strategy)
        self.wan_iface = wan_iface
        self.proc: subprocess.Popen | None = None
        self.bridge: DnsBridge | None = None
        self._stop = threading.Event()

    def _start_nfqws(self) -> None:
        argv = strategies.build_argv(self.strategy, with_exclude=paths.denylist_active(),
                                     all_sites=paths.all_sites_active())
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)

    def _teardown(self) -> None:
        # Sıra önemli: önce nft (yeni akışları durdur), sonra nfqws, sonra köprü
        try:
            nft_delete()
        finally:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            if self.bridge:
                self.bridge.stop()

    def run(self) -> int:
        """Her şeyi kur, bloke ol, çıkışta GARANTİ teardown. Dönüş = exit kodu."""
        load_modules()
        prepare_runtime()

        def _sig(_signum, _frame):
            self._stop.set()
        signal.signal(signal.SIGTERM, _sig)
        signal.signal(signal.SIGINT, _sig)

        try:
            self.bridge = DnsBridge()
            self.bridge.start()
            nft_apply(self.wan_iface)
            self._start_nfqws()
            config.write_state({
                "running": True,
                "pid": os.getpid(),
                "strategy": self.strategy,
                "wan_iface": self.wan_iface,
                "started": int(time.time()),
            })
            # Bekle: durdurma sinyali ya da nfqws2'nin beklenmedik ölümü
            while not self._stop.is_set():
                if self.proc and self.proc.poll() is not None:
                    # nfqws2 çöktü → çık (teardown finally'de). systemd yeniden başlatır.
                    return 1
                time.sleep(0.5)
            return 0
        finally:
            self._teardown()
            config.write_state({"running": False})


def run_service(strategy: str | None = None, wan_iface: str | None = None) -> int:
    """Servisi çalıştır. Argüman verilmezse yapılandırmadan okur, WAN'ı tespit eder."""
    cfg = config.load()
    strategy = strategy or cfg.get("strategy") or strategies.DEFAULT_STRATEGY
    if wan_iface is None:
        wan_iface = cfg.get("wan_iface")
    if wan_iface is None:
        from . import isp
        wan_iface = isp.detect_wan_iface()
    return Engine(strategy, wan_iface).run()


if __name__ == "__main__":
    # Dahili: `python3 -m byerte.engine [strateji] [wan_iface]`
    # (systemd/sudo çağırır; argümansızsa yapılandırmadan okur)
    strat = sys.argv[1] if len(sys.argv) > 1 else None
    wan = sys.argv[2] if len(sys.argv) > 2 else None
    raise SystemExit(run_service(strat, wan))
