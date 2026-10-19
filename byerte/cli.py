"""ByeRTE komut satırı arayüzü: aç / kapat / durum / tara / açılış."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time

from . import __version__, config, engine, isp, paths, strategies
from .dns import answer_count, make_query

UNIT = "byerte.service"
PIDFILE = paths.runtime_dir if False else None  # bkz. _pidfile()

# ANSI (sadece tty'de)
_C = sys.stdout.isatty()
def _g(s): return f"\033[32m{s}\033[0m" if _C else s      # yeşil
def _r(s): return f"\033[31m{s}\033[0m" if _C else s      # kırmızı
def _y(s): return f"\033[33m{s}\033[0m" if _C else s      # sarı
def _b(s): return f"\033[1m{s}\033[0m" if _C else s       # kalın


# --- Yetki ve servis soyutlaması --------------------------------------------

def _pidfile():
    return paths.runtime_dir() / "byerte.pid"


def _ensure_root(argv: list[str]) -> None:
    """Kök değilsek sudo ile yeniden çalıştır (paket yolunu koruyarak)."""
    if os.geteuid() == 0:
        return
    print(_y("yetki gerekiyor, sudo ile yeniden çalıştırılıyor..."))
    # sudo env'i sıfırlar; byerte paketinin bulunduğu dizini PYTHONPATH ile geçir
    import byerte
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(byerte.__file__)))
    os.execvp("sudo", ["sudo", "env", f"PYTHONPATH={pkg_parent}",
                        sys.executable, "-m", "byerte", *argv])


def _unit_installed() -> bool:
    if os.path.exists(f"/etc/systemd/system/{UNIT}"):
        return True
    r = subprocess.run(["systemctl", "cat", UNIT], capture_output=True)
    return r.returncode == 0


def _service_active() -> bool:
    if _unit_installed():
        r = subprocess.run(["systemctl", "is-active", "--quiet", UNIT])
        return r.returncode == 0
    # dev: pidfile + canlı süreç
    try:
        pid = int(_pidfile().read_text())
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return False


def _service_start() -> None:
    if _unit_installed():
        subprocess.run(["systemctl", "start", UNIT], check=True)
        return
    # dev: motoru ayrık arka plan sürecinde başlat
    logf = open(paths.runtime_dir() / "engine.log", "ab")
    p = subprocess.Popen(
        [sys.executable, "-m", "byerte.engine"],
        stdout=logf, stderr=logf, start_new_session=True,
    )
    _pidfile().write_text(str(p.pid))


def _service_stop() -> None:
    if _unit_installed():
        subprocess.run(["systemctl", "stop", UNIT])
    else:
        try:
            pid = int(_pidfile().read_text())
            os.kill(pid, 15)  # SIGTERM → engine finally teardown
            for _ in range(20):
                try:
                    os.kill(pid, 0); time.sleep(0.2)
                except ProcessLookupError:
                    break
        except (FileNotFoundError, ValueError, ProcessLookupError):
            pass
        _pidfile().unlink(missing_ok=True)
    engine.nft_delete()  # her hâlükârda backstop: tablo gitsin


# --- Sağlık kontrolü ---------------------------------------------------------

def _bridge_resolves(domain: str = "discord.com", timeout: float = 6.0) -> bool:
    """DoH köprüsü 127.0.0.1:5355 üzerinden çözüyor mu?"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(make_query(domain), (paths.DNS_BRIDGE_ADDR, paths.DNS_BRIDGE_PORT))
        resp, _ = s.recvfrom(4096)
        return answer_count(resp) > 0
    except OSError:
        return False


def _tls_ok(domain: str, timeout: float = 8.0) -> bool:
    """Gerçek TLS el sıkışması tamamlanıyor mu (engel aşılıyor mu)?"""
    import ssl
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                return bool(ss.version())
    except Exception:  # noqa: BLE001
        return False


# --- Komutlar ----------------------------------------------------------------

def cmd_ac(args) -> int:
    _ensure_root(_rebuild_argv(args))
    cfg = config.load()

    operator = args.operator or cfg.get("operator", "auto")
    if args.strateji:
        strategy = strategies.resolve_strategy(args.strateji)
        info = {"auto": False}
    elif operator == "auto":
        print("operatör otomatik tespit ediliyor (ASN)...")
        strategy, info = isp.suggest_strategy()
        if info.get("asn"):
            print(f"  ASN {info['asn']} → {strategies.STRATEGIES[strategy]['label']}")
        else:
            print(f"  tespit edilemedi, varsayılan: {strategies.STRATEGIES[strategy]['label']}")
    else:
        strategy = strategies.resolve_strategy(operator)
        info = {"auto": False}

    wan = cfg.get("wan_iface") or isp.detect_wan_iface()
    cfg.update({"operator": operator, "strategy": strategy, "wan_iface": cfg.get("wan_iface")})
    config.save(cfg)

    print(f"strateji : {_b(strategies.STRATEGIES[strategy]['label'])} ({strategy})")
    print(f"arayüz   : {wan or 'otomatik'}")

    if _service_active():
        print(_y("zaten çalışıyor, yeniden başlatılıyor..."))
        _service_stop()

    _service_start()

    # sağlık kontrolü
    print("başlatılıyor", end="", flush=True)
    ok_dns = ok_svc = False
    for _ in range(15):
        time.sleep(0.4); print(".", end="", flush=True)
        if _service_active() and engine.nft_present():
            ok_svc = True
            if _bridge_resolves():
                ok_dns = True
                break
    print()

    if not ok_svc:
        print(_r("✗ servis başlamadı"))
        _hint_log()
        return 1
    print(f"{_g('✓')} servis çalışıyor (nftables + nfqws2)")
    print(f"{_g('✓') if ok_dns else _r('✗')} şifreli DNS (DoH köprüsü)")

    d_ok = _tls_ok("discord.com"); r_ok = _tls_ok("www.roblox.com")
    print(f"{_g('✓') if d_ok else _y('?')} discord.com   {'erişilebilir' if d_ok else 'TLS başarısız'}")
    print(f"{_g('✓') if r_ok else _y('?')} roblox.com    {'erişilebilir' if r_ok else 'TLS başarısız'}")
    print()
    print(_g(_b("ByeRTE açık.")) + "  Kapatmak için:  byerte kapat")
    return 0


def cmd_kapat(args) -> int:
    _ensure_root(["kapat"])
    if not _service_active() and not engine.nft_present():
        print("zaten kapalı.")
        return 0
    _service_stop()
    time.sleep(0.5)
    if engine.nft_present():
        print(_r("uyarı: nftables tablosu hâlâ var, siliniyor..."))
        engine.nft_delete()
    print(_g(_b("ByeRTE kapandı.")) + "  Sistem eski haline döndü.")
    return 0


def cmd_durum(args) -> int:
    st = config.read_state()
    cfg = config.load()
    # "Açık" doğruluğu köksüz sinyallerden: köprü yanıtı + servis durumu.
    bridge = _bridge_resolves()
    svc = _service_active()
    active = bridge or svc
    print(_b("ByeRTE durumu"))
    print(f"  durum      : {_g('AÇIK') if active else _r('KAPALI')}")
    if _unit_installed():
        print(f"  servis     : {_g('çalışıyor') if svc else 'durdu'}")
    # nft/nfqws yalnızca root okuyabilir; köksüzken yanıltıcı göstermeyelim
    if os.geteuid() == 0:
        print(f"  nftables   : {_g('yüklü') if engine.nft_present() else 'yok'}")
        nfqws = subprocess.run(["pgrep", "-x", "nfqws2"], capture_output=True).returncode == 0
        print(f"  nfqws2     : {_g('çalışıyor') if nfqws else 'yok'}")
    strat = st.get("strategy") or cfg.get("strategy")
    if strat in strategies.STRATEGIES:
        print(f"  strateji   : {strategies.STRATEGIES[strat]['label']} ({strat})")
    print(f"  DNS köprüsü: {_g('çözüyor') if bridge else ('yanıt yok' if not active else _r('yanıt yok'))}")
    print(f"  discord    : {_g('erişilebilir') if _tls_ok('discord.com') else _y('TLS başarısız')}")
    print(f"  roblox     : {_g('erişilebilir') if _tls_ok('www.roblox.com') else _y('TLS başarısız')}")
    if _unit_installed():
        boot = subprocess.run(["systemctl", "is-enabled", "--quiet", UNIT]).returncode == 0
        print(f"  açılışta   : {'açık' if boot else 'kapalı (elle)'}")
    return 0


def cmd_tara(args) -> int:
    _ensure_root(_rebuild_argv(args, base="tara"))
    from . import probe
    operator = args.operator or config.load().get("operator", "auto")
    # Tarama tabloyu/kuyruğu/köprüyü tek başına kullanır; çalışan servisi durdur.
    if _service_active() or engine.nft_present():
        print("çalışan servis durduruluyor (tarama için)...")
        _service_stop()
        time.sleep(1)
    print(f"operatör: {operator} — stratejiler deneniyor (bu biraz sürer)...\n")
    best = probe.scan(operator, verbose=True)
    if not best:
        print(_r("\nçalışan strateji bulunamadı. Mobil veri/farklı DNS deneyin."))
        return 1
    cfg = config.load(); cfg["strategy"] = best; cfg["operator"] = operator
    config.save(cfg)
    print(f"\n{_g('✓')} en iyi strateji: {_b(strategies.STRATEGIES[best]['label'])} ({best}) — kaydedildi")
    print("Uygulamak için:  byerte aç")
    return 0


def cmd_acilis(args) -> int:
    _ensure_root(["acilis", args.durum])
    if not _unit_installed():
        print(_r("systemd birimi kurulu değil (install.sh ile kurun).")); return 1
    if args.durum in ("ac", "aç", "on"):
        subprocess.run(["systemctl", "enable", UNIT], check=True)
        print(_g("açılışta otomatik başlatma: AÇIK"))
    else:
        subprocess.run(["systemctl", "disable", UNIT])
        print("açılışta otomatik başlatma: KAPALI")
    return 0


def cmd_gunluk(args) -> int:
    if _unit_installed():
        os.execvp("journalctl", ["journalctl", "-u", UNIT, "-n", "50", "-f"])
    else:
        log = paths.runtime_dir() / "engine.log"
        if log.exists():
            os.execvp("tail", ["tail", "-n", "50", "-f", str(log)])
        print("günlük yok."); return 1
    return 0


# --- yardımcılar -------------------------------------------------------------

def _hint_log():
    if _unit_installed():
        print("  ayrıntı:  journalctl -u byerte -n 30")
    else:
        print(f"  ayrıntı:  cat {paths.runtime_dir() / 'engine.log'}")


def _rebuild_argv(args, base="aç") -> list[str]:
    out = [base]
    if getattr(args, "operator", None):
        out += ["--operator", args.operator]
    if getattr(args, "strateji", None):
        out += ["--strateji", args.strateji]
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="byerte",
        description="ByeRTE — Discord/Roblox DPI engel aşıcı (Linux). "
                    "Kapatınca sistem eski haline döner.")
    p.add_argument("--version", action="version", version=f"ByeRTE {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ops = list(strategies.STRATEGIES.keys()) + ["auto"]

    for name, aliases in [("aç", ["ac", "on"])]:
        s = sub.add_parser(name, aliases=aliases, help="DPI aşmayı başlat")
        s.add_argument("--operator", choices=ops, help="operatör/strateji (vars.: auto)")
        s.add_argument("--strateji", help="belirli bir stratejiyi zorla")
        s.set_defaults(func=cmd_ac)

    for name, aliases in [("kapat", ["off"])]:
        s = sub.add_parser(name, aliases=aliases, help="durdur ve sistemi geri al")
        s.set_defaults(func=cmd_kapat)

    for name, aliases in [("durum", ["status"])]:
        s = sub.add_parser(name, aliases=aliases, help="durumu göster")
        s.set_defaults(func=cmd_durum)

    for name, aliases in [("tara", ["scan"])]:
        s = sub.add_parser(name, aliases=aliases, help="çalışan stratejiyi otomatik bul")
        s.add_argument("--operator", choices=ops, help="operatör ipucu")
        s.set_defaults(func=cmd_tara)

    s = sub.add_parser("acilis", aliases=["autostart"], help="açılışta başlatmayı aç/kapat")
    s.add_argument("durum", choices=["ac", "aç", "on", "kapat", "off"], help="ac | kapat")
    s.set_defaults(func=cmd_acilis)

    s = sub.add_parser("gunluk", aliases=["log"], help="günlüğü izle")
    s.set_defaults(func=cmd_gunluk)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except subprocess.CalledProcessError as e:
        print(_r(f"komut başarısız: {e}"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
