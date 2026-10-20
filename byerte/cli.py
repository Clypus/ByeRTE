"""ByeRTE komut satırı arayüzü: aç / kapat / durum / tara / açılış.

Platforma özel işler (yetki yükseltme, servis/süreç yönetimi, açılışta başlatma,
günlük) byerte.platforms arka ucuna devredilir; bu dosya iki platformda da aynıdır.
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time

from . import __version__, config, isp, paths, strategies
from .dns import answer_count, make_query
from .platforms import current as _platform

plat = _platform()

# ANSI (sadece tty'de; Windows'ta VT + UTF-8 konsolu da burada açılır)
_C = plat.setup_console()
def _g(s): return f"\033[32m{s}\033[0m" if _C else s      # yeşil
def _r(s): return f"\033[31m{s}\033[0m" if _C else s      # kırmızı
def _y(s): return f"\033[33m{s}\033[0m" if _C else s      # sarı
def _b(s): return f"\033[1m{s}\033[0m" if _C else s       # kalın


# --- Sağlık kontrolü ---------------------------------------------------------

def _bridge_resolves(domain: str = "discord.com", timeout: float = 6.0) -> bool:
    """DoH köprüsü 127.0.0.1:<port> üzerinden çözüyor mu?"""
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
    plat.ensure_admin(_rebuild_argv(args))
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

    if plat.service_active():
        print(_y("zaten çalışıyor, yeniden başlatılıyor..."))
        plat.service_stop()

    plat.service_start()

    # sağlık kontrolü
    print("başlatılıyor", end="", flush=True)
    ok_dns = ok_svc = False
    for _ in range(15):
        time.sleep(0.4); print(".", end="", flush=True)
        if plat.service_active() and plat.engine_present():
            ok_svc = True
            if _bridge_resolves():
                ok_dns = True
                break
    print()

    if not ok_svc:
        print(_r("✗ servis başlamadı"))
        _hint_log()
        return 1
    print(f"{_g('✓')} servis çalışıyor ({plat.ENGINE_LABEL})")
    print(f"{_g('✓') if ok_dns else _r('✗')} şifreli DNS (DoH köprüsü)")

    d_ok = _tls_ok("discord.com"); r_ok = _tls_ok("www.roblox.com")
    print(f"{_g('✓') if d_ok else _y('?')} discord.com   {'erişilebilir' if d_ok else 'TLS başarısız'}")
    print(f"{_g('✓') if r_ok else _y('?')} roblox.com    {'erişilebilir' if r_ok else 'TLS başarısız'}")
    print()
    print(_g(_b("ByeRTE açık.")) + "  Kapatmak için:  byerte kapat")
    print(f"Listeler: {paths.user_hostlist_file().parent}  "
          "(hostlist.txt = siteler, denylist.txt = hariç tut)")
    return 0


def cmd_kapat(args) -> int:
    plat.ensure_admin(["kapat"])
    if not plat.service_active() and not plat.engine_present():
        print("zaten kapalı.")
        return 0
    plat.service_stop()
    time.sleep(0.5)
    if plat.engine_present():
        print(_r(plat.RESIDUAL_WARNING))
        plat.force_cleanup()
    print(_g(_b("ByeRTE kapandı.")) + "  Sistem eski haline döndü.")
    return 0


def cmd_durum(args) -> int:
    st = config.read_state()
    cfg = config.load()
    # "Açık" doğruluğu yetkisiz sinyallerden: köprü yanıtı + servis durumu.
    bridge = _bridge_resolves()
    svc = plat.service_active()
    active = bridge or svc
    paused = bool(st.get("paused_for_vpn"))
    print(_b("ByeRTE durumu"))
    if paused and active:
        print(f"  durum      : {_y('DURAKLATILDI')}  (VPN algılandı — VPN'iniz zaten koruyor)")
    else:
        print(f"  durum      : {_g('AÇIK') if active else _r('KAPALI')}")
    if plat.service_installed():
        print(f"  {'servis':<11}: {_g('çalışıyor') if svc else 'durdu'}")
    for label, value, good in plat.status_rows():
        print(f"  {label:<11}: {_g(value) if good else value}")
    strat = st.get("strategy") or cfg.get("strategy")
    if strat in strategies.STRATEGIES:
        print(f"  strateji   : {strategies.STRATEGIES[strat]['label']} ({strat})")
    print(f"  DNS köprüsü: {_g('çözüyor') if bridge else ('yanıt yok' if not active else _r('yanıt yok'))}")
    print(f"  discord    : {_g('erişilebilir') if _tls_ok('discord.com') else _y('TLS başarısız')}")
    print(f"  roblox     : {_g('erişilebilir') if _tls_ok('www.roblox.com') else _y('TLS başarısız')}")
    if plat.service_installed():
        boot = plat.autostart_enabled()
        print(f"  {'açılışta':<11}: {'açık' if boot else 'kapalı (elle)'}")
    return 0


def cmd_tara(args) -> int:
    plat.ensure_admin(_rebuild_argv(args, base="tara"))
    from . import probe
    operator = args.operator or config.load().get("operator", "auto")
    # Tarama tabloyu/kuyruğu/köprüyü tek başına kullanır; çalışan servisi durdur.
    if plat.service_active() or plat.engine_present():
        print("çalışan servis durduruluyor (tarama için)...")
        plat.service_stop()
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
    plat.ensure_admin(["acilis", args.durum])
    if plat.autostart_enabled() is None:
        print(_r(plat.service_missing_hint())); return 1
    if args.durum in ("ac", "aç", "on"):
        plat.set_autostart(True)
        print(_g("açılışta otomatik başlatma: AÇIK"))
    else:
        plat.set_autostart(False)
        print("açılışta otomatik başlatma: KAPALI")
    return 0


def cmd_gunluk(args) -> int:
    return plat.follow_log()


def cmd_engine(args) -> int:
    """Gizli: donmuş (PyInstaller) Windows exe'sinin kendini arka plan motoru olarak
    başlatması için. Linux'ta motor systemd/dev tarafından `python -m byerte.engine`
    ile çalıştırılır; bu komut yalnızca Windows içindir."""
    if paths.IS_WINDOWS:
        from .win.engine import run_service, _setup_logging
        _setup_logging()
    else:
        from .engine import run_service
    return run_service()


# --- yardımcılar -------------------------------------------------------------

def _hint_log():
    print(plat.log_hint())


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
        description="ByeRTE — Discord/Roblox DPI engel aşıcı. "
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

    s = sub.add_parser("_engine", help=argparse.SUPPRESS)
    s.set_defaults(func=cmd_engine)

    return p


PAUSE_FLAG = "--_pause"  # Windows: UAC ile açılan görünür konsol çıkışta beklesin


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Gizli bayrak: kendini UAC ile yükselten CLI ekler (bkz. win.winutil). O ayrı
    # pencere iş bitince kapanmasın, kullanıcı çıktıyı okuyabilsin.
    pause = PAUSE_FLAG in argv
    if pause:
        argv = [a for a in argv if a != PAUSE_FLAG]
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except subprocess.CalledProcessError as e:
        print(_r(f"komut başarısız: {e}"), file=sys.stderr)
        return 1
    finally:
        if pause:
            try:
                input("\nKapatmak için Enter'a basın...")
            except (EOFError, KeyboardInterrupt):
                pass


if __name__ == "__main__":
    raise SystemExit(main())
