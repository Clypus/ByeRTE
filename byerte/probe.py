"""Strateji tarama: hangi DPI atlatma stratejisi bu hatta çalışıyor?

nftables tablosu + DoH köprüsü bir kez açılır; her strateji için yalnızca nfqws2
değiştirilerek discord/roblox'a gerçek TLS el sıkışması denenir. En çok başarı +
en düşük gecikme kazanır. Tarama bittiğinde her şey tam olarak geri alınır.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import time

from . import engine, paths, strategies
from .dns import DnsBridge

PROBE_TARGETS = ["discord.com", "www.roblox.com", "gateway.discord.gg"]
TRIES_PER_TARGET = 2


def _tls_handshake(domain: str, timeout: float = 6.0) -> float | None:
    """TLS el sıkışması süresi (sn) ya da None (başarısız)."""
    ctx = ssl.create_default_context()
    t = time.time()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                if ss.version():
                    return time.time() - t
    except Exception:  # noqa: BLE001
        return None
    return None


def _score_current() -> tuple[int, float]:
    """Aktif nfqws2 ile başarı sayısı ve toplam gecikme."""
    ok = 0
    total_latency = 0.0
    for dom in PROBE_TARGETS:
        for _ in range(TRIES_PER_TARGET):
            dt = _tls_handshake(dom)
            if dt is not None:
                ok += 1
                total_latency += dt
    return ok, total_latency


def scan(operator: str = "auto", verbose: bool = False) -> str | None:
    """Stratejileri dene, en iyisinin adını döndür (veya None)."""
    order = strategies.PROBE_ORDER.get(operator, strategies.PROBE_ORDER["auto"])
    wan = None
    from . import isp
    wan = isp.detect_wan_iface()

    engine.load_modules()
    engine.prepare_runtime()
    bridge = DnsBridge()
    bridge.start()
    engine.nft_apply(wan)

    results: list[tuple[str, int, float]] = []
    proc = None
    try:
        for strat in order:
            if strat not in strategies.STRATEGIES:
                continue
            argv = strategies.build_argv(strat)
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            time.sleep(1.2)  # nfqws2 kuyruğa bağlansın
            ok, lat = _score_current()
            maxok = len(PROBE_TARGETS) * TRIES_PER_TARGET
            if verbose:
                bar = f"{ok}/{maxok}"
                extra = f" ({lat/ok:.2f}s ort)" if ok else ""
                print(f"  {strategies.STRATEGIES[strat]['label']:32} {bar}{extra}")
            results.append((strat, ok, lat))
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
            proc = None
            # Tam başarı + makul gecikme ise erken çık
            if ok == maxok and lat / max(ok, 1) < 1.0:
                break
    finally:
        if proc and proc.poll() is None:
            proc.kill()
        engine.nft_delete()
        bridge.stop()

    # en iyi: en çok başarı, eşitlikte en düşük ortalama gecikme
    working = [(s, ok, lat) for s, ok, lat in results if ok > 0]
    if not working:
        return None
    working.sort(key=lambda x: (-x[1], x[2] / x[1]))
    return working[0][0]
