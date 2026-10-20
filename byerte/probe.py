"""Strateji tarama: hangi DPI atlatma stratejisi bu hatta çalışıyor?

Yakalama (Linux: nftables tablosu, Windows: WinDivert DNS yönlendirmesi) + DoH
köprüsü bir kez açılır; her strateji için yalnızca motor (nfqws2/winws2)
değiştirilerek discord/roblox'a gerçek TLS el sıkışması denenir. En çok başarı +
en düşük gecikme kazanır. Tarama bittiğinde her şey tam olarak geri alınır.

Platforma özel kurulum/temizlik byerte.platforms.*.ProbeEnv içindedir.
"""

from __future__ import annotations

import socket
import ssl
import time

from . import paths, strategies
from .platforms import current as _platform

PROBE_TARGETS = ["discord.com", "www.roblox.com", "gateway.discord.gg"]
TRIES_PER_TARGET = 2
MAX_CUSTOM_TARGETS = 3  # hostlist'e eklenen özel sitelerden kaç tanesi taranır

# Varsayılan/gömülü hostlist alanları (bunlar zaten PROBE_TARGETS'ta temsil ediliyor;
# özel hedef seçerken elenir). Ayrıca ALL=1 gibi belirteçler de elenir.
_BUILTIN = {"discord.com", "discord.gg", "discord.media", "discord.store", "discord.net",
            "discordapp.com", "discordapp.net", "discord.dev", "discordstatus.com",
            "roblox.com", "rbxcdn.com", "rbxinfra.net", "rbxtrk.com", "roblox.cn.com"}


def _probe_targets() -> list[str]:
    """Tarama hedefleri: sabit discord/roblox + kullanıcının hostlist'e eklediği
    özel siteler (ör. pornhub.com). Böylece tara, eklenen siteyi açan stratejiyi de
    arar. ALL=1 belirteci ve gömülü alanlar elenir."""
    targets = list(PROBE_TARGETS)
    for d in paths.load_list(paths.active_hostlist_file()):
        if d in paths.ALL_SITES_TOKENS or d in _BUILTIN or d in targets:
            continue
        targets.append(d)
        if len(targets) >= len(PROBE_TARGETS) + MAX_CUSTOM_TARGETS:
            break
    return targets


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


def _score_current(targets: list[str]) -> tuple[int, float]:
    """Aktif motor ile başarı sayısı ve toplam gecikme (verilen hedefler üzerinden)."""
    ok = 0
    total_latency = 0.0
    for dom in targets:
        for _ in range(TRIES_PER_TARGET):
            dt = _tls_handshake(dom)
            if dt is not None:
                ok += 1
                total_latency += dt
    return ok, total_latency


def scan(operator: str = "auto", verbose: bool = False) -> str | None:
    """Stratejileri dene, en iyisinin adını döndür (veya None)."""
    order = strategies.PROBE_ORDER.get(operator, strategies.PROBE_ORDER["auto"])
    targets = _probe_targets()
    maxok = len(targets) * TRIES_PER_TARGET

    results: list[tuple[str, int, float]] = []
    with _platform().ProbeEnv() as env:
        proc = None
        try:
            for strat in order:
                if strat not in strategies.STRATEGIES:
                    continue
                proc = env.spawn(strat)
                time.sleep(env.settle)  # motor yakalamaya bağlansın
                ok, lat = _score_current(targets)
                if verbose:
                    bar = f"{ok}/{maxok}"
                    extra = f" ({lat/ok:.2f}s ort)" if ok else ""
                    print(f"  {strategies.STRATEGIES[strat]['label']:32} {bar}{extra}")
                results.append((strat, ok, lat))
                env.kill(proc)
                proc = None
                # Tam başarı + makul gecikme ise erken çık
                if ok == maxok and lat / max(ok, 1) < 1.0:
                    break
        finally:
            if proc is not None:
                env.kill(proc)

    # en iyi: en çok başarı, eşitlikte en düşük ortalama gecikme
    working = [(s, ok, lat) for s, ok, lat in results if ok > 0]
    if not working:
        return None
    working.sort(key=lambda x: (-x[1], x[2] / x[1]))
    return working[0][0]
