"""DPI atlatma stratejileri (zapret2 nfqws2 LUA) ve operatör eşlemeleri.

Her strateji, nfqws2 için bir profil kümesine çevrilir. Tüm strateji dizeleri
`nfqws2 --dry-run` ile doğrulanabilir (bkz. validate_all / byerte.probe).

Kaynak: Unwall (github.com/WinTone01/Unwall) ve splitwire-turkey preset'leri.
"""

from __future__ import annotations

from . import paths

# --- Strateji tanımları ------------------------------------------------------
# tls  : TCP/443 TLS ClientHello için --lua-desync dizesi
# quic : UDP/443 QUIC Initial için --lua-desync dizesi (None = QUIC'e dokunma)
# label: kullanıcıya gösterilen ad

# tls/quic: bir profildeki --lua-desync fonksiyon ZİNCİRİ (sıra önemli).
# TT hotspot'ta canlı doğrulandı (2026-10): md5sig fooling'li fake, TT'nin SNI
# üzerine RST enjeksiyonunu aşıyor; multisplit SNI yeniden-birleştirmeye karşı
# ikinci kat. Discord app + Sober dahil 12 alan adında 36/36.
_MD5_SPLIT = ["fake:blob=fake_default_tls:tcp_md5", "multisplit:pos=1,midsld"]
_QUIC_DEFAULT = ["fake:blob=fake_default_quic:ip_ttl=4"]

STRATEGIES: dict[str, dict] = {
    "turk-telekom": {
        "label": "Türk Telekom / TTNet",
        "tls": _MD5_SPLIT,
        "quic": _QUIC_DEFAULT,
    },
    "turk-telekom-alt": {
        "label": "Türk Telekom (alternatif, ttl)",
        "tls": ["fake:blob=fake_default_tls:ip_ttl=4"],
        "quic": _QUIC_DEFAULT,
    },
    "md5sig": {
        "label": "Sade md5sig (TT ailesi)",
        "tls": ["fake:blob=fake_default_tls:tcp_md5"],
        "quic": _QUIC_DEFAULT,
    },
    "superonline": {
        "label": "Superonline / Turkcell",
        "tls": _MD5_SPLIT,
        "quic": _QUIC_DEFAULT,
    },
    "vodafone": {
        "label": "Vodafone",
        "tls": _MD5_SPLIT,
        "quic": _QUIC_DEFAULT,
    },
    "turkcell-mobil": {
        "label": "Turkcell Mobil / Hotspot",
        "tls": ["fake:blob=fake_default_tls:ip_ttl=4"],
        "quic": _QUIC_DEFAULT,
    },
    "kablonet": {
        "label": "Kablonet / TurkNet",
        "tls": _MD5_SPLIT,
        "quic": _QUIC_DEFAULT,
    },
    # Bilinmeyen ISS için genel/güçlü seçenekler
    "genel-1": {
        "label": "Genel: md5sig + disorder",
        "tls": ["fake:blob=fake_default_tls:tcp_md5", "multidisorder:pos=1,midsld"],
        "quic": _QUIC_DEFAULT,
    },
    "genel-2": {
        "label": "Genel: split + seqovl",
        "tls": ["multisplit:pos=1,midsld:seqovl=3"],
        "quic": _QUIC_DEFAULT,
    },
}

DEFAULT_STRATEGY = "turk-telekom"

# ASN → strateji. ASN, zehirlenmemiş yoldan (DoH) sorulur. Bkz. byerte.isp.
ASN_TO_STRATEGY: dict[int, str] = {
    9121: "turk-telekom",     # Türk Telekom
    47331: "turk-telekom",    # TTNet (bazı bloklar)
    34984: "superonline",     # Superonline (Turkcell)
    16135: "turkcell-mobil",  # Turkcell mobil
    15897: "vodafone",        # Vodafone TR
    197328: "vodafone",       # Vodafone Net
    47524: "kablonet",        # Kablonet (Turksat)
    12735: "turk-telekom",    # TurkNet → TT benzeri davranır
}

# Bir operatör için denenecek strateji sırası (byerte tara bunu kullanır).
# En güvenilir (md5sig) başta.
PROBE_ORDER: dict[str, list[str]] = {
    "turk-telekom": ["turk-telekom", "md5sig", "turk-telekom-alt", "genel-1", "genel-2"],
    "superonline": ["superonline", "md5sig", "turk-telekom-alt", "genel-1", "genel-2"],
    "vodafone": ["vodafone", "md5sig", "turkcell-mobil", "genel-1", "genel-2"],
    "turkcell-mobil": ["turkcell-mobil", "md5sig", "superonline", "genel-1", "genel-2"],
    "kablonet": ["kablonet", "md5sig", "genel-1", "genel-2"],
    "auto": ["turk-telekom", "md5sig", "turk-telekom-alt", "genel-1", "genel-2"],
}


def _as_list(v) -> list[str]:
    return v if isinstance(v, list) else [v]


def resolve_strategy(name: str) -> str:
    """İsim ya da operatör anahtarını geçerli bir strateji adına çevir."""
    if name in STRATEGIES:
        return name
    aliases = {"tt": "turk-telekom", "ttnet": "turk-telekom",
               "turkcell": "superonline", "vf": "vodafone"}
    if name in aliases:
        return aliases[name]
    return DEFAULT_STRATEGY


def _engine_header(s: dict, with_quic: bool) -> list[str]:
    """Motorun platforma özel başı. Profiller (aşağıda) iki platformda aynıdır."""
    if paths.IS_WINDOWS:
        # winws2: nftables yok; yakalamayı kendi WinDivert filtresi yapar. Giden
        # TCP 80/443 + gelen SYN/FIN/RST (filtre kurucusu ekler). UDP 443 yalnızca
        # QUIC profili varsa yakalanır. --user yok: winws2 başlatıldıktan sonra
        # kendini Low integrity + job sandbox'a alır.
        argv = [str(paths.winws2_bin()), f"--wf-tcp-out={paths.PORTS_TCP}"]
        if with_quic and s.get("quic"):
            argv.append(f"--wf-udp-out={paths.PORTS_UDP}")
        return argv
    return [
        str(paths.nfqws2_bin()),
        f"--qnum={paths.QUEUE_NUM}",
        f"--fwmark=0x{paths.FWMARK:08X}",
        f"--user={paths.DROP_USER}",
    ]


def build_argv(strategy_name: str, *, with_quic: bool = True,
               autohostlist: bool = True, with_exclude: bool = False,
               all_sites: bool = False) -> list[str]:
    """Bir strateji için tam nfqws2 / winws2 argüman listesini üret.

    Her profil kendi filtrelerini taşır (zapret2'de filtreler profil-özeldir);
    profiller --new ile AYRILIR. Hiçbir profile uymayan paketler örtük boş
    profil 0'a düşer ve dokunulmadan geçer.

    with_exclude=True ise her profile --hostlist-exclude=<denylist> eklenir
    (denylist'teki alanlara DPI uygulanmaz). Varsayılan False: denylist boşken
    argv birebir eskisi gibi kalır.

    all_sites=True ise --hostlist (ve --hostlist-auto) EKLENMEZ → desync TÜM
    TLS/QUIC akışlarına uygulanır (denylist yine hariç tutar). CPU'yu artırır ve
    engelsiz bazı siteleri bozabilir; bilinçli bir seçenektir.
    """
    s = STRATEGIES[strategy_name]
    # Çalışma anı kopyası (/run/byerte): nfqws2 nobody'ye düşünce de okuyabilsin.
    hostlist = paths.arg_path(paths.active_hostlist_file())
    auto = paths.arg_path(paths.autohostlist_file())
    exclude = paths.arg_path(paths.active_denylist_file()) if with_exclude else None

    argv: list[str] = _engine_header(s, with_quic)
    argv += paths.lua_init_args()

    # --- TLS profili (TCP/443) — İLK profil, başında --new YOK ---
    # zapret2'de --new profiller arası AYIRICIDIR. Başa konursa filtresiz boş bir
    # profil 1 oluşur; ilk eşleşen profil kazandığı için bu boş profil her paketi
    # alır ve hiçbir şey yapmadan geçirir (strateji hiç uygulanmaz).
    argv += ["--name=tls", "--filter-tcp=443"]
    if not all_sites:
        argv.append(f"--hostlist={hostlist}")
    if exclude:
        argv.append(f"--hostlist-exclude={exclude}")
    argv.append("--payload=tls_client_hello")
    for fn in _as_list(s["tls"]):
        argv.append(f"--lua-desync={fn}")
    if autohostlist and not all_sites:   # tüm siteler modunda auto-hostlist anlamsız
        argv += [
            f"--hostlist-auto={auto}",
            "--hostlist-auto-fail-threshold=2",
        ]

    # --- QUIC profili (UDP/443), opsiyonel ---
    if with_quic and s.get("quic"):
        argv += ["--new", "--name=quic", "--filter-udp=443"]
        if not all_sites:
            argv.append(f"--hostlist={hostlist}")
        if exclude:
            argv.append(f"--hostlist-exclude={exclude}")
        argv.append("--payload=quic_initial")
        for fn in _as_list(s["quic"]):
            argv.append(f"--lua-desync={fn}")

    return argv


def dry_run(strategy_name: str, **kw) -> tuple[bool, str]:
    """Stratejiyi nfqws2/winws2 --dry-run ile doğrula. (başarılı?, çıktı).

    Windows'ta winws2.exe manifest'i yönetici ister: --dry-run bile yetkisiz
    çalışmaz (WinError 740 → False döner)."""
    import subprocess

    # Doğrulama strateji sözdizimi içindir; autohostlist nobody'ye ait olduğundan
    # kök olmayan kullanıcıyla yazma testi başarısız olur — doğrulamada gereksiz.
    kw.setdefault("autohostlist", False)
    argv = build_argv(strategy_name, **kw)
    # --dry-run'ı araya ekle (intercept başlatmadan parametreleri doğrular).
    # --user=... yetki düşürmeyi dener (root gerektirir); doğrulamada gereksiz,
    # çıkar — yoksa root olmadan initgroups başarısız olur.
    argv = [a for a in argv if not a.startswith("--user=")]
    argv = [argv[0], "--dry-run"] + argv[1:]
    extra = {"creationflags": subprocess.CREATE_NO_WINDOW} if paths.IS_WINDOWS else {}
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=15, **extra)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return False, str(e)
