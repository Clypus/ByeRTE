# ByeRTE

**A GoodbyeDPI-style DPI bypass for Linux — unblocks Discord & Roblox in Turkey.**
**Linux için GoodbyeDPI tarzı DPI engel aşıcı — Discord & Roblox (Türkiye).**

ByeRTE is **not a VPN**. Your traffic never leaves your machine through anyone's
server — packets are only processed locally. It defeats both layers of the block:
DNS poisoning (via a local DoH bridge) and SNI-based DPI (via the zapret2 `nfqws2`
engine).

> **Core promise:** turning it off restores the system **completely**. If the engine
> crashes your internet does **not** drop (fail-open). No persistent settings are
> changed (`/etc/resolv.conf`, sysctl, systemd-resolved are **never touched**); a
> reboot comes up clean. Opt-in autostart only.

Confirmed working on Türk Telekom (DNS poisoning + TCP/TLS SNI RST-injection):
Discord desktop app, Roblox web, and Sober all reachable.

---

## How it works / Nasıl çalışır

- **Engine:** bundled [zapret2](https://github.com/bol-van/zapret2) `nfqws2` (static, GPLv3).
- **One `inet byerte` nftables table.** Queue rules use `bypass` → if the engine dies,
  packets pass through untouched (fail-open, internet never breaks).
- **DNS:** all port-53 traffic is redirected (same table, `nat` chain) to a local
  stdlib DoH bridge on `127.0.0.1:5355`. It connects to **CDN-fronted** DoH endpoints
  (Cloudflare `mozilla.cloudflare-dns.com`, NextDNS, ControlD) by pinned IP — the famous
  resolver IPs (1.1.1.1 …) are blocked on 443 in Turkey, so this is required.
- **Off = `nft delete table inet byerte`** → instant, full revert. A systemd
  `ExecStopPost` removes the table even on `kill -9`.

## Install / Kurulum

```bash
unzip byerte.zip && cd ByeRTE    # or: git clone … && cd ByeRTE
sudo ./install.sh
```

The installer only installs **missing** dependencies (it never upgrades present
packages — avoids Arch partial-upgrade breakage) and verifies bundled binaries by
SHA-256. Needs: `nftables`, `python3` (core) and `gtk4` + `libadwaita` +
`python-gobject` (GUI). Supports Arch/EndeavourOS, Ubuntu/Mint, Fedora, openSUSE.

> On Arch, run `sudo pacman -Syu` first if anything is out of date.

## Usage / Kullanım

```bash
byerte aç            # start — auto-detects operator (ASN) and picks the strategy
byerte aç --operator turk-telekom   # or: superonline | vodafone | turkcell-mobil | ...
byerte durum         # status: on/off, DNS, Discord/Roblox reachability
byerte tara          # auto-find the best working strategy on your line
byerte kapat         # stop, revert the system
byerte acilis ac     # (optional) start automatically at boot
```

GUI: launch **ByeRTE** from your app menu (or `byerte-gui`) — a big on/off switch,
operator selector and a "Tara" (scan) button. It uses `pkexec` (needs a polkit agent;
present on GNOME/KDE, use e.g. `hyprpolkitagent` on Hyprland).

### After turning it on, restart your apps / Açtıktan sonra uygulamaları yeniden başlat

Apps already running when you `byerte aç` can stay stuck ("Discord: checking for
updates", Sober won't open) because they cached the **poisoned DNS**. This is not a
bypass failure — fully quit and reopen them:

- Discord: quit completely (tray → Quit), reopen
- Sober:  `flatpak kill org.vinegarhq.Sober`, then reopen

Best order: run `byerte aç` **first**, then open the apps.

## Safety / Güvenlik

| Event | Result |
|---|---|
| nfqws2 crashes | packets pass via `bypass`, internet stays up; systemd restarts it |
| engine `kill -9` | systemd `ExecStopPost` deletes the table → DNS/internet back to normal |
| `byerte kapat` | table removed, DNS/HTTPS normal instantly |
| reboot | service off by default (opt-in) → clean boot |

Only Discord/Roblox domains (the hostlist) are touched; other traffic is unchanged.

## Uninstall / Kaldırma

```bash
sudo ./uninstall.sh           # remove files + service, delete the table
sudo ./uninstall.sh --purge   # also remove /etc/byerte config
```

## License

GPLv3 (the bundled zapret2 engine and Lua scripts are GPLv3). See `LICENSE` and
`NOTICE`. zapret2 © bol-van; Turkish strategy presets adapted from Unwall and
splitwire-turkey. Türkçe ayrıntılı rehber: [README.tr.md](README.tr.md).

> Anti-censorship tool for lawful, educational use on networks you are authorized to use.
