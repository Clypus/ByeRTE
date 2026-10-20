# ByeRTE

**A GoodbyeDPI-style DPI bypass for Linux & Windows — unblocks Discord & Roblox in Turkey.**
**Linux ve Windows için GoodbyeDPI tarzı DPI engel aşıcı — Discord & Roblox (Türkiye).**

ByeRTE is **not a VPN**. Your traffic never leaves your machine through anyone's
server — packets are only processed locally. It defeats both layers of the block:
DNS poisoning (via a local DoH bridge) and SNI-based DPI (via the zapret2 engine —
`nfqws2` on Linux, `winws2` on Windows).

> **Core promise:** turning it off restores the system **completely**. If the engine
> crashes your internet does **not** drop (fail-open). No persistent settings are
> changed; a reboot comes up clean. Opt-in autostart only.
>
> - **Linux:** one `nftables` table with `bypass` queue rules (`/etc/resolv.conf`,
>   sysctl, systemd-resolved are **never touched**).
> - **Windows:** all interception is handle-based (WinDivert). The moment the engine
>   process exits — normal quit, crash, or `taskkill /F` — every WinDivert handle is
>   closed by the OS and capture stops instantly, so there is no persistent state to
>   leak. No registry, firewall, or DNS settings are changed.

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

## Install (Linux) / Kurulum

```bash
git clone https://github.com/Clypus/ByeRTE.git && cd ByeRTE
sudo ./install.sh
```

The installer only installs **missing** dependencies (it never upgrades present
packages — avoids Arch partial-upgrade breakage) and verifies bundled binaries by
SHA-256. Needs: `nftables`, `python3` (core) and `gtk4` + `libadwaita` +
`python-gobject` (GUI). Supports Arch/EndeavourOS, Ubuntu/Mint, Fedora, openSUSE.

> On Arch, run `sudo pacman -Syu` first if anything is out of date.

## Install (Windows) / Windows Kurulumu

Needs **Windows 10/11 x64**. Easiest — no Python needed:

1. Download **`ByeRTE-windows-x64.zip`** from the
   [Releases](https://github.com/Clypus/ByeRTE/releases/latest) page.
2. **Extract it to a folder** (don't run it from inside the zip).
3. Run **`byerte-gui.exe`** (portable), or right-click `install.ps1` → *Run with
   PowerShell* to install to `%ProgramFiles%\ByeRTE` (PATH + Start-Menu shortcut).

The exe is not code-signed, so SmartScreen may warn on first run: *More info →
Run anyway*.

**Build from source** (Python 3.10+; the GUI uses stdlib `tkinter`, `winws2.exe` +
WinDivert are bundled):

```powershell
# 1) build the two exes (verifies bundled binaries by SHA-256 first)
python packaging\windows\build.py
# 2) install to %ProgramFiles%\ByeRTE  (adds PATH + Start-Menu shortcut; UAC prompt)
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1
```

Or **portable**: just copy `dist\ByeRTE\` anywhere and run `byerte-gui.exe`.

- Privilege is obtained via **UAC** (the CLI self-elevates; the GUI elevates per
  action — the equivalent of `sudo`/`pkexec` on Linux). `byerte durum` needs no admin.
- The **WinDivert** driver installs itself on the first `byerte aç` (one UAC prompt)
  and is removed by `uninstall.ps1` (or on reboot). **Antivirus software may flag
  WinDivert** — it is a legitimate packet-filter driver (the Windows equivalent of
  `nftables`/`iptables`), not malware; add an exclusion if needed.
- Autostart uses a **Task Scheduler** task (`byerte acilis ac`), run at logon with
  the highest privileges — no logon password/UAC prompt, no Windows service.

## Usage / Kullanım

```bash
byerte aç            # start — auto-detects operator (ASN) and picks the strategy
byerte aç --operator turk-telekom   # or: superonline | vodafone | turkcell-mobil | ...
byerte durum         # status: on/off, DNS, Discord/Roblox reachability
byerte tara          # auto-find the best working strategy on your line
byerte kapat         # stop, revert the system
byerte acilis ac     # (optional) start automatically at boot
```

The same commands work on **Windows** (from any terminal once installed, or the
elevated window the CLI opens). There `acilis ac` creates the logon Task Scheduler
task instead of enabling a systemd unit.

GUI: launch **ByeRTE** from your app menu (or `byerte-gui`) — a big on/off switch,
operator selector and a "Tara" (scan) button. On Linux it uses `pkexec` (needs a
polkit agent; present on GNOME/KDE, use e.g. `hyprpolkitagent` on Hyprland). On
Windows (Start Menu → **ByeRTE**) each action raises a UAC prompt.

### After turning it on, restart your apps / Açtıktan sonra uygulamaları yeniden başlat

Apps already running when you `byerte aç` can stay stuck ("Discord: checking for
updates", Roblox web → "Experiences failed to load", Sober won't open) because they
cached the **poisoned DNS**. This is not a bypass failure — the poisoned entry (e.g.
`apis.roblox.com` → a TT sinkhole IP) lingers in a cache until its TTL expires:

- **Windows:** the engine runs `ipconfig /flushdns` automatically on start, so the
  OS cache is clean — but **browsers keep their own DNS cache**, so hard-reload the
  Roblox tab (Ctrl+Shift+R) or fully reopen the browser. Desktop apps: quit & reopen.
- **Linux:** fully quit and reopen the app — Discord (tray → Quit), Sober
  (`flatpak kill org.vinegarhq.Sober`).

Best order: run `byerte aç` **first**, then open the apps.

## Custom site lists / Site listeleri

ByeRTE ships two **user-editable** lists. Edit them, then re-apply with
`byerte kapat && byerte aç` (or the GUI off/on):

- **`hostlist.txt`** — sites the DPI bypass is **applied to**. Discord & Roblox come
  preloaded; **add any other blocked site here** (e.g. a site + its CDN domain).
  Subdomains apply automatically. DNS is already handled for every site (global DoH),
  so adding a domain here is usually all it takes to unblock it.
- **`denylist.txt`** — sites to **leave completely alone**: no DPI desync, and DNS
  resolved by your normal resolver (not DoH). Use this for third-party APIs that
  misbehave through ByeRTE. Opt-in — empty by default, so nothing changes until you
  add a domain.

Locations: **Windows** `%ProgramData%\ByeRTE\hostlist.txt` / `denylist.txt` (or the
GUI's **Siteler… / Hariç tut…** buttons); **Linux** `/etc/byerte/hostlist.txt` /
`denylist.txt`.

> On Linux the denylist currently affects the **DPI layer only** (DNS exclusion is
> Windows-only for now). The include `hostlist` works on both.

## Safety / Güvenlik

**Linux**

| Event | Result |
|---|---|
| nfqws2 crashes | packets pass via `bypass`, internet stays up; systemd restarts it |
| engine `kill -9` | systemd `ExecStopPost` deletes the table → DNS/internet back to normal |
| `byerte kapat` | table removed, DNS/HTTPS normal instantly |
| reboot | service off by default (opt-in) → clean boot |

**Windows**

| Event | Result |
|---|---|
| winws2 crashes | its WinDivert handle closes → DPI bypass off; the engine exits and is relaunched by `aç`/autostart |
| engine `taskkill /F` | the OS closes all WinDivert handles (DNS + DPI) → everything reverts instantly |
| `byerte kapat` | engine process tree killed, WinDivert handles closed → DNS/HTTPS normal instantly |
| reboot | nothing starts unless autostart (opt-in) is enabled → clean boot |

Only Discord/Roblox domains (the hostlist) are touched; other traffic is unchanged.

## Uninstall / Kaldırma

```bash
# Linux
sudo ./uninstall.sh           # remove files + service, delete the table
sudo ./uninstall.sh --purge   # also remove /etc/byerte config
```

```powershell
# Windows (Yönetici PowerShell)
powershell -ExecutionPolicy Bypass -File packaging\windows\uninstall.ps1
powershell -ExecutionPolicy Bypass -File packaging\windows\uninstall.ps1 -Purge   # config de silinir
```

## License

GPLv3 (the bundled zapret2 engine and Lua scripts are GPLv3). See `LICENSE` and
`NOTICE`. zapret2 © bol-van; Turkish strategy presets adapted from Unwall and
splitwire-turkey. Türkçe ayrıntılı rehber: [README.tr.md](README.tr.md).

> Anti-censorship tool for lawful, educational use on networks you are authorized to use.
