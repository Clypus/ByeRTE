#!/usr/bin/env python3
"""ByeRTE grafik arayüzü (Windows, tkinter/ttk).

Kullanıcı olarak çalışır; ayrıcalıklı işlemler `byerte` CLI'ı UAC ile yükseltilerek
yapılır (Linux GTK arayüzünün `pkexec` modelinin karşılığı). Durum tespiti
yetkisizdir: DoH köprüsü (127.0.0.1:<port>) yanıt veriyorsa ByeRTE açıktır.

Yalnızca stdlib (tkinter) kullanır — PyInstaller ile sorunsuz donar.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk

# byerte paketini bul (donmuş / kurulu / repo)
if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from byerte import config, paths  # noqa: E402
from byerte.dns import answer_count, make_query  # noqa: E402
from byerte.win import winutil  # noqa: E402

OPERATORS = [
    ("auto", "Otomatik (önerilen)"),
    ("turk-telekom", "Türk Telekom / TTNet"),
    ("superonline", "Superonline / Turkcell"),
    ("vodafone", "Vodafone"),
    ("turkcell-mobil", "Turkcell Mobil"),
    ("kablonet", "Kablonet"),
]

TASK_NAME = "ByeRTE"
_NOWIN = {"creationflags": winutil.CREATE_NO_WINDOW}

OK_COLOR = "#2ec27e"
FAIL_COLOR = "#e01b24"
IDLE_COLOR = "#9a9996"


# --- Yetkisiz durum tespiti --------------------------------------------------

def bridge_up(timeout: float = 2.0) -> bool:
    """DoH köprüsü 127.0.0.1:<port> çözüyor mu? (ByeRTE açık mı)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(make_query("discord.com"), (paths.DNS_BRIDGE_ADDR, paths.DNS_BRIDGE_PORT))
        resp, _ = s.recvfrom(4096)
        return answer_count(resp) > 0
    except OSError:
        return False


def tls_ok(domain: str, timeout: float = 6.0) -> bool:
    """Gerçek TLS el sıkışması tamamlanıyor mu (engel aşılıyor mu)?"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                return bool(ss.version())
    except Exception:  # noqa: BLE001
        return False


def autostart_enabled() -> bool:
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                           capture_output=True, **_NOWIN)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


# --- byerte CLI'ı yükseltilmiş çalıştır --------------------------------------

def _run_cli_elevated(args: list[str]) -> int:
    """byerte CLI'ı UAC ile (gizli konsol) çalıştır, çıkış kodunu döndür.
    126 = yetki verilmedi.

    winutil.self_argv donmuş modda kardeş byerte.exe'yi (CLI) hedefler — GUI
    exe'sinin kendisini değil — bu yüzden tek çağrı iki durumu da kapsar."""
    return winutil.run_byerte_elevated(args, show_window=False)


# --- Uygulama ----------------------------------------------------------------

class ByeRTEApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self._busy = False
        root.title("ByeRTE — Bye Restrictions, Throttling & Eavesdropping")
        root.geometry("460x600")
        root.minsize(420, 560)

        style = ttk.Style(root)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Hero.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 10), foreground=IDLE_COLOR)
        style.configure("Big.TButton", font=("Segoe UI", 13, "bold"), padding=12)

        outer = ttk.Frame(root, padding=24)
        outer.pack(fill="both", expand=True)

        # Durum kahramanı
        self.icon = ttk.Label(outer, text="●", font=("Segoe UI", 64), foreground=IDLE_COLOR)
        self.icon.pack(pady=(8, 4))
        self.title_lbl = ttk.Label(outer, text="…", style="Hero.TLabel")
        self.title_lbl.pack()
        self.sub_lbl = ttk.Label(outer, text="durum okunuyor", style="Sub.TLabel")
        self.sub_lbl.pack(pady=(0, 16))

        # Büyük aç/kapat
        self.toggle = ttk.Button(outer, text="Aç", style="Big.TButton", command=self._on_toggle)
        self.toggle.pack(fill="x", pady=(0, 18))

        # Ayarlar
        box = ttk.LabelFrame(outer, text="Ayarlar", padding=12)
        box.pack(fill="x", pady=(0, 12))
        ttk.Label(box, text="Operatör").grid(row=0, column=0, sticky="w", pady=4)
        self.op = ttk.Combobox(box, state="readonly", values=[lbl for _, lbl in OPERATORS])
        self.op.current(0)
        self.op.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        box.columnconfigure(1, weight=1)

        self.scan_btn = ttk.Button(box, text="Tara", command=self._on_scan)
        self.scan_btn.grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(box, text="Operatör için en iyi ayarı dener",
                  style="Sub.TLabel").grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(8, 0))

        # Düzenlenebilir listeler
        lists = ttk.Frame(box)
        lists.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        ttk.Button(lists, text="Siteler…",
                   command=lambda: self._open_list(paths.user_hostlist_file())).pack(side="left")
        ttk.Button(lists, text="Hariç tut…",
                   command=lambda: self._open_list(paths.denylist_file())).pack(side="left", padx=(8, 0))
        ttk.Label(box, text="Siteler: bypass uygulananlar • Hariç tut: hiç dokunulmayanlar (API'ler)",
                  style="Sub.TLabel", wraplength=380).grid(row=3, column=0, columnspan=2,
                                                           sticky="w", pady=(4, 0))

        # Erişim göstergeleri
        acc = ttk.LabelFrame(outer, text="Erişim", padding=12)
        acc.pack(fill="x", pady=(0, 12))
        self.discord_dot = self._probe_row(acc, 0, "Discord")
        self.roblox_dot = self._probe_row(acc, 1, "Roblox")
        acc.columnconfigure(1, weight=1)

        # Açılışta başlat
        self.autostart_btn = ttk.Button(outer, text="Açılışta başlatmayı aç",
                                        command=self._on_autostart)
        self.autostart_btn.pack(fill="x")

        # Bildirim / günlük satırı
        self.toast = ttk.Label(outer, text="", style="Sub.TLabel")
        self.toast.pack(side="bottom", pady=(12, 0))

        self._refresh_async()
        self._schedule_tick()

    def _probe_row(self, parent, row, title) -> ttk.Label:
        ttk.Label(parent, text=title).grid(row=row, column=0, sticky="w", pady=3)
        dot = ttk.Label(parent, text="●", foreground=IDLE_COLOR, font=("Segoe UI", 14))
        dot.grid(row=row, column=2, sticky="e", pady=3)
        return dot

    # --- durum ---------------------------------------------------------------

    def _schedule_tick(self):
        if not self._busy:
            self._refresh_async()
        self.root.after(5000, self._schedule_tick)

    def _refresh_async(self):
        def work():
            up = bridge_up()
            d = tls_ok("discord.com")
            r = tls_ok("www.roblox.com")
            auto = autostart_enabled()
            try:
                paused = bool(config.read_state().get("paused_for_vpn"))
            except Exception:  # noqa: BLE001
                paused = False
            self.root.after(0, lambda: self._apply_status(up, d, r, auto, paused))
        threading.Thread(target=work, daemon=True).start()

    def _apply_status(self, up, d, r, auto, paused=False):
        if paused and up:
            self.icon.configure(foreground=IDLE_COLOR)
            self.title_lbl.configure(text="Duraklatıldı")
            self.sub_lbl.configure(text="VPN algılandı — VPN'iniz zaten koruyor")
            self.toggle.configure(text="Kapat")
        elif up:
            self.icon.configure(foreground=OK_COLOR)
            self.title_lbl.configure(text="Açık")
            self.sub_lbl.configure(text="Discord ve Roblox engeli aşılıyor")
            self.toggle.configure(text="Kapat")
        else:
            self.icon.configure(foreground=IDLE_COLOR)
            self.title_lbl.configure(text="Kapalı")
            self.sub_lbl.configure(text="Koruma devre dışı — sistem normal")
            self.toggle.configure(text="Aç")
        self.discord_dot.configure(foreground=OK_COLOR if d else FAIL_COLOR)
        self.roblox_dot.configure(foreground=OK_COLOR if r else FAIL_COLOR)
        self.autostart_btn.configure(
            text="Açılışta başlatmayı kapat" if auto else "Açılışta başlatmayı aç")
        self._auto_on = auto

    def _selected_operator(self) -> str:
        return OPERATORS[self.op.current()][0]

    def _open_list(self, path) -> None:
        """Bir liste dosyasını varsayılan düzenleyicide (notepad) aç. Yoksa önce
        tohumla. Değişiklik bir sonraki aç/kapat ile etkinleşir."""
        try:
            paths.seed_user_lists()
        except Exception:  # noqa: BLE001
            pass
        try:
            os.startfile(str(path))  # type: ignore[attr-defined]  (Windows)
            self.toast.configure(text="Düzenledikten sonra: kapat → aç")
        except Exception:  # noqa: BLE001
            self.toast.configure(text=f"açılamadı: {path}")

    # --- eylemler ------------------------------------------------------------

    def _on_toggle(self):
        if self._busy:
            return
        if self.title_lbl.cget("text") in ("Açık", "Duraklatıldı"):
            self._run(["kapat"], "Kapatılıyor…")
        else:
            self._run(["aç", "--operator", self._selected_operator()], "Açılıyor…")

    def _on_scan(self):
        if self._busy:
            return
        self._run(["tara", "--operator", self._selected_operator()],
                  "Taranıyor… (biraz sürebilir)")

    def _on_autostart(self):
        if self._busy:
            return
        self._run(["acilis", "kapat" if getattr(self, "_auto_on", False) else "ac"],
                  "Açılış ayarı değiştiriliyor…")

    def _run(self, args, busy_msg):
        self._busy = True
        self._set_sensitive(False)
        self.toast.configure(text=busy_msg)

        def work():
            try:
                rc = _run_cli_elevated(args)
                msg = "yetki verilmedi" if rc == 126 else ("tamam" if rc == 0 else f"hata ({rc})")
            except Exception as e:  # noqa: BLE001
                msg = str(e)
            self.root.after(0, lambda: self._done(msg))
        threading.Thread(target=work, daemon=True).start()

    def _done(self, msg):
        self._busy = False
        self._set_sensitive(True)
        self.toast.configure(text=msg)
        self._refresh_async()

    def _set_sensitive(self, on: bool):
        state = "normal" if on else "disabled"
        self.toggle.configure(state=state)
        self.scan_btn.configure(state=state)
        self.autostart_btn.configure(state=state)
        self.op.configure(state="readonly" if on else "disabled")


def main():
    root = tk.Tk()
    ByeRTEApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
