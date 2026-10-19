#!/usr/bin/env python3
"""ByeRTE grafik arayüzü (GTK4 + libadwaita).

Kullanıcı olarak çalışır; ayrıcalıklı işlemler `pkexec /usr/bin/byerte ...` ile.
Durum tespiti köksüzdür: DoH köprüsü (127.0.0.1:5355) yanıt veriyorsa ByeRTE açıktır.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

# byerte paketini bul (kurulu ya da repo)
sys.path.insert(0, "/usr/lib/byerte")
try:
    from byerte import paths, strategies
    from byerte.dns import answer_count, make_query
except ImportError:
    _repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, _repo)
    from byerte import paths, strategies
    from byerte.dns import answer_count, make_query

BYERTE_BIN = shutil.which("byerte") or "/usr/bin/byerte"

OPERATORS = [
    ("auto", "Otomatik (önerilen)"),
    ("turk-telekom", "Türk Telekom / TTNet"),
    ("superonline", "Superonline / Turkcell"),
    ("vodafone", "Vodafone"),
    ("turkcell-mobil", "Turkcell Mobil"),
    ("kablonet", "Kablonet"),
]


def bridge_up(timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(make_query("discord.com"), (paths.DNS_BRIDGE_ADDR, paths.DNS_BRIDGE_PORT))
        resp, _ = s.recvfrom(4096)
        return answer_count(resp) > 0
    except OSError:
        return False


def tls_ok(domain: str, timeout: float = 6.0) -> bool:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                return bool(ss.version())
    except Exception:  # noqa: BLE001
        return False


class ByeRTEWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="ByeRTE")
        self.set_default_size(460, 600)
        self._busy = False

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar.add_top_bar(header)

        # menü (açılışta başlat vb.)
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic")
        popover = Gtk.Popover()
        pbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, margin_top=8,
                       margin_bottom=8, margin_start=8, margin_end=8)
        self.autostart_btn = Gtk.Button(label="Açılışta başlatmayı aç")
        self.autostart_btn.connect("clicked", self._toggle_autostart)
        pbox.append(self.autostart_btn)
        popover.set_child(pbox)
        menu_btn.set_popover(popover)
        header.pack_end(menu_btn)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                          margin_top=24, margin_bottom=24, margin_start=24, margin_end=24)
        toolbar.set_content(content)
        self.set_content(toolbar)

        # Durum kahramanı
        self.status_icon = Gtk.Image(icon_name="network-offline-symbolic", pixel_size=72)
        content.append(self.status_icon)
        self.status_label = Gtk.Label()
        self.status_label.add_css_class("title-1")
        content.append(self.status_label)
        self.sub_label = Gtk.Label()
        self.sub_label.add_css_class("dim-label")
        content.append(self.sub_label)

        # Büyük aç/kapat
        self.switch = Gtk.Switch(halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        self.switch.set_size_request(80, 44)
        self._switch_handler = self.switch.connect("state-set", self._on_switch)
        content.append(self.switch)

        # Operatör seçimi
        group = Adw.PreferencesGroup(title="Ayarlar")
        self.op_row = Adw.ComboRow(title="Operatör")
        op_model = Gtk.StringList()
        for _, label in OPERATORS:
            op_model.append(label)
        self.op_row.set_model(op_model)
        group.add(self.op_row)

        scan_row = Adw.ActionRow(title="Çalışan stratejiyi bul", subtitle="Operatör için en iyi ayarı dener")
        self.scan_btn = Gtk.Button(label="Tara", valign=Gtk.Align.CENTER)
        self.scan_btn.add_css_class("suggested-action")
        self.scan_btn.connect("clicked", self._on_scan)
        scan_row.add_suffix(self.scan_btn)
        scan_row.set_activatable_widget(self.scan_btn)
        group.add(scan_row)
        content.append(group)

        # Erişim göstergeleri
        probe_group = Adw.PreferencesGroup(title="Erişim")
        self.discord_row = Adw.ActionRow(title="Discord")
        self.discord_dot = Gtk.Image(icon_name="content-loading-symbolic")
        self.discord_row.add_suffix(self.discord_dot)
        probe_group.add(self.discord_row)
        self.roblox_row = Adw.ActionRow(title="Roblox")
        self.roblox_dot = Gtk.Image(icon_name="content-loading-symbolic")
        self.roblox_row.add_suffix(self.roblox_dot)
        probe_group.add(self.roblox_row)
        content.append(probe_group)

        # Günlük / bildirim
        self.toast = Adw.ToastOverlay()
        self.toast.set_child(toolbar)
        self.set_content(self.toast)

        self._refresh()
        GLib.timeout_add_seconds(5, self._tick)

    # --- durum ---------------------------------------------------------------

    def _tick(self):
        if not self._busy:
            self._refresh_async()
        return True

    def _refresh_async(self):
        def work():
            up = bridge_up()
            d = tls_ok("discord.com")
            r = tls_ok("www.roblox.com")
            GLib.idle_add(self._apply_status, up, d, r)
        threading.Thread(target=work, daemon=True).start()

    def _refresh(self):
        self._refresh_async()

    def _apply_status(self, up, d, r):
        self.switch.handler_block(self._switch_handler)
        self.switch.set_active(up)
        self.switch.handler_unblock(self._switch_handler)
        if up:
            self.status_icon.set_from_icon_name("network-vpn-symbolic")
            self.status_label.set_text("Açık")
            self.sub_label.set_text("Discord ve Roblox engeli aşılıyor")
        else:
            self.status_icon.set_from_icon_name("network-offline-symbolic")
            self.status_label.set_text("Kapalı")
            self.sub_label.set_text("Koruma devre dışı — sistem normal")
        for dot, ok in ((self.discord_dot, d), (self.roblox_dot, r)):
            dot.set_from_icon_name("emblem-ok-symbolic" if ok else "dialog-error-symbolic")
        self._update_autostart_label()
        return False

    def _selected_operator(self) -> str:
        return OPERATORS[self.op_row.get_selected()][0]

    # --- eylemler ------------------------------------------------------------

    def _on_switch(self, _sw, state):
        if self._busy:
            return True
        if state:
            self._run(["aç", "--operator", self._selected_operator()], "Açılıyor…")
        else:
            self._run(["kapat"], "Kapatılıyor…")
        return True  # durumu biz _refresh ile ayarlarız

    def _on_scan(self, _btn):
        if self._busy:
            return
        self._run(["tara", "--operator", self._selected_operator()], "Taranıyor… (biraz sürebilir)")

    def _toggle_autostart(self, _btn):
        enabled = self._autostart_enabled()
        self._run(["acilis", "kapat" if enabled else "ac"],
                  "Açılış ayarı değiştiriliyor…")

    def _run(self, args, busy_msg):
        self._busy = True
        self._set_sensitive(False)
        self.toast.add_toast(Adw.Toast(title=busy_msg, timeout=2))

        def work():
            try:
                p = subprocess.run(["pkexec", BYERTE_BIN, *args],
                                   capture_output=True, text=True, timeout=120)
                out = (p.stdout + p.stderr).strip().splitlines()
                msg = out[-1] if out else ("tamam" if p.returncode == 0 else "hata")
                rc = p.returncode
            except Exception as e:  # noqa: BLE001
                msg, rc = str(e), 1
            GLib.idle_add(self._done, msg, rc)
        threading.Thread(target=work, daemon=True).start()

    def _done(self, msg, rc):
        self._busy = False
        self._set_sensitive(True)
        # pkexec iptal = 126/127
        if rc in (126, 127):
            msg = "yetki verilmedi"
        self.toast.add_toast(Adw.Toast(title=msg, timeout=3))
        self._refresh_async()
        return False

    def _set_sensitive(self, s):
        self.switch.set_sensitive(s)
        self.scan_btn.set_sensitive(s)
        self.op_row.set_sensitive(s)

    # --- açılışta başlatma ---------------------------------------------------

    def _autostart_enabled(self) -> bool:
        return subprocess.run(["systemctl", "is-enabled", "--quiet", "byerte.service"]).returncode == 0

    def _update_autostart_label(self):
        try:
            en = self._autostart_enabled()
            self.autostart_btn.set_label("Açılışta başlatmayı kapat" if en
                                         else "Açılışta başlatmayı aç")
        except Exception:  # noqa: BLE001
            pass


class ByeRTEApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="tr.byerte.Gui")

    def do_activate(self):
        win = self.props.active_window or ByeRTEWindow(self)
        win.present()


def main():
    app = ByeRTEApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
