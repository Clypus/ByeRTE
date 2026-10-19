#!/usr/bin/env bash
# ByeRTE kaldırma. root olarak:  sudo ./uninstall.sh
# Servisi durdurur, nftables tablosunu siler, tüm kurulan dosyaları kaldırır.
# Sistemi kurulumdan önceki haline getirir (hiç kalıcı değişiklik yoktu).
set -uo pipefail

die() { echo "HATA: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "root gerekiyor:  sudo ./uninstall.sh"

echo "==> Servis durduruluyor ve devre dışı bırakılıyor"
systemctl stop byerte.service 2>/dev/null || true
systemctl disable byerte.service 2>/dev/null || true

echo "==> nftables tablosu siliniyor (varsa)"
nft delete table inet byerte 2>/dev/null || true

echo "==> Dosyalar kaldırılıyor"
rm -f /etc/systemd/system/byerte.service
rm -f /usr/bin/byerte /usr/bin/byerte-gui
rm -f /usr/share/polkit-1/rules.d/50-byerte.rules
rm -f /usr/share/applications/byerte.desktop
rm -rf /usr/lib/byerte
rm -rf /run/byerte
# yapılandırma: isteğe bağlı koru
if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/byerte
  echo "   /etc/byerte de silindi (--purge)"
else
  echo "   /etc/byerte korundu (silmek için: --purge)"
fi

systemctl daemon-reload 2>/dev/null || true
command -v update-desktop-database >/dev/null && update-desktop-database -q /usr/share/applications 2>/dev/null || true

echo
echo "✓ ByeRTE kaldırıldı. Sistem eski haline döndü."
