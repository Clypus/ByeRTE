#!/usr/bin/env bash
# ByeRTE kurulum betiği. root olarak çalıştırın:  sudo ./install.sh
# Dağıtım bağımlılıklarını kurar, dosyaları yerleştirir, sha256 doğrular.
# Servisi AÇILIŞTA ETKİNLEŞTİRMEZ (elle: byerte aç).
set -euo pipefail

PREFIX_LIB=/usr/lib/byerte
BIN=/usr/bin
UNIT=/etc/systemd/system/byerte.service
POLKIT=/usr/share/polkit-1/rules.d/50-byerte.rules
DESKTOP=/usr/share/applications/byerte.desktop
SELF="$(cd "$(dirname "$0")" && pwd)"

die() { echo "HATA: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "root gerekiyor:  sudo ./install.sh"

echo "==> Bağımlılıklar denetleniyor"
# YALNIZCA eksik olan yetenekler için paket kurulur. Mevcut (eski olsa da)
# paketlere DOKUNULMAZ — özellikle Arch'ta `pacman -S <mevcut>` kısmi yükseltme
# yapıp libnftnl/nftables gibi şeyleri kırabilir. Eksik paket ilk kez kurulurken
# güncel bağımlılıklarıyla tutarlı gelir.
have_gtk() { python3 -c 'import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1")' 2>/dev/null; }

# paket adları dağıtıma göre: "yetenek:arch:apt:dnf:zypper"
declare -a MISSING_CORE=() MISSING_GUI=()
pm=""
for c in pacman apt-get dnf zypper; do command -v "$c" >/dev/null && { pm="$c"; break; }; done

pkg() { # $1=arch $2=apt $3=dnf $4=zypper
  case "$pm" in pacman) echo "$1";; apt-get) echo "$2";; dnf) echo "$3";; zypper) echo "$4";; esac
}

command -v nft >/dev/null     || MISSING_CORE+=("$(pkg nftables nftables nftables nftables)")
command -v python3 >/dev/null || MISSING_CORE+=("$(pkg python python3 python3 python3)")
if ! have_gtk; then
  case "$pm" in
    pacman)  MISSING_GUI+=(gtk4 libadwaita python-gobject);;
    apt-get) MISSING_GUI+=(python3-gi gir1.2-gtk-4.0 gir1.2-adw-1);;
    dnf)     MISSING_GUI+=(python3-gobject gtk4 libadwaita);;
    zypper)  MISSING_GUI+=(python3-gobject gtk4 libadwaita);;
  esac
fi

inst() {  # yalnızca verilen (eksik) paketleri kur
  [ "$#" -gt 0 ] || return 0
  echo "   kuruluyor: $*"
  case "$pm" in
    pacman)  pacman -S --needed --noconfirm "$@";;
    apt-get) apt-get update -qq; apt-get install -y "$@";;
    dnf)     dnf install -y "$@";;
    zypper)  zypper install -y "$@";;
  esac
}

if [ "${#MISSING_CORE[@]}" -eq 0 ] && [ "${#MISSING_GUI[@]}" -eq 0 ]; then
  echo "   tüm bağımlılıklar mevcut, paket kurulmadı"
else
  [ -n "$pm" ] || die "paket yöneticisi bulunamadı; şunları elle kurun: ${MISSING_CORE[*]} ${MISSING_GUI[*]}"
  if [ "$pm" = pacman ] && [ "${#MISSING_CORE[@]}" -gt 0 -o "${#MISSING_GUI[@]}" -gt 0 ]; then
    echo "   NOT: Arch'ta eksik paket kurmadan önce 'sudo pacman -Syu' önerilir (kısmi yükseltmeyi önler)"
  fi
  inst "${MISSING_CORE[@]}" "${MISSING_GUI[@]}" || echo "   uyarı: bazı paketler kurulamadı"
fi
command -v nft >/dev/null || die "nftables yok; elle kurun"
command -v python3 >/dev/null || die "python3 yok"
have_gtk || echo "   uyarı: GTK4/libadwaita yok — CLI çalışır ama grafik arayüz açılmaz"

echo "==> Bütünlük doğrulanıyor (sha256)"
( cd "$SELF/data" && sha256sum -c SHA256SUMS >/dev/null ) || die "sha256 doğrulaması başarısız — nfqws2/lua bozuk olabilir"

echo "==> Dosyalar yerleştiriliyor ($PREFIX_LIB)"
rm -rf "$PREFIX_LIB"
install -d "$PREFIX_LIB"
cp -r "$SELF/byerte" "$PREFIX_LIB/byerte"
cp -r "$SELF/data" "$PREFIX_LIB/data"
install -m 0755 "$SELF/gui/byerte-gui.py" "$PREFIX_LIB/byerte-gui.py"
# derleme önbelleğini temizle
find "$PREFIX_LIB" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
chmod -R a+rX "$PREFIX_LIB"          # nobody da okuyabilsin
chmod +x "$PREFIX_LIB/data/nfqws2/"*/nfqws2

install -m 0755 "$SELF/packaging/byerte" "$BIN/byerte"
install -m 0755 "$SELF/packaging/byerte-gui" "$BIN/byerte-gui"

echo "==> systemd birimi"
install -m 0644 "$SELF/packaging/systemd/byerte.service" "$UNIT"
systemctl daemon-reload

echo "==> polkit kuralı (GUI için)"
if [ -d /usr/share/polkit-1/rules.d ]; then
  install -m 0644 "$SELF/packaging/polkit/50-byerte.rules" "$POLKIT"
else
  echo "   polkit rules.d yok; GUI pkexec'te parola soracak (sorun değil)"
fi

echo "==> masaüstü girdisi"
install -m 0644 "$SELF/packaging/byerte.desktop" "$DESKTOP"
command -v update-desktop-database >/dev/null && update-desktop-database -q /usr/share/applications 2>/dev/null || true

echo
echo "✓ ByeRTE kuruldu."
echo
echo "  Terminalden:   byerte aç        (kapatmak: byerte kapat)"
echo "  Arayüzden:     menüden 'ByeRTE' veya  byerte-gui"
echo "  Açılışta:      byerte acilis ac (opsiyonel; varsayılan kapalı)"
echo "  Kaldırmak:     sudo ./uninstall.sh"
