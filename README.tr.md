# ByeRTE

**Linux için GoodbyeDPI tarzı DPI engel aşıcı — Discord ve Roblox (Türkiye).**

Türkiye'de Discord ve Roblox hem DNS zehirleme hem SNI tabanlı DPI ile engelli.
ByeRTE bu iki katmanı da yerel olarak aşar: VPN değildir, trafiğiniz kimsenin
sunucusundan geçmez, sadece kendi makinenizde işlenir.

> **En önemli söz:** Kapatınca sistem **tam olarak** eski haline döner. Program
> çökse bile internetiniz kesilmez (fail-open). Hiçbir kalıcı ayar değişmez
> (`/etc/resolv.conf`, sysctl, systemd-resolved'e **dokunulmaz**); yeniden
> başlatınca sistem tertemiz açılır.

---

## Nasıl çalışır?

- **Motor:** [zapret2](https://github.com/bol-van/zapret2)'nin `nfqws2`'si (statik, gömülü).
- **Tek `inet byerte` nftables tablosu.** Queue kuralları `bypass` bayraklı: motor
  ölse bile paketler dokunulmadan geçer → internet kesilmez.
- **DNS:** Tüm 53 trafiği, aynı tablodaki bir `nat` kuralıyla yerel bir DoH
  köprüsüne (127.0.0.1:5355) yönlenir. Köprü, CDN-arkası DoH uçlarına (Cloudflare
  `mozilla.cloudflare-dns.com`, NextDNS, ControlD) IP ile bağlanır — meşhur DNS
  IP'leri (1.1.1.1 vb.) Türkiye'de 443'te engelli olduğu için bu şart.
- **Kapatma = `nft delete table inet byerte`.** Anında, tam geri dönüş.
- **systemd** servisi `ExecStopPost` ile tabloyu her hâlükârda (çökme, `kill -9`
  dahil) siler. Açılışta **varsayılan kapalıdır** (elle açılır).

Yalnızca Discord/Roblox alan adlarına (hostlist) dokunulur; diğer trafik değişmez.

## Kurulum

```bash
git clone <repo> ByeRTE && cd ByeRTE
sudo ./install.sh
```

Kurulum yalnızca **eksik** bağımlılıkları kurar (mevcut paketlere dokunmaz —
Arch'ta kısmi yükseltmeyi önler). Gerekenler: `nftables`, `python3` (çekirdek) ve
`gtk4` + `libadwaita` + `python-gobject` (grafik arayüz için).

> Arch/EndeavourOS'ta eksik paket varsa önce `sudo pacman -Syu` önerilir.

## Kullanım

```bash
byerte aç            # otomatik operatör tespiti (ASN) + en uygun strateji
byerte aç --operator turk-telekom   # elle operatör: turk-telekom|superonline|vodafone|...
byerte durum         # açık mı, DNS/Discord/Roblox erişilebilir mi
byerte tara          # bu hatta çalışan en iyi stratejiyi otomatik bul
byerte kapat         # durdur, sistemi geri al
byerte acilis ac     # (opsiyonel) açılışta otomatik başlat
byerte gunluk        # günlüğü izle
```

Grafik arayüz: uygulama menüsünden **ByeRTE** ya da `byerte-gui`. Büyük aç/kapat
düğmesi, operatör seçimi ve "Tara" butonu. Ayrıcalık `pkexec` ile alınır (GUI root
değildir); bir polkit yetkilendirme ajanı gerekir (GNOME/KDE'de hazır; Hyprland'de
`hyprpolkitagent` vb.).

## Operatöre göre strateji

Çalışan DPI atlatma yöntemi operatöre göre değişir. ByeRTE genel IP'nizin ASN'ini
(zehirlenmemiş DoH yolundan Team Cymru'ya sorarak) tespit edip uygun stratejiyi
seçer. Türk Telekom/TTNet, Superonline/Turkcell, Vodafone, Turkcell Mobil, Kablonet
ve TurkNet için hazır profiller vardır; `byerte tara` ile hattınıza en uygunu
otomatik seçilebilir.

## Roblox notu

Roblox web/uygulama (Sober) TLS ve CDN (`rbxcdn.com`) üzerinden çalışır; bunlar
hostlist'te. Oyunun kendi UDP trafiği Türkiye'de engelli görünmediğinden ona
dokunulmaz. Ayar değiştirince Sober'ı tamamen kapatıp açın:
`flatpak kill org.vinegarhq.Sober`.

## Güvenlik profili

| Durum | Sonuç |
|---|---|
| nfqws2 çökerse | Paketler `bypass` ile geçer, internet kesilmez; systemd servisi yeniden kurar |
| Motor `kill -9` | systemd `ExecStopPost` tabloyu siler → DNS/internet normale döner (ya da servis otomatik toparlar) |
| `byerte kapat` | Tablo silinir, DNS/HTTPS anında normale döner |
| Yeniden başlatma | Servis açılışta kapalı (opt-in); sistem tertemiz açılır |

## Kaldırma

```bash
sudo ./uninstall.sh            # dosyaları + servisi kaldırır, tabloyu siler
sudo ./uninstall.sh --purge    # /etc/byerte yapılandırmasını da siler
```

## Lisans

GPLv3 (gömülü zapret2 ve Lua betikleri GPLv3 olduğundan). Bkz. `LICENSE`.
zapret2 © bol-van; TR strateji presetleri Unwall ve splitwire-turkey'den uyarlandı.

> ByeRTE bir güvenlik/erişim aracıdır; yalnızca kendi ağınızda, yasal ve
> eğitim amaçlı kullanım içindir.
