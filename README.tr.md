# ByeRTE

*ByeRTE = **Bye** **R**estrictions, **T**hrottling & **E**avesdropping — engellemeye, hız kısmaya ve (DPI tabanlı) dinlemeye elveda.*

**Linux ve Windows için GoodbyeDPI tarzı DPI engel aşıcı — Discord ve Roblox (Türkiye).**

Türkiye'de Discord ve Roblox hem DNS zehirleme hem SNI tabanlı DPI ile engelli.
ByeRTE bu iki katmanı da yerel olarak aşar: VPN değildir, trafiğiniz kimsenin
sunucusundan geçmez, sadece kendi makinenizde işlenir.

> **En önemli söz:** Kapatınca sistem **tam olarak** eski haline döner. Program
> çökse bile internetiniz kesilmez (fail-open). Hiçbir kalıcı ayar değişmez;
> yeniden başlatınca sistem tertemiz açılır.
>
> - **Linux:** tek bir `nftables` tablosu + `bypass` queue kuralları
>   (`/etc/resolv.conf`, sysctl, systemd-resolved'e **dokunulmaz**).
> - **Windows:** tüm yakalama handle tabanlıdır (WinDivert). Motor süreci nasıl
>   biterse bitsin (normal çıkış, çökme, `taskkill /F`) işletim sistemi tüm
>   WinDivert handle'larını kapatır ve yakalama anında durur — geride sızacak
>   kalıcı durum yoktur. Kayıt defteri/güvenlik duvarı/DNS ayarı değişmez.

---

## Nasıl çalışır?

- **Motor:** [zapret2](https://github.com/bol-van/zapret2) — Linux'ta `nfqws2`,
  Windows'ta `winws2` (statik, gömülü; SHA-256 ile doğrulanır).
- **Yakalama:** Linux'ta tek `inet byerte` nftables tablosu; queue kuralları
  `bypass` bayraklı: motor ölse bile paketler dokunulmadan geçer → internet
  kesilmez. Windows'ta aynı işi WinDivert yapar (süreç ölünce yakalama biter).
- **DNS:** Tüm 53 trafiği yerel bir DoH köprüsüne yönlenir — Linux'ta aynı tablodaki
  `nat` kuralıyla, Windows'ta WinDivert ile. Köprü, CDN-arkası DoH uçlarına
  (Cloudflare `mozilla.cloudflare-dns.com`, NextDNS, ControlD) IP ile bağlanır —
  meşhur DNS IP'leri (1.1.1.1 vb.) Türkiye'de 443'te engelli olduğu için bu şart.
- **Kapatma:** Linux'ta `nft delete table inet byerte`; Windows'ta motor süreç
  ağacı sonlandırılır → WinDivert handle'ları kapanır. İkisi de anında tam geri dönüş.
- **Açılışta varsayılan kapalıdır** (elle açılır): Linux'ta systemd birimi
  (`ExecStopPost` tabloyu her hâlde siler), Windows'ta Görev Zamanlayıcı görevi.

Yalnızca Discord/Roblox alan adlarına (hostlist) dokunulur; diğer trafik değişmez.

## Kurulum (Linux)

```bash
git clone https://github.com/Clypus/ByeRTE.git && cd ByeRTE
sudo ./install.sh
```

Kurulum yalnızca **eksik** bağımlılıkları kurar (mevcut paketlere dokunmaz —
Arch'ta kısmi yükseltmeyi önler). Gerekenler: `nftables`, `python3` (çekirdek) ve
`gtk4` + `libadwaita` + `python-gobject` (grafik arayüz için).

> Arch/EndeavourOS'ta eksik paket varsa önce `sudo pacman -Syu` önerilir.

## Kurulum (Windows)

**Windows 10/11 x64** gerekir. En kolayı — Python gerekmez:

1. [Releases](https://github.com/Clypus/ByeRTE/releases/latest) sayfasından
   **`ByeRTE-windows-x64.zip`** dosyasını indirin.
2. **Bir klasöre çıkarın** (zip'in içinden çalıştırmayın).
3. **`byerte-gui.exe`**'yi çalıştırın (taşınabilir), ya da `install.ps1`'e sağ tık →
   *PowerShell ile çalıştır* diyerek `%ProgramFiles%\ByeRTE`'ye kurun (PATH + Başlat
   Menüsü kısayolu).

Exe kod imzalı olmadığı için ilk açılışta SmartScreen uyarabilir: *Ek bilgi →
Yine de çalıştır*.

**Kaynaktan derleme** (Python 3.10+; GUI stdlib `tkinter` kullanır, `winws2.exe` +
WinDivert gömülüdür):

```powershell
# 1) iki exe'yi derle (önce gömülü ikilileri SHA-256 ile doğrular)
python packaging\windows\build.py
# 2) %ProgramFiles%\ByeRTE'ye kur (PATH + Başlat Menüsü kısayolu; UAC ister)
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1
```

Ya da **taşınabilir**: `dist\ByeRTE\` klasörünü kopyalayıp `byerte-gui.exe`'yi çalıştırın.

- Yetki **UAC** ile alınır (CLI kendini yükseltir; GUI her eylemde yükseltir —
  Linux'taki `sudo`/`pkexec` karşılığı). `byerte durum` yönetici istemez.
- **WinDivert** sürücüsü ilk `byerte aç`ta kendiliğinden kurulur (bir UAC istemi),
  `uninstall.ps1` ile (ya da yeniden başlatmada) kalkar. **Antivirüsler WinDivert'i
  işaretleyebilir** — kötü amaçlı değil, meşru bir paket-filtre sürücüsüdür
  (Windows'taki `nftables`/`iptables` karşılığı); gerekirse istisna ekleyin.
- Açılışta başlatma bir **Görev Zamanlayıcı** görevidir (`byerte acilis ac`); oturum
  açılışında en yüksek ayrıcalıkla çalışır — parola/UAC istemi yok, Windows servisi yok.

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

Aynı komutlar **Windows**'ta da çalışır (kurulduktan sonra herhangi bir terminalden,
ya da CLI'ın açtığı yükseltilmiş pencerede). Orada `acilis ac`, systemd birimi yerine
oturum açılışı Görev Zamanlayıcı görevini oluşturur. `byerte gunluk` Windows'ta
winws2.log/engine.log'u izler.

Grafik arayüz: uygulama menüsünden **ByeRTE** ya da `byerte-gui`. Büyük aç/kapat
düğmesi, operatör seçimi ve "Tara" butonu. Linux'ta ayrıcalık `pkexec` ile alınır
(bir polkit ajanı gerekir; GNOME/KDE'de hazır, Hyprland'de `hyprpolkitagent` vb.).
Windows'ta (Başlat Menüsü → **ByeRTE**) her eylem bir UAC istemi çıkarır.

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

**"Experiences failed to load" / zehirli DNS önbelleği:** Roblox'un bazı alt alan
adları (ör. `apis.roblox.com`) ByeRTE açılmadan önce zehirli IP'ye (TT'de
`195.175.254.2` sinkhole) çözülüp önbelleğe alınmış olabilir; ana sayfa açılsa da
deneyim listesi bu yüzden yüklenmez. Windows'ta motor açılışta `ipconfig /flushdns`
ile OS önbelleğini otomatik temizler — ama **tarayıcının kendi DNS önbelleği ayrıdır**:
Roblox sekmesini Ctrl+Shift+R ile sert yenileyin ya da tarayıcıyı tamamen kapatıp açın.
En iyisi: önce `byerte aç`, sonra tarayıcıyı açın.

## Site listeleri (özelleştirme)

İki **düzenlenebilir** liste var. Düzenledikten sonra `byerte kapat && byerte aç`
(ya da arayüzde kapat/aç) ile uygulanır:

- **`hostlist.txt`** — DPI atlatmanın **uygulanacağı** siteler. Discord ve Roblox
  hazır gelir; **başka engelli siteleri buraya ekleyin** (ör. site + CDN alan adı,
  PH vb.). Alt alan adları otomatik kapsanır. DNS zaten tüm sitelerde DoH'tan
  gittiği için çoğu zaman bir alanı buraya eklemek engeli açmaya yeter.
- **`denylist.txt`** — **hiç dokunulmayacak** siteler: DPI uygulanmaz, DNS normal
  çözümleyicinizden gider (DoH'tan değil). ByeRTE açıkken bozulan üçüncü-parti
  API'ler için. Opt-in — varsayılan boş, bir alan eklemeden hiçbir şey değişmez.

Konum: **Windows** `%ProgramData%\ByeRTE\hostlist.txt` / `denylist.txt` (ya da
arayüzdeki **Siteler… / Hariç tut…** düğmeleri); **Linux** `/etc/byerte/hostlist.txt`
/ `denylist.txt`.

> Linux'ta denylist şimdilik yalnızca **DPI katmanını** etkiler (DNS hariç tutma
> şu an Windows'a özel). Ekleme listesi (`hostlist`) her iki platformda çalışır.

## Güvenlik profili

**Linux**

| Durum | Sonuç |
|---|---|
| nfqws2 çökerse | Paketler `bypass` ile geçer, internet kesilmez; systemd servisi yeniden kurar |
| Motor `kill -9` | systemd `ExecStopPost` tabloyu siler → DNS/internet normale döner |
| `byerte kapat` | Tablo silinir, DNS/HTTPS anında normale döner |
| Yeniden başlatma | Servis açılışta kapalı (opt-in); sistem tertemiz açılır |

**Windows**

| Durum | Sonuç |
|---|---|
| winws2 çökerse | WinDivert handle'ı kapanır → DPI bypass biter; motor çıkar, `aç`/açılış görevi yeniden kurar |
| Motor `taskkill /F` | İşletim sistemi tüm WinDivert handle'larını (DNS + DPI) kapatır → her şey anında normale döner |
| `byerte kapat` | Motor süreç ağacı öldürülür, WinDivert handle'ları kapanır → DNS/HTTPS anında normale döner |
| Yeniden başlatma | Açılış görevi (opt-in) kapalıysa hiçbir şey başlamaz; sistem tertemiz açılır |

## Kaldırma

```bash
# Linux
sudo ./uninstall.sh            # dosyaları + servisi kaldırır, tabloyu siler
sudo ./uninstall.sh --purge    # /etc/byerte yapılandırmasını da siler
```

```powershell
# Windows (Yönetici PowerShell)
powershell -ExecutionPolicy Bypass -File packaging\windows\uninstall.ps1
powershell -ExecutionPolicy Bypass -File packaging\windows\uninstall.ps1 -Purge   # yapılandırma da silinir
```

## Lisans

GPLv3 (gömülü zapret2 ve Lua betikleri GPLv3 olduğundan). Bkz. `LICENSE`.
zapret2 © bol-van; TR strateji presetleri Unwall ve splitwire-turkey'den uyarlandı.

> ByeRTE bir güvenlik/erişim aracıdır; yalnızca kendi ağınızda, yasal ve
> eğitim amaçlı kullanım içindir.
