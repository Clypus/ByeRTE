<#
  ByeRTE Windows kurulumu. Yönetici PowerShell'de çalıştırın:
      powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1

  Ne yapar:
   - Derlenen dist\ByeRTE klasörünü %ProgramFiles%\ByeRTE'ye kopyalar.
   - byerte.exe için makine PATH'ine ekler (terminalden `byerte aç` çalışsın).
   - Başlat Menüsü'ne "ByeRTE" kısayolu (byerte-gui.exe) ekler.
   - SERVİS/otomatik başlatma KURMAZ (açılış için: byerte acilis ac).

  WinDivert sürücüsü ilk `byerte aç`ta kendiliğinden kurulur (yönetici ister).
  Kalıcı sistem ayarı değişmez; kaldırma için uninstall.ps1.
#>
[CmdletBinding()]
param(
    [string]$Source = "",
    [string]$Dest   = "$env:ProgramFiles\ByeRTE"
)
$ErrorActionPreference = "Stop"

# Kaynak: release zip'inde bu betik byerte.exe ile AYNI klasördedir; repo'da ise
# derleme çıktısı dist\ByeRTE'dir.
if (-not $Source) {
    if (Test-Path (Join-Path $PSScriptRoot "byerte.exe")) { $Source = $PSScriptRoot }
    else { $Source = Join-Path $PSScriptRoot "..\..\dist\ByeRTE" }
}

# --- Yönetici değilse UAC ile yeniden başlat ---
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) {
    Write-Host "yetki gerekiyor, Yönetici olarak yeniden başlatılıyor (UAC)..."
    Start-Process powershell -Verb RunAs -ArgumentList `
        "-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"","-Source","`"$Source`"","-Dest","`"$Dest`""
    exit
}

if (-not (Test-Path (Join-Path $Source "byerte.exe"))) {
    throw "Derleme bulunamadı: $Source`nÖnce derleyin:  python packaging\windows\build.py"
}

Write-Host "==> Kopyalanıyor -> $Dest"
# Çalışan motor varsa önce durdur (dosya kilidi olmasın)
if (Test-Path (Join-Path $Dest "byerte.exe")) {
    try { & (Join-Path $Dest "byerte.exe") kapat 2>$null } catch {}
    Start-Sleep -Milliseconds 500
}
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item -Recurse -Force -Path (Join-Path $Source "*") -Destination $Dest

# --- PATH (makine) ---
$curr = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($curr -notlike "*$Dest*") {
    Write-Host "==> PATH'e ekleniyor"
    [Environment]::SetEnvironmentVariable("Path", ($curr.TrimEnd(';') + ";" + $Dest), "Machine")
}

# --- Başlat Menüsü kısayolu ---
Write-Host "==> Başlat Menüsü kısayolu"
$lnk = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\ByeRTE.lnk"
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnk)
$sc.TargetPath = Join-Path $Dest "byerte-gui.exe"
$sc.WorkingDirectory = $Dest
$sc.Description = "ByeRTE — Discord/Roblox DPI engel aşıcı"
$sc.Save()

Write-Host ""
Write-Host "OK  ByeRTE kuruldu: $Dest" -ForegroundColor Green
Write-Host "  Terminalden:  byerte ac        (YENI terminal gerekir; kapatmak: byerte kapat)"
Write-Host "  Arayuzden:    Baslat Menusu > ByeRTE"
Write-Host "  Acilista:     byerte acilis ac (opsiyonel)"
Write-Host "  Kaldirmak:    powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\uninstall.ps1`""
