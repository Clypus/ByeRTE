<#
  ByeRTE Windows kaldırma. Yönetici PowerShell'de:
      powershell -ExecutionPolicy Bypass -File packaging\windows\uninstall.ps1
      (yapılandırmayı da silmek için:  -Purge)

  Durdurur (winws2 + motor), açılış görevini ve WinDivert sürücüsünü kaldırır,
  kısayol + PATH + dosyaları siler. Sistem kurulumdan önceki haline döner.
#>
[CmdletBinding()]
param(
    [string]$Dest = "$env:ProgramFiles\ByeRTE",
    [switch]$Purge
)
$ErrorActionPreference = "SilentlyContinue"

$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) {
    Write-Host "yetki gerekiyor, Yönetici olarak yeniden başlatılıyor (UAC)..."
    $pp = if ($Purge) { "-Purge" } else { "" }
    Start-Process powershell -Verb RunAs -ArgumentList `
        "-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"","-Dest","`"$Dest`"",$pp
    exit
}

Write-Host "==> Durduruluyor"
if (Test-Path (Join-Path $Dest "byerte.exe")) {
    & (Join-Path $Dest "byerte.exe") kapat 2>$null
    Start-Sleep -Milliseconds 500
}
taskkill /IM winws2.exe /T /F 2>$null | Out-Null

Write-Host "==> Açılış görevi kaldırılıyor"
schtasks /Delete /TN ByeRTE /F 2>$null | Out-Null

Write-Host "==> WinDivert sürücüsü kaldırılıyor (varsa)"
# winws2 tarafından isteğe bağlı kurulan 'WinDivert' servisi. Süreçler durdu, güvenli.
sc.exe stop WinDivert 2>$null | Out-Null
sc.exe delete WinDivert 2>$null | Out-Null

Write-Host "==> Başlat Menüsü kısayolu"
Remove-Item (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\ByeRTE.lnk") -Force

Write-Host "==> PATH temizleniyor"
$curr = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($curr -like "*$Dest*") {
    $new = ($curr.Split(';') | Where-Object { $_ -and ($_ -ne $Dest) }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $new, "Machine")
}

Write-Host "==> Dosyalar kaldırılıyor"
Remove-Item -Recurse -Force $Dest

if ($Purge) {
    Remove-Item -Recurse -Force (Join-Path $env:ProgramData "ByeRTE")
    Write-Host "   %ProgramData%\ByeRTE de silindi (-Purge)"
} else {
    # çalışma anı durumunu temizle, yapılandırmayı koru
    Remove-Item -Recurse -Force (Join-Path $env:ProgramData "ByeRTE\run")
    Write-Host "   yapılandırma korundu (%ProgramData%\ByeRTE) — silmek için -Purge"
}

Write-Host ""
Write-Host "OK  ByeRTE kaldirildi. Sistem eski haline dondu." -ForegroundColor Green
