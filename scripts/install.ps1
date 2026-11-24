# CORVUS Red - instalador para Windows (PowerShell)
#   .\install.ps1               -> global:    $HOME\.claude\skills\corvus
#   .\install.ps1 -Project      -> proyecto:  .\.claude\skills\corvus
#   .\install.ps1 -Target DIR   -> ruta a medida
param(
    [switch]$Project,
    [string]$Target = ""
)
$ErrorActionPreference = "Stop"
$Repo = "https://github.com/xn4vi/corvus-red.git"

if (-not $Target) {
    if ($Project) { $Target = Join-Path (Get-Location) ".claude\skills\corvus" }
    else { $Target = Join-Path $HOME ".claude\skills\corvus" }
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "Necesitas git (https://git-scm.com/download/win)." }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Host "[i] Sin Python: la skill funciona, pero scripts\corvus.py no." }

if (Test-Path (Join-Path $Target ".git")) {
    Write-Host "[*] Actualizando $Target"
    git -C $Target pull --ff-only
} else {
    if (Test-Path $Target) { throw "$Target ya existe y no es un clon de git. Muevelo o usa -Target." }
    New-Item -ItemType Directory -Force (Split-Path $Target) | Out-Null
    git clone --depth 1 $Repo $Target
}

Write-Host ""
Write-Host "[+] CORVUS Red instalada en $Target"
Write-Host "    Personaliza tu firma sin tocar el repo:  Copy-Item `"$Target\brand.json`" `"$Target\brand.local.json`"  (y edita 'auditor')"
Write-Host "    Usala en Claude Code:                    /corvus alcance https://objetivo-autorizado"
