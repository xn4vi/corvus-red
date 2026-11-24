#!/usr/bin/env bash
# CORVUS Red — instalador para Linux / macOS / Git Bash
#   ./install.sh               → global:    ~/.claude/skills/corvus
#   ./install.sh --project     → proyecto:  ./.claude/skills/corvus
#   ./install.sh --target DIR  → ruta a medida
set -euo pipefail

REPO="https://github.com/xn4vi/corvus-red.git"
TARGET="${HOME}/.claude/skills/corvus"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) TARGET="$(pwd)/.claude/skills/corvus"; shift ;;
    --target)  TARGET="$2"; shift 2 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
done

command -v git >/dev/null    || { echo "[!] Necesitas git." >&2; exit 1; }
command -v python3 >/dev/null || command -v python >/dev/null || echo "[i] Sin Python: la skill funciona, pero scripts/corvus.py no."

if [[ -d "$TARGET/.git" ]]; then
  echo "[*] Actualizando $TARGET"
  git -C "$TARGET" pull --ff-only
else
  [[ -e "$TARGET" ]] && { echo "[!] $TARGET ya existe y no es un clon de git. Muévelo o usa --target." >&2; exit 1; }
  mkdir -p "$(dirname "$TARGET")"
  git clone --depth 1 "$REPO" "$TARGET"
fi

echo
echo "[+] CORVUS Red instalada en $TARGET"
echo "    Personaliza tu firma sin tocar el repo:  cp \"$TARGET/brand.json\" \"$TARGET/brand.local.json\"  (y edita 'auditor')"
echo "    Úsala en Claude Code:                    /corvus alcance https://objetivo-autorizado"
