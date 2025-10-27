have(){ [ -n "${1:-}" ] && [ -f "$1" ]; }
#!/usr/bin/env bash
set -euo pipefail

: "${DMG_PATH:?set DMG_PATH}"
: "${PKG_PATH:?set PKG_PATH}"
: "${APP_PATH:?set APP_PATH}"
: "${MSI_PATH:?set MSI_PATH}"
: "${EXE_PATH:?set EXE_PATH}"

python3 deep.py --out /tmp/s1.json "$DMG_PATH" "$PKG_PATH" "$APP_PATH" >/dev/null
jq -e '.[0].dmg.ok == true' /tmp/s1.json >/dev/null
jq -e '.[1].pkg.path != null and (.[1].pkg.identifier != null or .[1].pkg.version != null)' /tmp/s1.json >/dev/null
jq -e '.[2].app.info.CFBundleIdentifier != null' /tmp/s1.json >/dev/null

python3 deep.py --out /tmp/s2.json "$MSI_PATH" >/dev/null
have "$MSI_PATH" && jq -e '.[0].msi.type == "msi" and (.[0].msi.is_msi == true or .[0].msi.is_msi == false)' /tmp/s2.json >/dev/null

python3 deep.py --out /tmp/s3.json "$EXE_PATH" >/dev/null
have "$EXE_PATH" && jq -e '.[0].exe.type == "exe" and (.[0].exe.entropy.value != null)' /tmp/s3.json >/dev/null

echo "smoke OK"
