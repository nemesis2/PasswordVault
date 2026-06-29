#!/usr/bin/env bash
# build-zip.sh — produce a Chrome/Edge extension .zip (manifest.json at the zip
# root) ready to:
#   • load unpacked via chrome://extensions (Developer mode → Load unpacked on
#     this directory — no zip needed), or
#   • upload to the Chrome Web Store / Edge Add-ons dashboard.
#
# No Node/npm dependency beyond `node` for the version string + `zip`.
set -euo pipefail
cd "$(dirname "$0")"

NAME="vault-autofill-companion-chrome"
VERSION="$(node -p "require('./manifest.json').version")"
OUT="web-ext-artifacts"
ZIP="$OUT/${NAME}-${VERSION}.zip"

# Whitelist only the files the shipped extension actually needs (so dev files —
# selftest.js, README.md, this script, node_modules — never leak into the zip).
FILES=(
  manifest.json
  background.js
  offscreen.html
  offscreen.js
  vault-session.js
  crypto-vault.js
  crypto-ciphers.js
  webauthn.js
  argon2-worker.js
  content.js
  content_passkey_main.js
  content_passkey_bridge.js
  approve.html
  approve.js
  popup.html
  popup.js
  popup.css
  icons
)

mkdir -p "$OUT"
rm -f "$ZIP"
zip -r -FS "$ZIP" "${FILES[@]}" -x '*.DS_Store'

echo
echo "Built $ZIP ($(du -h "$ZIP" | cut -f1))"
