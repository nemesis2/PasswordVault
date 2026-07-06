#!/usr/bin/env bash
# build-xpi.sh — produce an UNSIGNED .xpi (a plain zip with manifest.json at the
# zip root, which is exactly what an .xpi is). Use it to:
#   • install temporarily via about:debugging, or
#   • upload to addons.mozilla.org (AMO) to be signed, or
#   • feed to `web-ext sign` (see `npm run sign`).
#
# This intentionally has no Node/npm dependency — just `zip` + `node` for the
# version string. For an automatically signed build use `npm run sign` instead.
set -euo pipefail
cd "$(dirname "$0")"

NAME="vault-autofill-companion"
VERSION="$(node -p "require('./manifest.json').version")"
OUT="web-ext-artifacts"
XPI="$OUT/${NAME}-${VERSION}.xpi"

# Whitelist only the files the shipped add-on actually needs (so dev files —
# selftest.js, README.md, this script, package.json, node_modules — never leak
# into the package).
FILES=(
  manifest.json
  background.js
  code-pins.js
  vault-session.js
  crypto-vault.js
  crypto-ciphers.js
  webauthn.js
  argon2-worker.js
  content.js
  content_passkey_bridge.js
  passkey-inpage.js
  approve.html
  approve.js
  popup.html
  popup.js
  popup.css
  icons
)

mkdir -p "$OUT"
rm -f "$XPI"
zip -r -FS "$XPI" "${FILES[@]}" -x '*.DS_Store'

echo
echo "Built $XPI ($(du -h "$XPI" | cut -f1))"
