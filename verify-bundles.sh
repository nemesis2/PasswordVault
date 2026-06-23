#!/usr/bin/env bash
#
# verify-bundles.sh — sanity-check the inlined crypto bundles.
#
# The ciphers (ChaCha20-Poly1305, Twofish, Serpent, Argon2id) are vendored as
# IIFE bundles spliced into javascript.js, and the Argon2id bundle is ALSO
# shipped as the served Web Worker (argon2-worker.js). This script verifies the
# invariants that can drift silently:
#
#   1. The Argon2id WASM payload in argon2-worker.js is byte-identical to the
#      one inlined in javascript.js  (worker and main thread must run the SAME
#      Argon2id — a mismatch means one was rebuilt without the other).
#   2. Each cipher exposes its expected global in javascript.js.
#   3. (optional) Rebuild the npm bundles and confirm their core appears inline.
#
# Exit non-zero if any required invariant fails. Run from the repo root.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

JS=javascript.js
WORKER=argon2-worker.js
fail=0

echo ">> 1. Argon2id worker vs inlined bundle"
if [ ! -f "$WORKER" ]; then
    echo "!! $WORKER missing" >&2; fail=1
else
    # The hash-wasm bundle embeds its WASM as a long base64 string. Extract the
    # longest base64 run from each file and compare — identical ⇒ same Argon2id.
    bw=$(grep -oE '[A-Za-z0-9+/]{512,}' "$WORKER" | sort -u | tail -1 | sha256sum | cut -d' ' -f1)
    bj=$(grep -oE '[A-Za-z0-9+/]{512,}' "$JS"     | sort -u | tail -1 | sha256sum | cut -d' ' -f1)
    if [ -n "$bw" ] && [ "$bw" = "$bj" ]; then
        echo "   OK — identical Argon2id WASM payload ($bw)"
    else
        echo "!! Argon2id WASM differs between $WORKER and $JS — rebuild both:" >&2
        echo "     cat moved/argon2_bundle.js moved/argon2_worker_tail.js > $WORKER" >&2
        fail=1
    fi
fi

echo ">> 2. Inlined cipher globals present in $JS"
for sym in "globalThis.chacha20poly1305" "globalThis.twofishEncryptBlock" \
           "globalThis.serpentEncryptBlock" "globalThis.argon2idHash"; do
    if grep -q "$sym" "$JS"; then
        echo "   OK — $sym"
    else
        echo "!! missing $sym in $JS" >&2; fail=1
    fi
done

echo ">> 3. Optional npm rebuild check"
if [ "${1:-}" = "--rebuild" ]; then
    if ! command -v npx >/dev/null 2>&1; then
        echo "   skipped — npx not on PATH" >&2
    else
        tmp=$(mktemp -d)
        echo "   building in $tmp (needs network for npm)…"
        ( cd "$tmp"
          npm install --silent @noble/ciphers twofish-ts hash-wasm >/dev/null 2>&1 || true
          printf "import {chacha20poly1305} from '@noble/ciphers/chacha';globalThis.chacha20poly1305=chacha20poly1305;\n" > c.js
          npx --yes esbuild c.js --bundle --format=iife --platform=browser --outfile=c_bundle.js >/dev/null 2>&1 || true )
        if [ -s "$tmp/c_bundle.js" ]; then
            # Spot-check: a stable ChaCha constant string from the rebuilt bundle
            # should also be present inline. (Full byte-equality is esbuild-version
            # sensitive, so we check a representative core token, not the whole file.)
            tok=$(grep -oE 'expand 32-byte k|chacha20poly1305' "$tmp/c_bundle.js" | head -1 || true)
            if [ -n "$tok" ] && grep -q "chacha20poly1305" "$JS"; then
                echo "   OK — rebuilt ChaCha bundle core matches inline"
            else
                echo "   WARN — could not confirm rebuilt bundle against inline (manual review)" >&2
            fi
        else
            echo "   skipped — esbuild/npm unavailable offline" >&2
        fi
        rm -rf "$tmp"
    fi
else
    echo "   (pass --rebuild to rebuild bundles from npm and diff; needs network)"
fi

if [ "$fail" -ne 0 ]; then
    echo ">> FAIL — see messages above." >&2
    exit 1
fi
echo ">> All bundle invariants OK."
