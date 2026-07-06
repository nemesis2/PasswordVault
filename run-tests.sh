#!/usr/bin/env bash
# =============================================================================
# run-tests.sh — run the whole vault test suite and report an aggregate result.
#
#   ./run-tests.sh            # run everything available
#   ./run-tests.sh --quick    # skip the slow parity test (PHP byte-for-byte)
#
# Suites:
#   test-client.js          crypto round-trip, padding, tags, strength, TOTP,
#                           manifest HMAC                       (needs: node)
#   test-client-extras.js   OTP parse, CSV, avatar/fav hashing, group keys,
#                           search index, record validation     (needs: node)
#   test-server.js          server.js write protocol + validators, no PHP
#                                                                (needs: node)
#   test-http.js            server.js HTTP layer: static guards, auth, CSRF,
#                           rate-limit, headers, via a live server (needs: node)
#   test-tui.js             tui.node: lib/vault.js storage, lib/crypto.js v6
#                           cascade, lib/model.js Vault CRUD against seeded
#                           temp dirs, and byte-format interop with the
#                           browser's javascript.js                (needs: node)
#   selftest.js (×2)        Firefox + Chrome extension passkey crypto round-trip
#                                                                (needs: node)
#   test-browser.js         end-to-end PWA in headless Chromium: unlock, reveal,
#                           decrypt, CSP event-binding   (needs: node + playwright)
#   parity-test.js          server.js vs the live post.php, byte-for-byte
#                                                          (needs: node + php)
#
# The browser suite is skipped (not failed) when Playwright isn't installed
# (cd test-browser && npm install && npx playwright install chromium) and on
# --quick. The parity test is skipped when `php` is not on PATH.
#
# Exit code is non-zero if any suite fails. The parity test is skipped (not
# failed) when `php` is not on PATH.
# =============================================================================
set -u
cd "$(dirname "$0")"

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

pass=0 fail=0 skip=0
hr() { printf '%s\n' '────────────────────────────────────────────────────────'; }

run() {                                   # run <label> <cmd...>
    local label="$1"; shift
    hr; printf '▶ %s\n' "$label"; hr
    if "$@"; then
        printf '✓ %s passed\n\n' "$label"; pass=$((pass + 1))
    else
        printf '✗ %s FAILED\n\n' "$label"; fail=$((fail + 1))
    fi
}

if ! command -v node >/dev/null 2>&1; then
    echo "node not found on PATH — cannot run the suite." >&2
    exit 2
fi

run "client crypto (test-client.js)"        node test-client.js
run "client logic (test-client-extras.js)"  node test-client-extras.js
run "server protocol (test-server.js)"      node test-server.js
run "server HTTP layer (test-http.js)"      node test-http.js
run "TUI (test-tui.js)"                     node test-tui.js
run "firefox extension (selftest.js)"       node firefox-extension/selftest.js
run "chrome extension (selftest.js)"        node chrome-extension/selftest.js

if [ "$QUICK" -eq 1 ]; then
    printf '○ browser (test-browser.js) skipped (--quick)\n\n'; skip=$((skip + 1))
elif [ -d test-browser/node_modules/playwright ]; then
    run "browser DOM (test-browser.js)"      node test-browser/test-browser.js
else
    printf '○ browser (test-browser.js) skipped — playwright not installed\n'
    printf '   (cd test-browser && npm install && npx playwright install chromium)\n\n'; skip=$((skip + 1))
fi

if [ "$QUICK" -eq 1 ]; then
    printf '○ parity (parity-test.js) skipped (--quick)\n\n'; skip=$((skip + 1))
elif command -v php >/dev/null 2>&1; then
    run "PHP parity (parity-test.js)"        node parity-test.js
else
    printf '○ parity (parity-test.js) skipped — php not on PATH\n\n'; skip=$((skip + 1))
fi

hr
printf 'SUITES: %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
hr
[ "$fail" -eq 0 ]
