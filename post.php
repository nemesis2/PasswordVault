<?php

// ---- HTTP Basic Auth ----
// Credentials accepted for any write (add / edit / delete). CHANGE THESE.
// Stored server-side only; post.php is executed, never served as source.
const VAULT_AUTH_USER = 'pass';
const VAULT_AUTH_PASS = 'word';

function vault_basic_credentials() {
    // php-fpm usually splits Basic auth into PHP_AUTH_USER/PW...
    $user = $_SERVER['PHP_AUTH_USER'] ?? '';
    $pass = $_SERVER['PHP_AUTH_PW']   ?? '';
    // ...but if not, decode the raw Authorization header ourselves.
    if ($user === '') {
        $hdr = $_SERVER['HTTP_AUTHORIZATION']
            ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if (stripos($hdr, 'Basic ') === 0) {
            $decoded = base64_decode(substr($hdr, 6), true);
            if ($decoded !== false && strpos($decoded, ':') !== false) {
                list($user, $pass) = explode(':', $decoded, 2);
            }
        }
    }
    return array($user, $pass);
}

// ---- Rate limiting (brute-force throttle for Basic Auth) ----
// Per-client-IP sliding window kept in the system temp dir, which lives outside
// the web root and is therefore never served over HTTP (no .htaccess / nginx
// deny rule needed). After RL_MAX_FAIL failed auths within RL_WINDOW seconds,
// further attempts from that IP are refused with 429 until the window slides
// clear. REMOTE_ADDR is the real client IP under the nginx + php-fpm setup
// (passed via fastcgi_params); if a proxy collapses everyone to one address the
// limiter just becomes global, which still throttles brute force.
const RL_WINDOW   = 900;  // 15 minutes
const RL_MAX_FAIL = 5;    // failures per window before lockout

// ---- Backup retention ----
// Keep at most this many timestamped lines backups in bak/. They accumulate one
// per write and are full ciphertext-DB copies, so cap them to bound disk use and
// on-disk retention of historical vault state.
const BAK_KEEP = 50;

// ---- Bulk replace cap ----
// Upper bound on the bulk_data payload (whole-vault replace, used by the
// master-password-change flow). ~100× the current DB size.
const BULK_MAX_BYTES = 4194304;

function rl_file_path() {
    $ip  = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $dir = sys_get_temp_dir() . '/vault-auth-rl';
    if (!is_dir($dir)) { @mkdir($dir, 0700); }
    // Hash the IP so the filename leaks nothing if the temp dir is inspected.
    return $dir . '/' . hash('sha256', $ip);
}

// Open + exclusively lock this IP's counter file and return
// [handle|null, recent-failure-timestamps[]] with stale entries pruned.
// A null handle means the limiter is unavailable (temp dir not writable); the
// caller then proceeds WITHOUT throttling rather than locking everyone out.
function rl_begin() {
    $fp = @fopen(rl_file_path(), 'c+');
    if ($fp === false || !flock($fp, LOCK_EX)) {
        if ($fp !== false) fclose($fp);
        return array(null, array());
    }
    rewind($fp);
    $raw = stream_get_contents($fp);
    $cutoff = time() - RL_WINDOW;
    $times = array();
    if (is_string($raw) && $raw !== '') {
        foreach (preg_split('/\s+/', trim($raw), -1, PREG_SPLIT_NO_EMPTY) as $t) {
            $t = (int)$t;
            if ($t >= $cutoff) $times[] = $t;
        }
    }
    return array($fp, $times);
}

// Write the (pruned) timestamp list back and release the lock. No-op on a null
// handle so the fail-open path above stays a no-op here too.
function rl_commit($fp, array $times) {
    if ($fp === null) return;
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, implode("\n", $times));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
}

function require_basic_auth() {
    list($fp, $fails) = rl_begin();

    // Locked out: too many recent failures from this IP. Refuse without even
    // checking the credentials (blocked attempts are not counted, so the window
    // slides clear on its own rather than extending under continued hammering).
    if (count($fails) >= RL_MAX_FAIL) {
        $retry = RL_WINDOW - (time() - min($fails));
        if ($retry < 1) $retry = 1;
        rl_commit($fp, $fails);
        header('Retry-After: ' . $retry);
        http_response_code(429);
        exit('Too many authentication attempts. Try again later.');
    }

    list($u, $p) = vault_basic_credentials();
    // Constant-time compare; evaluate both halves regardless of the first.
    $ok_user = hash_equals(VAULT_AUTH_USER, $u);
    $ok_pass = hash_equals(VAULT_AUTH_PASS, $p);

    if ($ok_user && $ok_pass) {
        // Success — clear this IP's failure history.
        rl_commit($fp, array());
        return;
    }

    // Failure — record the attempt, then challenge.
    $fails[] = time();
    rl_commit($fp, $fails);
    header('WWW-Authenticate: Basic realm="Password Vault", charset="UTF-8"');
    http_response_code(401);
    exit('Authentication required');
}

require_basic_auth();

// ---- Regenerate-only mode ----
// `regen=1` (GET or POST) rebuilds index.html from the current `lines` plus the
// part1/part2 templates, WITHOUT adding, editing, or deleting any record. Use it
// after editing the templates by hand (e.g. the About modal). It is still gated
// by Basic Auth, but skips the same-origin/CSRF check and the record-validation
// path: regen takes no attacker-influenced input and only re-emits index.html
// from the already-trusted server-side `lines`, so a forged request can at worst
// trigger a no-op rebuild. It does not back up or rewrite `lines`.
$regen = isset($_POST['regen']) || isset($_GET['regen']);

// ---- CSRF / same-origin check ----
function is_same_origin() {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    if ($host === '') return false;

    // Require the XMLHttpRequest sentinel header our JS always sends.
    // Simple HTML <form> submissions cannot set custom headers, so this
    // blocks the most common CSRF vector.
    $xrw = strtolower($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '');
    if ($xrw !== 'xmlhttprequest') return false;

    // Verify the Origin header when present (set by all modern browsers).
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '') {
        $origin_host = parse_url($origin, PHP_URL_HOST) ?? '';
        return $origin_host === $host;
    }

    // Fallback: check Referer (older browsers, Safari in some modes).
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    if ($referer !== '') {
        $referer_host = parse_url($referer, PHP_URL_HOST) ?? '';
        return $referer_host === $host;
    }

    return false;
}

if (!$regen && ($_SERVER['REQUEST_METHOD'] !== 'POST' || !is_same_origin())) {
    http_response_code(403);
    exit('Forbidden');
}

// ---- Record format validation ----
// Confirms data is a well-formed v6 record before it is written to `lines`.
//
// v6:  encNameHEX | v6 | recSalt1 | recSalt2 | nameNonce1 | nameNonce2 | iv1 | nonce2 | nonce3 | nonce4 | encHEX
//      Two Argon2id salts (one per master password); all per-cipher keys are
//      HKDF-derived. Name = AES-GCM(MK1) wrapped in ChaCha20-Poly1305(MK2);
//      payload = ChaCha20 -> AES-GCM -> Twofish-CTR -> Serpent-CTR.
function is_valid_record($s) {
    // Generous overall size cap — encHEX grows with the notes field.
    if (strlen($s) > 65536) return false;

    $p = explode('|', $s);

    if (count($p) === 11 && $p[1] === 'v6') {
        // encNameHEX [0]: non-empty, even-length hex
        if ($p[0] === '' || strlen($p[0]) % 2 !== 0 || !ctype_xdigit($p[0])) return false;
        // recSalt1(64), recSalt2(64), nameNonce1(24), nameNonce2(24), iv1(24), nonce2(24), nonce3(32), nonce4(32)
        $hexlens = array(2 => 64, 3 => 64, 4 => 24, 5 => 24, 6 => 24, 7 => 24, 8 => 32, 9 => 32);
        foreach ($hexlens as $i => $len) {
            if (strlen($p[$i]) !== $len || !ctype_xdigit($p[$i])) return false;
        }
        // Payload ciphertext [10]: non-empty, even-length hex
        if ($p[10] === '' || strlen($p[10]) % 2 !== 0 || !ctype_xdigit($p[10])) return false;
        return true;
    }

    return false;
}

// ---- Input validation ----
// Skipped entirely in regen mode (no record is read from the request).
$data       = null;
$de         = -1;
$delete_rec = null;   // delete-by-content: the full record string to remove
$bulk       = false;  // whole-vault replace (master-password change)
$bulk_lines = null;
$expect_hash = '';
if (!$regen) {
    $bulk = isset($_POST['bulk']);
    if ($bulk) {
        // Bulk replace is exclusive — no per-record params may ride along.
        if (isset($_POST['data']) || isset($_POST['delete']) || isset($_POST['delete_rec'])) {
            http_response_code(400);
            exit('Invalid data');
        }
        $bulk_data   = isset($_POST['bulk_data'])   ? $_POST['bulk_data']   : '';
        $expect_hash = isset($_POST['expect_hash']) ? $_POST['expect_hash'] : '';
        if (!preg_match('/^[0-9a-f]{64}$/', $expect_hash)) {
            http_response_code(400);
            exit('Invalid data');
        }
        if ($bulk_data === '' || strlen($bulk_data) > BULK_MAX_BYTES) {
            http_response_code(400);
            exit('Invalid data');
        }
        $bulk_lines = preg_split('/\R/', $bulk_data, -1, PREG_SPLIT_NO_EMPTY);
        if (!$bulk_lines) {
            http_response_code(400);
            exit('Invalid data');
        }
        foreach ($bulk_lines as $bl) {
            if (!is_valid_record($bl)) {
                http_response_code(400);
                exit('Invalid data');
            }
        }
    } else {
        $data       = isset($_POST['data']) ? $_POST['data'] : null;
        $de         = isset($_POST['delete']) ? intval($_POST['delete']) : -1;
        $delete_rec = isset($_POST['delete_rec']) ? $_POST['delete_rec'] : null;

        // delete index must be -1 (no delete) or a non-negative integer.
        // (Legacy path — kept only for clients that predate delete_rec.)
        if ($de < -1) $de = -1;

        // delete_rec must itself be a well-formed v6 record (it is one of ours)
        if ($delete_rec !== null && !is_valid_record($delete_rec)) {
            http_response_code(400);
            exit('Invalid data');
        }

        // Reject newlines in data — they would corrupt the one-record-per-line format
        if ($data !== null && (strpos($data, "\n") !== false || strpos($data, "\r") !== false)) {
            http_response_code(400);
            exit('Invalid data');
        }

        // Reject anything that is not a well-formed v6 record
        if ($data !== null && !is_valid_record($data)) {
            http_response_code(400);
            exit('Invalid data');
        }
    }
}

// ---- Acquire an exclusive lock for the whole read-modify-write ----
// Open `lines` (creating it if absent) and hold an exclusive lock across the
// read, the in-memory edit, the write-back, AND the index.html rebuild. Without
// this, two concurrent POSTs could each read the same `lines`, edit their own
// copy, and have the later write clobber the earlier one (a lost update). The
// lock is held on this single handle and released at the end; all writes below
// reuse it (rewind+truncate+write) rather than re-locking, which would deadlock.
$linesfp = fopen('lines', 'c+');
if ($linesfp === false || !flock($linesfp, LOCK_EX)) {
    http_response_code(500);
    exit('Lock failed');
}

$current = stream_get_contents($linesfp);
if ($current === false) $current = '';

// Split the locked snapshot into records, dropping empty lines (was
// FILE_SKIP_EMPTY_LINES); \R also tolerates any stray CRLF endings.
// Every mode below (regen / normal / bulk) works from this one array.
$array = $current === '' ? [] : preg_split('/\R/', $current, -1, PREG_SPLIT_NO_EMPTY);

// 409: the client's view of `lines` is out of date (another client wrote in
// between). Nothing has been backed up or modified at this point.
function respond_stale($linesfp) {
    http_response_code(409);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'stale']);
    flock($linesfp, LOCK_UN);
    fclose($linesfp);
    exit;
}

// ---- Staleness checks (inside the lock, before any backup or mutation) ----
if (!$regen) {
    if ($bulk) {
        // The client hashes the record list it re-encrypted (records joined
        // with "\n", no trailing newline). A mismatch means `lines` changed
        // under it, so its re-encryption is incomplete — refuse the replace.
        $have_hash = hash('sha256', implode("\n", $array));
        if (!hash_equals($have_hash, $expect_hash)
            || count($bulk_lines) !== count($array)) {
            respond_stale($linesfp);
        }
    } elseif ($delete_rec !== null) {
        // Delete by content: records are unique (random per-record salts), so
        // an exact string match identifies the entry regardless of how other
        // clients have reordered the file since this client loaded it.
        $idx = array_search($delete_rec, $array, true);
        if ($idx === false) {
            respond_stale($linesfp);
        }
        $de = $idx;
    }
}

// Delete all but the $keep most recent bak/lines.* files. The timestamp suffix
// is fixed-width and zero-padded, so a lexical sort is chronological (oldest first).
function prune_backups($keep) {
    $files = @glob('./bak/lines.*');
    if ($files === false || count($files) <= $keep) return;
    sort($files, SORT_STRING);
    foreach (array_slice($files, 0, count($files) - $keep) as $f) { @unlink($f); }
}

// ---- Backup the lines file before modifying it ----
// Back up the locked snapshot; abort if it cannot be written so we never modify
// the only copy. Skip when there is nothing to back up (empty/new file), and in
// regen mode, which never modifies `lines`.
if (!$regen && $current !== '') {
    if (!is_dir('bak')) { @mkdir('bak', 0700); }
    // Microsecond suffix keeps two writes in the same second from sharing a
    // backup filename; fixed width preserves the lexical-sort order above.
    $mt = microtime(true);
    $dt = date('Y-m-d_H.i.s') . sprintf('.%06d', (int)round(($mt - floor($mt)) * 1e6) % 1000000);
    $bakfile = './bak/lines.' . $dt;
    if (@file_put_contents($bakfile, $current) === false) {
        http_response_code(500);
        exit('Backup failed');
    }
    // Backups hold the full ciphertext DB — keep them owner-only on disk.
    @chmod($bakfile, 0600);
    // Drop the oldest backups beyond the retention cap.
    prune_backups(BAK_KEEP);
}

// ---- Update the database (lines file) ----
if ($regen) {
    // Regen: just normalise the order for the rebuild below; `lines` untouched.
    sort($array, SORT_STRING);
} else {
    if ($bulk) {
        // Whole-vault replace: count + hash already verified above, every
        // record already validated. This is the master-password-change commit.
        $array = $bulk_lines;
    } else {
        if ($de >= 0 && $de < count($array)) {
            array_splice($array, $de, 1);   // remove and re-index in one step
        }
        if ($data !== null) {
            $array[] = $data;
        }
    }
    sort($array, SORT_STRING);
    $out = $array ? implode("\n", $array) . "\n" : '';
    rewind($linesfp);
    if (!ftruncate($linesfp, 0) || fwrite($linesfp, $out) === false) {
        http_response_code(500);
        exit('Write failed');
    }
    fflush($linesfp);
}

// ---- Rebuild index.html from templates + entries ----
$array1 = file('part1');
if ($array1 === false) {
    http_response_code(500);
    exit('Template missing');
}

$asize = count($array);

for ($x = 0; $x < $asize; $x++) {
    $row   = trim($array[$x]);
    $parts = explode('|', $row);
    $ver   = isset($parts[1]) ? $parts[1] : '';

    // No inline onclick — CSP forbids 'unsafe-inline' scripts. The click is
    // wired in JS (_initEntries) from this data-row attribute.
    $data_row = htmlspecialchars($row . '|' . $x, ENT_QUOTES | ENT_HTML5, 'UTF-8');

    if ($ver === 'v6') {
        // Name is encrypted — button starts hidden; JS reveals it when both key fields are filled and the second key field loses focus.
        $array1[] = "<button class=\"entry-btn v5-locked\" style=\"display:none\" data-row=\"$data_row\">&#x1F512;</button>\n";
    } else {
        $name         = $parts[0];
        $display_name = htmlspecialchars($name, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $array1[] = "<button class=\"entry-btn\" title=\"$display_name\" data-row=\"$data_row\">$display_name</button>\n";
    }
}

$array2 = file('part2');
if ($array2 === false) {
    http_response_code(500);
    exit('Template missing');
}
foreach ($array2 as $line) {
    $array1[] = $line;
}

if (file_put_contents('index.html', $array1, LOCK_EX) === false) {
    http_response_code(500);
    exit('Write failed');
}

header('Content-Type: application/json; charset=utf-8');
$entries = [];
foreach ($array as $i => $line) {
    $row = trim($line);
    if ($row !== '') {
        $entries[] = $row . '|' . $i;
    }
}
echo json_encode(['ok' => true, 'regen' => $regen, 'entries' => $entries]);

// Release the exclusive lock held since the start of the critical section.
// (PHP would also release it on script end, but free it explicitly.)
flock($linesfp, LOCK_UN);
fclose($linesfp);
?>
