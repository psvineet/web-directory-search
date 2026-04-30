<?php
// ============================================================
//  SECURE DATA DIRECTORY — srs.php  (Upgraded)
// ============================================================
session_start([
    'cookie_httponly'  => true,
    'cookie_samesite'  => 'Strict',
    'use_strict_mode'  => true,
    'gc_maxlifetime'   => 1800,         // 30-min idle expiry
]);

// Regenerate session ID on every request to prevent fixation
if (empty($_SESSION['_init'])) {
    session_regenerate_id(true);
    $_SESSION['_init'] = true;
}

// Hardened cache headers (no caching for sensitive pages)
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');

// ── CSRF helper ──────────────────────────────────────────────
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}
function csrf_valid(): bool {
    $tok = $_POST['csrf_token'] ?? '';
    return !empty($tok) && hash_equals($_SESSION['csrf_token'] ?? '', $tok);
}

// ── Password (store the hash only; never the plaintext) ──────
// To change: php -r "echo password_hash('yourpassword', PASSWORD_ARGON2ID);"
$hashedPassword = password_hash('1234', PASSWORD_ARGON2ID);

// ── Rate-limiting via session (keyed by hashed IP) ───────────
$ipKey    = hash('sha256', $_SERVER['REMOTE_ADDR'] . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
$ratePath = 'login_attempts';

if (!isset($_SESSION[$ratePath][$ipKey])) {
    $_SESSION[$ratePath][$ipKey] = ['count' => 0, 'first' => time(), 'locked_until' => 0];
}
$ra  = &$_SESSION[$ratePath][$ipKey];
$now = time();

// Reset window if 24 h have passed since the first attempt
if ($now - $ra['first'] > 86400) {
    $ra = ['count' => 0, 'first' => $now, 'locked_until' => 0];
}

// ── Auth state ───────────────────────────────────────────────
$isAuthenticated = !empty($_SESSION['authenticated']);
$isLocked        = $ra['locked_until'] > $now;
$error           = null;

// ── Handle POST ──────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$isAuthenticated && !$isLocked) {

    // CSRF check
    if (!csrf_valid()) {
        $error = 'Invalid request. Please refresh and try again.';
    } else {
        // Regenerate CSRF after each attempt
        unset($_SESSION['csrf_token']);

        $pw = $_POST['password'] ?? '';

        // Constant-time verification (password_verify already is)
        if (is_string($pw) && strlen($pw) <= 128 && password_verify($pw, $hashedPassword)) {
            session_regenerate_id(true);           // Privilege escalation: new session
            $_SESSION['authenticated'] = true;
            $_SESSION['auth_time']     = $now;
            $isAuthenticated           = true;
            $ra = ['count' => 0, 'first' => $now, 'locked_until' => 0];
        } else {
            $ra['count']++;

            if ($ra['count'] >= 10) {
                $ra['locked_until'] = $now + 86400;
                $error = 'Account locked for 24 hours due to too many failed attempts.';
            } elseif ($ra['count'] >= 5) {
                $ra['locked_until'] = $now + 300;
                $error = 'Too many attempts. Please wait 5 minutes.';
            } else {
                $left  = 5 - $ra['count'];
                $error = "Incorrect password. $left attempt(s) remaining before lockout.";
            }
        }
    }
}

// Re-check lock (after POST may have just set it)
$isLocked = $ra['locked_until'] > $now;
if ($isLocked && !$error) {
    $mins  = ceil(($ra['locked_until'] - $now) / 60);
    $error = "Access locked. Try again in {$mins} minute(s).";
}

// ── Absolute session age (force re-auth after 30 min) ────────
if ($isAuthenticated && isset($_SESSION['auth_time']) && ($now - $_SESSION['auth_time'] > 1800)) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ── Logout (must be before any HTML output) ─────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout']) && csrf_valid()) {
    session_unset();
    session_destroy();
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true,
    ]);
    session_regenerate_id(true);
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ── File search (authenticated only) ─────────────────────────
$searchResults = [];
$searchQuery   = '';
$searched      = false;

$excludedFiles = [
    '.htaccess', '.htpasswd', 'config.php', 'settings.php',
    'database.php'
];
$excludedDirs = ['.git', 'node_modules'];

function searchFiles(string $dir, string $query, array $excludedFiles, array $excludedDirs): array {
    $results = [];
    try {
        $items = @scandir($dir);
        if ($items === false) return $results;
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            if (in_array($item, $excludedFiles) || in_array($item, $excludedDirs)) continue;
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $results = array_merge($results, searchFiles($path, $query, $excludedFiles, $excludedDirs));
            } elseif (stripos($item, $query) !== false) {
                $results[] = $path;
            }
        }
    } catch (Throwable) { /* silently skip unreadable dirs */ }
    return $results;
}

function getRelativePath(string $abs): string {
    $root = realpath($_SERVER['DOCUMENT_ROOT'] ?? '') ?: '';
    return $root ? str_replace($root, '', $abs) : $abs;
}

if ($isAuthenticated && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['search']) && csrf_valid()) {
    $raw         = trim($_POST['search'] ?? '');
    $searchQuery = preg_replace('/[^a-zA-Z0-9._\- ]/', '', $raw); // sanitize
    $searched    = true;
    if (strlen($searchQuery) >= 3) {
        $searchResults = searchFiles(__DIR__, $searchQuery, $excludedFiles, $excludedDirs);
    }
}

// Viewer routing: PDF->Google, Office->Microsoft
$pdfExts    = ['pdf'];
$officeExts = ['doc','docx','odt','ppt','pptx','odp','xls','xlsx','ods'];
$docViewerExts = array_merge($pdfExts, $officeExts);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  <meta name="robots" content="noindex, nofollow" />
  <link rel="icon" type="image/png" href="https://i.ibb.co/gFgcbp0d/3979425.png">
  <title>Data Directory</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@500;700&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />

  <style>
  /* ── Design Tokens ──────────────────────────────────────── */
  :root {
    --cream:        #fdf8ee;
    --cream-mid:    #f5edcf;
    --cream-border: #e8d9a8;
    --navy:         #0d1f3c;
    --navy-mid:     #162a4a;
    --navy-light:   #1f3a5f;
    --gold:         #c8981e;
    --gold-light:   #e0b040;
    --gold-pale:    #f7e9b8;
    --text-dark:    #1a1a2e;
    --text-mid:     #3d4a5c;
    --text-soft:    #7a8699;
    --danger:       #c0392b;
    --danger-bg:    #fdf0ef;
    --radius-sm:    8px;
    --radius-md:    14px;
    --radius-lg:    22px;
    --shadow-sm:    0 2px 8px rgba(13,31,60,0.08);
    --shadow-md:    0 6px 24px rgba(13,31,60,0.12);
    --shadow-lg:    0 16px 48px rgba(13,31,60,0.18);
    --transition:   0.25s cubic-bezier(.4,0,.2,1);
  }

  *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

  html { scroll-behavior: smooth; }

  body {
    font-family: 'DM Sans', sans-serif;
    font-weight: 400;
    background-color: var(--cream);
    background-image:
      radial-gradient(ellipse 70% 40% at 10% 0%, rgba(200,152,30,0.10) 0%, transparent 60%),
      radial-gradient(ellipse 60% 50% at 90% 100%, rgba(13,31,60,0.07) 0%, transparent 55%),
      url("data:image/svg+xml,%3Csvg width='52' height='52' viewBox='0 0 52 52' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M26 0 L52 26 L26 52 L0 26Z' fill='none' stroke='rgba(200,152,30,0.05)' stroke-width='1'/%3E%3C/svg%3E");
    min-height: 100vh;
    color: var(--text-dark);
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 0 0 60px;
  }

  /* ── Desktop content wrapper ─────────────────────────────── */
  .content-wrap {
    width: 100%;
    max-width: 1000px;
    padding: 0 28px;
    display: grid;
    grid-template-columns: 260px 1fr;
    gap: 28px;
    align-items: start;
    margin-top: 20px;
  }

  /* ── Sidebar ─────────────────────────────────────────────── */
  .sidebar {
    display: flex;
    flex-direction: column;
    gap: 16px;
    position: sticky;
    top: 24px;
    animation: fadeUp .5s ease both;
  }

  .sidebar-brand {
    background: var(--navy);
    border-radius: 16px;
    padding: 22px 20px;
    color: #fff;
  }

  .sidebar-brand .sb-icon {
    width: 38px; height: 38px;
    background: rgba(255,255,255,0.10);
    border: 1px solid rgba(255,255,255,0.14);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    margin-bottom: 14px;
  }
  .sidebar-brand .sb-icon svg { width: 18px; height: 18px; fill: var(--gold-light); }

  .sidebar-brand h2 {
    font-family: 'Playfair Display', serif;
    font-size: 1.15rem;
    font-weight: 700;
    color: #fff;
    letter-spacing: .02em;
    margin-bottom: 5px;
  }

  .sidebar-brand p {
    font-size: .75rem;
    color: rgba(255,255,255,0.45);
    line-height: 1.5;
    letter-spacing: .02em;
  }

  .sidebar-divider {
    height: 1px;
    background: rgba(255,255,255,0.08);
    margin: 14px 0;
  }

  .sidebar-stat {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: .76rem;
    color: rgba(255,255,255,0.5);
  }
  .sidebar-stat .dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: #2ecc71;
    box-shadow: 0 0 0 2px rgba(46,204,113,.2);
    flex-shrink: 0;
  }
  .sidebar-stat.locked .dot { background: var(--danger); box-shadow: 0 0 0 2px rgba(192,57,43,.2); }

  .sidebar-info {
    background: #fff;
    border: 1px solid var(--cream-border);
    border-radius: 14px;
    padding: 16px 18px;
  }

  .sidebar-info h4 {
    font-size: .72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--text-soft);
    margin-bottom: 10px;
  }

  .sidebar-info-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 0;
    border-bottom: 1px solid var(--cream-border);
    font-size: .78rem;
    color: var(--text-mid);
  }
  .sidebar-info-row:last-child { border-bottom: none; }
  .sidebar-info-row i {
    color: var(--gold);
    font-size: .72rem;
    width: 14px;
    text-align: center;
    flex-shrink: 0;
  }

  @media (max-width: 760px) {
    .content-wrap {
      grid-template-columns: 1fr;
      padding: 0 16px;
      margin-top: 14px;
      gap: 18px;
    }
    .sidebar { position: static; }
  }

  /* ── Header nav bar ─────────────────────────────────────── */
  .page-header {
    width: 100%;
    max-width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 0;
    background: var(--navy);
    border-radius: 0;
    padding: 0;
    box-shadow: 0 2px 16px rgba(13,31,60,0.18);
    animation: fadeDown .5s ease both;
    position: relative;
    z-index: 100;
  }

  @media (min-width: 761px) {
    .page-header { display: none; }
  }

  .nav-inner {
    width: 100%;
    max-width: 1000px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 0 28px;
    height: 44px;
  }

  /* left: brand icon */
  .nav-left {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  /* center: title */
  .nav-center {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  /* right: menu icon */
  .nav-right {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 6px;
    flex-shrink: 0;
  }

  .brand-icon {
    width: 26px; height: 26px;
    background: rgba(255,255,255,0.10);
    border: 1px solid rgba(255,255,255,0.14);
    border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }

  .brand-icon svg { width: 13px; height: 13px; fill: var(--gold-light); }

  .nav-center h1 {
    font-family: 'Playfair Display', serif;
    font-size: 1.05rem;
    font-weight: 700;
    color: #fff;
    letter-spacing: .04em;
    line-height: 1;
    white-space: nowrap;
  }

  .nav-menu-btn {
    width: 28px; height: 28px;
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer;
    transition: background var(--transition), border-color var(--transition);
    flex-shrink: 0;
    position: relative;
  }
  .nav-menu-btn:hover {
    background: rgba(255,255,255,0.14);
    border-color: rgba(255,255,255,0.24);
  }
  .nav-menu-btn i { color: rgba(255,255,255,0.80); font-size: .78rem; }

  /* dropdown menu */
  .nav-dropdown {
    display: none;
    position: absolute;
    top: calc(100% + 8px);
    right: 0;
    min-width: 160px;
    background: var(--navy-mid);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 10px;
    box-shadow: var(--shadow-lg);
    overflow: hidden;
    z-index: 9999;
    animation: fadeDown .18s ease both;
  }
  .nav-dropdown.open { display: block; }

  .nav-dropdown a,
  .nav-dropdown button {
    display: flex;
    align-items: center;
    gap: 9px;
    width: 100%;
    padding: 10px 14px;
    font-family: 'DM Sans', sans-serif;
    font-size: .82rem;
    font-weight: 500;
    color: rgba(255,255,255,0.75);
    background: none;
    border: none;
    cursor: pointer;
    text-decoration: none;
    transition: background var(--transition), color var(--transition);
    letter-spacing: .01em;
  }
  .nav-dropdown a:hover,
  .nav-dropdown button:hover {
    background: rgba(255,255,255,0.08);
    color: #fff;
  }
  .nav-dropdown .dd-divider {
    height: 1px;
    background: rgba(255,255,255,0.07);
    margin: 2px 0;
  }
  .nav-dropdown .dd-signout {
    color: var(--gold-light);
  }
  .nav-dropdown .dd-signout:hover {
    background: rgba(200,152,30,0.12);
    color: var(--gold-light);
  }
  .nav-dropdown i { font-size: .78rem; width: 14px; text-align: center; }

  /* nav status dot (kept for accessibility, hidden visually in right) */
  .nav-status {
    display: none; /* moved into dropdown label */
  }

  @media (max-width: 520px) {
    .page-header { padding: 9px 12px; gap: 8px; }
    .nav-center h1 { font-size: .88rem; }
  }

  /* ── Card ───────────────────────────────────────────────── */
  .card {
    width: 100%;
    background: #fff;
    border: 1px solid var(--cream-border);
    border-radius: var(--radius-lg);
    box-shadow: 0 4px 32px rgba(13,31,60,0.10);
    overflow: hidden;
    animation: fadeUp .5s .1s ease both;
    position: relative;
  }

  .card-body { padding: 28px 28px 24px; }

  /* ── Skeleton ───────────────────────────────────────────── */
  .skeleton-wrap {
    padding: 36px;
  }

  .skel-line {
    background: linear-gradient(90deg, var(--cream-mid) 25%, var(--cream) 50%, var(--cream-mid) 75%);
    background-size: 300% 100%;
    animation: shimmer 1.5s infinite;
    border-radius: 6px;
    margin-bottom: 14px;
  }

  .skel-line.title { height: 22px; width: 52%; margin-bottom: 26px; }
  .skel-line.l1    { height: 13px; width: 88%; }
  .skel-line.l2    { height: 13px; width: 72%; }
  .skel-line.l3    { height: 13px; width: 80%; }
  .skel-line.btn   { height: 44px; width: 100%; margin-top: 20px; border-radius: 10px; }

  @keyframes shimmer {
    0%   { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }

  /* ── Section labels ─────────────────────────────────────── */
  .section-label {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 20px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--cream-border);
  }

  .section-label .icon-wrap {
    width: 32px; height: 32px;
    background: var(--navy);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
  }

  .section-label .icon-wrap i {
    color: var(--gold-light);
    font-size: .82rem;
  }

  .section-label h2 {
    font-family: 'Playfair Display', serif;
    font-size: 1rem;
    font-weight: 700;
    color: var(--navy);
  }

  .section-label p {
    font-size: .72rem;
    color: var(--text-soft);
    margin-top: 1px;
  }

  /* ── Inputs ─────────────────────────────────────────────── */
  .field {
    position: relative;
    margin-bottom: 16px;
  }

  .field i.field-icon {
    position: absolute;
    left: 16px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-soft);
    font-size: .9rem;
    pointer-events: none;
    transition: color var(--transition);
  }

  .field input {
    width: 100%;
    padding: 14px 16px 14px 44px;
    border: 1.5px solid var(--cream-border);
    border-radius: var(--radius-md);
    background: var(--cream);
    font-family: 'DM Sans', sans-serif;
    font-size: .95rem;
    color: var(--text-dark);
    transition: border-color var(--transition), box-shadow var(--transition), background var(--transition);
    outline: none;
  }

  .field input::placeholder { color: var(--text-soft); }

  .field input:focus {
    border-color: var(--navy);
    background: #fff;
    box-shadow: 0 0 0 3px rgba(13,31,60,0.08);
  }

  .field input:focus + .field-icon,
  .field:focus-within i.field-icon { color: var(--navy); }

  /* ── Search row (input + button inline) ────────────────── */
  .search-row {
    display: flex;
    align-items: center;
    border: 1.5px solid var(--cream-border);
    border-radius: 12px;
    background: var(--cream);
    transition: border-color var(--transition), box-shadow var(--transition), background var(--transition);
    overflow: hidden;
    margin-bottom: 16px;
    height: 46px;
    gap: 0;
  }
  .search-row:focus-within {
    border-color: var(--navy);
    background: #fff;
    box-shadow: 0 0 0 3px rgba(13,31,60,0.07);
  }
  .search-row .search-icon {
    display: flex; align-items: center; justify-content: center;
    padding: 0 10px 0 14px;
    color: var(--text-soft);
    font-size: .8rem;
    flex-shrink: 0;
    pointer-events: none;
    transition: color var(--transition);
  }
  .search-row:focus-within .search-icon { color: var(--gold); }
  .search-row input {
    flex: 1;
    padding: 0;
    border: none;
    background: transparent;
    font-family: 'DM Sans', sans-serif;
    font-size: .88rem;
    color: var(--text-dark);
    outline: none;
    min-width: 0;
    text-overflow: ellipsis;
  }
  .search-row input::placeholder {
    color: var(--text-soft);
    text-overflow: ellipsis;
  }
  .search-row .search-submit {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 0 14px;
    margin: 4px;
    height: 34px;
    background: var(--navy);
    border: none;
    border-radius: 8px;
    color: #fff;
    font-family: 'DM Sans', sans-serif;
    font-size: .8rem;
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
    transition: background var(--transition), box-shadow var(--transition);
    letter-spacing: .04em;
    white-space: nowrap;
    text-transform: uppercase;
  }
  .search-row .search-submit:hover {
    background: var(--navy-light);
    box-shadow: 0 2px 8px rgba(13,31,60,0.25);
  }
  .search-row .search-submit i { font-size: .72rem; }

  @media (max-width: 480px) {
    .search-row .search-submit span { display: none; }
    .search-row .search-submit { padding: 0 12px; }
  }

  /* Eye toggle */
  .eye-toggle {
    position: absolute;
    right: 14px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--text-soft);
    cursor: pointer;
    font-size: .9rem;
    padding: 4px;
    transition: color var(--transition);
    width: auto;
  }

  .eye-toggle:hover { color: var(--navy); }

  /* ── Buttons ─────────────────────────────────────────────── */
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 14px 28px;
    border: none;
    border-radius: var(--radius-md);
    font-family: 'DM Sans', sans-serif;
    font-size: .95rem;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition);
    position: relative;
    overflow: hidden;
    letter-spacing: .01em;
  }

  .btn::after {
    content: '';
    position: absolute;
    inset: 0;
    background: rgba(255,255,255,0);
    transition: background var(--transition);
  }
  .btn:hover::after { background: rgba(255,255,255,0.08); }
  .btn:active::after { background: rgba(0,0,0,0.06); }

  .btn-primary {
    width: 100%;
    background: var(--navy);
    color: #fff;
    box-shadow: 0 4px 16px rgba(13,31,60,0.28);
  }

  .btn-primary:hover {
    background: var(--navy-light);
    box-shadow: 0 6px 22px rgba(13,31,60,0.34);
    transform: translateY(-1px);
  }

  .btn-primary:active { transform: translateY(0); box-shadow: var(--shadow-sm); }

  .btn-sm {
    padding: 8px 16px;
    font-size: .82rem;
    border-radius: var(--radius-sm);
  }

  .btn-ghost {
    background: transparent;
    color: var(--text-soft);
    border: 1.5px solid var(--cream-border);
    font-size: .82rem;
    padding: 7px 14px;
    border-radius: var(--radius-sm);
  }
  .btn-ghost:hover { background: var(--cream); color: var(--navy); border-color: var(--navy); }

  /* ── Alert / Error ──────────────────────────────────────── */
  .alert {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px 16px;
    border-radius: var(--radius-md);
    margin-bottom: 22px;
    font-size: .88rem;
    line-height: 1.5;
    font-weight: 500;
    border: 1.5px solid;
    animation: slideIn .3s ease;
  }

  .alert-error {
    background: var(--danger-bg);
    color: var(--danger);
    border-color: rgba(192,57,43,.2);
  }

  .alert i { margin-top: 1px; flex-shrink: 0; }

  /* ── Divider ────────────────────────────────────────────── */
  .divider {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 20px 0;
  }

  .divider::before, .divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--cream-border);
  }

  .divider span {
    font-size: .75rem;
    color: var(--text-soft);
    letter-spacing: .06em;
    text-transform: uppercase;
  }

  /* ── Search results ─────────────────────────────────────── */
  .results-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 20px 0 12px;
  }

  .results-header h3 {
    font-family: 'Playfair Display', serif;
    font-size: .88rem;
    color: var(--navy);
    font-weight: 700;
  }

  .results-header .badge {
    background: var(--navy);
    color: #fff;
    font-size: .68rem;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 20px;
    letter-spacing: .04em;
  }

  .result-list {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .result-list li {
    display: flex;
    align-items: center;
    gap: 11px;
    padding: 10px 12px;
    background: var(--cream);
    border: 1px solid transparent;
    border-radius: 10px;
    transition: all var(--transition);
    cursor: pointer;
    text-decoration: none;
    color: var(--text-dark);
    animation: fadeUp .25s ease both;
  }

  .result-list li:hover {
    border-color: var(--navy);
    background: #fff;
    box-shadow: 0 2px 12px rgba(13,31,60,0.08);
    transform: translateX(2px);
  }

  .result-list li .file-icon {
    width: 30px; height: 30px;
    border-radius: 7px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }

  .result-list li .file-icon i {
    font-size: .8rem;
  }

  .result-list li .file-name {
    font-size: .85rem;
    font-weight: 500;
    color: var(--navy);
    word-break: break-all;
    line-height: 1.3;
  }

  .result-list li .file-path {
    font-size: .7rem;
    color: var(--text-soft);
    margin-top: 1px;
  }

  .result-list li .open-icon {
    color: var(--text-soft);
    font-size: .72rem;
    flex-shrink: 0;
    opacity: 0;
    transition: opacity var(--transition);
  }
  .result-list li:hover .open-icon { opacity: 1; }

  /* Empty state */
  .empty-state {
    text-align: center;
    padding: 36px 20px;
    color: var(--text-soft);
  }

  .empty-state i {
    font-size: 2.2rem;
    color: var(--cream-border);
    margin-bottom: 14px;
    display: block;
  }

  .empty-state p { font-size: .9rem; }

  /* ── Auth footer strip ──────────────────────────────────── */
  .auth-footer {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 9px 24px;
    background: var(--cream);
    border-top: 1px solid var(--cream-border);
    font-size: .72rem;
    color: var(--text-soft);
  }

  /* ── Modal ──────────────────────────────────────────────── */
  .modal-backdrop {
    display: none;
    position: fixed; inset: 0;
    background: rgba(10,20,40,0.75);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    z-index: 9000;
    align-items: center;
    justify-content: center;
    padding: 12px;
    animation: fadeIn .2s ease;
  }

  .modal-backdrop.open { display: flex; }

  .modal-box {
    width: 100%;
    max-width: 960px;
    height: calc(100vh - 24px);
    max-height: 920px;
    background: var(--navy);
    border-radius: var(--radius-md);
    overflow: hidden;
    box-shadow: 0 30px 80px rgba(0,0,0,0.5);
    display: flex;
    flex-direction: column;
    animation: scaleIn .25s ease;
    position: relative;
  }

  @media (max-width: 600px) {
    .modal-backdrop { padding: 8px; }
    .modal-box {
      height: calc(100vh - 16px);
      border-radius: var(--radius-sm);
    }
  }

  .btn-close {
    width: 30px; height: 30px;
    background: rgba(255,255,255,0.08);
    border: none;
    border-radius: 50%;
    color: #fff;
    cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    font-size: .85rem;
    transition: background var(--transition);
    flex-shrink: 0;
  }
  .btn-close:hover { background: rgba(192,57,43,0.6); }

  .modal-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 9px 12px;
    background: var(--navy-mid);
    border-bottom: 1px solid rgba(255,255,255,0.07);
    gap: 10px;
    flex-shrink: 0;
  }

  .modal-bar-left {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    overflow: hidden;
  }

  .modal-bar-right {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-shrink: 0;
  }

  .modal-file-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
    transition: background .3s;
  }

  .modal-title {
    font-size: .82rem;
    color: rgba(255,255,255,0.85);
    font-weight: 500;
    font-family: 'DM Sans', sans-serif;
    display: flex; align-items: center; gap: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .modal-title i { font-size: .78rem; flex-shrink: 0; }

  .modal-viewer-badge {
    font-size: .62rem;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 20px;
    border: 1px solid;
    letter-spacing: .04em;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .modal-action-btn {
    width: 27px; height: 27px;
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 6px;
    color: rgba(255,255,255,0.55);
    cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    font-size: .75rem;
    transition: all var(--transition);
  }

  .modal-action-btn:hover { background: rgba(255,255,255,0.14); color: #fff; }

  /* viewer overlays */
  .viewer-loading,
  .viewer-error {
    position: absolute;
    inset: 0;
    top: 48px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
    background: var(--navy);
    z-index: 5;
    text-align: center;
    padding: 24px;
  }

  .viewer-spinner {
    width: 38px; height: 38px;
    border: 3px solid rgba(255,255,255,0.1);
    border-top-color: var(--gold);
    border-radius: 50%;
    animation: spin .8s linear infinite;
    margin-bottom: 4px;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .viewer-loading p { color: rgba(255,255,255,0.75); font-size: .9rem; font-weight: 500; }
  .viewer-loading-sub { color: rgba(255,255,255,0.35) !important; font-size: .75rem !important; margin-top: -4px; }

  .viewer-error-icon {
    width: 52px; height: 52px;
    background: rgba(192,57,43,0.14);
    border: 2px solid rgba(192,57,43,0.28);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
  }
  .viewer-error-icon i { font-size: 1.3rem; color: #e74c3c; }
  .viewer-error p { color: rgba(255,255,255,0.8); font-size: .88rem; font-weight: 500; }
  .viewer-error-sub { color: rgba(255,255,255,0.38) !important; font-size: .76rem !important; margin-top: -4px; }
  .viewer-error-btns { display: flex; gap: 8px; margin-top: 6px; flex-wrap: wrap; justify-content: center; }

  #modal-frame {
    position: absolute;
    inset: 0;
    top: 48px;
    width: 100%;
    height: calc(100% - 48px);
    border: none;
    background: #fff;
    opacity: 0;
    pointer-events: none;
    transition: opacity .3s ease;
  }

  /* ── Lockout state ──────────────────────────────────────── */
  .lock-state {
    text-align: center;
    padding: 24px 0 8px;
  }

  .lock-state .lock-icon {
    width: 64px; height: 64px;
    background: var(--cream);
    border: 2px solid var(--cream-border);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 20px;
  }

  .lock-state .lock-icon i {
    font-size: 1.6rem;
    color: var(--danger);
  }

  .lock-state h3 {
    font-family: 'Playfair Display', serif;
    font-size: 1.15rem;
    color: var(--navy);
    margin-bottom: 8px;
  }

  .lock-state p {
    font-size: .88rem;
    color: var(--text-soft);
    max-width: 320px;
    margin: 0 auto;
    line-height: 1.6;
  }

  /* ── Animations ─────────────────────────────────────────── */
  @keyframes fadeUp {
    from { opacity:0; transform:translateY(14px); }
    to   { opacity:1; transform:translateY(0); }
  }
  @keyframes fadeDown {
    from { opacity:0; transform:translateY(-10px); }
    to   { opacity:1; transform:translateY(0); }
  }
  @keyframes fadeIn {
    from { opacity:0; } to { opacity:1; }
  }
  @keyframes scaleIn {
    from { opacity:0; transform:scale(.96); }
    to   { opacity:1; transform:scale(1); }
  }
  @keyframes slideIn {
    from { opacity:0; transform:translateY(-6px); }
    to   { opacity:1; transform:translateY(0); }
  }

  .sidebar-nav {
    display: flex;
    flex-direction: row;
    gap: 6px;
    margin-top: 14px;
  }

  .sidebar-nav-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    flex: 1;
    padding: 8px 10px;
    border-radius: 9px;
    border: 1px solid rgba(255,255,255,0.10);
    background: rgba(255,255,255,0.06);
    color: rgba(255,255,255,0.75);
    font-family: 'DM Sans', sans-serif;
    font-size: .78rem;
    font-weight: 500;
    cursor: pointer;
    text-decoration: none;
    transition: background var(--transition), color var(--transition), border-color var(--transition);
    letter-spacing: .01em;
    white-space: nowrap;
  }
  .sidebar-nav-btn i { font-size: .72rem; flex-shrink: 0; }
  .sidebar-nav-btn:hover {
    background: rgba(255,255,255,0.12);
    color: #fff;
    border-color: rgba(255,255,255,0.20);
  }
  .sidebar-nav-btn.signout {
    color: var(--gold-light);
    border-color: rgba(200,152,30,0.25);
    background: rgba(200,152,30,0.08);
  }
  .sidebar-nav-btn.signout:hover {
    background: rgba(200,152,30,0.16);
    border-color: rgba(200,152,30,0.40);
  }

  /* ── Responsive ─────────────────────────────────────────── */
  @media (max-width: 760px) {
    body { padding: 0 0 48px; }
    .nav-inner { height: 40px; padding: 0 14px; }
    .card-body { padding: 20px 18px 18px; }
    .auth-footer { padding: 8px 18px; }
    .sidebar { display: none; }
  }
  </style>
</head>
<body>

<!-- ── Page Header ──────────────────────────────────────────── -->
<header class="page-header">
 <div class="nav-inner">
  <!-- Left: brand icon -->
  <div class="nav-left">
    <div class="brand-icon">
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M20 6h-2.18A3 3 0 0 0 15 4H9a3 3 0 0 0-2.82 2H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2zM9 6h6v2H9V6zm6 9h-3v3h-2v-3H7v-2h3V10h2v3h3v2z"/>
      </svg>
    </div>
  </div>

  <!-- Center: title -->
  <div class="nav-center">
    <h1>Data Directory</h1>
  </div>

  <!-- Right: hamburger menu -->
  <div class="nav-right">
    <div style="position:relative;">
      <button class="nav-menu-btn" id="nav-menu-btn" aria-label="Menu" aria-expanded="false">
        <i class="fa-solid fa-bars"></i>
      </button>
      <div class="nav-dropdown" id="nav-dropdown">
        <?php if ($isAuthenticated): ?>
          <a href="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>">
            <i class="fa-solid fa-house"></i> Home
          </a>
          <div class="dd-divider"></div>
          <form method="POST" style="display:contents;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
            <input type="hidden" name="logout" value="1">
            <button type="submit" class="dd-signout">
              <i class="fa-solid fa-arrow-right-from-bracket"></i> Sign out
            </button>
          </form>
        <?php else: ?>
          <span style="display:flex;align-items:center;gap:9px;padding:10px 14px;font-size:.82rem;color:rgba(255,255,255,0.38);font-family:'DM Sans',sans-serif;">
            <i class="fa-solid fa-lock" style="font-size:.78rem;width:14px;text-align:center;"></i> Locked
          </span>
        <?php endif; ?>
      </div>
    </div>
  </div>
 </div>
</header>

<!-- ── Desktop Layout ────────────────────────────────────────── -->
<div class="content-wrap">

  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="sidebar-brand">
      <div class="sb-icon">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M20 6h-2.18A3 3 0 0 0 15 4H9a3 3 0 0 0-2.82 2H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2zM9 6h6v2H9V6zm6 9h-3v3h-2v-3H7v-2h3V10h2v3h3v2z"/>
        </svg>
      </div>
      <h2>Data Directory</h2>
      <p>Secure file registry with access control and document viewer.</p>
      <div class="sidebar-divider"></div>
      <div class="sidebar-stat <?= $isAuthenticated ? '' : 'locked' ?>">
        <span class="dot"></span>
        <?= $isAuthenticated ? 'Session active' : 'Authentication required' ?>
      </div>

      <?php if ($isAuthenticated): ?>
      <div class="sidebar-nav">
        <a href="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" class="sidebar-nav-btn">
          <i class="fa-solid fa-house"></i> Home
        </a>
        <form method="POST" style="display:contents;">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <input type="hidden" name="logout" value="1">
          <button type="submit" class="sidebar-nav-btn signout">
            <i class="fa-solid fa-arrow-right-from-bracket"></i> Sign out
          </button>
        </form>
      </div>
      <?php endif; ?>
    </div>

    <div class="sidebar-info">
      <h4>About</h4>
      <div class="sidebar-info-row">
        <i class="fa-solid fa-shield-halved"></i>
        CSRF protected
      </div>
      <div class="sidebar-info-row">
        <i class="fa-solid fa-clock"></i>
        30 min session timeout
      </div>
      <div class="sidebar-info-row">
        <i class="fa-solid fa-eye"></i>
        PDF &amp; Office viewer
      </div>
      <div class="sidebar-info-row">
        <i class="fa-solid fa-folder-tree"></i>
        Recursive file search
      </div>
    </div>
  </aside>

  <!-- Main Card -->
  <div>
  <div class="card" id="main-card">

  <!-- Skeleton (visible until JS hides it) -->
  <div class="skeleton-wrap" id="skeleton">
    <div class="skel-line title"></div>
    <div class="skel-line l1"></div>
    <div class="skel-line l2"></div>
    <div class="skel-line l3"></div>
    <div class="skel-line btn"></div>
  </div>

  <!-- Real content (hidden until loaded) -->
  <div class="card-body" id="content" style="display:none; opacity:0;">

    <?php if ($isLocked && !$isAuthenticated): ?>
    <!-- ── Locked state ─────────────────────────────────────── -->
    <div class="lock-state">
      <div class="lock-icon"><i class="fa-solid fa-lock"></i></div>
      <h3>Access Temporarily Locked</h3>
      <p><?= htmlspecialchars($error ?? 'Too many failed attempts.') ?></p>
    </div>

    <?php elseif (!$isAuthenticated): ?>
    <!-- ── Login form ───────────────────────────────────────── -->
    <div class="section-label">
      <div class="icon-wrap"><i class="fa-solid fa-key"></i></div>
      <div>
        <h2>Authentication Required</h2>
        <p>Enter your access credential to continue</p>
      </div>
    </div>

    <?php if (isset($error) && !$isLocked): ?>
    <div class="alert alert-error" role="alert">
      <i class="fa-solid fa-circle-exclamation"></i>
      <span><?= htmlspecialchars($error) ?></span>
    </div>
    <?php endif; ?>

    <form method="POST" autocomplete="off" novalidate id="login-form">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

      <div class="field">
        <i class="fa-solid fa-lock field-icon"></i>
        <input
          type="password"
          name="password"
          id="pw-input"
          placeholder="Enter password"
          maxlength="128"
          required
          autofocus
          autocomplete="current-password"
        />
        <button type="button" class="eye-toggle" id="eye-btn" aria-label="Toggle visibility">
          <i class="fa-solid fa-eye" id="eye-icon"></i>
        </button>
      </div>

      <button type="submit" class="btn btn-primary">
        <i class="fa-solid fa-arrow-right-to-bracket"></i>
        Unlock Directory
      </button>
    </form>

    <?php else: ?>
    <!-- ── Authenticated: Search ────────────────────────────── -->
    <div class="section-label">
      <div class="icon-wrap"><i class="fa-solid fa-folder-open"></i></div>
      <div>
        <h2>File Directory</h2>
        <p>Search across all accessible files</p>
      </div>
    </div>

    <form method="POST" id="search-form" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">

      <div class="search-row">
        <i class="fa-solid fa-magnifying-glass search-icon"></i>
        <input
          type="text"
          name="search"
          id="search-input"
          placeholder="Search files…"
          value="<?= htmlspecialchars($searchQuery) ?>"
          maxlength="120"
          autofocus
        />
        <button type="submit" class="search-submit" id="search-btn">
          <i class="fa-solid fa-magnifying-glass"></i>
          <span>Search</span>
        </button>
      </div>
    </form>

    <?php if ($searched): ?>
    <?php if (strlen($searchQuery) < 3): ?>
    <div class="alert alert-error" role="alert" style="margin-top:20px;">
      <i class="fa-solid fa-circle-exclamation"></i>
      <span>Please enter at least 3 characters.</span>
    </div>

    <?php elseif (empty($searchResults)): ?>
    <div class="divider"><span>Results</span></div>
    <div class="empty-state">
      <i class="fa-solid fa-file-circle-question"></i>
      <p>No files matched "<strong><?= htmlspecialchars($searchQuery) ?></strong>"</p>
    </div>

    <?php else: ?>
    <div class="results-header">
      <h3>Results for "<?= htmlspecialchars($searchQuery) ?>"</h3>
      <span class="badge"><?= count($searchResults) ?> found</span>
    </div>

    <ul class="result-list" id="result-list">
      <?php foreach ($searchResults as $i => $absPath):
        $rel       = getRelativePath($absPath);
        $filename  = basename($rel);
        $ext       = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
        $url       = 'https://' . htmlspecialchars($_SERVER['HTTP_HOST']) . $rel;
        $isDoc     = in_array($ext, $docViewerExts);
        $viewerUrl = null;
        $viewerType = 'none';
        if ($isDoc) {
          if (in_array($ext, $pdfExts)) {
            $viewerUrl  = 'https://docs.google.com/viewer?embedded=true&url=' . rawurlencode($url);
            $viewerType = 'google';
          } else {
            $viewerUrl  = 'https://view.officeapps.live.com/op/embed.aspx?src=' . rawurlencode($url);
            $viewerType = 'office';
          }
        }

        // Coloured icon per file type
        $iconData = [
          'pdf'  => ['fa-file-pdf',        '#E34234'],
          'doc'  => ['fa-file-word',        '#2B5797'],
          'docx' => ['fa-file-word',        '#2B5797'],
          'odt'  => ['fa-file-word',        '#2B5797'],
          'xls'  => ['fa-file-excel',       '#1D6F42'],
          'xlsx' => ['fa-file-excel',       '#1D6F42'],
          'ods'  => ['fa-file-excel',       '#1D6F42'],
          'ppt'  => ['fa-file-powerpoint',  '#C43E1C'],
          'pptx' => ['fa-file-powerpoint',  '#C43E1C'],
          'odp'  => ['fa-file-powerpoint',  '#C43E1C'],
          'jpg'  => ['fa-image',            '#8B5CF6'],
          'jpeg' => ['fa-image',            '#8B5CF6'],
          'png'  => ['fa-image',            '#8B5CF6'],
          'gif'  => ['fa-image',            '#8B5CF6'],
          'webp' => ['fa-image',            '#8B5CF6'],
          'svg'  => ['fa-image',            '#F59E0B'],
          'zip'  => ['fa-box-archive',      '#6B7280'],
          'rar'  => ['fa-box-archive',      '#6B7280'],
          '7z'   => ['fa-box-archive',      '#6B7280'],
          'php'  => ['fa-code',             '#7C3AED'],
          'js'   => ['fa-code',             '#F7DF1E'],
          'ts'   => ['fa-code',             '#3178C6'],
          'html' => ['fa-code',             '#E34C26'],
          'css'  => ['fa-code',             '#264DE4'],
          'txt'  => ['fa-align-left',       '#9CA3AF'],
          'md'   => ['fa-align-left',       '#374151'],
          'mp4'  => ['fa-film',             '#EF4444'],
          'mp3'  => ['fa-music',            '#10B981'],
          'wav'  => ['fa-music',            '#10B981'],
        ];
        $iconEntry = $iconData[$ext] ?? ['fa-file', '#94A3B8'];
        $ico       = $iconEntry[0];
        $icoColor  = $iconEntry[1];

        $delay = $i * 0.045;
        $displayPath = dirname($rel) !== '/' ? dirname($rel) : '';
      ?>
      <li
        style="animation-delay: <?= $delay ?>s"
        data-href="<?= htmlspecialchars($isDoc ? $viewerUrl : $url) ?>"
        data-modal="<?= $isDoc ? '1' : '0' ?>"
        data-modal-title="<?= htmlspecialchars($filename) ?>"
        data-viewer-type="<?= htmlspecialchars($viewerType) ?>"
        data-raw-url="<?= htmlspecialchars($url) ?>"
        onclick="handleFileClick(this)"
        role="link"
        tabindex="0"
        onkeydown="if(event.key==='Enter') handleFileClick(this)"
      >
        <div class="file-icon" style="background:<?= $icoColor ?>18;border:1.5px solid <?= $icoColor ?>30;">
          <i class="fa-solid <?= $ico ?>" style="color:<?= $icoColor ?>;"></i>
        </div>
        <div style="min-width:0;">
          <div class="file-name"><?= htmlspecialchars($filename) ?></div>
          <?php if ($displayPath): ?>
          <div class="file-path"><?= htmlspecialchars($displayPath) ?></div>
          <?php endif; ?>
        </div>
        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
          <i class="fa-solid fa-arrow-up-right-from-square open-icon"></i>
        </div>
      </li>
      <?php endforeach; ?>
    </ul>
    <?php endif; ?>
    <?php endif; ?>
    <?php endif; ?>

  </div><!-- /card-body -->

  <?php if ($isAuthenticated): ?>
  <div class="auth-footer">
    <span style="display:flex;align-items:center;gap:6px;">
      <i class="fa-solid fa-shield-halved" style="color:var(--gold);font-size:.75rem;"></i>
      Session active &mdash; use <strong style="color:var(--navy);margin:0 3px;">Sign out</strong> in the nav when done
    </span>
  </div>
  <?php endif; ?>

</div><!-- /card -->
</div><!-- /main col -->

</div><!-- /content-wrap -->

<!-- ── Doc Viewer Modal ─────────────────────────────────────── -->
<div class="modal-backdrop" id="modal" role="dialog" aria-modal="true">
  <div class="modal-box">
    <div class="modal-bar">
      <div class="modal-bar-left">
        <div class="modal-file-dot" id="modal-file-dot"></div>
        <span class="modal-title">
          <i class="fa-solid fa-file" id="modal-icon"></i>
          <span id="modal-filename">Document</span>
        </span>
        <span class="modal-viewer-badge" id="modal-viewer-badge"></span>
      </div>
      <div class="modal-bar-right">
        <button class="modal-action-btn" id="btn-retry" onclick="retryViewer()" title="Retry">
          <i class="fa-solid fa-rotate-right"></i>
        </button>
        <button class="modal-action-btn" id="btn-open-new" onclick="openInNew()" title="Open in new tab">
          <i class="fa-solid fa-arrow-up-right-from-square"></i>
        </button>
        <button class="btn-close" onclick="closeModal()" aria-label="Close">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>
    </div>
    <div class="viewer-loading" id="viewer-loading">
      <div class="viewer-spinner"></div>
      <p id="viewer-loading-msg">Loading document…</p>
      <p class="viewer-loading-sub" id="viewer-sub-msg">This may take a moment</p>
    </div>
    <div class="viewer-error" id="viewer-error" style="display:none;">
      <div class="viewer-error-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
      <p id="viewer-error-msg">Could not load document</p>
      <p class="viewer-error-sub" id="viewer-error-sub">The viewer could not render this file.</p>
      <div class="viewer-error-btns">
        <button class="btn btn-primary btn-sm" onclick="retryViewer()">
          <i class="fa-solid fa-rotate-right"></i> Retry
        </button>
        <button class="btn btn-ghost btn-sm" onclick="openInNew()">
          <i class="fa-solid fa-arrow-up-right-from-square"></i> Open directly
        </button>
      </div>
    </div>
    <iframe id="modal-frame" src="" title="Document viewer"></iframe>
  </div>
</div>



<script>
(function () {
  'use strict';

  // ── Skeleton reveal ────────────────────────────────────────
  const skeleton = document.getElementById('skeleton');
  const content  = document.getElementById('content');

  setTimeout(() => {
    skeleton.style.transition = 'opacity .4s ease';
    skeleton.style.opacity    = '0';
    setTimeout(() => {
      skeleton.style.display = 'none';
      content.style.display  = 'block';
      requestAnimationFrame(() => {
        content.style.transition = 'opacity .4s ease';
        content.style.opacity    = '1';
      });
    }, 420);
  }, 900);

  // ── Password show/hide ─────────────────────────────────────
  const eyeBtn  = document.getElementById('eye-btn');
  const eyeIcon = document.getElementById('eye-icon');
  const pwInput = document.getElementById('pw-input');

  if (eyeBtn && pwInput) {
    eyeBtn.addEventListener('click', () => {
      const isHidden = pwInput.type === 'password';
      pwInput.type   = isHidden ? 'text' : 'password';
      eyeIcon.className = isHidden ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
    });
  }

  // ── Hamburger menu toggle ──────────────────────────────────
  const navMenuBtn  = document.getElementById('nav-menu-btn');
  const navDropdown = document.getElementById('nav-dropdown');
  if (navMenuBtn && navDropdown) {
    navMenuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = navDropdown.classList.toggle('open');
      navMenuBtn.setAttribute('aria-expanded', open);
    });
    document.addEventListener('click', () => {
      navDropdown.classList.remove('open');
      navMenuBtn.setAttribute('aria-expanded', 'false');
    });
    navDropdown.addEventListener('click', (e) => e.stopPropagation());
  }

  // ── Search validation ──────────────────────────────────────
  const searchForm = document.getElementById('search-form');
  const searchInput = document.getElementById('search-input');

  if (searchForm && searchInput) {
    searchForm.addEventListener('submit', (e) => {
      if (searchInput.value.trim().length < 3) {
        e.preventDefault();
        searchInput.style.borderColor = 'var(--danger)';
        searchInput.focus();
        setTimeout(() => { searchInput.style.borderColor = ''; }, 2000);
      }
    });
  }

  // ── Bulletproof PDF/Office Viewer with infinite smart retry ─
  const modal         = document.getElementById('modal');
  const modalFrame    = document.getElementById('modal-frame');
  const modalName     = document.getElementById('modal-filename');
  const modalIcon     = document.getElementById('modal-icon');
  const modalBadge    = document.getElementById('modal-viewer-badge');
  const modalDot      = document.getElementById('modal-file-dot');
  const viewerLoading = document.getElementById('viewer-loading');
  const viewerError   = document.getElementById('viewer-error');
  const loadingMsg    = document.getElementById('viewer-loading-msg');
  const loadingSub    = document.getElementById('viewer-sub-msg');
  const errorSub      = document.getElementById('viewer-error-sub');

  // ── Viewer URL builders ─────────────────────────────────────
  // Google Docs viewer (works for PDF + office files)
  // Microsoft Office Online (works best for office files)
  // We cycle through strategies on each retry
  function buildViewerUrl(rawUrl, strategy) {
    const enc = encodeURIComponent(rawUrl);
    switch (strategy) {
      case 'google':         return 'https://docs.google.com/viewer?embedded=true&url=' + enc;
      case 'google-nocache': return 'https://docs.google.com/viewer?embedded=true&url=' + enc + '&t=' + Date.now();
      case 'office':         return 'https://view.officeapps.live.com/op/embed.aspx?src=' + enc;
      case 'office-nocache': return 'https://view.officeapps.live.com/op/embed.aspx?src=' + enc + '&t=' + Date.now();
      default:               return rawUrl;
    }
  }

  // Strategy sequence per file type
  function strategyList(vtype) {
    if (vtype === 'google') {
      // PDF: try Google, retry Google with cache bust, try Office, retry Google again, keep retrying
      return ['google', 'google-nocache', 'office', 'google-nocache', 'google-nocache'];
    }
    // Office: try Office, retry Office, fallback Google, retry Google
    return ['office', 'office-nocache', 'google', 'google-nocache', 'office-nocache'];
  }

  // ── State ───────────────────────────────────────────────────
  let _rawUrl       = '';
  let _vtype        = 'none';
  let _attempt      = 0;
  let _strategies   = [];
  let _timer        = null;       // timeout watchdog
  let _pollTimer    = null;       // content-ready poll
  let _loading      = false;
  let _aborted      = false;

  // How long to wait before declaring a timeout and retrying (ms)
  // Google Docs is slow — give it 20s before retrying
  const TIMEOUT_MS  = 20000;
  // How often we poll the iframe to check it has real content
  const POLL_MS     = 1500;

  const typeVisual = {
    pdf:  { icon: 'fa-file-pdf',        color: '#E34234' },
    doc:  { icon: 'fa-file-word',        color: '#2B5797' },
    docx: { icon: 'fa-file-word',        color: '#2B5797' },
    odt:  { icon: 'fa-file-word',        color: '#2B5797' },
    xls:  { icon: 'fa-file-excel',       color: '#1D6F42' },
    xlsx: { icon: 'fa-file-excel',       color: '#1D6F42' },
    ods:  { icon: 'fa-file-excel',       color: '#1D6F42' },
    ppt:  { icon: 'fa-file-powerpoint',  color: '#C43E1C' },
    pptx: { icon: 'fa-file-powerpoint',  color: '#C43E1C' },
    odp:  { icon: 'fa-file-powerpoint',  color: '#C43E1C' },
  };

  function extOf(name) { return (name.split('.').pop() || '').toLowerCase(); }

  // ── UI state helpers ────────────────────────────────────────
  function showLoading(msg, sub) {
    viewerLoading.style.display    = 'flex';
    viewerError.style.display      = 'none';
    modalFrame.style.opacity       = '0';
    modalFrame.style.pointerEvents = 'none';
    if (msg) loadingMsg.textContent = msg;
    if (sub) loadingSub.textContent = sub;
  }

  function showReady() {
    viewerLoading.style.display    = 'none';
    viewerError.style.display      = 'none';
    modalFrame.style.opacity       = '1';
    modalFrame.style.pointerEvents = 'auto';
  }

  function showError(sub) {
    viewerLoading.style.display    = 'none';
    viewerError.style.display      = 'flex';
    modalFrame.style.opacity       = '0';
    modalFrame.style.pointerEvents = 'none';
    if (sub) errorSub.textContent = sub;
  }

  // ── Content verification ────────────────────────────────────
  // Google Docs viewer loads a "preview unavailable" page that
  // still fires the `load` event — we must detect real content.
  // Strategy: the iframe src domain confirms the viewer loaded
  // something. We check body dimensions & title via postMessage
  // probe — but since it's cross-origin we rely on timing + size.
  function verifyIframeContent(onSuccess, onFail) {
    // We can't read cross-origin iframe internals.
    // Best heuristic: wait a short moment after `load` fires,
    // then check if the iframe has nonzero scrollHeight via
    // a ResizeObserver on the iframe element itself.
    // If still 0 after 3s → fail.
    let checks = 0;
    const maxChecks = 6; // 6 × 500ms = 3s
    clearInterval(_pollTimer);
    _pollTimer = setInterval(() => {
      if (_aborted) { clearInterval(_pollTimer); return; }
      checks++;
      const rect = modalFrame.getBoundingClientRect();
      const hasSize = rect.width > 50 && rect.height > 100;
      if (hasSize) {
        // iframe is visible and sized — treat as success
        clearInterval(_pollTimer);
        onSuccess();
      } else if (checks >= maxChecks) {
        clearInterval(_pollTimer);
        onFail();
      }
    }, 500);
  }

  // ── Core load function ──────────────────────────────────────
  function loadAttempt() {
    if (_aborted) return;
    clearTimeout(_timer);
    clearInterval(_pollTimer);

    const strategy = _strategies[_attempt] || _strategies[_strategies.length - 1];
    const url      = buildViewerUrl(_rawUrl, strategy);

    // Update loading message
    const totalStrategies = _strategies.length;
    if (_attempt === 0) {
      showLoading('Loading document\u2026', 'Please wait\u2026');
    } else {
      const isFallback = strategy.startsWith('office') && _vtype === 'google';
      showLoading(
        'Retrying\u2026',
        isFallback
          ? 'Trying Microsoft Office viewer\u2026'
          : 'Attempt ' + (_attempt + 1) + ' \u2014 please wait\u2026'
      );
    }

    // Reset iframe src cleanly
    modalFrame.removeEventListener('load', _onLoad);
    modalFrame.removeEventListener('error', _onError);
    modalFrame.src = 'about:blank';

    setTimeout(() => {
      if (_aborted) return;
      modalFrame.addEventListener('load',  _onLoad,  { once: true });
      modalFrame.addEventListener('error', _onError, { once: true });
      modalFrame.src = url;

      // Hard timeout watchdog — keeps spinner going, then retries
      _timer = setTimeout(() => {
        if (_aborted) return;
        _attempt++;
        loadAttempt(); // retry — spinner stays on
      }, TIMEOUT_MS);
    }, 120);
  }

  // ── Load event ──────────────────────────────────────────────
  // Fires for BOTH success and "preview unavailable" pages
  function _onLoad() {
    if (_aborted) return;
    clearTimeout(_timer);

    // Give the iframe body a moment to paint, then verify
    setTimeout(() => {
      if (_aborted) return;
      verifyIframeContent(
        () => {
          // Real content detected
          if (!_aborted) showReady();
        },
        () => {
          // Iframe loaded but content looks empty → retry
          if (!_aborted) {
            _attempt++;
            loadAttempt();
          }
        }
      );
    }, 800);
  }

  // ── Error event ─────────────────────────────────────────────
  function _onError() {
    if (_aborted) return;
    clearTimeout(_timer);
    clearInterval(_pollTimer);
    _attempt++;
    loadAttempt(); // keep retrying silently with spinner
  }

  // ── Public API ──────────────────────────────────────────────
  window.handleFileClick = function (el) {
    const isModal = el.dataset.modal === '1';
    const title   = el.dataset.modalTitle || 'Document';
    const rawUrl  = el.dataset.rawUrl || el.dataset.href;
    const vtype   = el.dataset.viewerType || 'none';

    if (!isModal) { window.open(el.dataset.href, '_blank', 'noopener,noreferrer'); return; }

    const ext = extOf(title);
    const vis = typeVisual[ext] || { icon: 'fa-file', color: '#94A3B8' };

    modalName.textContent     = title;
    modalIcon.className       = 'fa-solid ' + vis.icon;
    modalIcon.style.color     = vis.color;
    modalDot.style.background = vis.color;

    const isGoogle = vtype === 'google';
    const isOffice = vtype === 'office';
    modalBadge.textContent   = isGoogle ? 'Google Docs' : isOffice ? 'Microsoft Office' : '';
    modalBadge.style.cssText = isGoogle
      ? 'background:#4285F415;color:#4285F4;border-color:#4285F430;display:inline;'
      : isOffice
      ? 'background:#0078D415;color:#0078D4;border-color:#0078D430;display:inline;'
      : 'display:none;';

    modal.classList.add('open');
    document.body.style.overflow = 'hidden';

    _rawUrl     = rawUrl;
    _vtype      = vtype;
    _attempt    = 0;
    _aborted    = false;
    _strategies = strategyList(vtype);

    showLoading('Loading document\u2026', 'Please wait\u2026');
    loadAttempt();
  };

  window.retryViewer = function () {
    if (!_rawUrl) return;
    _attempt = 0;
    _aborted = false;
    showLoading('Retrying\u2026', 'Starting fresh\u2026');
    loadAttempt();
  };

  window.openInNew = function () {
    if (_rawUrl) window.open(_rawUrl, '_blank', 'noopener,noreferrer');
  };

  window.closeModal = function () {
    _aborted = true;
    clearTimeout(_timer);
    clearInterval(_pollTimer);
    modal.classList.remove('open');
    modalFrame.removeEventListener('load',  _onLoad);
    modalFrame.removeEventListener('error', _onError);
    modalFrame.src = 'about:blank';
    showLoading('Loading document\u2026', 'Please wait\u2026');
    _rawUrl = '';
    document.body.style.overflow = '';
  };

  modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) closeModal();
  });
})();
</script>
</body>
</html>
