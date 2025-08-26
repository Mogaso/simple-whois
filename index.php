<?php
declare(strict_types=1);

// --- (optional) TEMP DEBUG ---
// ini_set('display_errors','1'); error_reporting(E_ALL);

// --- Polyfills für ältere PHPs (harmlos unter 8.3) ---
if (!function_exists('str_starts_with')) {
  function str_starts_with(string $haystack, string $needle): bool {
    return $needle !== '' && strncmp($haystack, $needle, strlen($needle)) === 0;
  }
}
if (!function_exists('str_contains')) {
  function str_contains(string $haystack, string $needle): bool {
    return $needle === '' || strpos($haystack, $needle) !== false;
  }
}

/**
 * Single-file WHOIS & DNS Lookup — index.php
 * Requirements: PHP 8.1+, intl empfohlen (für IDN), keine externen Tools.
 * Place: httpdocs/whois/index.php   |   Cache: httpdocs/whois/cache/
 */

///////////////////////
// Security Headers  //
///////////////////////
header("Referrer-Policy: same-origin");
header("X-Content-Type-Options: nosniff");
// Inline CSS/JS nötig -> 'unsafe-inline' bewusst gesetzt (nur eigene Seite)
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'");

///////////////////////
// Environment       //
///////////////////////
date_default_timezone_set('Europe/Berlin');
ini_set('default_socket_timeout', '5'); // WHOIS sockets
set_time_limit(10); // Gesamtbudget

$SCRIPT_DIR = __DIR__;
$CACHE_DIR  = $SCRIPT_DIR . DIRECTORY_SEPARATOR . 'cache';
if (!is_dir($CACHE_DIR)) @mkdir($CACHE_DIR, 0755, true);

///////////////////////
// Utilities         //
///////////////////////
function h(?string $s): string { return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function clientIp(): string {
    foreach (['HTTP_CLIENT_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $k) {
        if (!empty($_SERVER[$k])) {
            $ip = explode(',', (string)$_SERVER[$k])[0];
            return trim($ip);
        }
    }
    return '0.0.0.0';
}

function isIpPrivate(string $ip): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $long = ip2long($ip);
        $ranges = [
            ['10.0.0.0', '10.255.255.255'],
            ['172.16.0.0','172.31.255.255'],
            ['192.168.0.0','192.168.255.255'],
            ['127.0.0.0','127.255.255.255'],
        ];
        foreach ($ranges as [$a,$b]) if ($long >= ip2long($a) && $long <= ip2long($b)) return true;
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if (str_starts_with($ip, 'fe80:') || str_starts_with($ip,'fc') || str_starts_with($ip,'fd') || $ip === '::1') return true;
    }
    return false;
}

function idnToAsciiSafe(string $host): array {
    $unicode = $host;
    $host = trim($host, " \t\n\r\0\x0B.");
    $ascii = strtolower($host);
    $note = null;

    if (function_exists('idn_to_ascii')) {
        $variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46
                 : (defined('INTL_IDNA_VARIANT_2003') ? INTL_IDNA_VARIANT_2003 : 0);
        $flags   = defined('IDNA_DEFAULT') ? IDNA_DEFAULT : 0;

        $converted = @idn_to_ascii($host, $flags, $variant);
        if ($converted === false) {
            // Fallback: ohne Flags/Variant versuchen
            $converted = @idn_to_ascii($host);
        }
        if ($converted !== false) {
            $ascii = strtolower($converted);
            if ($ascii !== strtolower($unicode)) $note = 'IDN → Punycode umgesetzt';
        } else {
            $note = 'IDN-Konvertierung fehlgeschlagen';
        }
    } else {
        $note = 'IDN-Konvertierung nicht verfügbar (intl fehlt)';
    }
    return [$ascii, $unicode, $note];
}

function isValidAsciiLabel(string $label): bool {
    return (bool)preg_match('/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/', $label);
}

function validateInput(string $q): array {
    $q = trim($q);
    if ($q === '') return ['type'=>'invalid','error'=>'Leere Eingabe'];
    // IP?
    if (filter_var($q, FILTER_VALIDATE_IP)) {
        return ['type'=>'ip','ip'=>$q];
    }
    // URL versehentlich?
    if (preg_match('~^[a-z]+://~i', $q)) {
        return ['type'=>'invalid','error'=>'Bitte nur Domain/Hostname oder IP, keine URLs.'];
    }
    // Unicode Domain → ASCII
    [$ascii, $unicode, $idnNote] = idnToAsciiSafe($q);
    $labels = explode('.', $ascii);
    if (count($labels) < 2) return ['type'=>'invalid','error'=>'Ungültige Domain (TLD fehlt).'];
    foreach ($labels as $lab) if (!isValidAsciiLabel($lab)) return ['type'=>'invalid','error'=>'Ungültiger Hostname/Label.'];
    if (strlen($ascii) > 253) return ['type'=>'invalid','error'=>'FQDN zu lang (>253 Zeichen).'];
    return ['type'=>'domain','host_unicode'=>$unicode,'host'=>$ascii,'idn_note'=>$idnNote];
}

// registrable domain heuristic (for WHOIS): handles common 2LD TLDs
function registrableDomain(string $asciiDomain): string {
    $d = strtolower($asciiDomain);
    $parts = explode('.', $d);
    if (count($parts) <= 2) return $d;
    $twoLevelTlds = [
        'co.uk','org.uk','ac.uk','gov.uk',
        'com.au','net.au','org.au',
        'co.jp','ne.jp','or.jp',
        'com.br','com.tr','com.pl','net.pl',
        'co.za','co.in','co.nz','com.cn','com.mx','com.sg','com.hk','com.ar','com.pe','com.ph'
    ];
    $last2 = implode('.', array_slice($parts, -2));
    $last3 = implode('.', array_slice($parts, -3));
    if (in_array($last2, $twoLevelTlds, true)) {
        return implode('.', array_slice($parts, -3));
    }
    if (in_array($last3, $twoLevelTlds, true)) {
        return implode('.', array_slice($parts, -4)); // extreme edge
    }
    return implode('.', array_slice($parts, -2));
}

function tldOf(string $asciiDomain): string {
    $labels = explode('.', strtolower($asciiDomain));
    return end($labels);
}

function isHostPublic(string $hostname): bool {
    $ips = @dns_get_record($hostname, DNS_A | DNS_AAAA); // korrekt: bitweises OR
    if (!$ips) return false; // treat unresolved as unsafe for SSRF
    foreach ($ips as $rec) {
        $ip = $rec['type'] === 'AAAA' ? ($rec['ipv6'] ?? null) : ($rec['type']==='A' ? ($rec['ip'] ?? null) : null);
        if (!$ip) continue;
        if (isIpPrivate($ip)) return false;
    }
    return true;
}

function socketWhois(string $server, string $query, int $timeout = 5): array {
    $raw = '';
    $err = null;
    if (!preg_match('/^[A-Za-z0-9\.\-]+$/', $server)) {
        return ['', 'WHOIS-Server ungültig gebildet.'];
    }
    if (!isHostPublic($server)) {
        return ['', 'WHOIS-Server ist nicht öffentlich resolvbar oder zeigt auf private IP.'];
    }
    $errno = 0; $errstr = '';
    $fp = @fsockopen('tcp://'.$server, 43, $errno, $errstr, $timeout);
    if (!$fp) return ['', "WHOIS-Verbindung fehlgeschlagen: $errstr ($errno)"];
    stream_set_timeout($fp, $timeout);
    fwrite($fp, $query . "\r\n");
    while (!feof($fp)) {
        $raw .= fgets($fp, 2048);
        if (strlen($raw) > 2_000_000) break; // safety limit
    }
    fclose($fp);
    return [$raw, null];
}

function ianaWhoisServer(string $tld): ?string {
    // primary: IANA whois
    [$raw, $err] = socketWhois('whois.iana.org', $tld);
    if ($raw && preg_match('/\nwhois:\s*([^\s]+)\s*/i', $raw, $m)) {
        return trim($m[1]);
    }
    // fallback map für häufige TLDs
    $map = [
        'com'=>'whois.verisign-grs.com',
        'net'=>'whois.verisign-grs.com',
        'org'=>'whois.pir.org',
        'info'=>'whois.afilias.net',
        'de'=>'whois.denic.de',
        'eu'=>'whois.eu',
        'io'=>'whois.nic.io',
        'uk'=>'whois.nic.uk',
        'nl'=>'whois.domain-registry.nl'
    ];
    return $map[$tld] ?? null;
}

function parseWhois(string $raw): array {
    $lines = preg_split('/\r?\n/', $raw);
    $out = [
        'domain'=>null,
        'registry'=>[],
        'registrar'=>[],
        'status'=>[],
        'nameservers'=>[],
        'dates'=>[],
        'contacts'=>[], // registrant/admin/tech (best effort)
        'notice'=>null
    ];
    foreach ($lines as $ln) {
        if (!str_contains($ln, ':')) continue;
        [$k, $v] = array_map('trim', explode(':', $ln, 2));
        $kl = strtolower($k);
        if ($kl === 'domain name' || $kl === 'domain') $out['domain'] = $v;
        if ($kl === 'registrar') $out['registrar']['name'] = $v;
        if ($kl === 'registrar iana id') $out['registrar']['iana_id'] = $v;
        if ($kl === 'registrar url' || $kl === 'registrar url ') $out['registrar']['url'] = $v;
        if (str_starts_with($kl, 'domain status')) $out['status'][] = $v;
        if ($kl === 'status') $out['status'][] = $v; // DENIC
        if (str_starts_with($kl, 'name server') || $kl==='nserver') $out['nameservers'][] = $v;
        if (in_array($kl, ['creation date','created','created on','created date'])) $out['dates']['created'] = $v;
        if (in_array($kl, ['updated date','changed','last updated','modified'])) $out['dates']['updated'] = $v;
        if (in_array($kl, ['registry expiry date','expiry date','expires','paid-till'])) $out['dates']['expiry'] = $v;

        // contacts (best effort)
        if (str_starts_with($kl, 'registrant ')) $out['contacts']['registrant'][substr($k, 11)] = $v;
        if (str_starts_with($kl, 'admin '))      $out['contacts']['admin'][substr($k, 6)]       = $v;
        if (str_starts_with($kl, 'tech '))       $out['contacts']['tech'][substr($k, 5)]        = $v;
    }
    // mask personal hints
    if (!empty($out['contacts'])) {
        $out['notice'] = 'WHOIS-Daten können durch Datenschutzrichtlinien eingeschränkt oder anonymisiert sein.';
    }
    // normalize arrays
    $out['nameservers'] = array_values(array_unique(array_map('trim', $out['nameservers'])));
    $out['status']      = array_values(array_unique(array_map('trim', $out['status'])));
    return $out;
}

function whoisLookup(string $domainAscii, bool $fast=false): array {
    $tld = tldOf($domainAscii);
    $server = ianaWhoisServer($tld);
    $allRaw = [];
    $meta = ['tld'=>$tld, 'iana_server'=>'whois.iana.org', 'registry_server'=>$server, 'registrar_server'=>null];
    if (!$server) {
        return ['error'=>"Kein WHOIS-Server für .{$tld} gefunden (IANA-Abfrage fehlgeschlagen).", 'raw'=>$allRaw, 'meta'=>$meta];
    }
    // Query registry
    [$raw1, $err1] = socketWhois($server, $domainAscii);
    if ($err1) return ['error'=>$err1, 'raw'=>$allRaw, 'meta'=>$meta];
    $allRaw[] = "## WHOIS Server: {$server}\n".$raw1;

    $registrarServer = null;
    if (!$fast) {
        if (preg_match('/Registrar WHOIS Server:\s*([^\s]+)/i', $raw1, $m)) {
            $registrarServer = trim($m[1]);
        } elseif (preg_match('/whois server:\s*([^\s]+)/i', $raw1, $m2)) {
            $registrarServer = trim($m2[1]);
        } elseif (preg_match('/ReferralServer:\s*whois:\/\/([^\s]+)/i', $raw1, $m3)) {
            $registrarServer = trim($m3[1]);
        }
        if ($registrarServer && isHostPublic($registrarServer)) {
            $meta['registrar_server'] = $registrarServer;
            [$raw2, $err2] = socketWhois($registrarServer, $domainAscii);
            if (!$err2 && $raw2) $allRaw[] = "## Registrar WHOIS: {$registrarServer}\n".$raw2;
        }
    }
    $parsed = parseWhois(implode("\n-----\n", $allRaw));
    return ['parsed'=>$parsed, 'raw'=>$allRaw, 'meta'=>$meta];
}

function dnsQueryType(string $host, int $type): array {
    $out = [];
    $records = @dns_get_record($host, $type, $auth, $add);
    if (!$records) return $out;
    foreach ($records as $r) {
        $row = ['host'=>$r['host'] ?? $host, 'ttl'=>$r['ttl'] ?? null, 'type'=>$r['type'] ?? ''];
        switch ($r['type'] ?? '') {
            case 'A':    $row['ip'] = $r['ip']; break;
            case 'AAAA': $row['ipv6'] = $r['ipv6']; break;
            case 'CNAME':$row['target'] = $r['target']; break;
            case 'NS':   $row['target'] = $r['target']; break;
            case 'MX':   $row['pri'] = $r['pri']; $row['target'] = $r['target']; break;
            case 'TXT':  $row['txt'] = $r['txt']; break;
            case 'SOA':
                $row += [
                    'mname'=>$r['mname']??null, 'rname'=>$r['rname']??null, 'serial'=>$r['serial']??null,
                    'refresh'=>$r['refresh']??null, 'retry'=>$r['retry']??null, 'expire'=>$r['expire']??null, 'minimum'=>$r['minimum']??null
                ];
                break;
            case 'SRV':
                $row += ['pri'=>$r['pri']??null,'weight'=>$r['weight']??null,'port'=>$r['port']??null,'target'=>$r['target']??null];
                break;
            case 'CAA':
                $row += ['flags'=>$r['flags']??null, 'tag'=>$r['tag']??null, 'value'=>$r['value']??null];
                break;
            case 'PTR':
                $row['target'] = $r['target'] ?? null;
                break;
        }
        $out[] = $row;
    }
    return $out;
}

function dnsLookupAll(string $host, bool $fast=false): array {
    $result = [
        'A'=>[], 'AAAA'=>[], 'CNAME'=>[], 'NS'=>[], 'MX'=>[], 'TXT'=>[], 'SOA'=>[], 'SRV'=>[], 'CAA'=>[],
        'PTR'=>[], 'dnssec'=>['has_ds'=>false,'has_rrsig'=>false]
    ];
    // fast: only A/AAAA
    $types = $fast ? ['A'=>DNS_A,'AAAA'=>DNS_AAAA] : [
        'A'=>DNS_A,'AAAA'=>DNS_AAAA,'CNAME'=>DNS_CNAME,'NS'=>DNS_NS,'MX'=>DNS_MX,'TXT'=>DNS_TXT,'SOA'=>DNS_SOA,
        'SRV'=>DNS_SRV,'CAA'=> (defined('DNS_CAA')? DNS_CAA : 8192)
    ];
    foreach ($types as $name=>$flag) {
        $result[$name] = dnsQueryType($host, $flag);
    }
    // DNSSEC hints
    if (!$fast) {
        if (defined('DNS_DS')) {
            $ds = dnsQueryType($host, DNS_DS);
            $result['dnssec']['has_ds'] = !empty($ds);
        }
        if (defined('DNS_RRSIG')) {
            $sig = dnsQueryType($host, DNS_RRSIG);
            $result['dnssec']['has_rrsig'] = !empty($sig);
        }
    }
    // PTR für A/AAAA
    $ips = [];
    foreach ($result['A'] as $r)   if (!empty($r['ip']))   $ips[] = $r['ip'];
    foreach ($result['AAAA'] as $r)if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
    $ptrs = [];
    foreach (array_unique($ips) as $ip) {
        $rev = @gethostbyaddr($ip);
        $ptrs[] = ['ip'=>$ip, 'ptr'=>$rev !== false ? $rev : null];
    }
    $result['PTR'] = $ptrs;
    return $result;
}

///////////////////////
// Rate Limiting     //
///////////////////////
function rateLimitCheck(string $cacheDir, string $ip, int $limit=30, int $windowSec=300): ?string {
    $f = $cacheDir . DIRECTORY_SEPARATOR . 'ratelimit_' . preg_replace('/[^0-9A-Fa-f:\.]/','_', $ip) . '.json';
    $now = time();
    $list = [];
    if (is_file($f)) {
        $list = json_decode((string)@file_get_contents($f), true) ?: [];
        $list = array_values(array_filter($list, fn($ts)=> ($now - (int)$ts) < $windowSec));
    }
    if (count($list) >= $limit) {
        return "Limit erreicht: max. {$limit} Abfragen pro ".($windowSec/60)." Minuten. Bitte später erneut versuchen.";
    }
    $list[] = $now;
    @file_put_contents($f, json_encode($list));
    return null;
}

///////////////////////
// Controller        //
///////////////////////
$q      = isset($_GET['q']) ? trim((string)$_GET['q']) : '';
$fast   = isset($_GET['fast']) && ($_GET['fast']==='1' || $_GET['fast']==='true');
$force  = isset($_GET['force']) && ($_GET['force']==='1' || $_GET['force']==='true');
$format = isset($_GET['format']) ? strtolower((string)$_GET['format']) : ''; // 'json'
$nowIso = date('c');

$errors = [];
$data   = null;
$usedCache = false;

if ($q !== '') {
    // Rate limit
    $rl = rateLimitCheck($CACHE_DIR, clientIp());
    if ($rl) $errors[] = $rl;

    // Validate
    $val = validateInput($q);
    if ($val['type'] === 'invalid') {
        $errors[] = $val['error'];
    } else {
        // Cache key
        $cacheKey = '';
        if ($val['type'] === 'ip') {
            $cacheKey = 'ip__'.str_replace(':','_',str_replace('.','_',$val['ip'])).($fast?'_f':'');
        } else {
            $reg = registrableDomain($val['host']);
            $cacheKey = 'dom__'.$reg.($fast?'_f':'');
        }
        $cacheJson = $CACHE_DIR . DIRECTORY_SEPARATOR . $cacheKey . '.json';
        $cacheRaw  = $CACHE_DIR . DIRECTORY_SEPARATOR . $cacheKey . '.whois.txt';

        if (!$force && is_file($cacheJson) && (time() - filemtime($cacheJson) < 900)) {
            $data = json_decode((string)@file_get_contents($cacheJson), true);
            if (is_array($data)) { $usedCache = true; }
        }
        if (!$data) {
            $result = ['meta'=>[
                'input'=>$q, 'type'=>$val['type'], 'fast'=>$fast, 'timestamp'=>$nowIso, 'cache'=>'fresh'
            ]];
            if ($val['type'] === 'ip') {
                // Only PTR for IP
                $ip = $val['ip'];
                $ptr = @gethostbyaddr($ip);
                $result['overview'] = [
                    'domain_or_ip'=>$ip,
                    'registrar'=>null,'status'=>[],'dates'=>[],
                    'ips'=>[$ip],'nameservers'=>[]
                ];
                $result['whois'] = ['parsed'=>null,'raw'=>[],'meta'=>['note'=>'WHOIS für IP nicht unterstützt.']];
                $result['dns']   = ['A'=>[], 'AAAA'=>[], 'CNAME'=>[], 'NS'=>[], 'MX'=>[], 'TXT'=>[], 'SOA'=>[], 'SRV'=>[], 'CAA'=>[], 'PTR'=>[['ip'=>$ip,'ptr'=>$ptr?:null]], 'dnssec'=>['has_ds'=>false,'has_rrsig'=>false]];
                $result['network'] = ['ptr'=>$result['dns']['PTR']];
                $rawDump = '';
            } else {
                $hostAscii = $val['host'];
                $hostUnicode = $val['host_unicode'];
                $regdom = registrableDomain($hostAscii);

                $who = whoisLookup($regdom, $fast);
                $dns = dnsLookupAll($hostAscii, $fast);

                $overview = [
                    'domain_or_ip'=>$hostUnicode,
                    'canonical_ascii'=>$hostAscii,
                    'registrable'=>$regdom,
                    'tld'=>tldOf($regdom),
                    'registrar'=>$who['parsed']['registrar']['name'] ?? null,
                    'status'=>$who['parsed']['status'] ?? [],
                    'dates'=>$who['parsed']['dates'] ?? [],
                    'nameservers'=>$who['parsed']['nameservers'] ?? [],
                    'ips'=>array_values(array_unique(array_merge(
                        array_map(fn($r)=>$r['ip']??null, $dns['A']),
                        array_map(fn($r)=>$r['ipv6']??null, $dns['AAAA'])
                    ))),
                    'dnssec'=> $dns['dnssec'],
                ];

                $result['overview'] = $overview;
                $result['whois']    = $who;
                $result['dns']      = $dns;
                $result['network']  = ['ptr'=>$dns['PTR']];
                $rawDump = implode("\n-----\n", $who['raw'] ?? []);
                $result['meta']['idn_note'] = $val['idn_note'] ?? null;
            }
            $data = $result;
            // Save cache
            @file_put_contents($cacheJson, json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
            @file_put_contents($cacheRaw, $rawDump ?? '');
        }
        // attach cache info
        if ($data && isset($data['meta'])) {
            $data['meta']['cache'] = $usedCache ? 'cache' : 'fresh';
            $data['meta']['cached_at'] = @date('c', @filemtime($cacheJson) ?: time());
        }
    }
}

// JSON export
if ($format === 'json') {
    header('Content-Type: application/json; charset=UTF-8');
    if (!empty($errors)) {
        echo json_encode(['ok'=>false,'errors'=>$errors], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['ok'=>true,'data'=>$data], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// Helper for title
$pagetitle = 'WHOIS & DNS Lookup';
if ($q !== '' && empty($errors)) {
    $disp = $data['overview']['domain_or_ip'] ?? $q;
    $pagetitle = 'WHOIS • ' . $disp;
}
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0b1220">
<title><?=h($pagetitle)?></title>
<link rel="icon" href="data:image/svg+xml,<?=rawurlencode('<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 64 64%22><defs><linearGradient id=%22g%22 x1=%220%22 x2=%221%22 y1=%220%22 y2=%221%22><stop stop-color=%22#22d3ee%22/><stop offset=%221%22 stop-color=%22#0ea5e9%22/></linearGradient></defs><rect rx=%2212%22 width=%2264%22 height=%2264%22 fill=%22#0b1220%22/><path d=%22M32 10c10 0 18 8 18 18s-8 18-18 18S14 38 14 28 22 10 32 10Zm0 6c6 0 12 6 12 12s-6 12-12 12-12-6-12-12 6-12 12-12Z%22 fill=%22url(#g)%22/></svg>')?>">
<style>
/* ====== Design Tokens ====== */
:root{
  --bg:#0b1220; --card:#0f172a; --muted:#8aa0b6; --text:#e5e7eb; --accent:#22d3ee; --accent-2:#0ea5e9;
  --ok:#10b981; --warn:#f59e0b; --error:#ef4444; --ring:rgba(14,165,233,.4);
  --br:14px; --space:12px; --shadow:0 10px 30px rgba(2,6,23,.35), 0 2px 8px rgba(2,6,23,.25);
}
@media (prefers-color-scheme: light){
  :root{ --bg:#f6f7fb; --card:#ffffff; --muted:#4b5563; --text:#0f172a; --accent:#0ea5e9; --accent-2:#0369a1; --ring:rgba(3,105,161,.25);
         --shadow:0 8px 20px rgba(17,24,39,.08), 0 1px 4px rgba(17,24,39,.06);}
}
/* ====== Base ====== */
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif;background:radial-gradient(1000px 600px at 20% -10%,rgba(14,165,233,.15),transparent), var(--bg);color:var(--text)}
.container{max-width:1160px;margin:0 auto;padding:18px 18px 40px}
header{position:sticky;top:0;z-index:10;background:linear-gradient(180deg,rgba(11,18,32,.85),rgba(11,18,32,.60) 60%,transparent);backdrop-filter:saturate(140%) blur(6px);padding:10px 0 8px;margin:-18px -18px 8px;box-shadow:inset 0 -1px 0 rgba(148,163,184,.15)}
.header-inner{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:0 18px}
.brand{display:flex;gap:10px;align-items:center}
.logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 6px 14px rgba(14,165,233,.35)}
.title{font-weight:800;font-size:18px;letter-spacing:.2px}
.meta{color:var(--muted);font-size:12px}

/* ====== Form ====== */
.searchbar{display:grid;grid-template-columns:1fr auto auto auto auto;gap:8px;align-items:center;margin-top:8px}
@media(max-width:760px){.searchbar{grid-template-columns:1fr auto auto;grid-auto-rows:auto}}
.input{flex:1;min-width:220px;background:var(--card);border:1px solid rgba(148,163,184,.18);color:var(--text);padding:12px 12px;border-radius:12px;outline:none;box-shadow:inset 0 0 0 1px transparent}
.input:focus{border-color:var(--accent-2);box-shadow:0 0 0 4px var(--ring)}
.btn{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:white;border:none;padding:12px 14px;border-radius:12px;font-weight:700;cursor:pointer;box-shadow:var(--shadow)}
.btn:hover{filter:saturate(110%)}
.btn.secondary{background:transparent;border:1px solid rgba(148,163,184,.25);color:var(--text);box-shadow:none}
.btn.ghost{background:transparent;border:1px dashed rgba(148,163,184,.35);color:var(--text);box-shadow:none}
.small{padding:9px 11px;border-radius:10px;font-size:12px}
.switch{display:flex;gap:8px;align-items:center;color:var(--muted)}
.toggle{width:38px;height:22px;background:#334155;border-radius:999px;position:relative;cursor:pointer;border:1px solid rgba(148,163,184,.25)}
.toggle input{display:none}
.knob{position:absolute;top:2px;left:2px;width:16px;height:16px;background:white;border-radius:50%;transition:transform .18s}
.toggle input:checked + .knob{transform:translateX(16px)}

/* ====== Tabs ====== */
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0 8px}
.tab{padding:8px 14px;border-radius:999px;border:1px solid rgba(148,163,184,.25);cursor:pointer;position:relative}
.tab.active{color:white;background:linear-gradient(135deg,var(--accent),var(--accent-2));border-color:transparent;box-shadow:0 6px 18px rgba(14,165,233,.35)}
/* ====== Cards & Grid ====== */
.grid{display:grid;grid-template-columns:1fr;gap:14px;margin-top:10px}
@media(min-width:920px){.grid{grid-template-columns:1fr 1fr}}
.card{background:linear-gradient(180deg,rgba(255,255,255,.02),rgba(255,255,255,.00)), var(--card);border:1px solid rgba(148,163,184,.18);border-radius:var(--br);padding:12px;position:relative;box-shadow:var(--shadow)}
.card h3{margin:0 0 6px 0;font-size:14px;letter-spacing:.2px}
.tools{position:absolute;right:8px;top:8px;display:flex;gap:6px}
.tool{background:transparent;border:1px solid rgba(148,163,184,.25);color:var(--text);padding:6px 8px;border-radius:10px;cursor:pointer;font-size:12px}

/* ====== Badges / Tables ====== */
.badge{display:inline-block;padding:4px 8px;border-radius:999px;border:1px solid rgba(148,163,184,.3);margin:2px 6px 2px 0;font-size:12px;background:rgba(2,6,23,.14)}
.badge.ok{border-color:rgba(16,185,129,.35);color:var(--ok)}
.badge.warn{border-color:rgba(245,158,11,.35);color:var(--warn)}
.badge.err{border-color:rgba(239,68,68,.35);color:var(--error)}
.hr{border:none;border-top:1px solid rgba(148,163,184,.18);margin:8px 0}
.table{width:100%;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid rgba(148,163,184,.18);padding:8px;text-align:left;vertical-align:top;white-space:nowrap}
td.wrap{white-space:normal;word-break:break-word}

/* ====== Toast / A11y / Print ====== */
.toast{position:fixed;left:50%;bottom:18px;transform:translateX(-50%);background:#0b1325;color:#e5e7eb;border:1px solid rgba(148,163,184,.25);padding:10px 12px;border-radius:10px;opacity:0;pointer-events:none;transition:opacity .15s}
.toast.show{opacity:1}
.footer{margin-top:18px;color:var(--muted);font-size:12px}
.error{background:#7f1d1d;border:1px solid #ef4444;color:#fee2e2;padding:10px 12px;border-radius:12px}
.sr-only{position:absolute !important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media print{
  .searchbar, .tabs, .tools, .toast { display:none !important; }
  .container{max-width:100%;padding:0}
  body{background:#fff;color:#000}
  .card{background:#fff;border:1px solid #ddd;box-shadow:none}
}

/* ====== Motion Pref ====== */
@media (prefers-reduced-motion: reduce){
  *{animation:none !important;transition:none !important}
}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-inner">
      <div class="brand">
        <div class="logo" aria-hidden="true"></div>
        <div class="title">WHOIS & DNS Lookup</div>
      </div>
      <div class="meta"><?=h($nowIso)?></div>
    </div>
  </header>

  <form class="searchbar" method="get" action="" role="search">
    <label class="sr-only" for="q">Domain, Hostname oder IP</label>
    <input id="q" name="q" class="input" placeholder="example.com, heise.de, 1.1.1.1" value="<?=h($q)?>" autocomplete="off" required>
    <button class="btn" type="submit" title="Abfragen">Abfragen</button>
    <button class="btn ghost small" type="button" id="shareBtn" title="Link kopieren">Teilen</button>
    <button class="btn secondary small" type="submit" name="force" value="1" title="Cache ignorieren">Neu laden</button>
    <label class="switch" title="Nur A/AAAA & WHOIS-Kurz">
      <span>Schnellmodus</span>
      <span class="toggle">
        <input type="checkbox" name="fast" value="1" <?= $fast?'checked':''?> onchange="this.form.submit()">
        <span class="knob"></span>
      </span>
    </label>
    <input type="hidden" name="format" value="">
  </form>

  <?php if (!empty($errors)): ?>
    <div class="card"><div class="error" role="alert" aria-live="assertive">
      <?php foreach ($errors as $e): ?><div>• <?=h($e)?></div><?php endforeach; ?>
    </div></div>
  <?php endif; ?>

  <?php if ($q !== '' && empty($errors) && $data):
    $overview = $data['overview'] ?? [];
    $whois    = $data['whois'] ?? [];
    $dns      = $data['dns'] ?? [];
    $network  = $data['network'] ?? [];
    $isCache  = ($data['meta']['cache'] ?? '') === 'cache';
    $cachedAt = $data['meta']['cached_at'] ?? null;
    $dispHost = $overview['domain_or_ip'] ?? $q;
    $badges = (array)($overview['status'] ?? []);
    $ips = array_values(array_filter($overview['ips'] ?? []));
    $nameservers = (array)($overview['nameservers'] ?? []);
  ?>

  <!-- Tabs -->
  <div class="tabs" role="tablist" aria-label="Darstellung wählen">
    <button class="tab active" data-tab="tab-overview" role="tab" aria-selected="true" aria-controls="tab-overview">Übersicht</button>
    <button class="tab" data-tab="tab-whois" role="tab" aria-controls="tab-whois">WHOIS</button>
    <button class="tab" data-tab="tab-dns" role="tab" aria-controls="tab-dns">DNS</button>
    <button class="tab" data-tab="tab-net" role="tab" aria-controls="tab-net">Netzwerk</button>
    <button class="tab" data-tab="tab-raw" role="tab" aria-controls="tab-raw">Rohdaten</button>
  </div>

  <!-- OVERVIEW -->
  <section id="tab-overview" class="grid" role="tabpanel" aria-labelledby="Übersicht">
    <div class="card">
      <div class="tools">
        <button class="tool" data-copy-target="#ovtxt" title="Inhalt kopieren">Kopieren</button>
        <a class="tool" href="?q=<?=rawurlencode($q)?>&format=json<?= $fast?'&fast=1':''?>" rel="nofollow" title="Als JSON">Als JSON</a>
        <?php if ($isCache): ?><span class="tool" title="aus Cache">Cache</span><?php endif; ?>
      </div>
      <h3>Überblick</h3>
      <div class="meta">Aktualisiert: <?=h($cachedAt ?? $nowIso)?> · Quelle: <?=$isCache?'Cache (≤15 min)':'Live'?> <?= $fast?'· Schnellmodus':'' ?></div>
      <div class="hr"></div>
      <div id="ovtxt">
        <div><b>Domain/Host</b>: <?=h($dispHost)?><?php if (!empty($overview['canonical_ascii']) && strtolower($overview['canonical_ascii']) !== strtolower($dispHost)): ?>
          <span class="badge">ACE: <?=h($overview['canonical_ascii'])?></span><?php endif; ?></div>

        <?php if (!empty($overview['registrable'])): ?>
          <div><b>Registrierbare Domain</b>: <?=h($overview['registrable'])?> <span class="badge"><?=h('.'.$overview['tld'])?></span></div>
        <?php endif; ?>

        <?php if (!empty($whois['meta']['registry_server'])): ?>
          <div><b>Registry WHOIS</b>: <span class="badge"><?=h($whois['meta']['registry_server'])?></span></div>
        <?php endif; ?>
        <?php if (!empty($whois['meta']['registrar_server'])): ?>
          <div><b>Registrar WHOIS</b>: <span class="badge"><?=h($whois['meta']['registrar_server'])?></span></div>
        <?php endif; ?>

        <?php if (!empty($overview['dates'])): ?>
          <div><b>Daten</b>:
            <?php if (!empty($overview['dates']['created'])): ?><span class="badge">Erst: <?=h($overview['dates']['created'])?></span><?php endif; ?>
            <?php if (!empty($overview['dates']['updated'])): ?><span class="badge">Update: <?=h($overview['dates']['updated'])?></span><?php endif; ?>
            <?php if (!empty($overview['dates']['expiry'])): ?><span class="badge">Ablauf: <?=h($overview['dates']['expiry'])?></span><?php endif; ?>
          </div>
        <?php endif; ?>

        <?php if (!empty($badges)): ?>
          <div><b>Status</b>:
            <?php foreach ($badges as $st):
              $cls = str_contains(strtolower($st), 'ok') || str_contains(strtolower($st),'active') ? 'ok' :
                     (str_contains(strtolower($st),'prohibit')||str_contains(strtolower($st),'client')?'warn':'');
            ?>
              <span class="badge <?=$cls?>"><?=h($st)?></span>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>

        <?php if (!empty($ips)): ?>
          <div><b>IPs</b>:
            <?php foreach ($ips as $ip): ?><span class="badge"><?=h($ip)?></span><?php endforeach; ?>
          </div>
        <?php endif; ?>

        <?php if (!empty($nameservers)): ?>
          <div><b>Nameserver</b>:
            <div><?php foreach ($nameservers as $ns): ?><span class="badge"><?=h($ns)?></span><?php endforeach; ?></div>
          </div>
        <?php endif; ?>

        <?php if (!empty($overview['dnssec']) && ($overview['dnssec']['has_ds']||$overview['dnssec']['has_rrsig'])): ?>
          <div><b>DNSSEC</b>:
            <?php if ($overview['dnssec']['has_ds']): ?><span class="badge ok">DS</span><?php endif; ?>
            <?php if ($overview['dnssec']['has_rrsig']): ?><span class="badge ok">RRSIG</span><?php endif; ?>
          </div>
        <?php endif; ?>
      </div>
    </div>

    <div class="card">
      <h3>Hinweise</h3>
      <div class="meta">Datenschutz & Genauigkeit</div>
      <div class="hr"></div>
      <div class="meta">
        WHOIS-Daten können durch DSGVO/Registry-Richtlinien eingeschränkt sein. Alle Angaben ohne Gewähr.
        <?php if (!empty($data['meta']['idn_note'])): ?><div><?=h($data['meta']['idn_note'])?></div><?php endif; ?>
      </div>
    </div>
  </section>

  <!-- WHOIS -->
  <section id="tab-whois" class="grid" style="display:none" role="tabpanel">
    <div class="card">
      <div class="tools"><button class="tool" data-copy-target="#whois-keys" title="Inhalt kopieren">Kopieren</button></div>
      <h3>WHOIS – Struktur</h3>
      <div id="whois-keys">
        <?php if (!empty($whois['parsed'])): $p = $whois['parsed']; ?>
          <?php if (!empty($p['registrar'])): ?>
            <div><b>Registrar</b>:
              <?php foreach ($p['registrar'] as $k=>$v): ?><span class="badge"><?=h($k)?>: <?=h($v)?></span><?php endforeach; ?>
            </div>
          <?php endif; ?>
          <?php if (!empty($p['status'])): ?>
            <div><b>Status</b>:
              <?php foreach ($p['status'] as $s): ?><span class="badge"><?=h($s)?></span><?php endforeach; ?>
            </div>
          <?php endif; ?>
          <?php if (!empty($p['dates'])): ?>
            <div><b>Daten</b>:
              <?php foreach ($p['dates'] as $k=>$v): ?><span class="badge"><?=h($k)?>: <?=h($v)?></span><?php endforeach; ?>
            </div>
          <?php endif; ?>
          <?php if (!empty($p['nameservers'])): ?>
            <div><b>Nameserver</b>: <?php foreach ($p['nameservers'] as $ns): ?><span class="badge"><?=h($ns)?></span><?php endforeach; ?></div>
          <?php endif; ?>
          <?php if (!empty($p['contacts'])): ?>
            <div><b>Kontakte</b> (gekürzt):
              <?php foreach ($p['contacts'] as $role=>$fields): ?>
                <div><span class="badge"><?=h($role)?></span>
                <?php foreach ($fields as $k=>$v): ?><span class="badge"><?=h($k)?>: <?=h($v)?></span><?php endforeach; ?>
                </div>
              <?php endforeach; ?>
            </div>
          <?php endif; ?>
          <?php if (!empty($p['notice'])): ?><div class="meta"><?=h($p['notice'])?></div><?php endif; ?>
        <?php else: ?>
          <div class="meta">Keine strukturierten WHOIS-Daten verfügbar.</div>
        <?php endif; ?>
      </div>
    </div>

    <div class="card">
      <div class="tools"><button class="tool" data-copy-target="#whois-raw" title="Rohdaten kopieren">Rohdaten kopieren</button></div>
      <h3>Roh-WHOIS anzeigen</h3>
      <pre id="whois-raw" style="white-space:pre-wrap;max-height:420px;overflow:auto"><?php
        echo h(implode("\n-----\n", $whois['raw'] ?? []));
      ?></pre>
    </div>
  </section>

  <!-- DNS -->
  <section id="tab-dns" class="grid" style="display:none" role="tabpanel">
    <?php
      $sections = [
        'A'=>'A (IPv4)', 'AAAA'=>'AAAA (IPv6)','CNAME'=>'CNAME','NS'=>'NS','MX'=>'MX','TXT'=>'TXT','SOA'=>'SOA','SRV'=>'SRV','CAA'=>'CAA'
      ];
      foreach ($sections as $key=>$label):
        $rows = $dns[$key] ?? [];
    ?>
    <div class="card">
      <div class="tools"><button class="tool" data-copy-target="#tbl-<?=$key?>" title="Tabelle kopieren">Kopieren</button></div>
      <h3>DNS <?=h($label)?></h3>
      <div class="table" id="tbl-<?=$key?>">
        <?php if (empty($rows)): ?>
          <div class="meta">Keine Einträge.</div>
        <?php else: ?>
        <table>
          <thead><tr><th>Name</th><th>TTL</th><th>Daten</th></tr></thead>
          <tbody>
            <?php foreach ($rows as $r): ?>
              <tr>
                <td><?=h($r['host'] ?? $overview['canonical_ascii'] ?? $q)?></td>
                <td><?=h((string)($r['ttl'] ?? ''))?></td>
                <td class="wrap">
                  <?php switch ($key):
                    case 'A':    echo h($r['ip']??''); break;
                    case 'AAAA': echo h($r['ipv6']??''); break;
                    case 'CNAME':case 'NS': case 'PTR': echo h($r['target']??''); break;
                    case 'MX':   echo 'pri '.h((string)($r['pri']??'')) . ' → ' . h($r['target']??''); break;
                    case 'TXT':  echo h($r['txt']??''); break;
                    case 'SOA':  echo 'mname '.h($r['mname']??'').' · rname '.h($r['rname']??'').' · serial '.h((string)($r['serial']??'')).
                      ' · refresh '.h((string)($r['refresh']??'')).' · retry '.h((string)($r['retry']??'')).' · expire '.h((string)($r['expire']??'')).' · min '.h((string)($r['minimum']??'')); break;
                    case 'SRV':  echo 'pri '.h((string)($r['pri']??'')).' · weight '.h((string)($r['weight']??'')).' · port '.h((string)($r['port']??'')).' → '.h($r['target']??''); break;
                    case 'CAA':  echo 'flags '.h((string)($r['flags']??'')).' · tag '.h($r['tag']??'').' · value '.h((string)($r['value']??'')); break;
                    default: echo '';
                  endswitch; ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
        <?php endif; ?>
      </div>
    </div>
    <?php endforeach; ?>
  </section>

  <!-- NETWORK -->
  <section id="tab-net" class="grid" style="display:none" role="tabpanel">
    <div class="card">
      <h3>Reverse DNS (PTR)</h3>
      <div class="table">
        <?php $ptrs = $network['ptr'] ?? []; if (empty($ptrs)): ?>
          <div class="meta">Keine PTR-Daten.</div>
        <?php else: ?>
          <table><thead><tr><th>IP</th><th>PTR-Host</th></tr></thead><tbody>
            <?php foreach ($ptrs as $p): ?>
              <tr><td><?=h($p['ip'] ?? '')?></td><td class="wrap"><?=h($p['ptr'] ?? '')?></td></tr>
            <?php endforeach; ?>
          </tbody></table>
        <?php endif; ?>
      </div>
    </div>
    <div class="card">
      <h3>ASN/Organisation</h3>
      <div class="meta">Optional (erfordert externe APIs) – hier bewusst deaktiviert. Platzhalter für zukünftige lokale Integration.</div>
    </div>
  </section>

  <!-- RAW -->
  <section id="tab-raw" class="grid" style="display:none" role="tabpanel">
    <div class="card">
      <div class="tools"><button class="tool" data-copy-target="#rawjson" title="JSON kopieren">Kopieren</button></div>
      <h3>Komplettdump (JSON)</h3>
      <pre id="rawjson" style="white-space:pre-wrap;max-height:420px;overflow:auto"><?php
        echo h(json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
      ?></pre>
    </div>
  </section>

  <?php endif; ?>

  <div class="footer">
    <div>Daten ohne Gewähr; WHOIS-Antworten können durch Registry/DSGVO eingeschränkt sein. Stand: <?=h($nowIso)?></div>
  </div>
</div>

<div class="toast" id="toast" role="status" aria-live="polite">In Zwischenablage kopiert</div>

<script>
const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

// Focus & autoselect
window.addEventListener('load', () => {
  const q = $('#q'); if (q && !q.value) { q.focus(); q.select(); }

  // Tabs (click + keyboard)
  const tabs = $$('.tab');
  function activateTab(id){
    tabs.forEach(t=>t.classList.remove('active'));
    tabs.forEach(t=>t.setAttribute('aria-selected','false'));
    const btn = tabs.find(t=>t.dataset.tab===id); if(btn){ btn.classList.add('active'); btn.setAttribute('aria-selected','true'); }
    ['tab-overview','tab-whois','tab-dns','tab-net','tab-raw'].forEach(x=>{
      const el = $('#'+x); if (el) el.style.display = (x===id)?'grid':'none';
    });
  }
  tabs.forEach(t=>{
    t.addEventListener('click', ()=>activateTab(t.dataset.tab));
    t.addEventListener('keydown', e=>{
      if (e.key==='ArrowRight' || e.key==='ArrowLeft'){
        const i = tabs.indexOf(t);
        const n = e.key==='ArrowRight' ? (i+1)%tabs.length : (i-1+tabs.length)%tabs.length;
        tabs[n].focus();
      }
    });
  });

  // Copy buttons
  const toast = $('#toast');
  function showToast(msg){ toast.textContent=msg; toast.classList.add('show'); setTimeout(()=>toast.classList.remove('show'),1200); }
  $$('.tool[data-copy-target]').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const target = btn.getAttribute('data-copy-target');
      const el = $(target);
      if (!el) return;
      const txt = el.innerText || el.textContent || '';
      navigator.clipboard.writeText(txt).then(()=>showToast('In Zwischenablage kopiert')).catch(()=>showToast('Kopieren nicht möglich'));
    });
  });

  // Share / link copy
  $('#shareBtn')?.addEventListener('click', async ()=>{
    const url = new URL(window.location.href);
    // keep q & fast only
    const qv = $('#q')?.value || '';
    if (qv) url.searchParams.set('q', qv);
    const fast = document.querySelector('input[name="fast"]')?.checked;
    if (fast) url.searchParams.set('fast','1'); else url.searchParams.delete('fast');
    url.searchParams.delete('force'); url.searchParams.delete('format');
    try {
      if (navigator.share) { await navigator.share({title:document.title,url:String(url)}); }
      else { await navigator.clipboard.writeText(String(url)); showToast('Link kopiert'); }
    } catch(e){ await navigator.clipboard.writeText(String(url)); showToast('Link kopiert'); }
  });
});
</script>
</body>
</html>
