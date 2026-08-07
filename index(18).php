<?php
/**
 * icm - Postfaecher sortieren. Eine Datei.
 *
 * Debian, nginx, PHP 8.1+, Erweiterungen sodium, mbstring, curl.
 *
 * Ausgehend noetig:  443/TCP zur Claude-API, 993/TCP zu den IMAP-Servern, DNS.
 * Eingehend:         80/443 fuer die Oberflaeche.
 *
 * Cron:  *5 * * * *  php /pfad/index.php cron
 */

declare(strict_types=1);

const VERSION = '3.0';
const TOTP_WINDOW = 1;
const LOGIN_MAX = 5;
const LOGIN_LOCK = 900;
const MAX_BODY = 8388608;
const BATCH = 200;
const RELAY_DOMAIN = 'privaterelay.appleid.com';
const STEP = 5;                       // kleinste Zeiteinheit in Minuten

const PROVIDERS = [
    'icloud' => ['name' => 'iCloud', 'host' => 'imap.mail.me.com', 'port' => 993, 'apple' => true],
    'google' => ['name' => 'Google', 'host' => 'imap.gmail.com', 'port' => 993, 'apple' => false],
    'other'  => ['name' => 'Anderer', 'host' => '', 'port' => 993, 'apple' => false],
];

/** Voreinstellung. Der Admin kann die Liste aendern. */
const DEFAULT_FOLDERS = [
    'Sicherheit'      => 'Anmeldungen, Zwei-Faktor, Codes, Passwoerter, Kontowarnungen',
    'Finanzen'        => 'alles mit echtem Geld: Banken, Zahlungsdienste, Rechnungen, Depots',
    'Finanzen/Krypto' => 'nur Kryptoboersen und Wallets',
    'Bestellungen'    => 'Kaeufe, Bestaetigungen, Versand, Pakete, Marktplatz',
    'Werbung'         => 'Werbung, Rabatte, Gutscheine, Newsletter',
    'Apple'           => 'Apple-Dienste: Quittungen, Abos, Geraetemeldungen',
    'Dienste'         => 'Online-Konten, Entwicklung, Hosting, Social, Gaming',
    'Behoerden'       => 'Aemter, Krankenkasse, Aerzte, Telekommunikation, Vertraege',
    'Spam'            => 'unerwuenschte Massenmail, Dating',
    'Persoenlich'     => 'echte Menschen und alles nicht sicher Zuordenbare',
    'Alias'           => 'Post an eine Nebenadresse - der Pfad wird hier gesetzt',
];

const SYSTEM_FOLDERS = ['inbox', 'sent', 'sent messages', 'drafts', 'deleted messages',
    'trash', 'junk', 'archive', 'notes', 'outbox', '[gmail]'];

// ===========================================================================
// Ablage
// ===========================================================================

function data_dir(): string
{
    $env = getenv('ICM_DATA_DIR');
    $base = is_string($env) && $env !== '' ? rtrim($env, '/') : __DIR__ . '/icm-data';
    // simple-apple.php legt seinen Stand daneben ab, im selben Ordner.
    return defined('ICM_DATA_SUB') ? $base . '/' . ICM_DATA_SUB : $base;
}

function bail(string $msg): never
{
    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, $msg . "\n");
        exit(1);
    }
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    exit($msg . "\n");
}

function jread(string $path, array $default = []): array
{
    if (!is_file($path)) {
        return $default;
    }
    $d = json_decode((string) @file_get_contents($path), true);
    return is_array($d) ? $d : $default;
}

function jwrite(string $path, array $data): void
{
    $tmp = $path . '.tmp' . bin2hex(random_bytes(4));
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false || @file_put_contents($tmp, $json, LOCK_EX) === false || !@rename($tmp, $path)) {
        @unlink($tmp);
        bail('Schreiben fehlgeschlagen: ' . $path);
    }
    @chmod($path, 0600);
}

function locked(string $path, callable $fn): array
{
    $lock = fopen($path . '.lock', 'c');
    flock($lock, LOCK_EX);
    try {
        $data = $fn(jread($path));
        jwrite($path, $data);
        return $data;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function config(): array
{
    return jread(data_dir() . '/config.json');
}

function config_set(callable $fn): array
{
    return locked(data_dir() . '/config.json', $fn);
}

/** Ordnerkatalog aus der Konfiguration, sonst die Voreinstellung. */
function folders_catalogue(): array
{
    $custom = config()['folders'] ?? null;
    if (!is_array($custom) || $custom === []) {
        $custom = DEFAULT_FOLDERS;
    }
    $out = [];
    foreach ($custom as $name => $what) {
        if (is_string($name) && folder_shape_ok($name)) {
            $out[$name] = (string) $what;
        }
    }
    if (defined('ICM_NO_ALIAS')) {
        unset($out['Alias']);
    } else {
        $out['Alias'] ??= DEFAULT_FOLDERS['Alias'];
    }
    return $out;
}

function user_path(string $id): string
{
    if (!preg_match('/^[a-f0-9]{16}$/', $id)) {
        bail('Ungueltige Nutzer-ID');
    }
    return data_dir() . '/users/' . $id . '.json';
}

/** @return list<array> */
function users(): array
{
    $out = [];
    foreach (glob(data_dir() . '/users/*.json') ?: [] as $file) {
        $u = jread($file);
        if ($u !== []) {
            $out[] = $u;
        }
    }
    usort($out, static fn($a, $b) => strcmp((string) $a['address'], (string) $b['address']));
    return $out;
}

function user_load(string $id): ?array
{
    $u = jread(user_path($id));
    return $u === [] ? null : $u;
}

function user_set(string $id, callable $fn): array
{
    return locked(user_path($id), $fn);
}

// ===========================================================================
// Krypto
// ===========================================================================

function key_bytes(): string
{
    $path = data_dir() . '/key.bin';
    if (!is_file($path)) {
        $key = random_bytes(32);
        file_put_contents($path, $key, LOCK_EX);
        @chmod($path, 0600);
        return $key;
    }
    return (string) file_get_contents($path);
}

function enc(string $plain): string
{
    $n = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($n . sodium_crypto_secretbox($plain, $n, key_bytes()));
}

function dec(string $blob): string
{
    $raw = base64_decode($blob, true);
    if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        return '';
    }
    $p = sodium_crypto_secretbox_open(
        substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
        substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), key_bytes());
    return $p === false ? '' : $p;
}

function new_token(): string
{
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

function b32enc(string $bytes): string
{
    $a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($bytes) as $c) {
        $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $out .= $a[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
    }
    return $out;
}

function b32dec(string $text): string
{
    $a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split(strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $text) ?? '')) as $c) {
        $i = strpos($a, $c);
        if ($i !== false) {
            $bits .= str_pad(decbin($i), 5, '0', STR_PAD_LEFT);
        }
    }
    $out = '';
    foreach (str_split($bits, 8) as $chunk) {
        if (strlen($chunk) === 8) {
            $out .= chr(bindec($chunk));
        }
    }
    return $out;
}

function totp_at(string $secret, int $counter): string
{
    $h = hash_hmac('sha1', pack('N*', 0, $counter), b32dec($secret), true);
    $o = ord($h[19]) & 0x0F;
    $v = ((ord($h[$o]) & 0x7F) << 24) | ((ord($h[$o + 1]) & 0xFF) << 16)
        | ((ord($h[$o + 2]) & 0xFF) << 8) | (ord($h[$o + 3]) & 0xFF);
    return str_pad((string) ($v % 1000000), 6, '0', STR_PAD_LEFT);
}

function totp_check(string $secret, string $code, int $last = -1): ?int
{
    $code = preg_replace('/\D/', '', $code) ?? '';
    if (strlen($code) !== 6 || $secret === '') {
        return null;
    }
    $now = intdiv(time(), 30);
    for ($i = -TOTP_WINDOW; $i <= TOTP_WINDOW; $i++) {
        if ($now + $i > $last && hash_equals(totp_at($secret, $now + $i), $code)) {
            return $now + $i;
        }
    }
    return null;
}

// ===========================================================================
// IMAP
// ===========================================================================

final class ImapError extends RuntimeException {}

final class Imap
{
    /**
     * Abschliessende Liste. Was hier fehlt, wird nie gesendet.
     * Es gibt bewusst kein Kommando, das Nachrichteninhalte liest, und keines,
     * das Nachrichten loescht. DELETE betrifft nur Ordner, und nur leere.
     */
    private const ALLOWED = [
        '/^CAPABILITY$/',
        '/^LOGIN /',
        '/^LOGOUT$/',
        '/^LIST "" "\*"$/',
        '/^CREATE /',
        '/^DELETE /',
        '/^EXAMINE /',
        '/^SELECT /',
        '/^UID SEARCH ALL$/',
        '/^UID FETCH [0-9,:]+ \(BODY\.PEEK\[HEADER\.FIELDS \(FROM TO CC BCC\)\]\)$/',
        '/^UID MOVE [0-9,:]+ /',
    ];
    private const FETCH = '(BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC)])';

    /** @var resource */
    private $sock;
    private int $tag = 0;
    private array $caps = [];
    public string $uidvalidity = '';

    public function __construct(string $host, int $port, int $timeout = 20)
    {
        $ctx = stream_context_create(['ssl' => ['verify_peer' => true,
            'verify_peer_name' => true, 'SNI_enabled' => true, 'peer_name' => $host]]);
        $errno = 0;
        $errstr = '';
        $sock = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr,
            $timeout, STREAM_CLIENT_CONNECT, $ctx);
        if ($sock === false) {
            throw new ImapError(net_hint($host, $port, $errno, trim($errstr)));
        }
        $this->sock = $sock;
        stream_set_timeout($this->sock, 60);
        $this->line();
    }

    public function __destruct()
    {
        if (is_resource($this->sock)) {
            @fwrite($this->sock, "zz LOGOUT\r\n");
            @fclose($this->sock);
        }
    }

    private function line(): array
    {
        $text = '';
        $lit = [];
        while (true) {
            $chunk = fgets($this->sock);
            if ($chunk === false) {
                $meta = stream_get_meta_data($this->sock);
                throw new ImapError(!empty($meta['timed_out'])
                    ? 'Zeitueberschreitung beim Lesen.' : 'Verbindung abgebrochen.');
            }
            $chunk = rtrim($chunk, "\r\n");
            $text .= $chunk;
            if (preg_match('/\{(\d+)\}$/', $chunk, $m) !== 1) {
                break;
            }
            $need = (int) $m[1];
            $data = '';
            while (strlen($data) < $need) {
                $part = fread($this->sock, min(65536, $need - strlen($data)));
                if ($part === false || $part === '') {
                    throw new ImapError('Verbindung beim Lesen abgebrochen.');
                }
                $data .= $part;
            }
            $lit[] = $data;
            $text = substr($text, 0, -strlen($m[0])) . "\x01";
        }
        return ['text' => $text, 'lit' => $lit];
    }

    private function send(string $cmd): array
    {
        $ok = false;
        foreach (self::ALLOWED as $p) {
            if (preg_match($p, $cmd) === 1) {
                $ok = true;
                break;
            }
        }
        if (!$ok) {
            throw new ImapError('Nicht erlaubt: ' . $cmd);
        }
        $tag = sprintf('a%04d', ++$this->tag);
        fwrite($this->sock, "{$tag} {$cmd}\r\n");
        $untagged = [];
        while (true) {
            $line = $this->line();
            if (preg_match('/^' . $tag . ' (OK|NO|BAD)\b(.*)$/i', $line['text'], $m) === 1) {
                return [strtoupper($m[1]), trim($m[2]), $untagged];
            }
            $untagged[] = $line;
        }
    }

    public static function q(string $v): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"';
    }

    public function login(string $user, string $password): void
    {
        [$status, $info] = $this->send('LOGIN ' . self::q($user) . ' ' . self::q($password));
        if ($status !== 'OK') {
            throw new ImapError('Anmeldung abgelehnt. iCloud und Google verlangen ein '
                . 'Anwendungspasswort, nicht das Kontopasswort. Server: ' . $info);
        }
        [, , $untagged] = $this->send('CAPABILITY');
        foreach ($untagged as $l) {
            if (stripos($l['text'], 'CAPABILITY') !== false) {
                $this->caps = array_map('strtoupper', preg_split('/\s+/', $l['text']) ?: []);
            }
        }
        if (!in_array('MOVE', $this->caps, true)) {
            throw new ImapError('Der Server bietet MOVE nicht an. Es wird nichts verschoben.');
        }
    }

    /** @return list<array{name:string,system:bool}> */
    public function folders(): array
    {
        [$status, , $untagged] = $this->send('LIST "" "*"');
        if ($status !== 'OK') {
            throw new ImapError('Ordnerliste nicht lesbar.');
        }
        $out = [];
        foreach ($untagged as $line) {
            if (preg_match('/^\* LIST \(([^)]*)\) (?:"(?:[^"\\\\]|\\\\.)*"|NIL) (.+)$/i',
                    $line['text'], $m) !== 1) {
                continue;
            }
            $flags = strtolower($m[1]);
            if (str_contains($flags, '\noselect')) {
                continue;
            }
            $tok = trim($m[2]);
            if ($tok === "\x01") {
                $raw = $line['lit'][0] ?? '';
            } elseif (strlen($tok) > 1 && $tok[0] === '"') {
                $raw = str_replace(['\\"', '\\\\'], ['"', '\\'], substr($tok, 1, -1));
            } else {
                $raw = $tok;
            }
            if ($raw === '') {
                continue;
            }
            $name = mutf7_decode($raw);
            $system = in_array(strtolower($name), SYSTEM_FOLDERS, true)
                || preg_match('/\\\\(Sent|Drafts|Trash|Junk|Archive|All|Flagged|Important)\b/i', $flags) === 1;
            $out[] = ['name' => $name, 'system' => $system];
        }
        usort($out, static fn($a, $b) => strcmp($a['name'], $b['name']));
        return $out;
    }

    public function create(string $folder): bool
    {
        [$status, $info] = $this->send('CREATE ' . self::q(mutf7_encode($folder)));
        return $status === 'OK' || stripos($info, 'ALREADYEXISTS') !== false;
    }

    /** Nur fuer leere Ordner. Der Aufrufer raeumt vorher aus. */
    public function delete_folder(string $folder): bool
    {
        if (in_array(strtolower($folder), SYSTEM_FOLDERS, true)) {
            return false;
        }
        [$status] = $this->send('DELETE ' . self::q(mutf7_encode($folder)));
        return $status === 'OK';
    }

    /** @return list<string> UIDs */
    public function open(string $folder, bool $write = false): array
    {
        $cmd = ($write ? 'SELECT ' : 'EXAMINE ') . self::q(mutf7_encode($folder));
        [$status, , $untagged] = $this->send($cmd);
        if ($status !== 'OK') {
            throw new ImapError('Ordner nicht waehlbar: ' . $folder);
        }
        foreach ($untagged as $l) {
            if (preg_match('/UIDVALIDITY (\d+)/i', $l['text'], $m) === 1
                && strtoupper($folder) === 'INBOX') {
                $this->uidvalidity = $m[1];
            }
        }
        [$status, , $untagged] = $this->send('UID SEARCH ALL');
        foreach ($untagged as $l) {
            if (preg_match('/^\* SEARCH\b(.*)$/i', $l['text'], $m) === 1) {
                return preg_split('/\s+/', trim($m[1]), -1, PREG_SPLIT_NO_EMPTY) ?: [];
            }
        }
        return [];
    }

    /**
     * @param list<string> $uids
     * @return list<array{uid:string,from:?string,to:list<string>}>
     */
    public function headers(array $uids): array
    {
        $out = [];
        foreach (array_chunk($uids, BATCH) as $chunk) {
            [$status, , $untagged] = $this->send(
                'UID FETCH ' . implode(',', $chunk) . ' ' . self::FETCH);
            if ($status !== 'OK') {
                continue;
            }
            foreach ($untagged as $line) {
                if (!isset($line['lit'][0])
                    || preg_match('/UID (\d+)/', $line['text'], $m) !== 1) {
                    continue;
                }
                $h = parse_head($line['lit'][0]);
                $out[] = ['uid' => $m[1], 'from' => $h['from'], 'to' => $h['to']];
            }
        }
        return $out;
    }

    /** @param list<string> $uids */
    public function move(array $uids, string $target): int
    {
        foreach ($uids as $uid) {
            if (!ctype_digit($uid)) {
                throw new ImapError('UID muss eine Zahl sein.');
            }
        }
        $moved = 0;
        foreach (array_chunk($uids, BATCH) as $chunk) {
            [$status] = $this->send('UID MOVE ' . implode(',', $chunk)
                . ' ' . self::q(mutf7_encode($target)));
            if ($status !== 'OK') {
                throw new ImapError('Verschieben nach ' . $target . ' fehlgeschlagen.');
            }
            $moved += count($chunk);
        }
        return $moved;
    }
}

function net_hint(string $host, int $port, int $errno, string $errstr): string
{
    $hint = match ($errno) {
        111 => "Verbindung abgelehnt. Auf {$host} antwortet auf Port {$port} nichts.",
        110 => "Zeitueberschreitung. Pakete zu {$host}:{$port} werden verworfen - "
             . "meist eine Firewall. Ausgehend Port {$port} freigeben.",
        101, 113 => 'Netzwerk nicht erreichbar. Routing oder IPv6 pruefen.',
        0 => $errstr !== '' ? $errstr : 'Verbindung fehlgeschlagen.',
        default => $errstr !== '' ? $errstr : 'Verbindung fehlgeschlagen.',
    };
    return "{$host}:{$port} - {$hint}" . ($errno ? " (errno {$errno})" : '');
}

function mutf7_encode(string $name): string
{
    $out = '';
    $buf = '';
    $flush = static function (string &$buf, string &$out): void {
        if ($buf !== '') {
            $u = (string) mb_convert_encoding($buf, 'UTF-16BE', 'UTF-8');
            $out .= '&' . rtrim(strtr(base64_encode($u), '/', ','), '=') . '-';
            $buf = '';
        }
    };
    foreach (preg_split('//u', $name, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) {
        if ($ch === '&') {
            $flush($buf, $out);
            $out .= '&-';
        } elseif (strlen($ch) === 1 && ord($ch) >= 0x20 && ord($ch) <= 0x7E) {
            $flush($buf, $out);
            $out .= $ch;
        } else {
            $buf .= $ch;
        }
    }
    $flush($buf, $out);
    return $out;
}

function mutf7_decode(string $name): string
{
    if (!str_contains($name, '&')) {
        return $name;
    }
    $out = '';
    for ($i = 0, $len = strlen($name); $i < $len;) {
        if ($name[$i] !== '&') {
            $out .= $name[$i++];
            continue;
        }
        $end = strpos($name, '-', $i);
        if ($end === false) {
            $out .= substr($name, $i);
            break;
        }
        $chunk = substr($name, $i + 1, $end - $i - 1);
        if ($chunk === '') {
            $out .= '&';
        } else {
            $b64 = strtr($chunk, ',', '/');
            $b64 .= str_repeat('=', (4 - strlen($b64) % 4) % 4);
            $raw = base64_decode($b64, true);
            $out .= $raw === false ? substr($name, $i, $end - $i + 1)
                : (string) mb_convert_encoding($raw, 'UTF-8', 'UTF-16BE');
        }
        $i = $end + 1;
    }
    return $out;
}

/** @return array{from:?string,to:list<string>} */
function parse_head(string $raw): array
{
    $raw = preg_replace('/\r?\n[ \t]+/', ' ', str_replace("\r\n", "\n", $raw)) ?? $raw;
    $from = null;
    $to = [];
    foreach (explode("\n", $raw) as $line) {
        $pos = strpos($line, ':');
        if ($pos === false) {
            continue;
        }
        $field = strtolower(trim(substr($line, 0, $pos)));
        if (!in_array($field, ['from', 'to', 'cc', 'bcc'], true)) {
            continue;
        }
        preg_match_all('/[^\s<>,;:"()]+@[^\s<>,;:"()]+/', substr($line, $pos + 1), $m);
        foreach ($m[0] as $addr) {
            $addr = strtolower(rtrim(trim($addr), '.'));
            if ($field === 'from') {
                $from ??= $addr;
            } elseif (!in_array($addr, $to, true)) {
                $to[] = $addr;
            }
        }
    }
    return ['from' => $from, 'to' => $to];
}

// ===========================================================================
// Ordnerlogik
// ===========================================================================

function folder_shape_ok(string $name): bool
{
    $parts = explode('/', $name);
    if (count($parts) < 1 || count($parts) > 3) {
        return false;
    }
    if (in_array(strtolower($parts[0]), SYSTEM_FOLDERS, true)) {
        return false;
    }
    foreach ($parts as $p) {
        if (!preg_match('/^[A-Za-z0-9@._+\- ]{1,60}$/', $p) || !preg_match('/[A-Za-z0-9]/', $p)) {
            return false;
        }
    }
    return true;
}

function alias_path(string $recipient, array $user): ?string
{
    $r = strtolower(trim($recipient));
    if ($r === '' || !str_contains($r, '@') || $r === strtolower((string) $user['address'])) {
        return null;
    }
    $domain = substr($r, strrpos($r, '@') + 1);
    if ($domain === RELAY_DOMAIN || str_ends_with($domain, '.' . RELAY_DOMAIN)) {
        return !empty($user['privateappleid']) ? 'Apple/privateappleid' : null;
    }
    foreach ($user['domains'] ?? [] as $own) {
        $own = strtolower(ltrim((string) $own, '@'));
        if ($own !== '' && ($domain === $own || str_ends_with($domain, '.' . $own))) {
            return 'Alias/Domains/@' . $own;
        }
    }
    foreach ($user['addresses'] ?? [] as $own) {
        if (strtolower((string) $own) === $r) {
            return 'Alias/Adressen/' . $r;
        }
    }
    return null;
}

function alias_of(array $recipients, array $user): ?string
{
    foreach ($recipients as $to) {
        $p = alias_path((string) $to, $user);
        if ($p !== null) {
            return $p;
        }
    }
    return null;
}

function resolve_answer(string $answer, ?string $aliasPath): ?string
{
    if (!array_key_exists($answer, folders_catalogue())) {
        return null;
    }
    return $answer === 'Alias' ? $aliasPath : $answer;
}

// ===========================================================================
// Claude
// ===========================================================================

const DEFAULT_MODEL = 'claude-sonnet-5';
const DEFAULT_API_URL = 'https://api.anthropic.com/v1/messages';

/** Zwei Wege zur KI: die Messages-API oder eine Routine auf claude.ai. */
const API_KINDS = [
    'messages' => 'Claude-API (api.anthropic.com)',
    'routine'  => 'Claude-Routine (claude.ai/code/routines)',
];

function api_url(): string
{
    $url = (string) (config()['api_url'] ?? '');
    return str_starts_with($url, 'https://') ? $url : DEFAULT_API_URL;
}

function api_kind(): string
{
    $kind = (string) (config()['api_kind'] ?? 'messages');
    return isset(API_KINDS[$kind]) ? $kind : 'messages';
}

/**
 * Baut Anfrage und Kopfzeilen fuer den gewaehlten Weg.
 * @return array{0:string,1:list<string>}
 */
function api_request(string $kind, string $prompt, int $maxTokens, string $secret): array
{
    if ($kind === 'routine') {
        return [json_encode(['prompt' => $prompt], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ['content-type: application/json', 'accept: application/json',
             'authorization: Bearer ' . $secret]];
    }
    return [json_encode([
        'model' => (string) (config()['model'] ?? DEFAULT_MODEL),
        'max_tokens' => $maxTokens,
        'messages' => [['role' => 'user', 'content' => $prompt]],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ['content-type: application/json', 'x-api-key: ' . $secret,
         'anthropic-version: 2023-06-01']];
}

function api_secret(): string
{
    return dec((string) (config()['api_key'] ?? ''));
}

/** Zieht den Antworttext heraus, egal in welcher Huelle er steckt. */
function api_answer_text(string $raw): string
{
    $body = json_decode($raw, true);
    if (!is_array($body)) {
        return $raw;
    }
    $text = '';
    foreach ((array) ($body['content'] ?? []) as $part) {
        $text .= is_array($part) ? (string) ($part['text'] ?? '') : (string) $part;
    }
    if ($text !== '') {
        return $text;
    }
    foreach (['antwort', 'answer', 'result', 'output', 'text', 'message'] as $field) {
        if (isset($body[$field]) && is_scalar($body[$field])) {
            return (string) $body[$field];
        }
    }
    return $raw;
}

/** Die Aliasregeln entfallen, wenn es den Ordner Alias gar nicht gibt. */
function alias_rules(): string
{
    if (!array_key_exists('Alias', folders_catalogue())) {
        return '';
    }
    return "- Steht (Nebenadresse), antworte \"Alias\" - ausser es ist Sicherheit oder Finanzen.\n"
        . "  Diese beiden gehen immer vor.\n"
        . "- \"Alias\" ist nur bei (Nebenadresse) gueltig.\n";
}

/**
 * @param list<array{from:string,to:string,art:string}> $questions
 * @return array{0:array<string,string>,1:?string}
 */
function ask_claude(array $questions): array
{
    $config = config();
    $key = dec((string) ($config['api_key'] ?? ''));
    if ($key === '') {
        return [[], 'Kein API-Schluessel hinterlegt.'];
    }
    if ($questions === []) {
        return [[], null];
    }
    $catalogue = '';
    foreach (folders_catalogue() as $name => $what) {
        $catalogue .= "- {$name}: {$what}\n";
    }
    // Jede Zeile bekommt eine Nummer. Derselbe Absender kann an die Hauptadresse
    // und an eine Nebenadresse schreiben - das sind zwei getrennte Fragen.
    $lines = '';
    foreach ($questions as $nr => $q) {
        $lines .= sprintf("%d) %s -> %s (%s)\n", $nr, $q['from'], $q['to'], $q['art']);
    }
    $prompt = "Ordne jede Zeile genau einem Ordner zu.\n\n"
        . "Ordner (nur diese Werte sind gueltig):\n{$catalogue}\n"
        . "Regeln:\n" . alias_rules()
        . "- Finanzen nur, wo tatsaechlich Geld dahintersteht. Newsletter und Werbung eines\n"
        . "  Zahlungsanbieters gehoeren nach Werbung.\n"
        . "- Unsicher? Persoenlich.\n\n"
        . "Zeilen:\n{$lines}\n"
        . "Antworte ausschliesslich mit JSON, Zeilennummer auf Ordner: {\"0\": \"Ordner\"}\n";

    [$payload, $headers] = api_request(api_kind(), $prompt, 4096, $key);
    [$code, $raw, $error] = https_post(api_url(), $payload, $headers);
    if ($error !== null) {
        return [[], 'Claude nicht erreichbar: ' . $error];
    }
    if ($code < 200 || $code >= 300) {
        $body = json_decode((string) $raw, true);
        $message = (string) ($body['error']['message'] ?? ($body['message'] ?? ''));
        if ($code === 401 || $code === 403) {
            $message .= ' Das Token wurde abgelehnt - meist ein Tippfehler oder '
                . 'ein Leerzeichen. Das ist kein Netzwerkproblem.';
        }
        return [[], 'Claude antwortet mit HTTP ' . $code . '. ' . trim($message)];
    }
    $text = api_answer_text((string) $raw);
    $start = strpos($text, '{');
    $end = strrpos($text, '}');
    if ($start === false || $end === false) {
        return [[], 'Claude hat kein JSON geliefert.'];
    }
    $map = json_decode(substr($text, $start, $end - $start + 1), true);
    if (!is_array($map)) {
        return [[], 'Antwort nicht lesbar.'];
    }
    $catalogueKeys = folders_catalogue();
    $out = [];
    foreach ($map as $nr => $folder) {
        $folder = trim((string) $folder);
        if (isset($questions[(int) $nr]) && array_key_exists($folder, $catalogueKeys)) {
            $out[(int) $nr] = $folder;
        }
    }
    return [$out, null];
}

/** @return array{0:int,1:?string,2:?string} [status, body, fehler] */
function https_post(string $url, string $payload, array $headers): array
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => $headers, CURLOPT_POSTFIELDS => $payload,
            CURLOPT_TIMEOUT => 120, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2]);
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        return $raw === false ? [0, null, $err] : [$code, (string) $raw, null];
    }
    $ctx = stream_context_create(['http' => ['method' => 'POST',
        'header' => implode("\r\n", $headers), 'content' => $payload,
        'timeout' => 120, 'ignore_errors' => true]]);
    $raw = @file_get_contents($url, false, $ctx);
    $code = 0;
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d+)#', $line, $m)) {
            $code = (int) $m[1];
        }
    }
    return $raw === false ? [0, null, 'Anfrage fehlgeschlagen'] : [$code, (string) $raw, null];
}

// ===========================================================================
// Zeitplan
// ===========================================================================

function schedule_due(array $user, int $now): bool
{
    $last = isset($user['last_run']) ? strtotime((string) $user['last_run']) : 0;
    $mode = (string) ($user['schedule']['mode'] ?? 'interval');
    if ($mode === 'times') {
        $slot = date('H:i', $now - ($now % (STEP * 60)));
        if (!in_array($slot, (array) ($user['schedule']['times'] ?? []), true)) {
            return false;
        }
        return $last < $now - ($now % (STEP * 60));   // in diesem Fenster noch nicht gelaufen
    }
    $interval = max(STEP, (int) ($user['schedule']['interval'] ?? 60));
    return $last === 0 || ($now - $last) >= $interval * 60;
}

// ===========================================================================
// Durchlauf
// ===========================================================================

/**
 * @return array{gelesen:int,verschoben:int,offen:int,fehler:?string}
 */
function run_cycle(string $id, bool $initial = false): array
{
    $result = ['gelesen' => 0, 'verschoben' => 0, 'offen' => 0, 'fehler' => null];
    $user = user_load($id);
    if ($user === null) {
        $result['fehler'] = 'Nutzer nicht gefunden.';
        return $result;
    }
    // Ohne Claude keine Initialisierung. Lieber gar nicht anfangen, als den
    // Posteingang leerzuraeumen und dann ohne Ziel dazustehen.
    if ($initial) {
        [, $probe] = ask_claude([['from' => 'probe@example.com',
            'to' => (string) $user['address'], 'art' => 'Hauptadresse']]);
        if ($probe !== null) {
            $result['fehler'] = 'Claude ist nicht erreichbar, deshalb keine Initialisierung. '
                . $probe;
            return $result;
        }
    }

    try {
        $imap = new Imap((string) $user['host'], (int) $user['port']);
        $imap->login((string) $user['address'], dec((string) $user['password']));
        $folders = $imap->folders();

        if ($initial) {
            // 1. alles in den Posteingang, 2. leere Ordner loeschen.
            // Tiefste Ebene zuerst, sonst haengt ein Elternordner an seinen Kindern.
            $order = $folders;
            usort($order, static fn(array $a, array $b) =>
                substr_count($b['name'], '/') <=> substr_count($a['name'], '/'));
            foreach ($order as $f) {
                if (strtoupper($f['name']) === 'INBOX') {
                    continue;
                }
                // Systemordner bleiben stehen. Nur das Archiv wird geleert - dort
                // liegt echte Post, die mitsortiert werden soll. Gesendet,
                // Entwuerfe, Werbung und Papierkorb bleiben unangetastet.
                if ($f['system'] && strcasecmp($f['name'], 'Archive') !== 0) {
                    continue;
                }
                $uids = $imap->open($f['name'], true);
                if ($uids !== []) {
                    $imap->move($uids, 'INBOX');
                }
                if (!$f['system']) {
                    $imap->delete_folder($f['name']);
                }
            }
            $folders = $imap->folders();
            user_set($id, static function (array $u): array {
                $u['known_folders'] = [];
                $u['last_uid'] = 0;
                $u['knowledge'] = [];
                return $u;
            });
            $user = user_load($id) ?? $user;
        } else {
            $have = array_column($folders, 'name');
            $missing = array_values(array_diff($user['known_folders'] ?? [], $have));
            if ($missing !== []) {
                user_set($id, static function (array $u) use ($missing): array {
                    $u['status'] = 'neu_initialisieren';
                    $u['halt'] = 'Diese Ordner fehlen: ' . implode(', ', array_slice($missing, 0, 6));
                    return $u;
                });
                $result['fehler'] = 'Ordner wurden umbenannt oder geloescht. Bitte neu initialisieren.';
                return $result;
            }
        }

        $uids = $imap->open('INBOX', true);
        $messages = $imap->headers($uids);
        $watermark = (!$initial && ($user['uidvalidity'] ?? '') === $imap->uidvalidity)
            ? (int) ($user['last_uid'] ?? 0) : 0;
        $fresh = array_values(array_filter($messages,
            static fn(array $m) => (int) $m['uid'] > $watermark));
        $result['gelesen'] = count($fresh);

        // Was schon bekannt ist, direkt zuordnen; der Rest geht an Claude.
        $open = [];
        foreach ($fresh as $m) {
            $from = (string) ($m['from'] ?? '');
            $path = alias_of($m['to'], $user);
            $kind = $path === null ? 'primary' : 'alias';
            if (isset($user['knowledge'][$kind][$from])) {
                continue;
            }
            $open[$kind . '|' . $from] ??= ['from' => $from,
                'to' => $path === null ? (string) $user['address'] : ($m['to'][0] ?? ''),
                'art' => $kind === 'alias' ? 'Nebenadresse' : 'Hauptadresse', 'kind' => $kind];
        }
        $reachable = true;
        foreach (array_chunk($open, 60, true) as $batch) {
            // Fortlaufende Nummern je Anfrage, damit die Antwort eindeutig passt.
            $keys = array_keys($batch);
            [$answers, $error] = ask_claude(array_values($batch));
            if ($error !== null) {
                $result['fehler'] = $error;
                $reachable = false;
                break;
            }
            foreach ($answers as $nr => $answer) {
                $q = $open[$keys[$nr]] ?? null;
                if ($q === null || ($answer === 'Alias' && $q['kind'] !== 'alias')) {
                    continue;
                }
                $user['knowledge'][$q['kind']][$q['from']] = $answer;
                unset($open[$keys[$nr]]);
            }
        }
        // Claude war da, hat aber einzelne Zeilen nicht oder unbrauchbar
        // beantwortet. Die kommen nach Persoenlich, sonst bliebe der Merker
        // stehen und keine spaetere Mail wuerde je sortiert.
        if ($reachable) {
            foreach ($open as $key => $q) {
                $user['knowledge'][$q['kind']][$q['from']] =
                    $q['kind'] === 'alias' ? 'Alias' : 'Persoenlich';
                unset($open[$key]);
            }
        }

        $moves = [];
        foreach ($fresh as $m) {
            $from = (string) ($m['from'] ?? '');
            $path = alias_of($m['to'], $user);
            $kind = $path === null ? 'primary' : 'alias';
            $known = $user['knowledge'][$kind][$from] ?? null;
            $folder = is_string($known) ? resolve_answer($known, $path) : null;
            if ($folder !== null && folder_shape_ok($folder)) {
                $moves[$folder][] = $m['uid'];
            }
        }

        $have = array_column($imap->folders(), 'name');
        $used = [];
        foreach ($moves as $folder => $list) {
            if (!in_array($folder, $have, true)) {
                $parts = explode('/', $folder);
                for ($i = 1; $i <= count($parts); $i++) {
                    $imap->create(implode('/', array_slice($parts, 0, $i)));
                }
            }
            $imap->open('INBOX', true);
            $result['verschoben'] += $imap->move($list, $folder);
            $used[] = $folder;
        }
        $result['offen'] = count($open);

        $high = 0;
        foreach ($messages as $m) {
            $high = max($high, (int) $m['uid']);
        }
        $knowledge = $user['knowledge'] ?? [];
        $advance = $open === [];
        $uidvalidity = $imap->uidvalidity;
        user_set($id, static function (array $u) use ($knowledge, $advance, $high,
                                                      $uidvalidity, $used, $initial): array {
            $u['knowledge'] = $knowledge;
            $u['uidvalidity'] = $uidvalidity;
            if ($advance) {
                $u['last_uid'] = max((int) ($u['last_uid'] ?? 0), $high);
            }
            $u['known_folders'] = array_values(array_unique(
                array_merge($u['known_folders'] ?? [], $used)));
            $u['last_run'] = gmdate('c');
            $u['last_error'] = null;
            if ($initial) {
                $u['status'] = 'bereit';
                $u['halt'] = null;
                $u['initialised'] = gmdate('c');
            }
            return $u;
        });
    } catch (ImapError $e) {
        $result['fehler'] = $e->getMessage();
        user_set($id, static function (array $u) use ($e): array {
            $u['last_error'] = $e->getMessage();
            $u['last_run'] = gmdate('c');
            return $u;
        });
    }
    return $result;
}

// ===========================================================================
// Selbsttest fuer das Setup
// ===========================================================================

/** @return list<array{name:string,ok:bool,detail:string,required:bool}> */
function checks_system(): array
{
    $out = [];

    $php = PHP_VERSION;
    $out[] = ['name' => 'PHP-Version', 'ok' => PHP_VERSION_ID >= 80100,
        'detail' => PHP_VERSION_ID >= 80100 ? $php : $php . ' - noetig ist 8.1 oder neuer',
        'required' => true];

    foreach (['sodium' => 'php-sodium', 'mbstring' => 'php-mbstring',
              'curl' => 'php-curl'] as $ext => $pkg) {
        $have = extension_loaded($ext);
        $out[] = ['name' => 'Erweiterung ' . $ext, 'ok' => $have,
            'detail' => $have ? 'geladen' : 'apt install ' . $pkg, 'required' => true];
    }

    $limit = trim((string) ini_get('memory_limit'));
    $bytes = ini_bytes($limit);
    $out[] = ['name' => 'Speicherlimit', 'ok' => $bytes < 0 || $bytes >= 128 * 1024 * 1024,
        'detail' => $limit === '' ? 'unbekannt' : ($bytes < 0 ? 'ohne Begrenzung' : $limit),
        'required' => false];

    $dir = data_dir();
    $writable = (is_dir($dir) || @mkdir($dir, 0700, true)) && is_writable($dir);
    $out[] = ['name' => 'Datenverzeichnis', 'ok' => $writable,
        'detail' => $writable ? $dir . ' beschreibbar' : $dir . ' nicht beschreibbar',
        'required' => true];

    $free = @disk_free_space($dir) ?: 0;
    $out[] = ['name' => 'Freier Speicher', 'ok' => $free >= 100 * 1024 * 1024,
        'detail' => $free > 0 ? round($free / 1048576) . ' MB frei' : 'unbekannt',
        'required' => false];

    foreach (net_checks(DEFAULT_API_URL) as $row) {
        $out[] = $row;
    }
    return $out;
}

/** Netzwerk: DNS und die drei Ports, die der Server nach aussen braucht. */
function net_checks(string $url): array
{
    $out = [];
    $apiHost = (string) (parse_url($url, PHP_URL_HOST) ?: 'api.anthropic.com');

    $reach = static function (string $host, int $port): array {
        if (gethostbyname($host) === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
            return [false, $host . ' laesst sich nicht aufloesen - DNS pruefen (Port 53)'];
        }
        $errno = 0;
        $errstr = '';
        $sock = @stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, 3);
        if ($sock === false) {
            return [false, net_hint($host, $port, $errno, trim($errstr))];
        }
        fclose($sock);
        return [true, $host . ':' . $port . ' erreichbar'];
    };

    [$ok, $detail] = $reach($apiHost, 443);
    $out[] = ['name' => 'Ausgehend 443 - Claude', 'ok' => $ok, 'detail' => $detail,
        'required' => true];

    // Von den IMAP-Servern reicht einer. Wer nur iCloud einsetzt, braucht
    // Google nicht - die einzelnen Zeilen sind deshalb nur Hinweise.
    $anyImap = false;
    foreach ([['imap.mail.me.com', 'iCloud'], ['imap.gmail.com', 'Google']] as [$host, $label]) {
        [$ok, $detail] = $reach($host, 993);
        $anyImap = $anyImap || $ok;
        $out[] = ['name' => $label . ' - imap:993', 'ok' => $ok, 'detail' => $detail,
            'required' => false];
    }
    $out[] = ['name' => 'Ausgehend 993 - IMAP', 'ok' => $anyImap,
        'detail' => $anyImap ? 'offen' : 'Kein IMAP-Server erreichbar. Port 993 freigeben.',
        'required' => true];
    return $out;
}

function ini_bytes(string $value): int
{
    if ($value === '' || $value === '-1') {
        return -1;
    }
    $n = (int) $value;
    return match (strtolower(substr($value, -1))) {
        'g' => $n * 1073741824,
        'm' => $n * 1048576,
        'k' => $n * 1024,
        default => $n,
    };
}

/** Eine einzelne Zeile: antwortet die Gegenstelle mit diesem Token? */
function check_key(string $url, string $key, ?string $kind = null): array
{
    $kind = $kind !== null && isset(API_KINDS[$kind]) ? $kind : api_kind();
    if (!str_starts_with($url, 'https://')) {
        return ['name' => 'Verbindung zur KI', 'ok' => false,
            'detail' => 'Die API-URL muss mit https:// beginnen.', 'required' => true];
    }
    if ($key === '') {
        return ['name' => 'Verbindung zur KI', 'ok' => false,
            'detail' => 'Noch kein Token eingetragen.', 'required' => true];
    }
    if (($cached = key_probe_cached($url . '|' . $kind, $key)) !== null) {
        return $cached;
    }
    foreach (net_checks($url) as $row) {
        if ($row['required'] && !$row['ok'] && str_contains($row['name'], '443')) {
            return ['name' => 'Verbindung zur KI', 'ok' => false,
                'detail' => $row['detail'], 'required' => true];
        }
    }
    // Der Test laeuft mit dem eingetippten Token, nicht mit dem gespeicherten.
    [$payload, $headers] = api_request($kind, 'Antworte nur mit: ok', 16, $key);
    [$code, $raw, $error] = https_post($url, $payload, $headers);
    $ok = $error === null && $code >= 200 && $code < 300;
    if ($error !== null) {
        $detail = $error;
    } elseif ($ok) {
        $detail = 'Die KI antwortet.';
    } elseif ($code === 401 || $code === 403) {
        $detail = 'Token abgelehnt (' . $code . '). Tippfehler oder Leerzeichen?';
    } else {
        $body = json_decode((string) $raw, true);
        $detail = 'HTTP ' . $code . ' ' . (string) ($body['error']['message'] ?? '');
    }
    $row = ['name' => 'Verbindung zur KI', 'ok' => $ok, 'detail' => trim($detail),
        'required' => true];
    key_probe_store($url . '|' . $kind, $key, $row);
    return $row;
}

/** Die Liste wird im Sekundentakt geholt - der Schluessel aber nicht jedes Mal geprueft. */
const KEY_PROBE_TTL = 20;

function key_probe_id(string $url, string $key): string
{
    return hash('sha256', $url . "\0" . $key);
}

function key_probe_cached(string $url, string $key): ?array
{
    $entry = jread(data_dir() . '/keycheck.json');
    return ($entry['id'] ?? '') === key_probe_id($url, $key)
        && time() - (int) ($entry['t'] ?? 0) < KEY_PROBE_TTL
        ? (array) $entry['row'] : null;
}

function key_probe_store(string $url, string $key, array $row): void
{
    jwrite(data_dir() . '/keycheck.json',
        ['id' => key_probe_id($url, $key), 't' => time(), 'row' => $row]);
}

// ===========================================================================
// Cron
// ===========================================================================

function cron(): never
{
    if ((config()['setup_done'] ?? false) !== true) {
        bail('Noch nicht eingerichtet.');
    }
    $now = time();
    foreach (users() as $user) {
        if ((string) ($user['status'] ?? '') !== 'bereit' || !schedule_due($user, $now)) {
            continue;
        }
        $r = run_cycle((string) $user['id']);
        printf("%s: %d gelesen, %d verschoben, %d offen%s\n", $user['address'],
            $r['gelesen'], $r['verschoben'], $r['offen'],
            $r['fehler'] !== null ? ' - ' . $r['fehler'] : '');
    }
    exit(0);
}

// ===========================================================================
// Start
// ===========================================================================

function boot(): void
{
    foreach (['sodium' => 'php-sodium', 'mbstring' => 'php-mbstring'] as $ext => $pkg) {
        if (!extension_loaded($ext)) {
            bail("PHP-Erweiterung {$ext} fehlt (apt install {$pkg}).");
        }
    }
    if (!is_dir(data_dir())) {
        @mkdir(data_dir(), 0700, true);
    }
    @mkdir(data_dir() . '/users', 0700, true);
    if (!is_file(data_dir() . '/.htaccess')) {
        @file_put_contents(data_dir() . '/.htaccess', "Require all denied\n");
    }
}

// simple-apple.php bindet diese Datei als Baukasten ein und bringt seine
// eigene Oberflaeche mit. Dann laeuft hier unten nichts.
if (!defined('ICM_LIBRARY')) {
    boot();
    if (PHP_SAPI === 'cli') {
        ($argv[1] ?? '') === 'cron' ? cron() : bail('Aufruf: php index.php cron');
    }
    web();
}

// ===========================================================================
// Web
// ===========================================================================

function session_begin(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    session_name('icm');
    session_set_cookie_params(['lifetime' => 0, 'httponly' => true,
        'samesite' => 'Strict', 'secure' => $https]);
    session_start();
}

function csrf(): string
{
    return $_SESSION['csrf'] ??= new_token();
}

function csrf_ok(): void
{
    // Ohne Token in der Sitzung darf nichts durchgehen - zwei leere Werte
    // sind sonst gleich und die Pruefung waere wirkungslos.
    $want = (string) ($_SESSION['csrf'] ?? '');
    if ($want === '' || !hash_equals($want, (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('CSRF-Token stimmt nicht. Seite neu laden.');
    }
}

/** Weiterleitung auf diese Datei, notfalls mit Abfrage. Nie relativ. */
function go(string $query = ''): never
{
    $path = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/');
    header('Location: ' . $path . ($query !== '' ? '?' . $query : ''));
    exit;
}

function e(?string $v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
}

/** Einfache Mengenbegrenzung je Absender und Zeitfenster. */
function rate_ok(string $bucket, int $max, int $window): bool
{
    $now = time();
    $state = locked(data_dir() . '/rate.json',
        static function (array $d) use ($bucket, $now, $window): array {
            foreach ($d as $k => $v) {
                if ($now - (int) ($v['start'] ?? 0) >= $window) {
                    unset($d[$k]);
                }
            }
            $e = $d[$bucket] ?? ['start' => $now, 'n' => 0];
            $e['n'] = (int) $e['n'] + 1;
            $d[$bucket] = $e;
            return $d;
        });
    return (int) ($state[$bucket]['n'] ?? 0) <= $max;
}

function throttled(string $bucket): bool
{
    $entry = jread(data_dir() . '/logins.json')[$bucket] ?? null;
    return is_array($entry) && ($entry['n'] ?? 0) >= LOGIN_MAX
        && time() - ($entry['t'] ?? 0) < LOGIN_LOCK;
}

function note_try(string $bucket, bool $ok): void
{
    locked(data_dir() . '/logins.json', static function (array $d) use ($bucket, $ok): array {
        if ($ok) {
            unset($d[$bucket]);
        } else {
            $e = $d[$bucket] ?? ['n' => 0, 't' => 0];
            if (time() - $e['t'] >= LOGIN_LOCK) {
                $e = ['n' => 0, 't' => 0];
            }
            $d[$bucket] = ['n' => $e['n'] + 1, 't' => time()];
        }
        foreach ($d as $k => $v) {
            if (time() - ($v['t'] ?? 0) > LOGIN_LOCK * 4) {
                unset($d[$k]);
            }
        }
        return $d;
    });
}

function json_out(int $code, array $data): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function web(): never
{
    session_begin();
    $config = config();
    $setup = ($config['setup_done'] ?? false) === true;

    // Live-Pruefungen. Vor dem Setup nur fuer den, der gerade im passenden
    // Schritt steht, danach nur fuer den angemeldeten Admin.
    if (isset($_GET['check'])) {
        $admin = !empty($_SESSION['admin']);
        $inSetup = !$setup && is_array($_SESSION['setup'] ?? null);
        if (!$admin && !$inSetup) {
            json_out(403, ['error' => 'Nicht erlaubt']);
        }
        if (!rate_ok('check|' . (string) ($_SERVER['REMOTE_ADDR'] ?? ''), 90, 60)) {
            json_out(429, ['error' => 'Zu viele Anfragen']);
        }
        if ($_GET['check'] === 'key') {
            // Der Tokentest geht nach draussen - nur im dritten Schritt oder als Admin.
            if (!$admin && (int) ($_SESSION['setup']['step'] ?? 0) !== 3) {
                json_out(403, ['error' => 'Nicht erlaubt']);
            }
            json_out(200, ['pruefungen' => [check_key(
                trim((string) ($_GET['url'] ?? '')) ?: DEFAULT_API_URL,
                trim((string) ($_GET['key'] ?? '')))]]);
        }
        json_out(200, ['pruefungen' => checks_system()]);
    }

    if (!$setup) {
        setup_flow();
    }

    if (isset($_GET['usr'])) {
        portal();
    }

    if (($_GET['page'] ?? '') === 'logout') {
        csrf_ok();
        $_SESSION = [];
        session_destroy();
        go();
    }

    if (empty($_SESSION['admin'])) {
        $error = null;
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            csrf_ok();
            $bucket = 'admin|' . (string) ($_SERVER['REMOTE_ADDR'] ?? '');
            if (throttled($bucket)) {
                $error = 'Zu viele Fehlversuche. Spaeter erneut.';
            } else {
                $ok = password_verify((string) ($_POST['password'] ?? ''),
                    (string) $config['password_hash']);
                $step = $ok ? totp_check((string) $config['totp_secret'],
                    (string) ($_POST['code'] ?? ''), (int) ($config['totp_last'] ?? 0)) : null;
                if ($ok && $step !== null) {
                    note_try($bucket, true);
                    session_regenerate_id(true);
                    $_SESSION['admin'] = true;
                    $_SESSION['csrf'] = new_token();
                    config_set(static function (array $c) use ($step): array {
                        $c['totp_last'] = $step;
                        return $c;
                    });
                    go();
                }
                note_try($bucket, false);
                $error = 'Anmeldung fehlgeschlagen.';
            }
        }
        page_login($error);
    }

    $notice = null;
    $error = null;
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_ok();
        [$notice, $error] = admin_action();
    }

    $view = (string) ($_GET['view'] ?? '');
    if ($view === 'user' && ($u = user_load((string) ($_GET['id'] ?? ''))) !== null) {
        page_user($u, $notice, $error);
    }
    if ($view === 'system') {
        page_system($notice, $error);
    }
    page_users($notice, $error);
}

/** @return array{0:?string,1:?string} */
function admin_action(): array
{
    $action = (string) ($_POST['action'] ?? '');

    if ($action === 'add') {
        $provider = (string) ($_POST['provider'] ?? 'icloud');
        if (!isset(PROVIDERS[$provider])) {
            return [null, 'Unbekannter Anbieter.'];
        }
        $address = strtolower(trim((string) ($_POST['address'] ?? '')));
        $password = (string) ($_POST['password'] ?? '');
        $host = $provider === 'other'
            ? strtolower(trim((string) ($_POST['host'] ?? ''))) : PROVIDERS[$provider]['host'];
        $port = $provider === 'other' ? (int) ($_POST['port'] ?? 993) : PROVIDERS[$provider]['port'];
        if (!filter_var($address, FILTER_VALIDATE_EMAIL)) {
            return [null, 'Keine gueltige E-Mail-Adresse.'];
        }
        if ($password === '') {
            return [null, 'Anwendungspasswort fehlt.'];
        }
        if ($host === '' || !preg_match('/^[a-z0-9.-]+$/', $host) || $port < 1 || $port > 65535) {
            return [null, 'IMAP-Server oder Port ungueltig.'];
        }
        foreach (users() as $x) {
            if (strtolower((string) $x['address']) === $address) {
                return [null, 'Diese Adresse gibt es schon.'];
            }
        }
        try {
            (new Imap($host, $port))->login($address, $password);
        } catch (ImapError $e) {
            return [null, $e->getMessage()];
        }
        $id = bin2hex(random_bytes(8));
        jwrite(user_path($id), ['id' => $id, 'address' => $address, 'password' => enc($password),
            'provider' => $provider, 'host' => $host, 'port' => $port,
            'apple' => (bool) PROVIDERS[$provider]['apple'], 'privateappleid' => false,
            'domains' => [], 'addresses' => [], 'knowledge' => [], 'known_folders' => [],
            'schedule' => ['mode' => 'interval', 'interval' => 60, 'times' => []],
            'totp_secret' => '', 'status' => 'neu', 'created' => gmdate('c')]);
        sodium_memzero($password);
        return [$address . ' angelegt. Verbindung steht.', null];
    }

    $id = (string) ($_POST['id'] ?? '');
    if ($id !== '' && user_load($id) === null) {
        return [null, 'Nutzer nicht gefunden.'];
    }

    if ($action === 'init' || $action === 'run') {
        $r = run_cycle($id, $action === 'init');
        return $r['fehler'] !== null
            ? [null, $r['fehler']]
            : [sprintf('%d gelesen, %d einsortiert, %d offen.',
                $r['gelesen'], $r['verschoben'], $r['offen']), null];
    }

    if ($action === 'delete') {
        @unlink(user_path($id));
        @unlink(user_path($id) . '.lock');
        return ['Nutzer entfernt.', null];
    }

    if ($action === 'save_user') {
        $domains = [];
        foreach (preg_split('/[\s,]+/', (string) ($_POST['domains'] ?? '')) ?: [] as $d) {
            $d = strtolower(trim(ltrim($d, '@')));
            if ($d !== '' && preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/', $d)) {
                $domains[] = $d;
            }
        }
        $addresses = [];
        foreach (preg_split('/[\s,]+/', (string) ($_POST['addresses'] ?? '')) ?: [] as $a) {
            $a = strtolower(trim($a));
            if ($a !== '' && filter_var($a, FILTER_VALIDATE_EMAIL)) {
                $addresses[] = $a;
            }
        }
        $mode = ($_POST['mode'] ?? 'interval') === 'times' ? 'times' : 'interval';
        $interval = max(STEP, min(10080, (int) round(((int) ($_POST['interval'] ?? 60)) / STEP) * STEP));
        $times = [];
        foreach (preg_split('/[\s,]+/', (string) ($_POST['times'] ?? '')) ?: [] as $t) {
            if (preg_match('/^([01]\d|2[0-3]):([0-5]\d)$/', trim($t), $m)
                && (int) $m[2] % STEP === 0) {
                $times[] = trim($t);
            }
        }
        if ($mode === 'times' && $times === []) {
            return [null, 'Keine gueltige Uhrzeit. Format 08:00, nur ' . STEP . '-Minuten-Schritte.'];
        }
        $relay = !empty($_POST['privateappleid']);
        $totp = !empty($_POST['totp_on']);
        user_set($id, static function (array $u) use ($domains, $addresses, $mode,
                                                      $interval, $times, $relay, $totp): array {
            $u['domains'] = array_values(array_unique($domains));
            $u['addresses'] = array_values(array_unique($addresses));
            $u['schedule'] = ['mode' => $mode, 'interval' => $interval, 'times' => $times];
            $u['privateappleid'] = !empty($u['apple']) && $relay;
            if ($totp && ($u['totp_secret'] ?? '') === '') {
                $u['totp_secret'] = b32enc(random_bytes(20));
            } elseif (!$totp) {
                $u['totp_secret'] = '';
            }
            return $u;
        });
        return ['Gespeichert.', null];
    }

    if ($action === 'save_folders') {
        $lines = preg_split('/\R/', (string) ($_POST['folders'] ?? '')) ?: [];
        $catalogue = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            [$name, $what] = array_pad(explode('|', $line, 2), 2, '');
            $name = trim($name);
            if (!folder_shape_ok($name)) {
                return [null, 'Ordnername nicht erlaubt: ' . $name];
            }
            $catalogue[$name] = trim($what);
        }
        if (!isset($catalogue['Alias'])) {
            return [null, 'Der Eintrag "Alias" muss bestehen bleiben.'];
        }
        config_set(static function (array $c) use ($catalogue): array {
            $c['folders'] = $catalogue;
            return $c;
        });
        foreach (users() as $u) {
            user_set((string) $u['id'], static function (array $x): array {
                $x['status'] = 'neu_initialisieren';
                $x['halt'] = 'Die Ordnerliste wurde geaendert.';
                return $x;
            });
        }
        return ['Ordner gespeichert. Alle Nutzer muessen neu initialisiert werden.', null];
    }

    if ($action === 'save_api') {
        $url = trim((string) ($_POST['api_url'] ?? ''));
        $key = trim((string) ($_POST['api_key'] ?? ''));
        $model = trim((string) ($_POST['model'] ?? '')) ?: DEFAULT_MODEL;
        $kind = isset(API_KINDS[(string) ($_POST['api_kind'] ?? '')])
            ? (string) $_POST['api_kind'] : api_kind();
        if ($url !== '' && !str_starts_with($url, 'https://')) {
            return [null, 'Die API-URL muss mit https:// beginnen.'];
        }
        if (!preg_match('/^[A-Za-z0-9._-]{1,60}$/', $model)) {
            return [null, 'Modellname ungueltig.'];
        }
        // Nichts speichern, was nicht antwortet - sonst steht der Betrieb.
        $row = check_key($url !== '' ? $url : api_url(), $key !== '' ? $key : api_secret(), $kind);
        if (!$row['ok']) {
            return [null, $row['detail']];
        }
        config_set(static function (array $c) use ($url, $key, $model, $kind): array {
            if ($url !== '') {
                $c['api_url'] = $url;
            }
            if ($key !== '') {
                $c['api_key'] = enc($key);
            }
            $c['api_kind'] = $kind;
            $c['model'] = $model;
            return $c;
        });
        return ['Gespeichert. Die KI antwortet.', null];
    }

    return [null, null];
}

// --- Portal fuer einzelne Nutzer ------------------------------------------

function portal(): never
{
    $error = null;
    if (empty($_SESSION['portal'])) {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            csrf_ok();
            $bucket = 'usr|' . (string) ($_SERVER['REMOTE_ADDR'] ?? '');
            if (throttled($bucket)) {
                $error = 'Zu viele Fehlversuche.';
            } else {
                $address = strtolower(trim((string) ($_POST['address'] ?? '')));
                $found = null;
                foreach (users() as $u) {
                    if (strtolower((string) $u['address']) === $address
                        && ($u['totp_secret'] ?? '') !== '') {
                        $found = $u;
                    }
                }
                $step = $found !== null ? totp_check((string) $found['totp_secret'],
                    (string) ($_POST['code'] ?? ''), (int) ($found['totp_last'] ?? 0)) : null;
                if ($found !== null && $step !== null) {
                    note_try($bucket, true);
                    session_regenerate_id(true);
                    $_SESSION['portal'] = $found['id'];
                    $_SESSION['csrf'] = new_token();
                    user_set((string) $found['id'], static function (array $u) use ($step): array {
                        $u['totp_last'] = $step;
                        return $u;
                    });
                    go('usr');
                }
                note_try($bucket, false);
                $error = 'Anmeldung fehlgeschlagen.';
            }
        }
        page_portal_login($error);
    }

    $user = user_load((string) $_SESSION['portal']);
    if ($user === null) {
        $_SESSION = [];
        session_destroy();
        go('usr');
    }
    $notice = null;
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_ok();
        if (($_POST['action'] ?? '') === 'logout') {
            $_SESSION = [];
            session_destroy();
            go('usr');
        }
        // Der Nutzer darf nur seine eigenen Adressen und den Zeitplan aendern -
        // keine andere Aktion des Adminbereichs ist hier erreichbar.
        if (($_POST['action'] ?? '') === 'save_user') {
            $_POST['id'] = $user['id'];
            $_POST['totp_on'] = '1';          // den eigenen Zugang nicht aussperren
            [$notice] = admin_action();
            $user = user_load((string) $user['id']) ?? $user;
        }
    }
    page_portal($user, $notice);
}

// ===========================================================================
// Ansicht
// ===========================================================================

function head(string $title, ?string $nonce = null): void
{
    header('Content-Type: text/html; charset=utf-8');
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        . ($nonce !== null ? "script-src 'nonce-{$nonce}'; connect-src 'self'; " : '')
        . "form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    ?><!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= e($title) ?></title>
<style>
 :root{--bg:#f5f5f7;--card:#fff;--fg:#1c1c1e;--muted:#70707a;--line:#e2e2e7;
  --accent:#0a6cff;--accent-fg:#fff;--ok:#0f7a58;--okbg:#e3f4ed;--err:#c0392b;
  --errbg:#fce7e4;--warn:#8a6100;--warnbg:#fbf1d8;--mono:#f0f0f3}
 @media(prefers-color-scheme:dark){:root{--bg:#101013;--card:#1a1a1e;--fg:#ececee;
  --muted:#9797a0;--line:#2b2b31;--accent:#4d92ff;--accent-fg:#06121f;--ok:#45c79a;
  --okbg:#123027;--err:#ff7b6b;--errbg:#361b17;--warn:#e5be5c;--warnbg:#362c13;--mono:#212127}}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);
  font:14.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
 header{background:var(--card);border-bottom:1px solid var(--line)}
 header .in{max-width:1080px;margin:0 auto;padding:0 26px;display:flex;align-items:center;
  gap:24px;height:50px}
 header b{font-size:15px}
 header a{color:var(--muted);text-decoration:none}
 header a.on{color:var(--fg)}
 header form{margin-left:auto}
 main{max-width:1080px;margin:0 auto;padding:24px 26px 60px}
 main.narrow{max-width:400px;padding-top:64px}
 h1{font-size:18px;margin:0 0 16px}
 h2{font-size:13.5px;margin:0 0 12px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.05em}
 .card{background:var(--card);border:1px solid var(--line);border-radius:10px;
  padding:18px 20px;margin-bottom:14px}
 .cols{display:grid;grid-template-columns:1fr 320px;gap:14px;align-items:start}
 @media(max-width:880px){.cols{grid-template-columns:1fr}}
 table{width:100%;border-collapse:collapse}
 th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  text-align:left;padding:0 10px 8px;font-weight:600}
 td{padding:9px 10px;border-top:1px solid var(--line)}
 tr:first-child td{border-top:0}
 a{color:var(--accent)}
 label{display:block;font-size:12.5px;font-weight:600;margin:0 0 5px}
 input,select,textarea{width:100%;padding:8px 10px;font:inherit;font-size:14px;
  color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:7px}
 textarea{min-height:60px;font-family:ui-monospace,Consolas,monospace;font-size:13px}
 input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:-1px}
 .f{margin-bottom:12px}
 .two{display:grid;grid-template-columns:1fr 90px;gap:10px}
 .hint{font-size:12px;color:var(--muted);margin-top:4px}
 button{padding:8px 14px;font:inherit;font-size:14px;font-weight:600;color:var(--accent-fg);
  background:var(--accent);border:0;border-radius:7px;cursor:pointer;white-space:nowrap}
 button:disabled{opacity:.4;cursor:default}
 button.q{background:transparent;color:var(--accent);border:1px solid var(--line)}
 button.d{background:transparent;color:var(--err);border:1px solid var(--line)}
 .msg{border-radius:7px;padding:10px 12px;font-size:13.5px;margin:0 0 14px}
 .msg.ok{background:var(--okbg);color:var(--ok)}
 .msg.err{background:var(--errbg);color:var(--err)}
 .msg.warn{background:var(--warnbg);color:var(--warn)}
 .tag{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11.5px;font-weight:600}
 .tag.ok{background:var(--okbg);color:var(--ok)}
 .tag.warn{background:var(--warnbg);color:var(--warn)}
 .tag.err{background:var(--errbg);color:var(--err)}
 code{background:var(--mono);padding:1px 5px;border-radius:5px;font-size:12.5px;word-break:break-all}
 pre{background:var(--mono);border-radius:7px;padding:11px;overflow:auto;font-size:12.5px;
  white-space:pre-wrap;word-break:break-word;margin:0}
 .muted{color:var(--muted);font-size:12.5px}
 .inline{display:inline}
 details>summary{cursor:pointer;font-size:13.5px;color:var(--accent);list-style:none}
 details>summary::-webkit-details-marker{display:none}
 details[open]>summary{margin-bottom:14px}
 ul.chk{list-style:none;margin:0;padding:0}
 ul.chk li{display:flex;gap:10px;padding:7px 0;border-top:1px solid var(--line);font-size:13.5px}
 ul.chk li:first-child{border-top:0}
 ul.chk .st{width:16px;flex:none;font-weight:700}
 ul.chk .nm{width:210px;flex:none}
 ul.chk .dt{color:var(--muted);font-size:12.5px}
 li.good .st,li.good .nm{color:var(--ok)}
 li.bad .st,li.bad .nm{color:var(--err)}
 ol.steps{display:flex;gap:8px;list-style:none;margin:0 0 22px;padding:0;font-size:12.5px}
 ol.steps li{display:flex;align-items:center;gap:7px;color:var(--muted);flex:1}
 ol.steps .n{display:inline-flex;width:21px;height:21px;border-radius:50%;flex:none;
  align-items:center;justify-content:center;font-weight:700;font-size:11.5px;
  background:var(--mono);color:var(--muted)}
 ol.steps li.on{color:var(--fg);font-weight:600}
 ol.steps li.on .n{background:var(--accent);color:var(--accent-fg)}
 ol.steps li.done .n{background:var(--okbg);color:var(--ok)}
</style></head><body>
    <?php
}

function nav(string $on): void
{
    ?>
<header><div class="in"><b>icm</b>
 <a href="?" class="<?= $on === 'users' ? 'on' : '' ?>">Nutzer</a>
 <a href="?view=system" class="<?= $on === 'system' ? 'on' : '' ?>">System</a>
 <form method="post" action="?page=logout"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
  <button class="q" type="submit">Abmelden</button></form>
</div></header><main>
    <?php
}

function msgs(?string $notice, ?string $error): void
{
    if ($notice !== null) {
        echo '<div class="msg ok">' . e($notice) . '</div>';
    }
    if ($error !== null) {
        echo '<div class="msg err">' . e($error) . '</div>';
    }
}

/**
 * Einrichtung in drei Schritten. Der Stand liegt in der Sitzung, nicht in
 * versteckten Feldern - so laesst sich kein Schritt ueberspringen.
 */
function setup_flow(): never
{
    $state = $_SESSION['setup'] ?? null;
    if (!is_array($state)) {
        $state = ['step' => 1, 'secret' => b32enc(random_bytes(20)), 'hash' => null];
        $_SESSION['setup'] = $state;
    }
    $step = (int) $state['step'];
    $error = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_ok();
        $want = (int) ($_POST['step'] ?? 0);
        if (($_POST['zurueck'] ?? '') !== '') {
            $_SESSION['setup']['step'] = max(1, $want - 1);
            go();
        }
        if ($want !== $step) {
            $error = 'Bitte die Seite neu laden.';
        } elseif ($step === 1) {
            $offen = array_filter(checks_system(),
                static fn(array $c) => $c['required'] && !$c['ok']);
            if ($offen !== []) {
                $error = 'Noch offen: ' . implode(', ', array_column($offen, 'name'));
            } else {
                $_SESSION['setup']['step'] = 2;
                go();
            }
        } elseif ($step === 2) {
            $pass = (string) ($_POST['password'] ?? '');
            if (strlen($pass) < 12) {
                $error = 'Das Passwort braucht mindestens 12 Zeichen.';
            } elseif ($pass !== (string) ($_POST['password2'] ?? '')) {
                $error = 'Die beiden Passwoerter sind nicht gleich.';
            } elseif (totp_check((string) $state['secret'], (string) ($_POST['code'] ?? '')) === null) {
                $error = 'Der Code stimmt nicht. Uhrzeit des Servers pruefen.';
            } else {
                $_SESSION['setup']['hash'] = password_hash($pass, PASSWORD_DEFAULT);
                $_SESSION['setup']['step'] = 3;
                sodium_memzero($pass);
                go();
            }
        } elseif ($step === 3) {
            $kind = isset(API_KINDS[(string) ($_POST['api_kind'] ?? '')])
                ? (string) $_POST['api_kind'] : 'messages';
            $_SESSION['setup']['kind'] = $kind;
            if (($_POST['wechsel'] ?? '') !== '') {
                go();                       // nur die Zustellart gewechselt
            }
            $url = trim((string) ($_POST['api_url'] ?? '')) ?: DEFAULT_API_URL;
            $key = trim((string) ($_POST['api_key'] ?? ''));
            $row = check_key($url, $key, $kind);
            if (!$row['ok']) {
                $error = $row['detail'];
            } elseif (!is_string($state['hash'])) {
                $error = 'Das Adminkonto fehlt. Bitte von vorn beginnen.';
                $_SESSION['setup']['step'] = 2;
            } else {
                config_set(static fn(array $c): array => [
                    'setup_done' => true,
                    'password_hash' => (string) $_SESSION['setup']['hash'],
                    'totp_secret' => (string) $_SESSION['setup']['secret'],
                    'totp_last' => 0,
                    'api_url' => $url,
                    'api_key' => enc($key),
                    'api_kind' => $kind,
                    'model' => DEFAULT_MODEL,
                    'created' => gmdate('c'),
                ]);
                unset($_SESSION['setup']);
                session_regenerate_id(true);
                go();
            }
        }
        $step = (int) $_SESSION['setup']['step'];
    }

    match ($step) {
        2 => page_setup_admin((string) $state['secret'], $error),
        3 => page_setup_ki((string) ($_SESSION['setup']['kind'] ?? 'messages'), $error),
        default => page_setup_checks($error),
    };
}

function setup_head(int $step, ?string $error): void
{
    $titel = [1 => 'Voraussetzungen', 2 => 'Adminkonto', 3 => 'KI verbinden'];
    ?>
<main class="narrow" style="max-width:600px">
  <ol class="steps">
    <?php foreach ($titel as $n => $t): ?>
      <li class="<?= $n === $step ? 'on' : ($n < $step ? 'done' : '') ?>">
        <span class="n"><?= $n < $step ? '&check;' : $n ?></span><?= e($t) ?></li>
    <?php endforeach; ?>
  </ol>
  <h1><?= e($titel[$step]) ?></h1>
  <?php msgs(null, $error);
}

function page_setup_checks(?string $error): never
{
    $nonce = base64_encode(random_bytes(16));
    head('icm einrichten', $nonce);
    setup_head(1, $error);
    ?>
  <section class="card">
    <ul class="chk" id="chk"><li><span class="st">&hellip;</span><span class="nm">wird geprueft</span></li></ul>
  </section>
  <section class="card">
    <h2>Was der Server nach aussen braucht</h2>
    <table>
      <tr><td>443/TCP</td><td class="muted">zur Claude-API</td></tr>
      <tr><td>993/TCP</td><td class="muted">zum Postfach, IMAP ueber TLS</td></tr>
      <tr><td>53</td><td class="muted">DNS</td></tr>
      <tr><td>80 und 443</td><td class="muted">eingehend, fuer diese Seite</td></tr>
    </table>
  </section>
  <form method="post">
    <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
    <input type="hidden" name="step" value="1">
    <button id="go" type="submit" disabled>Weiter</button>
    <span class="hint" id="gohint">Wartet auf die Pruefung.</span>
  </form>
<?php checklist_script($nonce, '?check=system', 'chk', 'go', 'gohint'); ?>
</main></body></html>
    <?php
    exit;
}

function page_setup_admin(string $secret, ?string $error): never
{
    head('icm einrichten');
    setup_head(2, $error);
    ?>
  <form method="post" autocomplete="off">
    <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
    <input type="hidden" name="step" value="2">
    <section class="card">
      <div class="f"><label for="p">Passwort</label>
        <input id="p" name="password" type="password" required minlength="12" autofocus>
        <div class="hint">Mindestens 12 Zeichen. Es gibt keinen Benutzernamen.</div></div>
      <div class="f"><label for="p2">Passwort wiederholen</label>
        <input id="p2" name="password2" type="password" required></div>
    </section>
    <section class="card">
      <h2>Zweiter Faktor</h2>
      <div class="f"><label>Geheimnis fuer die Authenticator-App</label>
        <pre><?= e(chunk_split($secret, 4, ' ')) ?></pre>
        <div class="hint">Jetzt eintragen und sichern. Danach wird es nicht mehr angezeigt.</div></div>
      <div class="f"><label for="c">Code aus der App</label>
        <input id="c" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required
               autocomplete="one-time-code"></div>
    </section>
    <div style="display:flex;gap:8px">
      <button class="q" type="submit" name="zurueck" value="1" formnovalidate>Zurueck</button>
      <button type="submit">Weiter</button>
    </div>
  </form>
</main></body></html>
    <?php
    exit;
}

function page_setup_ki(string $kind, ?string $error): never
{
    $nonce = base64_encode(random_bytes(16));
    head('icm einrichten', $nonce);
    setup_head(3, $error);
    $routine = $kind === 'routine';
    ?>
  <form method="post" autocomplete="off" id="kiform">
    <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
    <input type="hidden" name="step" value="3">
  <section class="card">
    <h2>1. Woher die Antwort kommt</h2>
    <div class="f"><select id="kd" name="api_kind">
      <?php foreach (API_KINDS as $k => $label): ?>
        <option value="<?= e($k) ?>" <?= $k === $kind ? 'selected' : '' ?>><?= e($label) ?></option>
      <?php endforeach; ?>
    </select></div>
  </section>
  <section class="card">
    <h2>2. Diesen Text in die KI geben</h2>
    <p class="muted" style="margin:0 0 10px"><?= $routine
        ? 'Auf claude.ai/code/routines eine Routine anlegen und den Text als Auftrag einsetzen. '
          . 'Danach gibt die Routine dir eine API-URL und ein Token.'
        : 'Der Text beschreibt, was die KI tun soll. Das Token kommt aus der Anthropic-Konsole.' ?></p>
    <pre id="auftrag"><?= e(routine_text($kind)) ?></pre>
    <div style="margin-top:10px"><button class="q" type="button" id="copy">Text kopieren</button></div>
  </section>
  <section class="card">
    <h2>3. Zugang eintragen</h2>
    <div>
      <div class="f"><label for="au">API-URL</label>
        <input id="au" name="api_url"
               value="<?= e($routine ? '' : DEFAULT_API_URL) ?>"
               placeholder="<?= e($routine ? 'https://claude.ai/api/... aus der Routine' : DEFAULT_API_URL) ?>"></div>
      <div class="f"><label for="ak">API-Token</label>
        <input id="ak" name="api_key" type="password" required autofocus>
        <div class="hint">Wird verschluesselt abgelegt und nie wieder angezeigt.</div></div>
      <ul class="chk" id="chk"><li><span class="st">&hellip;</span><span class="nm">Token eintragen</span></li></ul>
      <div style="display:flex;gap:8px;margin-top:14px">
        <button class="q" type="submit" name="zurueck" value="1" formnovalidate>Zurueck</button>
        <button id="go" type="submit" disabled>Fertig</button>
      </div>
      <div class="hint" id="gohint">Erst moeglich, wenn die KI antwortet.</div>
    </div>
  </section>
  </form>
<?php checklist_script($nonce, '?check=key', 'chk', 'go', 'gohint', true); ?>
</main></body></html>
    <?php
    exit;
}

/** Der Auftrag, den der Betreiber der KI vorlegt. Kurz und ohne Beiwerk. */
function routine_text(string $kind = 'messages', string $name = 'icm'): string
{
    $folders = '';
    foreach (folders_catalogue() as $folder => $what) {
        $folders .= "- {$folder}: {$what}\n";
    }
    $weg = $kind === 'routine' ? 'per HTTP an diese Routine' : 'ueber die Messages-API';
    return "Auftrag fuer {$name} (Postfach sortieren)\n\n"
        . "Ein Webserver schickt dir {$weg} Zeilen der Form\n"
        . "  0) absender@example.com -> empfaenger@example.com (Hauptadresse)\n"
        . "Du antwortest ausschliesslich mit JSON: {\"0\": \"Ordner\"}\n\n"
        . "Erlaubte Ordner:\n" . $folders . "\n"
        . "Regeln:\n"
        . (array_key_exists('Alias', folders_catalogue())
            ? "- (Nebenadresse) bedeutet Alias - ausser Sicherheit oder Finanzen, die gehen vor.\n"
            : '')
        . "- Finanzen nur, wo echtes Geld dahintersteht. Newsletter eines Zahlungsdienstes\n"
        . "  gehoeren nach Werbung.\n"
        . "- Unsicher? Persoenlich.\n\n"
        . "Der Server liest nur Absender und Empfaenger, nie den Inhalt einer Nachricht.\n"
        . "Gebraucht werden dafuer die API-URL und ein API-Token.\n";
}

/**
 * Holt eine Pruefliste im Sekundentakt nach und schaltet den Knopf frei.
 * Immer nur eine Anfrage zugleich, sonst stauen sich die Zeitablaeufe.
 */
function checklist_script(string $nonce, string $endpoint, string $listId,
                          string $buttonId, string $hintId, bool $withKey = false): void
{
    ?>
<script nonce="<?= e($nonce) ?>">
(function () {
  var list = document.getElementById(<?= json_encode($listId) ?>);
  var go = document.getElementById(<?= json_encode($buttonId) ?>);
  var hint = document.getElementById(<?= json_encode($hintId) ?>);
  var withKey = <?= $withKey ? 'true' : 'false' ?>;
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c];
    });
  }
  function again() { setTimeout(tick, 1000); }
  function tick() {
    var q = <?= json_encode($endpoint) ?>;
    if (withKey) {
      q += '&url=' + encodeURIComponent(document.getElementById('au').value)
         + '&key=' + encodeURIComponent(document.getElementById('ak').value);
    }
    fetch(q, {cache: 'no-store'})
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var all = true, html = '';
        (d.pruefungen || []).forEach(function (c) {
          if (c.required && !c.ok) { all = false; }
          html += '<li class="' + (c.ok ? 'good' : 'bad') + '"><span class="st">'
               + (c.ok ? '✓' : '✗') + '</span><span class="nm">' + esc(c.name)
               + '</span><span class="dt">' + esc(c.detail) + '</span></li>';
        });
        list.innerHTML = html;
        go.disabled = !all;
        hint.textContent = all ? 'Alles bereit.' : 'Wird jede Sekunde erneut geprueft.';
      })
      .catch(function () {})
      .then(again);
  }
  tick();
  var kd = document.getElementById('kd');
  if (kd) {
    kd.addEventListener('change', function () {
      var m = document.createElement('input');
      m.type = 'hidden'; m.name = 'wechsel'; m.value = '1';
      kd.form.appendChild(m);
      kd.form.submit();
    });
  }
  var copy = document.getElementById('copy');
  if (copy) {
    copy.addEventListener('click', function () {
      var t = document.getElementById('auftrag').textContent;
      if (navigator.clipboard) { navigator.clipboard.writeText(t); }
      copy.textContent = 'Kopiert';
      setTimeout(function () { copy.textContent = 'Text kopieren'; }, 1500);
    });
  }
})();
</script>
    <?php
}

function page_login(?string $error): never
{
    head('icm');
    ?>
<main class="narrow"><h1>Anmelden</h1>
  <?php msgs(null, $error); ?>
  <form method="post" class="card" autocomplete="off">
    <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
    <div class="f"><label for="p">Passwort</label>
      <input id="p" name="password" type="password" required autofocus></div>
    <div class="f"><label for="c">Code</label>
      <input id="c" name="code" inputmode="numeric" pattern="[0-9]{6}" required
             autocomplete="one-time-code"></div>
    <button type="submit">Anmelden</button>
  </form></main></body></html>
    <?php
    exit;
}

function page_users(?string $notice, ?string $error): never
{
    $list = users();
    $nonce = base64_encode(random_bytes(16));
    head('icm', $nonce);
    nav('users');
    msgs($notice, $error);
    ?>
  <section class="card">
    <table>
      <tr><th>Adresse</th><th>Anbieter</th><th>Status</th><th>Plan</th><th></th></tr>
      <?php if ($list === []): ?>
        <tr><td colspan="5" class="muted">Kein Nutzer angelegt.</td></tr>
      <?php endif; ?>
      <?php foreach ($list as $u):
          $st = (string) ($u['status'] ?? 'neu');
          [$cls, $txt] = match ($st) {
              'bereit' => ['ok', 'bereit'],
              'neu_initialisieren' => ['err', 'neu initialisieren'],
              default => ['warn', 'nicht initialisiert'],
          };
          $sch = $u['schedule'] ?? [];
          $plan = ($sch['mode'] ?? 'interval') === 'times'
              ? implode(' ', array_slice((array) ($sch['times'] ?? []), 0, 4))
              : 'alle ' . (int) ($sch['interval'] ?? 60) . ' min'; ?>
      <tr>
        <td><a href="?view=user&amp;id=<?= e($u['id']) ?>"><?= e($u['address']) ?></a>
          <?php if (!empty($u['last_error'])): ?>
            <div class="muted"><?= e(mb_substr((string) $u['last_error'], 0, 100)) ?></div>
          <?php endif; ?></td>
        <td class="muted"><?= e(PROVIDERS[$u['provider']]['name'] ?? '') ?></td>
        <td><span class="tag <?= $cls ?>"><?= e($txt) ?></span></td>
        <td class="muted"><?= e($plan) ?></td>
        <td style="text-align:right">
          <form method="post" class="inline">
            <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
            <input type="hidden" name="id" value="<?= e($u['id']) ?>">
            <input type="hidden" name="action" value="<?= $st === 'bereit' ? 'run' : 'init' ?>">
            <button type="submit"><?= $st === 'bereit' ? 'Sortieren' : 'Initialisieren' ?></button>
          </form></td>
      </tr>
      <?php endforeach; ?>
    </table>
  </section>

  <section class="card">
    <details>
      <summary>Nutzer hinzufuegen</summary>
      <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
        <input type="hidden" name="action" value="add">
        <div class="cols">
          <div>
            <div class="f"><label for="ad">E-Mail</label>
              <input id="ad" name="address" type="email" required></div>
            <div class="f"><label for="pw">Anwendungspasswort</label>
              <input id="pw" name="password" type="password" required></div>
          </div>
          <div>
            <div class="f"><label for="pv">Anbieter</label>
              <select id="pv" name="provider">
                <?php foreach (PROVIDERS as $k => $p): ?>
                  <option value="<?= e($k) ?>"><?= e($p['name']) ?></option>
                <?php endforeach; ?>
              </select></div>
            <div id="own" style="display:none">
              <div class="f two">
                <div><label for="ho">IMAP-Server</label><input id="ho" name="host"></div>
                <div><label for="po">Port</label>
                  <input id="po" name="port" type="number" value="993"></div>
              </div>
            </div>
          </div>
        </div>
        <button type="submit">Anlegen</button>
      </form>
    </details>
  </section>
</main>
<script nonce="<?= e($nonce) ?>">
(function () {
  var sel = document.getElementById('pv'), own = document.getElementById('own');
  if (!sel) { return; }
  function sync() { own.style.display = sel.value === 'other' ? 'block' : 'none'; }
  sel.addEventListener('change', sync); sync();
})();
</script></body></html>
    <?php
    exit;
}

function stamp(?string $iso): string
{
    $t = $iso !== null && $iso !== '' ? strtotime($iso) : false;
    return $t === false ? '-' : date('d.m.Y H:i', $t);
}

/** Blendet Uhrzeiten oder Minuten aus, je nach gewaehltem Zeitplan. */
function schedule_script(string $nonce): void
{
    ?>
<script nonce="<?= e($nonce) ?>">
(function () {
  var sel = document.getElementById('md');
  var t = document.getElementById('bt'), i = document.getElementById('bi');
  if (!sel) { return; }
  function sync() {
    var times = sel.value === 'times';
    t.style.display = times ? 'block' : 'none';
    i.style.display = times ? 'none' : 'block';
  }
  sel.addEventListener('change', sync); sync();
})();
</script>
    <?php
}

function page_user(array $u, ?string $notice, ?string $error): never
{
    $nonce = base64_encode(random_bytes(16));
    head('icm - ' . (string) $u['address'], $nonce);
    nav('users');
    msgs($notice, $error);
    $st = (string) ($u['status'] ?? 'neu');
    $sch = $u['schedule'] ?? ['mode' => 'interval', 'interval' => 60, 'times' => []];
    ?>
  <h1><?= e($u['address']) ?></h1>
  <?php if ($st === 'neu'): ?>
    <div class="msg warn">Noch nicht initialisiert.</div>
  <?php elseif ($st === 'neu_initialisieren'): ?>
    <div class="msg err"><?= e((string) ($u['halt'] ?? 'Angehalten.')) ?></div>
  <?php endif; ?>
  <div class="cols">
    <section class="card">
      <form method="post">
        <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
        <input type="hidden" name="id" value="<?= e($u['id']) ?>">
        <input type="hidden" name="action" value="save_user">
        <div class="f"><label for="dm">Eigene Domains</label>
          <textarea id="dm" name="domains"><?= e(implode("\n", (array) ($u['domains'] ?? []))) ?></textarea></div>
        <div class="f"><label for="ax">Weitere Adressen</label>
          <textarea id="ax" name="addresses"><?= e(implode("\n", (array) ($u['addresses'] ?? []))) ?></textarea></div>
        <?php if (!empty($u['apple'])): ?>
          <div class="f"><label style="font-weight:400;display:flex;gap:8px;align-items:center">
            <input type="checkbox" name="privateappleid" style="width:auto"
                   <?= !empty($u['privateappleid']) ? 'checked' : '' ?>> Private Apple ID</label></div>
        <?php endif; ?>
        <div class="f"><label for="md">Zeitplan</label>
          <select id="md" name="mode">
            <option value="interval" <?= ($sch['mode'] ?? '') !== 'times' ? 'selected' : '' ?>>Intervall</option>
            <option value="times" <?= ($sch['mode'] ?? '') === 'times' ? 'selected' : '' ?>>Uhrzeiten</option>
          </select></div>
        <div class="f" id="bt"><label for="tm">Uhrzeiten</label>
          <input id="tm" name="times" placeholder="08:00 20:00"
                 value="<?= e(implode(' ', (array) ($sch['times'] ?? []))) ?>">
          <div class="hint">Mehrere durch Leerzeichen, nur <?= STEP ?>-Minuten-Schritte.</div></div>
        <div class="f" id="bi"><label for="iv">Alle wie viele Minuten</label>
          <input id="iv" name="interval" type="number" min="<?= STEP ?>" step="<?= STEP ?>"
                 value="<?= (int) ($sch['interval'] ?? 60) ?>"></div>
        <div class="f"><label style="font-weight:400;display:flex;gap:8px;align-items:center">
          <input type="checkbox" name="totp_on" style="width:auto"
                 <?= ($u['totp_secret'] ?? '') !== '' ? 'checked' : '' ?>> Eigener Zugang unter <code>?usr</code></label>
          <?php if (($u['totp_secret'] ?? '') !== ''): ?>
            <pre style="margin-top:8px"><?= e((string) $u['totp_secret']) ?></pre>
          <?php endif; ?></div>
        <button type="submit">Speichern</button>
      </form>
    </section>
    <div>
      <section class="card">
        <table>
          <tr><td>Server</td><td class="muted"><?= e($u['host'] . ':' . $u['port']) ?></td></tr>
          <tr><td>Letzter Lauf</td><td class="muted"><?= e(stamp($u['last_run'] ?? null)) ?></td></tr>
          <tr><td>Bekannte Absender</td><td class="muted"><?= array_sum(array_map('count', (array) ($u['knowledge'] ?? []))) ?></td></tr>
          <tr><td>Ordner</td><td class="muted"><?= count($u['known_folders'] ?? []) ?></td></tr>
        </table>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
          <form method="post" class="inline"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
            <input type="hidden" name="id" value="<?= e($u['id']) ?>">
            <input type="hidden" name="action" value="run">
            <button <?= $st === 'bereit' ? '' : 'class="q"' ?> type="submit">Sortieren</button></form>
          <form method="post" class="inline"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
            <input type="hidden" name="id" value="<?= e($u['id']) ?>">
            <input type="hidden" name="action" value="init">
            <button <?= $st === 'bereit' ? 'class="d"' : '' ?> type="submit">
              <?= $st === 'bereit' ? 'Neu initialisieren' : 'Initialisieren' ?></button></form>
          <form method="post" class="inline" style="margin-left:auto">
            <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
            <input type="hidden" name="id" value="<?= e($u['id']) ?>">
            <input type="hidden" name="action" value="delete"><button class="d" type="submit">Entfernen</button></form>
        </div>
        <?php if ($st === 'bereit'): ?>
          <div class="hint" style="margin-top:8px">Neu initialisieren raeumt alle Ordner in den
            Posteingang, loescht sie und sortiert von vorne.</div>
        <?php endif; ?>
      </section>
    </div>
  </div>
<?php schedule_script($nonce); ?>
</main></body></html>
    <?php
    exit;
}

function page_system(?string $notice, ?string $error): never
{
    $config = config();
    $text = '';
    foreach (folders_catalogue() as $name => $what) {
        $text .= $name . ' | ' . $what . "\n";
    }
    head('icm - System');
    nav('system');
    msgs($notice, $error);
    ?>
  <div class="cols">
    <section class="card">
      <h2>Ordner</h2>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
        <input type="hidden" name="action" value="save_folders">
        <div class="f"><textarea name="folders" style="min-height:280px"><?= e($text) ?></textarea>
          <div class="hint">Eine Zeile je Ordner: <code>Name | Beschreibung</code>.
            <code>Alias</code> muss bleiben. Nach dem Speichern muessen alle Nutzer neu
            initialisiert werden.</div></div>
        <button type="submit">Speichern</button>
      </form>
    </section>
    <div>
      <section class="card">
        <h2>Claude</h2>
        <form method="post">
          <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
          <input type="hidden" name="action" value="save_api">
          <div class="f"><label for="kd">Zustellart</label>
            <select id="kd" name="api_kind">
              <?php foreach (API_KINDS as $k => $label): ?>
                <option value="<?= e($k) ?>" <?= $k === api_kind() ? 'selected' : '' ?>><?= e($label) ?></option>
              <?php endforeach; ?>
            </select></div>
          <div class="f"><label for="au">API-URL</label>
            <input id="au" name="api_url" value="<?= e($config['api_url'] ?? DEFAULT_API_URL) ?>"></div>
          <div class="f"><label for="ak">API-Token</label>
            <input id="ak" name="api_key" type="password" placeholder="gespeichert"></div>
          <div class="f"><label for="mo">Modell</label>
            <input id="mo" name="model" value="<?= e($config['model'] ?? DEFAULT_MODEL) ?>"></div>
          <button type="submit">Speichern</button>
        </form>
      </section>
      <section class="card">
        <h2>Cron</h2>
        <pre>*/<?= STEP ?> * * * * php <?= e(__FILE__) ?> cron</pre>
      </section>
    </div>
  </div>
</main></body></html>
    <?php
    exit;
}

function page_portal_login(?string $error): never
{
    head('icm');
    ?>
<main class="narrow"><h1>Anmelden</h1>
  <?php msgs(null, $error); ?>
  <form method="post" class="card" autocomplete="off">
    <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
    <div class="f"><label for="a">E-Mail</label><input id="a" name="address" type="email" required></div>
    <div class="f"><label for="c">Code</label>
      <input id="c" name="code" inputmode="numeric" pattern="[0-9]{6}" required
             autocomplete="one-time-code"></div>
    <button type="submit">Anmelden</button>
  </form></main></body></html>
    <?php
    exit;
}

function page_portal(array $u, ?string $notice): never
{
    $sch = $u['schedule'] ?? ['mode' => 'interval', 'interval' => 60, 'times' => []];
    $nonce = base64_encode(random_bytes(16));
    head('icm', $nonce);
    ?>
<header><div class="in"><b>icm</b><span class="muted"><?= e($u['address']) ?></span>
 <form method="post"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
  <input type="hidden" name="action" value="logout">
  <button class="q" type="submit">Abmelden</button></form>
</div></header><main class="narrow" style="max-width:520px">
  <?php msgs($notice, null); ?>
  <section class="card">
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="hidden" name="action" value="save_user">
      <div class="f"><label for="dm">Eigene Domains</label>
        <textarea id="dm" name="domains"><?= e(implode("\n", (array) ($u['domains'] ?? []))) ?></textarea></div>
      <div class="f"><label for="ax">Weitere Adressen</label>
        <textarea id="ax" name="addresses"><?= e(implode("\n", (array) ($u['addresses'] ?? []))) ?></textarea></div>
      <?php if (!empty($u['apple'])): ?>
        <div class="f"><label style="font-weight:400;display:flex;gap:8px;align-items:center">
          <input type="checkbox" name="privateappleid" style="width:auto"
                 <?= !empty($u['privateappleid']) ? 'checked' : '' ?>> Private Apple ID</label></div>
      <?php endif; ?>
      <input type="hidden" name="totp_on" value="1">
      <div class="f"><label for="md">Zeitplan</label>
        <select id="md" name="mode">
          <option value="interval" <?= ($sch['mode'] ?? '') !== 'times' ? 'selected' : '' ?>>Intervall</option>
          <option value="times" <?= ($sch['mode'] ?? '') === 'times' ? 'selected' : '' ?>>Uhrzeiten</option>
        </select></div>
      <div class="f two">
        <div><label for="tm">Uhrzeiten</label>
          <input id="tm" name="times" placeholder="08:00 20:00"
                 value="<?= e(implode(' ', (array) ($sch['times'] ?? []))) ?>"></div>
        <div><label for="iv">Minuten</label>
          <input id="iv" name="interval" type="number" min="5" step="5"
                 value="<?= (int) ($sch['interval'] ?? 60) ?>"></div>
      </div>
      <button type="submit">Speichern</button>
    </form>
  </section>
<?php schedule_script($nonce); ?>
</main></body></html>
    <?php
    exit;
}
