<?php

declare(strict_types=1);

const VERSION = '3.0';
const SA_INTERVAL = 15;        // Minuten zwischen zwei Durchlaeufen
const SA_MAX_KONTEN = 50;
const SA_HOST = 'imap.mail.me.com';
const SA_PORT = 993;

const LOGIN_MAX = 5;

const LOGIN_LOCK = 900;

const MAX_BODY = 8388608;

const BATCH = 200;

const STEP = 5;                       // kleinste Zeiteinheit in Minuten

const RELAY_DOMAIN = 'privaterelay.appleid.com';

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
];

const SYSTEM_FOLDERS = ['inbox', 'sent', 'sent messages', 'drafts', 'deleted messages',
    'trash', 'junk', 'archive', 'notes', 'outbox', '[gmail]'];

function data_dir(): string
{
    $env = getenv('SA_DATA_DIR');
    return is_string($env) && $env !== '' ? rtrim($env, '/') : __DIR__ . '/simple-apple-data';
}

/**
 * Liegt die Ablage im Web-Wurzelverzeichnis, sind Schluessel und Passwoerter
 * ueber das Netz abrufbar. Eine .htaccess hilft nur unter Apache. Deshalb
 * wird hier lieber gar nicht erst gestartet.
 */
function data_dir_pruefen(): void
{
    if (getenv('SA_ALLOW_WEBROOT_DATA') === '1') {
        return;
    }
    $root = realpath((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''));
    $dir = realpath(data_dir());
    if ($root === false || $dir === false || $root === '' || $root === '/') {
        return;
    }
    if ($dir === $root || str_starts_with($dir, rtrim($root, '/') . '/')) {
        bail('Die Ablage ' . $dir . ' liegt im Web-Wurzelverzeichnis und waere '
            . 'ueber das Netz abrufbar - dort stehen der Schluessel und die '
            . 'verschluesselten Passwoerter. Bitte SA_DATA_DIR auf einen Pfad '
            . 'ausserhalb des Wurzelverzeichnisses setzen. Wer den Ordner im '
            . 'Webserver sicher gesperrt hat, kann diese Pruefung mit der '
            . 'Umgebungsvariable SA_ALLOW_WEBROOT_DATA=1 abschalten.');
    }
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
    $lock = @fopen($path . '.lock', 'c');
    if ($lock === false) {
        bail('Sperrdatei nicht schreibbar: ' . $path . '.lock');
    }
    @chmod($path . '.lock', 0600);
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
    unset($out['Alias']);   // hier gibt es keine Nebenadressen
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

function key_bytes(): string
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $path = data_dir() . '/key.bin';
    if (!is_file($path)) {
        // Exklusiv anlegen: zwei gleichzeitige Anfragen duerfen sich den
        // Schluessel nicht gegenseitig ueberschreiben - sonst waeren alle
        // bereits verschluesselten Passwoerter verloren.
        $h = @fopen($path, 'x');
        if ($h !== false) {
            @chmod($path, 0600);
            fwrite($h, random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
            fclose($h);
        }
    }
    $key = (string) @file_get_contents($path);
    if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
        bail('Der Schluessel in ' . $path . ' fehlt oder ist beschaedigt.');
    }
    return $cache = $key;
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

final class ImapError extends RuntimeException {}

final class Imap
{
    /**
     * Abschliessende Liste. Was hier fehlt, wird nie gesendet.
     * Es gibt bewusst kein Kommando, das Nachrichteninhalte liest, und keines,
     * das Nachrichten loescht: kein STORE (\Deleted), kein EXPUNGE. Einsortiert
     * wird mit MOVE oder - wo der Server kein MOVE kann - mit COPY. DELETE
     * betrifft nur Ordner, und nur leere.
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
        '/^UID COPY [0-9,:]+ /',
    ];
    private const FETCH = '(BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC)])';

    /** @var resource */
    private $sock;
    private int $tag = 0;
    private array $caps = [];
    private bool $canMove = false;
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
            if ($need > MAX_BODY) {
                throw new ImapError('Serverantwort zu gross.');
            }
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
        // Steuerzeichen wuerden eine zweite Befehlszeile einschleusen koennen.
        if (preg_match('/[\r\n\x00]/', $v) === 1) {
            throw new ImapError('Steuerzeichen im IMAP-Argument.');
        }
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
        // MOVE ist eine optionale IMAP-Erweiterung. iCloud bietet sie nicht an.
        // Fehlt sie, wird kopiert statt verschoben - die Anmeldung wird deshalb
        // nicht mehr abgelehnt.
        $this->canMove = in_array('MOVE', $this->caps, true);
    }

    public function can_move(): bool
    {
        return $this->canMove;
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
        // Ohne ausdrueckliches OK darf das Ergebnis nie als "leer" gelten -
        // sonst haelt der Aufrufer einen vollen Ordner fuer leer.
        if ($status !== 'OK') {
            throw new ImapError('Suche im Ordner fehlgeschlagen: ' . $folder);
        }
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
            // Nicht ueberspringen: sonst gelten bis zu BATCH Nachrichten als
            // nicht vorhanden und die Marke zieht an ihnen vorbei.
            if ($status !== 'OK') {
                throw new ImapError('Kopfzeilen nicht lesbar.');
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

    /**
     * Sortiert Nachrichten in einen Ordner. Mit MOVE, wo der Server es anbietet;
     * sonst mit COPY - dann liegt die Nachricht im Zielordner und das Original
     * bleibt im Quellordner stehen. Es wird dabei nie eine Nachricht geloescht.
     * @param list<string> $uids
     */
    public function move(array $uids, string $target): int
    {
        foreach ($uids as $uid) {
            if (!ctype_digit($uid)) {
                throw new ImapError('UID muss eine Zahl sein.');
            }
        }
        $verb = $this->canMove ? 'MOVE' : 'COPY';
        $done = 0;
        foreach (array_chunk($uids, BATCH) as $chunk) {
            [$status] = $this->send('UID ' . $verb . ' ' . implode(',', $chunk)
                . ' ' . self::q(mutf7_encode($target)));
            if ($status !== 'OK') {
                throw new ImapError('Einsortieren nach ' . $target . ' fehlgeschlagen.');
            }
            $done += count($chunk);
        }
        return $done;
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
    if ($want === '' || !hash_equals($want, post_str('csrf'))) {
        http_response_code(400);
        exit('CSRF-Token stimmt nicht. Seite neu laden.');
    }
}

/** Weiterleitung auf diese Datei, notfalls mit Abfrage. Nie relativ. */

/** Weiterleitung auf diese Datei, notfalls mit Abfrage. Nie relativ. */
function go(string $query = ''): never
{
    $path = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/');
    header('Location: ' . $path . ($query !== '' ? '?' . $query : ''));
    exit;
}

function e(mixed $v): string
{
    // Ein Feld wie address[]=x kaeme sonst als Array an und wuerde unter
    // strict_types eine Ausnahme werfen, mitten in der Ausgabe.
    return htmlspecialchars(is_scalar($v) ? (string) $v : '', ENT_QUOTES, 'UTF-8');
}

/** Ein POST-Feld als Zeichenkette. Arrays und Objekte gelten als leer. */
function post_str(string $name): string
{
    $v = $_POST[$name] ?? '';
    return is_scalar($v) ? (string) $v : '';
}

/** Einfache Mengenbegrenzung je Absender und Zeitfenster. */

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

function stamp(?string $iso): string
{
    $t = $iso !== null && $iso !== '' ? strtotime($iso) : false;
    return $t === false ? '-' : date('d.m.Y H:i', $t);
}

/** Blendet Uhrzeiten oder Minuten aus, je nach gewaehltem Zeitplan. */


// ===========================================================================
// Routine ansprechen
//
// Der Aufruf von .../fire startet nur eine Sitzung - die Antwort der KI steht
// nicht in der HTTP-Antwort. Deshalb laeuft es andersherum: der Server legt die
// Fragen bereit, die Routine holt sie ab und schickt die Zuordnung zurueck.
// ===========================================================================

const FIRE_BETA = 'experimental-cc-routine-2026-04-01';
const JOB_FRIST = 1800;        // Sekunden, bis eine Anfrage als verloren gilt
const JOB_MAX = 200;           // Zeilen je Anfrage - der Rest kommt beim naechsten Lauf

/** @return array{0:?string,1:?string} [Sitzungsadresse, Fehler] */
function sa_fire(string $url, string $key, string $text): array
{
    if (!preg_match('#^https://[a-z0-9.-]+/v1/claude_code/routines/[A-Za-z0-9_-]+/fire$#', $url)) {
        return [null, 'Die URL muss so aussehen: https://api.anthropic.com/v1/claude_code/'
            . 'routines/trig_.../fire'];
    }
    if ($key === '') {
        return [null, 'Das Token fehlt.'];
    }
    [$code, $raw, $error] = https_post($url,
        json_encode(['text' => $text], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ['content-type: application/json',
         'authorization: Bearer ' . $key,
         'anthropic-beta: ' . FIRE_BETA,
         'anthropic-version: 2023-06-01']);
    if ($error !== null) {
        return [null, 'Keine Verbindung: ' . $error];
    }
    $body = json_decode((string) $raw, true);
    if ($code === 401 || $code === 403) {
        return [null, 'Das Token wurde abgelehnt (' . $code . ').'];
    }
    if ($code < 200 || $code >= 300) {
        return [null, 'Die Routine antwortet mit HTTP ' . $code . '. '
            . trim((string) ($body['error']['message'] ?? ($body['message'] ?? '')))];
    }
    $sitzung = (string) ($body['claude_code_session_url'] ?? '');
    if ($sitzung === '' && ($body['claude_code_session_id'] ?? '') === '') {
        return [null, 'Unerwartete Antwort. Ist das wirklich eine Routine-URL?'];
    }
    return [$sitzung, null];
}

/** Adresse, unter der die Routine diesen Server erreicht. */
function sa_rueckweg(): string
{
    $fest = (string) (config()['rueckweg'] ?? '');
    if ($fest !== '') {
        return $fest;
    }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
    $pfad = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/');
    return ($https ? 'https://' : 'http://') . $host . $pfad;
}

/** Der Text, den die Routine als Auftrag gespeichert bekommt. */
function sa_auftrag(): string
{
    return "Auftrag: Postfach sortieren\n\n"
        . "Im <routine-fire-payload>-Block stehen eine URL und ein Token.\n"
        . "Fuehre genau diese Schritte aus, sonst nichts:\n\n"
        . "1. GET auf <URL>?auftrag=<TOKEN>\n"
        . "   Antwort ist JSON mit \"ordner\" (erlaubte Ordner mit Beschreibung),\n"
        . "   \"regeln\" (Text) und \"zeilen\" (je Nummer, von, an, art).\n"
        . "2. Ordne jede Zeile genau einem Ordner aus \"ordner\" zu.\n"
        . "   Halte dich dabei an \"regeln\".\n"
        . "3. POST auf dieselbe URL, Rumpf ausschliesslich die Zuordnung als JSON:\n"
        . "   {\"0\": \"Ordner\", \"1\": \"Ordner\", ...}\n"
        . "4. Schreibe zum Schluss eine Zeile, wie viele Zuordnungen du geschickt hast.\n\n"
        . "Du bekommst nur Absender und Empfaenger, keine Mailinhalte.\n"
        . "Ist \"zeilen\" leer, melde das und beende.\n";
}

/** Die Regeln, die mit den Fragen mitgehen. */
function sa_regeln(): string
{
    return "Finanzen nur, wo tatsaechlich Geld dahintersteht. Newsletter und Werbung "
        . "eines Zahlungsdienstes gehoeren nach Werbung. Sicherheit ist alles rund um "
        . "Anmeldung, Zwei-Faktor und Kontowarnungen. Unsicher? Persoenlich.";
}

// ===========================================================================
// Konten
// ===========================================================================

function sa_find(string $address): ?array
{
    foreach (users() as $u) {
        if (strcasecmp((string) $u['address'], $address) === 0) {
            return $u;
        }
    }
    return null;
}

/**
 * Konto anlegen oder das Passwort auffrischen. Geprueft wird immer am Server.
 * @return array{0:?array,1:?string} [Konto, Fehler]
 */
function sa_konto(string $address, string $password): array
{
    $address = strtolower(trim($address));
    if (!filter_var($address, FILTER_VALIDATE_EMAIL)) {
        return [null, 'Das ist keine gueltige E-Mail-Adresse.'];
    }
    if ($password === '') {
        return [null, 'Das app-spezifische Passwort fehlt.'];
    }
    try {
        (new Imap(SA_HOST, SA_PORT))->login($address, $password);
    } catch (ImapError $e) {
        return [null, $e->getMessage()];
    }
    $neu = enc($password);
    sodium_memzero($password);
    $u = sa_find($address);
    if ($u !== null) {
        return [user_set((string) $u['id'], static function (array $x) use ($neu): array {
            $x['password'] = $neu;
            return $x;
        }), null];
    }
    if (count(users()) >= SA_MAX_KONTEN) {
        return [null, 'Es sind keine Plaetze mehr frei.'];
    }
    $id = bin2hex(random_bytes(8));
    jwrite(user_path($id), [
        'id' => $id, 'address' => $address, 'password' => $neu,
        'host' => SA_HOST, 'port' => SA_PORT,
        // Ohne Nebenadressen: leer, damit jede Mail als Hauptadresse gilt.
        'privateappleid' => false, 'domains' => [], 'addresses' => [],
        'knowledge' => [], 'known_folders' => [], 'job' => null,
        'schedule' => ['mode' => 'interval', 'interval' => SA_INTERVAL, 'times' => []],
        'status' => 'neu', 'created' => gmdate('c'),
    ]);
    return [user_load($id), null];
}

// ===========================================================================
// Ablauf in zwei Schritten: erst fragen, dann sortieren
// ===========================================================================

/**
 * Der Ordner, in den Post dieses Absenders gehoert - oder null, wenn es keine
 * brauchbare Zuordnung gibt.
 */
function ziel_ordner(array $user, string $kind, string $from, ?string $aliasPfad): ?string
{
    $wohin = $user['knowledge'][$kind][$from] ?? null;
    if (!is_string($wohin)) {
        return null;
    }
    $ordner = resolve_answer($wohin, $aliasPfad);
    return $ordner !== null && folder_shape_ok($ordner) ? $ordner : null;
}

/**
 * Liegt zu diesem Absender eine Antwort vor, die der Katalog noch kennt?
 * Genau diese Pruefung entscheidet, ob gefragt wird - und nur nach ihr zaehlt
 * das Sortieren eine Nachricht als offen. Beide Seiten muessen dasselbe sagen,
 * sonst wartet der eine auf eine Antwort, die der andere nie erfragt.
 */
function antwort_brauchbar(array $user, string $kind, string $from): bool
{
    $wohin = $user['knowledge'][$kind][$from] ?? null;
    return is_string($wohin)
        && array_key_exists($wohin, folders_catalogue())
        && !($wohin === 'Alias' && $kind !== 'alias');
}

/**
 * Welche Nachrichten sieht sich ein Lauf an? Alles ab der Marke - und dazu
 * die, die beim letzten Mal noch auf eine Antwort gewartet haben. So haelt
 * eine einzelne unzuordenbare Nachricht nie den Fortschritt auf.
 * @param list<string> $uids
 * @return list<string>
 */
function zu_pruefen(array $uids, array $user, string $uidvalidity, bool $initial): array
{
    if ($initial || (string) ($user['uidvalidity'] ?? '') !== $uidvalidity) {
        return $uids;
    }
    $marke = (int) ($user['last_uid'] ?? 0);
    $warten = array_flip(array_map('strval', (array) ($user['offene_uids'] ?? [])));
    return array_values(array_filter($uids,
        static fn($u) => (int) $u > $marke || isset($warten[(string) $u])));
}

/** Alle Ordner ausser Systemordnern - plus Archiv, dessen Post mitsortiert wird. */
function sa_eigene(array $folders): array
{
    $out = [];
    foreach ($folders as $f) {
        if (strtoupper($f['name']) === 'INBOX') {
            continue;
        }
        if (!$f['system'] || strcasecmp($f['name'], 'Archive') === 0) {
            $out[] = $f;
        }
    }
    // Tiefste Ebene zuerst, sonst haengt ein Elternordner an seinen Kindern.
    usort($out, static fn(array $a, array $b) =>
        substr_count($b['name'], '/') <=> substr_count($a['name'], '/'));
    return $out;
}

/**
 * Liest nur mit: welche Absender sind noch unbekannt?
 * @return array{0:array<string,array>,1:?string} [offene Fragen, Fehler]
 */
function sa_fragen_sammeln(array $user, bool $initial): array
{
    try {
        $imap = new Imap((string) $user['host'], (int) $user['port']);
        $imap->login((string) $user['address'], dec((string) $user['password']));
        $quellen = [['name' => 'INBOX', 'system' => false]];
        // Ohne MOVE wird beim Aufraeumen nichts aus anderen Ordnern geholt -
        // dann muessen deren Absender auch nicht gefragt werden.
        if ($initial && $imap->can_move()) {
            foreach (sa_eigene($imap->folders()) as $f) {
                $quellen[] = $f;
            }
        }
        $offen = [];
        foreach ($quellen as $f) {
            $uids = $imap->open($f['name'], false);
            if ($f['name'] === 'INBOX') {
                $uids = zu_pruefen($uids, $user, $imap->uidvalidity, $initial);
            }
            foreach ($imap->headers($uids) as $m) {
                $from = (string) ($m['from'] ?? '');
                if ($from === '') {
                    continue;
                }
                $pfad = alias_of($m['to'], $user);
                $kind = $pfad === null ? 'primary' : 'alias';
                if (antwort_brauchbar($user, $kind, $from)) {
                    continue;
                }
                $offen[$kind . '|' . $from] ??= ['from' => $from,
                    'to' => (string) $user['address'],
                    'art' => 'Hauptadresse', 'kind' => $kind];
            }
        }
        return [$offen, null];
    } catch (ImapError $e) {
        return [[], $e->getMessage()];
    }
}

/**
 * Raeumt auf (nur beim ersten Mal) und sortiert, was zugeordnet ist.
 * @return array{gelesen:int,verschoben:int,offen:int,fehler:?string}
 */
function sa_sortieren(string $id, bool $initial): array
{
    $r = ['gelesen' => 0, 'verschoben' => 0, 'offen' => 0, 'fehler' => null];
    $user = user_load($id);
    if ($user === null) {
        $r['fehler'] = 'Konto nicht gefunden.';
        return $r;
    }
    try {
        $imap = new Imap((string) $user['host'], (int) $user['port']);
        $imap->login((string) $user['address'], dec((string) $user['password']));

        if ($initial) {
            // Mit MOVE: alles in den Posteingang holen und die dann leeren
            // eigenen Ordner loeschen. Systemordner bleiben stehen, nur das
            // Archiv wird geleert - Gesendet, Entwuerfe, Werbung und Papierkorb
            // bleiben unberuehrt.
            // Ohne MOVE (z. B. iCloud): es wird nichts aus Ordnern geholt und
            // nichts geloescht. Ein COPY nach INBOX wuerde nur Kopien erzeugen,
            // ein DELETE auf einen noch vollen Ordner koennte Post kosten. Die
            // bestehenden Ordner bleiben, sortiert wird allein der Posteingang.
            if ($imap->can_move()) {
                foreach (sa_eigene($imap->folders()) as $f) {
                    $uids = $imap->open($f['name'], true);
                    if ($uids !== []) {
                        $imap->move($uids, 'INBOX');
                    }
                    // Vor dem Loeschen noch einmal nachsehen. Geloescht wird
                    // nur, was nachweislich leer ist.
                    if (!$f['system'] && $imap->open($f['name'], true) === []) {
                        $imap->delete_folder($f['name']);
                    }
                }
            }
            $geraeumt = $imap->can_move();
            user_set($id, static function (array $u) use ($geraeumt): array {
                $u['known_folders'] = [];
                // Die Marke darf nur zurueck, wenn der Posteingang wirklich neu
                // gefuellt wurde. Sonst kopierte ein zweites Einrichten den
                // ganzen Posteingang ein weiteres Mal in die Ordner.
                if ($geraeumt) {
                    $u['last_uid'] = 0;
                    $u['offene_uids'] = [];
                }
                return $u;
            });
            $user = user_load($id) ?? $user;
        } else {
            $have = array_column($imap->folders(), 'name');
            $fehlend = array_values(array_diff($user['known_folders'] ?? [], $have));
            if ($fehlend !== []) {
                user_set($id, static function (array $u) use ($fehlend): array {
                    $u['status'] = 'neu';
                    $u['halt'] = 'Diese Ordner fehlen: ' . implode(', ', array_slice($fehlend, 0, 6));
                    return $u;
                });
                $r['fehler'] = 'Ordner wurden umbenannt oder geloescht. Es wird neu aufgeraeumt.';
                return $r;
            }
        }

        $uids = $imap->open('INBOX', true);
        $hoch = 0;
        foreach ($uids as $u) {
            $hoch = max($hoch, (int) $u);
        }
        // Nur die noetigen Kopfzeilen holen, nicht das ganze Postfach.
        $neu = $imap->headers(zu_pruefen($uids, $user, $imap->uidvalidity, $initial));
        $r['gelesen'] = count($neu);

        $moves = [];
        $offeneUids = [];
        foreach ($neu as $m) {
            $from = (string) ($m['from'] ?? '');
            $pfad = alias_of($m['to'], $user);
            $kind = $pfad === null ? 'primary' : 'alias';
            $ordner = $from === '' ? null : ziel_ordner($user, $kind, $from, $pfad);
            if ($ordner !== null) {
                $moves[$ordner][] = $m['uid'];
            } elseif ($from !== '' && !antwort_brauchbar($user, $kind, $from)) {
                // Wartet noch auf eine Antwort - beim naechsten Lauf gezielt
                // wieder ansehen.
                $offeneUids[] = (string) $m['uid'];
            }
            // Sonst: nicht zuzuordnen (kein lesbarer Absender oder die Antwort
            // ergibt keinen gueltigen Ordnernamen). Die Nachricht bleibt
            // einfach liegen und haelt niemanden auf.
        }
        $r['offen'] = count($offeneUids);

        $have = array_column($imap->folders(), 'name');
        $benutzt = [];
        foreach ($moves as $ordner => $liste) {
            if (!in_array($ordner, $have, true)) {
                $teile = explode('/', $ordner);
                for ($i = 1; $i <= count($teile); $i++) {
                    $imap->create(implode('/', array_slice($teile, 0, $i)));
                }
            }
            $imap->open('INBOX', true);
            $r['verschoben'] += $imap->move($liste, $ordner);
            $benutzt[] = $ordner;
        }

        // Die Marke rueckt immer vor. Ohne MOVE bleibt das Original im
        // Posteingang liegen - stuende die Marke still, wuerde jeder weitere
        // Lauf dieselbe Post noch einmal kopieren. Was offen blieb, steht in
        // offene_uids und wird gezielt wieder angesehen.
        $frisch = (string) ($user['uidvalidity'] ?? '') !== $imap->uidvalidity;
        $uidvalidity = $imap->uidvalidity;
        $offeneUids = array_slice($offeneUids, 0, 2000);
        user_set($id, static function (array $u) use ($hoch, $uidvalidity, $frisch,
                                                      $offeneUids, $benutzt, $initial): array {
            $u['uidvalidity'] = $uidvalidity;
            // Nach einem Wechsel der UIDVALIDITY faengt die Nummerierung von
            // vorn an - der alte Hoechststand passt dann nicht mehr.
            $u['last_uid'] = $frisch ? $hoch : max((int) ($u['last_uid'] ?? 0), $hoch);
            $u['offene_uids'] = $offeneUids;
            $u['known_folders'] = array_values(array_unique(
                array_merge($u['known_folders'] ?? [], $benutzt)));
            $u['last_run'] = gmdate('c');
            $u['last_error'] = null;
            if ($initial) {
                $u['status'] = 'bereit';
                $u['halt'] = null;
            }
            return $u;
        });
    } catch (ImapError $e) {
        $r['fehler'] = $e->getMessage();
        user_set($id, static function (array $u) use ($e): array {
            $u['last_error'] = $e->getMessage();
            return $u;
        });
    }
    return $r;
}

/**
 * Ein Schritt der Zustandsmaschine: fragen, warten oder sortieren.
 * @return array{0:?string,1:?string} [Meldung, Fehler]
 */
function sa_schritt(string $id): array
{
    // Nur ein Lauf je Postfach. Zwei ueberlappende Laeufe wuerden die Routine
    // doppelt wecken und ohne MOVE dieselbe Post zweimal einsortieren.
    $sperre = @fopen(user_path($id) . '.run', 'c');
    if ($sperre === false) {
        return [null, 'Sperrdatei nicht schreibbar.'];
    }
    if (!flock($sperre, LOCK_EX | LOCK_NB)) {
        fclose($sperre);
        return ['Dieses Postfach wird gerade bearbeitet.', null];
    }
    @chmod(user_path($id) . '.run', 0600);
    try {
        return sa_schritt_laufen($id);
    } finally {
        flock($sperre, LOCK_UN);
        fclose($sperre);
    }
}

/** @return array{0:?string,1:?string} [Meldung, Fehler] */
function sa_schritt_laufen(string $id): array
{
    $user = user_load($id);
    if ($user === null) {
        return [null, 'Konto nicht gefunden.'];
    }
    $job = is_array($user['job'] ?? null) ? $user['job'] : null;

    // 1. Antwort da? Dann sortieren.
    if ($job !== null && !empty($job['fertig'])) {
        $initial = ($job['art'] ?? '') === 'initial';
        user_set($id, static function (array $u): array {
            $u['job'] = null;
            return $u;
        });
        $r = sa_sortieren($id, $initial);
        if ($r['fehler'] !== null) {
            return [null, $r['fehler']];
        }
        return [sprintf('%d gelesen, %d einsortiert.', $r['gelesen'], $r['verschoben']), null];
    }

    // 2. Anfrage laeuft noch.
    if ($job !== null && time() - (int) ($job['gestellt'] ?? 0) < JOB_FRIST) {
        return ['Die Routine ist gefragt und hat noch nicht geantwortet.', null];
    }

    // 3. Fragen sammeln.
    $initial = (string) ($user['status'] ?? 'neu') !== 'bereit';
    [$offen, $fehler] = sa_fragen_sammeln($user, $initial);
    if ($fehler !== null) {
        return [null, $fehler];
    }
    if ($offen === []) {
        user_set($id, static function (array $u): array {
            $u['job'] = null;
            return $u;
        });
        $r = sa_sortieren($id, $initial);
        if ($r['fehler'] !== null) {
            return [null, $r['fehler']];
        }
        return [sprintf('%d gelesen, %d einsortiert.', $r['gelesen'], $r['verschoben']), null];
    }

    // 4. Auftrag anlegen und die Routine wecken.
    $token = new_token();
    $rest = count($offen) - JOB_MAX;
    if ($rest > 0) {
        // Lieber mehrere kleine Anfragen als eine, die die Routine erschlaegt.
        $offen = array_slice($offen, 0, JOB_MAX, true);
    }
    $zeilen = [];
    $nr = 0;
    foreach ($offen as $q) {
        $zeilen[] = ['nr' => $nr++, 'von' => $q['from'], 'an' => $q['to'],
            'art' => $q['art'], 'kind' => $q['kind']];
    }
    user_set($id, static function (array $u) use ($token, $zeilen, $initial): array {
        $u['job'] = ['token_hash' => hash('sha256', $token), 'art' => $initial ? 'initial' : 'lauf',
            'zeilen' => $zeilen, 'gestellt' => time(), 'fertig' => false, 'sitzung' => null];
        $u['status'] = $initial ? 'neu' : 'bereit';
        return $u;
    });
    [$sitzung, $fehler] = sa_fire(api_url(), api_secret(), sprintf(
        "URL: %s\nTOKEN: %s\n\n%d Zeilen warten. Hole sie ab, ordne sie zu und "
        . "schicke die Zuordnung an dieselbe URL zurueck.",
        sa_rueckweg(), $token, count($zeilen)));
    if ($fehler !== null) {
        user_set($id, static function (array $u): array {
            $u['job'] = null;
            return $u;
        });
        return [null, $fehler];
    }
    user_set($id, static function (array $u) use ($sitzung): array {
        if (is_array($u['job'] ?? null)) {
            $u['job']['sitzung'] = $sitzung;
        }
        return $u;
    });
    return [sprintf('%d Adressen an die Routine geschickt. Die Antwort kommt gleich zurueck.%s',
        count($zeilen), $rest > 0 ? ' ' . $rest . ' weitere folgen.' : ''), null];
}

function api_url(): string
{
    return (string) (config()['api_url'] ?? '');
}

function api_secret(): string
{
    return dec((string) (config()['api_key'] ?? ''));
}

// ===========================================================================
// Rueckweg: die Routine holt die Fragen und schickt die Zuordnung
// ===========================================================================

/** @return array{0:?array,1:?array} [Konto, Auftrag] */
function sa_job_finden(string $token): array
{
    if (strlen($token) < 20) {
        return [null, null];
    }
    $hash = hash('sha256', $token);
    foreach (users() as $u) {
        $job = $u['job'] ?? null;
        if (is_array($job) && (string) ($job['token_hash'] ?? '') !== ''
            && hash_equals((string) $job['token_hash'], $hash)) {
            return [$u, $job];
        }
    }
    return [null, null];
}

function sa_rueckweg_bedienen(string $token): never
{
    if (!rate_ok('auftrag|' . (string) ($_SERVER['REMOTE_ADDR'] ?? ''), 60, 60)) {
        json_out(429, ['fehler' => 'Zu viele Anfragen']);
    }
    [$u, $job] = sa_job_finden($token);
    if ($u === null || $job === null) {
        json_out(404, ['fehler' => 'Kein offener Auftrag zu diesem Token.']);
    }
    if (time() - (int) ($job['gestellt'] ?? 0) > JOB_FRIST) {
        json_out(410, ['fehler' => 'Der Auftrag ist abgelaufen.']);
    }
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        $zeilen = [];
        foreach ((array) ($job['zeilen'] ?? []) as $z) {
            $zeilen[] = ['nr' => (int) $z['nr'], 'von' => (string) $z['von'],
                'an' => (string) $z['an'], 'art' => (string) $z['art']];
        }
        json_out(200, ['ordner' => folders_catalogue(), 'regeln' => sa_regeln(),
            'zeilen' => $zeilen]);
    }

    $roh = (string) file_get_contents('php://input', false, null, 0, MAX_BODY);
    $map = json_decode($roh, true);
    if (!is_array($map)) {
        json_out(400, ['fehler' => 'Rumpf muss JSON sein: {"0": "Ordner", ...}']);
    }
    $katalog = folders_catalogue();
    if ($katalog === []) {
        json_out(500, ['fehler' => 'Es ist kein Ordner eingerichtet.']);
    }
    $zeilen = [];
    foreach ((array) ($job['zeilen'] ?? []) as $z) {
        $zeilen[(int) $z['nr']] = $z;
    }
    $wissen = is_array($u['knowledge'] ?? null) ? $u['knowledge'] : [];
    $genommen = 0;
    $abgelehnt = [];
    foreach ($map as $nr => $ordner) {
        // (int) haette "abc" zu 0 gemacht und damit die erste Zeile ueberschrieben.
        if (!is_scalar($ordner) || preg_match('/^\d{1,9}$/', (string) $nr) !== 1
            || !isset($zeilen[(int) $nr])) {
            continue;
        }
        $ordner = trim((string) $ordner);
        if (!array_key_exists($ordner, $katalog)) {
            $abgelehnt[] = $ordner;
            continue;
        }
        $z = $zeilen[(int) $nr];
        $wissen[(string) $z['kind']][(string) $z['von']] = $ordner;
        $genommen++;
    }
    // Was die Routine nicht beantwortet hat, geht nach Persoenlich - sonst
    // bliebe der Merker stehen und keine spaetere Mail wuerde je sortiert.
    $ersatz = array_key_exists('Persoenlich', $katalog)
        ? 'Persoenlich' : (string) array_key_first($katalog);
    $offen = 0;
    foreach ($zeilen as $z) {
        $kind = (string) $z['kind'];
        $von = (string) $z['von'];
        $da = $wissen[$kind][$von] ?? null;
        // Nur eine Antwort zaehlt, die der Katalog noch kennt. Ein blosses
        // isset() wuerde genau die veralteten Eintraege stehen lassen,
        // derentwegen ueberhaupt gefragt wurde.
        if (is_string($da) && array_key_exists($da, $katalog)) {
            continue;
        }
        $wissen[$kind][$von] = $ersatz;
        $offen++;
    }
    user_set((string) $u['id'], static function (array $x) use ($wissen): array {
        $x['knowledge'] = $wissen;
        if (is_array($x['job'] ?? null)) {
            $x['job']['fertig'] = true;
            $x['job']['token_hash'] = '';   // Token ist verbraucht
        }
        return $x;
    });
    json_out(200, ['uebernommen' => $genommen, 'ohne_antwort' => $offen,
        'unbekannte_ordner' => array_values(array_unique($abgelehnt))]);
}

// ===========================================================================
// Ansichten
// ===========================================================================

function sa_setup(?string $error): never
{
    $nonce = base64_encode(random_bytes(16));
    head('Einrichten', $nonce);
    ?>
<main class="narrow" style="max-width:560px">
  <section class="card">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
      <button class="q" type="button" id="copy">Auftrag kopieren</button>
      <span class="hint" style="margin:0">als Anweisung der Routine einsetzen</span>
    </div>
    <pre id="auftrag"><?= e(sa_auftrag()) ?></pre>
    <div class="hint" style="margin-top:10px">Die Routine muss diesen Server erreichen
      duerfen: in der Umgebung unter Netzwerkzugriff <code><?= e((string) (parse_url(
      sa_rueckweg(), PHP_URL_HOST) ?: 'diese Domain')) ?></code> freigeben.</div>
    <?php msgs(null, $error); ?>
    <form method="post" autocomplete="off" style="margin-top:16px">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <div class="f"><label for="au">API-URL</label>
        <input id="au" name="api_url" required autofocus
               value="<?= e($_POST['api_url'] ?? '') ?>"
               placeholder="https://api.anthropic.com/v1/claude_code/routines/trig_.../fire"></div>
      <div class="f"><label for="ak">API-Token</label>
        <input id="ak" name="api_key" type="password" required></div>
      <button type="submit">Weiter</button>
      <div class="hint">Der Test loest einen echten Lauf der Routine aus.</div>
    </form>
  </section>
</main>
<script nonce="<?= e($nonce) ?>">
document.getElementById('copy').addEventListener('click', function () {
  var t = document.getElementById('auftrag').textContent, b = this;
  if (navigator.clipboard) { navigator.clipboard.writeText(t); }
  b.textContent = 'Kopiert';
  setTimeout(function () { b.textContent = 'Auftrag kopieren'; }, 1500);
});
</script></body></html>
    <?php
    exit;
}

function sa_page(?string $notice, ?string $error): never
{
    head('Postfach sortieren');
    ?>
<main class="narrow" style="max-width:400px">
  <?php msgs($notice, $error); ?>
  <section class="card">
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <div class="f"><label for="ad">iCloud-Adresse</label>
        <input id="ad" name="address" type="email" required autofocus
               value="<?= e($_POST['address'] ?? '') ?>"></div>
      <div class="f"><label for="pw">App-spezifisches Passwort</label>
        <input id="pw" name="password" type="password" required></div>
      <button type="submit">Sortieren</button>
    </form>
  </section>
</main></body></html>
    <?php
    exit;
}

// ===========================================================================
// Ablauf
// ===========================================================================

function sa_web(): never
{
    session_begin();

    if (isset($_GET['auftrag'])) {
        sa_rueckweg_bedienen((string) $_GET['auftrag']);
    }

    if ((config()['setup_done'] ?? false) !== true) {
        $error = null;
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            csrf_ok();
            $url = trim(post_str('api_url'));
            $key = trim(post_str('api_key'));
            [, $error] = sa_fire($url, $key,
                'Einrichtungstest. Es wartet kein Auftrag - melde das und beende.');
            if ($error === null) {
                config_set(static fn(array $c): array => [
                    'setup_done' => true, 'api_url' => $url, 'api_key' => enc($key),
                    'rueckweg' => sa_rueckweg(), 'created' => gmdate('c'),
                ]);
                session_regenerate_id(true);
                go();
            }
        }
        sa_setup($error);
    }

    $notice = null;
    $error = null;
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_ok();
        $bucket = 'sa|' . (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if (throttled($bucket)) {
            $error = 'Zu viele Versuche. Spaeter erneut.';
        } else {
            [$u, $fehler] = sa_konto(post_str('address'), post_str('password'));
            if ($fehler !== null) {
                note_try($bucket, false);
                $error = $fehler;
            } else {
                note_try($bucket, true);
                [$notice, $error] = sa_schritt((string) $u['id']);
            }
        }
    }
    sa_page($notice, $error);
}

function sa_cron(): never
{
    if ((config()['setup_done'] ?? false) !== true) {
        bail('Noch nicht eingerichtet.');
    }
    $now = time();
    foreach (users() as $u) {
        $job = is_array($u['job'] ?? null) ? $u['job'] : null;
        // Eine offene Antwort und ein noch nicht aufgeraeumtes Postfach gehen
        // vor dem Zeitplan - sonst blieben sie bis zum naechsten Intervall liegen.
        $dran = ($job !== null && !empty($job['fertig']))
            || (string) ($u['status'] ?? '') !== 'bereit'
            || schedule_due($u, $now);
        if (!$dran) {
            continue;
        }
        [$text, $fehler] = sa_schritt((string) $u['id']);
        printf("%s: %s\n", $u['address'], $fehler !== null ? 'Fehler - ' . $fehler : (string) $text);
    }
    exit(0);
}

// ===========================================================================
// Start
// ===========================================================================

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
if (PHP_SAPI !== 'cli') {
    data_dir_pruefen();
}

if (PHP_SAPI === 'cli') {
    ($argv[1] ?? '') === 'cron' ? sa_cron() : bail('Aufruf: php simplev2.php cron');
}

sa_web();
