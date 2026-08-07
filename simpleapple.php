<?php
/**
 * simple-apple.php - der kleine Bruder von index.php.
 *
 * Einrichtung: nur die KI. Danach steht dauerhaft ein Formular bereit, in das
 * jemand seine iCloud-Adresse und ein app-spezifisches Passwort eintraegt.
 * Das Postfach wird einmal aufgeraeumt und danach im festen Takt sortiert.
 *
 * Keine Domains, keine weiteren Adressen, kein Private Relay - nur der
 * Posteingang und die Ordner aus index.php.
 *
 * Ablage: icm-data/simple neben der index.php.
 * Cron alle fuenf Minuten: php /pfad/simple-apple.php cron
 */

declare(strict_types=1);

const ICM_LIBRARY = true;      // index.php nur als Baukasten laden
const ICM_DATA_SUB = 'simple'; // eigener Stand im selben Ordner
const ICM_NO_ALIAS = true;     // ohne Alias-Ordner

$engine = __DIR__ . '/index.php';
if (!is_file($engine)) {
    http_response_code(500);
    exit('index.php fehlt. Beide Dateien gehoeren in denselben Ordner.');
}
require $engine;

const SA_INTERVAL = 15;        // Minuten zwischen zwei Durchlaeufen
const SA_MAX_KONTEN = 50;

boot();

// ===========================================================================
// Konten
// ===========================================================================

/** Nur iCloud. Alles andere braucht Angaben, die es hier nicht gibt. */
function sa_host(): string
{
    return PROVIDERS['icloud']['host'];
}

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
 * Legt ein Konto an, nachdem die Anmeldedaten am Server geprueft wurden.
 * @return array{0:?array,1:?string,2:?string} [Konto, Zugangscode, Fehler]
 */
function sa_add(string $address, string $password): array
{
    $address = strtolower(trim($address));
    if (!filter_var($address, FILTER_VALIDATE_EMAIL)) {
        return [null, null, 'Das ist keine gueltige E-Mail-Adresse.'];
    }
    if ($password === '') {
        return [null, null, 'Das app-spezifische Passwort fehlt.'];
    }
    if (sa_find($address) !== null) {
        return [null, null, 'Diese Adresse ist schon eingetragen.'];
    }
    if (count(users()) >= SA_MAX_KONTEN) {
        return [null, null, 'Es sind keine Plaetze mehr frei.'];
    }
    try {
        (new Imap(sa_host(), 993))->login($address, $password);
    } catch (ImapError $e) {
        return [null, null, $e->getMessage()];
    }
    $code = new_token();
    $id = bin2hex(random_bytes(8));
    jwrite(user_path($id), [
        'id' => $id, 'address' => $address, 'password' => enc($password),
        'provider' => 'icloud', 'host' => sa_host(), 'port' => 993,
        'apple' => true, 'privateappleid' => false, 'domains' => [], 'addresses' => [],
        'knowledge' => [], 'known_folders' => [],
        'schedule' => ['mode' => 'interval', 'interval' => SA_INTERVAL, 'times' => []],
        'totp_secret' => '', 'code_hash' => hash('sha256', $code),
        'status' => 'neu', 'created' => gmdate('c'),
    ]);
    sodium_memzero($password);
    return [user_load($id), $code, null];
}

/** Kontozugang ueber den einmal angezeigten Code. */
function sa_auth(string $address, string $code): ?array
{
    $u = sa_find(strtolower(trim($address)));
    if ($u === null) {
        return null;
    }
    return hash_equals((string) ($u['code_hash'] ?? ''), hash('sha256', trim($code))) ? $u : null;
}

// ===========================================================================
// Einrichtung: nur die KI
// ===========================================================================

function sa_setup(): never
{
    if (!is_array($_SESSION['setup'] ?? null)) {
        $_SESSION['setup'] = ['kind' => 'messages'];
    }
    $kind = (string) ($_SESSION['setup']['kind'] ?? 'messages');
    $error = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_ok();
        $kind = isset(API_KINDS[(string) ($_POST['api_kind'] ?? '')])
            ? (string) $_POST['api_kind'] : 'messages';
        $_SESSION['setup']['kind'] = $kind;
        if (($_POST['wechsel'] ?? '') !== '') {
            go();
        }
        $url = trim((string) ($_POST['api_url'] ?? '')) ?: DEFAULT_API_URL;
        $key = trim((string) ($_POST['api_key'] ?? ''));
        $zugang = trim((string) ($_POST['zugang'] ?? ''));
        $offen = array_filter(checks_system(), static fn(array $c) => $c['required'] && !$c['ok']);
        $row = check_key($url, $key, $kind);
        if ($offen !== []) {
            $error = 'Noch offen: ' . implode(', ', array_column($offen, 'name'));
        } elseif (!$row['ok']) {
            $error = $row['detail'];
        } else {
            config_set(static fn(array $c): array => [
                'setup_done' => true,
                'api_url' => $url, 'api_key' => enc($key), 'api_kind' => $kind,
                'model' => DEFAULT_MODEL,
                'zugang_hash' => $zugang === '' ? '' : password_hash($zugang, PASSWORD_DEFAULT),
                'created' => gmdate('c'),
            ]);
            unset($_SESSION['setup']);
            session_regenerate_id(true);
            go();
        }
    }

    $nonce = base64_encode(random_bytes(16));
    head('Postfach sortieren - einrichten', $nonce);
    $routine = $kind === 'routine';
    ?>
<main class="narrow" style="max-width:600px">
  <h1>Einrichten</h1>
  <?php msgs(null, $error); ?>
  <section class="card">
    <h2>Voraussetzungen</h2>
    <ul class="chk" id="chk"><li><span class="st">&hellip;</span><span class="nm">wird geprueft</span></li></ul>
  </section>
  <form method="post" autocomplete="off">
    <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
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
          ? 'Auf claude.ai/code/routines eine Routine anlegen und den Text als Auftrag '
            . 'einsetzen. Danach gibt die Routine dir eine API-URL und ein Token.'
          : 'Der Text beschreibt, was die KI tun soll. Das Token kommt aus der '
            . 'Anthropic-Konsole.' ?></p>
      <pre id="auftrag"><?= e(routine_text($kind, 'simple-apple')) ?></pre>
      <div style="margin-top:10px"><button class="q" type="button" id="copy">Text kopieren</button></div>
    </section>
    <section class="card">
      <h2>3. Zugang eintragen</h2>
      <div class="f"><label for="au">API-URL</label>
        <input id="au" name="api_url" value="<?= e($routine ? '' : DEFAULT_API_URL) ?>"
               placeholder="<?= e($routine ? 'aus der Routine' : DEFAULT_API_URL) ?>"></div>
      <div class="f"><label for="ak">API-Token</label>
        <input id="ak" name="api_key" type="password" required>
        <div class="hint">Wird verschluesselt abgelegt und nie wieder angezeigt.</div></div>
    </section>
    <section class="card">
      <h2>4. Wer darf sich eintragen</h2>
      <div class="f"><label for="zg">Zugangscode</label>
        <input id="zg" name="zugang" type="text">
        <div class="hint">Ohne Code kann jeder, der die Seite kennt, ein Postfach
          eintragen - und dabei dein KI-Token verbrauchen. Leer lassen nur, wenn
          die Seite ohnehin nicht oeffentlich erreichbar ist.</div></div>
      <button id="go" type="submit" disabled>Einrichten</button>
      <div class="hint" id="gohint">Erst moeglich, wenn die KI antwortet.</div>
    </section>
  </form>
<?php checklist_script($nonce, '?check=all', 'chk', 'go', 'gohint', true); ?>
</main></body></html>
    <?php
    exit;
}

// ===========================================================================
// Oberflaeche
// ===========================================================================

function sa_head(?string $notice, ?string $error): void
{
    ?>
<header><div class="in"><b>Postfach sortieren</b>
  <a href="?">Eintragen</a><a href="?konto">Mein Postfach</a></div></header>
<main class="narrow" style="max-width:520px">
  <?php msgs($notice, $error);
}

function sa_page_neu(?string $notice, ?string $error): never
{
    $zugang = (string) (config()['zugang_hash'] ?? '') !== '';
    head('Postfach sortieren');
    sa_head($notice, $error);
    ?>
  <section class="card">
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="hidden" name="aktion" value="anlegen">
      <div class="f"><label for="ad">iCloud-Adresse</label>
        <input id="ad" name="address" type="email" required autofocus></div>
      <div class="f"><label for="pw">App-spezifisches Passwort</label>
        <input id="pw" name="password" type="password" required>
        <div class="hint">appleid.apple.com &rarr; Anmeldung und Sicherheit &rarr;
          App-spezifische Passwoerter. Nicht das Passwort deiner Apple ID.</div></div>
      <?php if ($zugang): ?>
        <div class="f"><label for="zg">Zugangscode</label>
          <input id="zg" name="zugang" type="password" required></div>
      <?php endif; ?>
      <button type="submit">Postfach eintragen</button>
    </form>
  </section>
  <section class="card">
    <h2>Was danach passiert</h2>
    <ol style="margin:0;padding-left:18px">
      <li>Alles aus dem Archiv und den eigenen Ordnern geht in den Posteingang.</li>
      <li>Die eigenen Ordner werden geloescht und neu angelegt.</li>
      <li>Jede Nachricht wird einsortiert.</li>
      <li>Danach alle <?= SA_INTERVAL ?> Minuten die neue Post.</li>
    </ol>
    <p class="muted" style="margin:12px 0 0">Gesendet, Entwuerfe, Werbung und
      Papierkorb bleiben unberuehrt. Gelesen werden nur Absender und Empfaenger,
      nie der Inhalt einer Nachricht. Geloescht wird keine Nachricht.</p>
  </section>
  <section class="card">
    <h2>Ordner</h2>
    <table>
      <?php foreach (folders_catalogue() as $name => $was): ?>
        <tr><td><?= e($name) ?></td><td class="muted"><?= e($was) ?></td></tr>
      <?php endforeach; ?>
    </table>
  </section>
</main></body></html>
    <?php
    exit;
}

function sa_page_code(array $u, string $code): never
{
    head('Postfach sortieren');
    sa_head(null, null);
    ?>
  <section class="card">
    <div style="font-weight:600;margin:0 0 12px"><?= e($u['address']) ?> ist eingetragen</div>
    <div class="f"><label>Dein Zugangscode</label><pre><?= e($code) ?></pre>
      <div class="hint">Jetzt sichern. Er wird nur dieses eine Mal angezeigt und
        ist der einzige Weg zurueck zu diesem Postfach.</div></div>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="hidden" name="aktion" value="start">
      <input type="hidden" name="address" value="<?= e($u['address']) ?>">
      <input type="hidden" name="code" value="<?= e($code) ?>">
      <button type="submit">Jetzt aufraeumen</button>
      <div class="hint">Das dauert je nach Postfach ein bis zwei Minuten.</div>
    </form>
  </section>
</main></body></html>
    <?php
    exit;
}

function sa_page_konto(?array $u, ?string $notice, ?string $error): never
{
    head('Postfach sortieren');
    sa_head($notice, $error);
    if ($u === null) {
        ?>
  <section class="card">
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="hidden" name="aktion" value="anmelden">
      <div class="f"><label for="ad">iCloud-Adresse</label>
        <input id="ad" name="address" type="email" required autofocus></div>
      <div class="f"><label for="cd">Zugangscode</label>
        <input id="cd" name="code" type="password" required></div>
      <button type="submit">Anzeigen</button>
    </form>
  </section>
</main></body></html>
        <?php
        exit;
    }
    $st = (string) ($u['status'] ?? 'neu');
    ?>
  <section class="card">
    <div style="font-weight:600;margin:0 0 12px"><?= e($u['address']) ?></div>
    <table>
      <tr><td>Zustand</td><td class="muted"><?= e(match ($st) {
          'bereit' => 'sortiert alle ' . SA_INTERVAL . ' Minuten',
          'neu_initialisieren' => (string) ($u['halt'] ?? 'angehalten'),
          default => 'noch nicht aufgeraeumt',
      }) ?></td></tr>
      <tr><td>Letzter Lauf</td><td class="muted"><?= e(stamp($u['last_run'] ?? null)) ?></td></tr>
      <tr><td>Bekannte Absender</td><td class="muted"><?= array_sum(array_map('count',
          (array) ($u['knowledge'] ?? []))) ?></td></tr>
      <tr><td>Ordner</td><td class="muted"><?= count($u['known_folders'] ?? []) ?></td></tr>
    </table>
    <?php if (!empty($u['last_error'])): ?>
      <div class="msg err" style="margin:14px 0 0"><?= e((string) $u['last_error']) ?></div>
    <?php endif; ?>
    <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
      <form method="post" class="inline"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
        <input type="hidden" name="aktion" value="sortieren">
        <button <?= $st === 'bereit' ? '' : 'class="q"' ?> type="submit">Jetzt sortieren</button></form>
      <form method="post" class="inline"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
        <input type="hidden" name="aktion" value="start">
        <button <?= $st === 'bereit' ? 'class="d"' : '' ?> type="submit">
          <?= $st === 'bereit' ? 'Neu aufraeumen' : 'Aufraeumen' ?></button></form>
      <form method="post" class="inline">
        <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
        <input type="hidden" name="aktion" value="entfernen">
        <button class="d" type="submit">Postfach entfernen</button></form>
    </div>
    <?php if ($st === 'bereit'): ?>
      <div class="hint" style="margin-top:8px">Neu aufraeumen holt alles zurueck in
        den Posteingang und sortiert von vorne.</div>
    <?php endif; ?>
  </section>
  <section class="card">
    <form method="post"><input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="hidden" name="aktion" value="abmelden">
      <button class="q" type="submit">Abmelden</button></form>
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
    $setup = (config()['setup_done'] ?? false) === true;

    if (isset($_GET['check'])) {
        // Vor der Einrichtung offen, danach zu. Draussen wird nur mit einer
        // laufenden Einrichtungssitzung angeklopft.
        if ($setup || !is_array($_SESSION['setup'] ?? null)) {
            json_out(403, ['error' => 'Nicht erlaubt']);
        }
        if (!rate_ok('sacheck|' . (string) ($_SERVER['REMOTE_ADDR'] ?? ''), 90, 60)) {
            json_out(429, ['error' => 'Zu viele Anfragen']);
        }
        // Eine Liste, ein Knopf: Voraussetzungen und KI zusammen.
        $kind = isset(API_KINDS[(string) ($_SESSION['setup']['kind'] ?? '')])
            ? (string) $_SESSION['setup']['kind'] : 'messages';
        json_out(200, ['pruefungen' => array_merge(checks_system(), [check_key(
            trim((string) ($_GET['url'] ?? '')) ?: DEFAULT_API_URL,
            trim((string) ($_GET['key'] ?? '')), $kind)])]);
    }

    if (!$setup) {
        sa_setup();
    }

    $notice = null;
    $error = null;
    $konto = isset($_SESSION['konto']) ? user_load((string) $_SESSION['konto']) : null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_ok();
        $aktion = (string) ($_POST['aktion'] ?? '');
        $bucket = 'sa|' . (string) ($_SERVER['REMOTE_ADDR'] ?? '');

        if ($aktion === 'anlegen') {
            if (throttled($bucket)) {
                $error = 'Zu viele Versuche. Spaeter erneut.';
            } else {
                $hash = (string) (config()['zugang_hash'] ?? '');
                if ($hash !== '' && !password_verify((string) ($_POST['zugang'] ?? ''), $hash)) {
                    note_try($bucket, false);
                    $error = 'Der Zugangscode stimmt nicht.';
                } else {
                    [$u, $code, $fehler] = sa_add((string) ($_POST['address'] ?? ''),
                        (string) ($_POST['password'] ?? ''));
                    if ($fehler !== null) {
                        note_try($bucket, false);
                        $error = $fehler;
                    } else {
                        note_try($bucket, true);
                        session_regenerate_id(true);
                        $_SESSION['konto'] = $u['id'];
                        $_SESSION['csrf'] = new_token();
                        sa_page_code($u, (string) $code);
                    }
                }
            }
        } elseif ($aktion === 'anmelden') {
            if (throttled($bucket)) {
                $error = 'Zu viele Versuche. Spaeter erneut.';
            } else {
                $u = sa_auth((string) ($_POST['address'] ?? ''), (string) ($_POST['code'] ?? ''));
                if ($u === null) {
                    note_try($bucket, false);
                    $error = 'Adresse oder Code stimmt nicht.';
                } else {
                    note_try($bucket, true);
                    session_regenerate_id(true);
                    $_SESSION['konto'] = $u['id'];
                    $_SESSION['csrf'] = new_token();
                    go('konto');
                }
            }
        } elseif ($aktion === 'abmelden') {
            $_SESSION = [];
            session_destroy();
            go();
        } elseif ($konto !== null) {
            $id = (string) $konto['id'];
            if ($aktion === 'start' || $aktion === 'sortieren') {
                $r = run_cycle($id, $aktion === 'start');
                $konto = user_load($id);
                if ($r['fehler'] !== null) {
                    $error = $r['fehler'];
                } else {
                    $notice = sprintf('%d gelesen, %d einsortiert.',
                        $r['gelesen'], $r['verschoben']);
                }
            } elseif ($aktion === 'entfernen') {
                @unlink(user_path($id));
                @unlink(user_path($id) . '.lock');
                $_SESSION = [];
                session_destroy();
                go();
            }
        }
    }

    if (isset($_GET['konto']) || $konto !== null) {
        sa_page_konto($konto, $notice, $error);
    }
    sa_page_neu($notice, $error);
}

function sa_cron(): never
{
    if ((config()['setup_done'] ?? false) !== true) {
        bail('Noch nicht eingerichtet.');
    }
    $now = time();
    foreach (users() as $u) {
        if ((string) ($u['status'] ?? '') !== 'bereit' || !schedule_due($u, $now)) {
            continue;
        }
        $r = run_cycle((string) $u['id']);
        printf("%s: %d gelesen, %d verschoben%s\n", $u['address'], $r['gelesen'],
            $r['verschoben'], $r['fehler'] !== null ? ' - ' . $r['fehler'] : '');
    }
    exit(0);
}

if (PHP_SAPI === 'cli') {
    ($argv[1] ?? '') === 'cron' ? sa_cron() : bail('Aufruf: php simple-apple.php cron');
}

sa_web();
