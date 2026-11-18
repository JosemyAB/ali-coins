/**
 * Imports the authenticated Google Chrome session (macOS) into ali-coins.
 *
 * The bot uses its own Playwright Chromium and does NOT read Chrome's profile.
 * Without `session.json.enc`, it attempts the automatic login with
 * ALI_USER/ALI_PASSWORD and usually hits the anti-bot challenge (captcha/slider).
 * This utility reuses the aliexpress.com cookies already logged in the user's Chrome:
 *
 *   1. copies the profile's `Cookies` database (safe read, even with Chrome open);
 *   2. decrypts `v10`/`v11` values with the macOS Keychain's "Chrome Safe Storage"
 *      key (the system may ask for authorization on the first run);
 *   3. saves the session in the bot's format via `saveSession` (AES-256-GCM at
 *      rest), clearing the anti-bot gate/cooldown (`freshLogin: true`).
 *
 * Nothing is sent over the network. Cookies are never printed to the screen/log.
 *
 * Usage:
 *   node import_chrome_session.js                 # primary account, auto-detected profile
 *   node import_chrome_session.js --dry-run       # inspect only, writes nothing
 *   node import_chrome_session.js --account=2     # secondary account from credentials.env
 *   node import_chrome_session.js --profile="Profile 1"
 *   node import_chrome_session.js --cookies-db=/path/to/Cookies
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const dotenv = require('dotenv');
const { credentialsEnvPath, loadAccounts, getAccountArg } = require('./libs/core/config');
const { saveSession } = require('./libs/session');
const { validateSession } = require('./libs/core/security');
const { flushAndExit } = require('./libs/exit');
const logger = require('./libs/core/logger');

if (fs.existsSync(credentialsEnvPath)) {
  dotenv.config({ path: credentialsEnvPath, quiet: true });
}

const PROJECT_ROOT = __dirname;
const CHROME_DIR = path.join(os.homedir(), 'Library', 'Application Support', 'Google', 'Chrome');
const KEYCHAIN_SERVICE = 'Chrome Safe Storage';
const KEYCHAIN_ACCOUNT = 'Chrome';
// Chrome >= 130 prefixes the plaintext value with SHA-256(host_key) (32 bytes)
// to prevent direct cookie copying between domains/profiles.
const DOMAIN_HASH_BYTES = 32;
const AUTH_COOKIE_NAMES = new Set(['xman_us_t', 'login_aliyunid_ticket']);
const WINDOWS_EPOCH_OFFSET_SECONDS = 11644473600;
const ALIEXPRESS_HOST_SQL = "host_key = 'aliexpress.com' OR host_key LIKE '%.aliexpress.com'";
// The bot only recognizes PT/EN texts/labels. The account may be in another
// language (e.g., es_ES, like the user's Chrome UI); these cookies control the
// AliExpress session language and are normalized to en_US.
const LOCALE_COOKIES = new Set(['aep_usuc_f', 'xman_us_f']);
const TARGET_LOCALE = 'en_US';

class ChromeImportError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ChromeImportError';
  }
}

function commandExists(cmd) {
  try {
    execFileSync('which', [cmd], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Reads the password used by Chrome (macOS) to encrypt cookies.
 * The first read may open the Keychain dialog; "Always Allow" avoids further
 * prompts on subsequent runs.
 * @returns {string}
 */
function getChromeSafeStoragePassword() {
  try {
    return execFileSync(
      'security',
      ['find-generic-password', '-w', '-s', KEYCHAIN_SERVICE, '-a', KEYCHAIN_ACCOUNT],
      { encoding: 'utf8' }
    ).trim();
  } catch (err) {
    throw new ChromeImportError(
      'Não foi possível ler a chave "Chrome Safe Storage" do Keychain do macOS. ' +
        'Autorize o acesso quando o sistema perguntar e tente novamente. ' +
        `Detalhe: ${String((err && err.message) || err).split('\n')[0]}`
    );
  }
}

/**
 * Derives Chrome's AES-128 key and returns a ready-to-use decryptor.
 * @param {string} password
 * @returns {(encryptedValue: Buffer, hostKey: string) => string}
 */
function createCookieDecryptor(password) {
  const key = crypto.pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1');
  const iv = Buffer.alloc(16, 0x20);

  return function decryptCookieValue(encryptedValue, hostKey) {
    if (!encryptedValue || encryptedValue.length <= 3) return '';
    const version = encryptedValue.subarray(0, 3).toString('latin1');
    if (version !== 'v10' && version !== 'v11') {
      // v20 = app-bound encryption; there is no macOS support for modern Chrome
      // without a per-app key yet. Fail loudly instead of writing garbage.
      throw new ChromeImportError(
        `Cookie "${hostKey}" usa criptografia ${version || 'desconhecida'}, ainda não suportada. ` +
          'Atualize o Chrome ou use ./run_all.sh --manual-login para renovar a sessão.'
      );
    }
    try {
      const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
      // Node removes PKCS#7 padding automatically in final().
      const plain = Buffer.concat([decipher.update(encryptedValue.subarray(3)), decipher.final()]);
      // Chrome >= 130: drop the SHA-256(host_key) stored at the start of the value.
      const hostHash = crypto.createHash('sha256').update(hostKey).digest();
      const value =
        plain.length > DOMAIN_HASH_BYTES && plain.subarray(0, DOMAIN_HASH_BYTES).equals(hostHash)
          ? plain.subarray(DOMAIN_HASH_BYTES)
          : plain;
      return value.toString('utf8');
    } catch (err) {
      throw new ChromeImportError(
        `Falha ao descriptografar cookie de ${hostKey}: ${(err && err.message) || err}`
      );
    }
  };
}

function listChromeProfiles() {
  if (!fs.existsSync(CHROME_DIR)) {
    throw new ChromeImportError(`Diretório do Chrome não encontrado: ${CHROME_DIR}`);
  }
  return fs
    .readdirSync(CHROME_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => fs.existsSync(path.join(CHROME_DIR, name, 'Cookies')))
    .sort();
}

// Copies the database to a temporary directory: Chrome keeps a lock while it is
// open and a direct read could fail with SQLITE_BUSY.
function withCookiesDbCopy(cookiesDbPath, fn) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ali-coins-chrome-'));
  const tmpDb = path.join(tmpDir, 'Cookies');
  try {
    fs.copyFileSync(cookiesDbPath, tmpDb);
    const journal = `${cookiesDbPath}-journal`;
    if (fs.existsSync(journal)) fs.copyFileSync(journal, `${tmpDb}-journal`);
    return fn(tmpDb);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function readAliExpressCookieRows(cookiesDbPath) {
  const sql =
    'SELECT host_key, name, value, hex(encrypted_value) AS encrypted_hex, path, ' +
    'expires_utc, is_secure, is_httponly, samesite, last_access_utc ' +
    `FROM cookies WHERE (${ALIEXPRESS_HOST_SQL}) ORDER BY last_access_utc DESC`;
  let raw;
  try {
    raw = execFileSync('sqlite3', ['-json', cookiesDbPath, sql], {
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024
    });
  } catch (err) {
    throw new ChromeImportError(
      `Falha ao ler o banco de cookies do Chrome: ${String((err && err.message) || err).split('\n')[0]}`
    );
  }
  if (!raw.trim()) return [];
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new ChromeImportError(`Resposta inválida do sqlite3: ${(err && err.message) || err}`);
  }
}

function chromeTimeToUnixSeconds(expiresUtc) {
  const micros = Number(expiresUtc);
  if (!Number.isFinite(micros) || micros <= 0) return -1; // session cookie
  return Math.floor(micros / 1_000_000 - WINDOWS_EPOCH_OFFSET_SECONDS);
}

function isExpired(expires) {
  return typeof expires === 'number' && expires > 0 && expires * 1000 <= Date.now();
}

function toPlaywrightCookie(row, decryptValue) {
  const expires = chromeTimeToUnixSeconds(row.expires_utc);
  const cookie = {
    name: row.name,
    value: row.value || decryptValue(Buffer.from(row.encrypted_hex || '', 'hex'), row.host_key),
    domain: row.host_key,
    path: row.path || '/',
    expires,
    httpOnly: Boolean(row.is_httponly),
    secure: Boolean(row.is_secure)
  };
  // Chrome: -1 unspecified | 0=None | 1=Lax | 2=Strict
  const sameSite = { 0: 'None', 1: 'Lax', 2: 'Strict' }[Number(row.samesite)];
  if (sameSite) cookie.sameSite = sameSite;
  return cookie;
}

/**
 * Converts Chrome rows into a Playwright-compatible storageState.
 * @param {Array<object>} rows
 * @param {string} password
 * @returns {{cookies: Array<object>, expired: number, undecryptable: number}}
 */
function buildStorageState(rows, password) {
  const decryptValue = createCookieDecryptor(password);
  const cookies = [];
  let expired = 0;
  let undecryptable = 0;

  for (const row of rows) {
    if (!row || !row.name) continue;
    let cookie;
    try {
      cookie = toPlaywrightCookie(row, decryptValue);
    } catch (err) {
      undecryptable += 1;
      logger.warn({ cookie: row.name, host: row.host_key }, err.message);
      continue;
    }
    if (!cookie.value) continue;
    if (isExpired(cookie.expires)) {
      expired += 1;
      continue;
    }
    cookies.push(cookie);
  }

  return { cookies, expired, undecryptable };
}

function authCookiesOf(cookies) {
  return cookies.filter((c) => AUTH_COOKIE_NAMES.has(c.name) && c.value && !isExpired(c.expires));
}

function setQueryParam(rawValue, key, value) {
  const parts = String(rawValue || '')
    .split('&')
    .filter((part) => part.length > 0);
  let found = false;
  const updated = parts.map((part) => {
    const eq = part.indexOf('=');
    if (eq === -1) return part;
    if (part.slice(0, eq) !== key) return part;
    found = true;
    return `${key}=${value}`;
  });
  if (!found) updated.push(`${key}=${value}`);
  return updated.join('&');
}

function isAliExpressCookie(cookie) {
  const domain = String(cookie.domain || '');
  return domain === 'aliexpress.com' || domain.endsWith('.aliexpress.com');
}

/**
 * Aligns the imported session language with the bot parsers (PT/EN).
 * Modifies only the copy that will be saved to session.json.enc; Chrome's
 * profile remains untouched.
 * @param {Array<object>} cookies
 * @returns {Array<object>}
 */
function forceEnglishLocale(cookies) {
  const list = cookies.map((cookie) => ({ ...cookie }));
  for (const cookie of list) {
    if (!isAliExpressCookie(cookie) || !LOCALE_COOKIES.has(cookie.name)) continue;
    if (cookie.name === 'aep_usuc_f') {
      cookie.value = setQueryParam(cookie.value, 'b_locale', TARGET_LOCALE);
    } else if (cookie.name === 'xman_us_f') {
      cookie.value = setQueryParam(cookie.value, 'x_locale', TARGET_LOCALE);
      cookie.value = setQueryParam(cookie.value, 'intl_locale', TARGET_LOCALE);
    }
  }

  if (!list.some((c) => isAliExpressCookie(c) && c.name === 'intl_locale')) {
    list.push({
      name: 'intl_locale',
      value: TARGET_LOCALE,
      domain: '.aliexpress.com',
      path: '/',
      expires: Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60,
      httpOnly: false,
      secure: true,
      sameSite: 'Lax'
    });
  }
  return list;
}

/**
 * Picks the profile that actually has an AliExpress authentication cookie,
 * prioritizing the most recent access (avoids an old/secondary profile).
 * @param {Array<{profile: string, cookies: Array<object>, lastAccess: number}>} candidates
 * @returns {{profile: string, cookies: Array<object>, lastAccess: number}|null}
 */
function pickBestCandidate(candidates) {
  return (
    candidates
      .filter((candidate) => authCookiesOf(candidate.cookies).length > 0)
      .sort((a, b) => b.lastAccess - a.lastAccess)[0] || null
  );
}

function parseArgValue(args, name) {
  const withEquals = args.find((arg) => arg.startsWith(`${name}=`));
  if (withEquals) return withEquals.slice(name.length + 1);
  const index = args.indexOf(name);
  if (index !== -1 && args[index + 1] && !args[index + 1].startsWith('-')) return args[index + 1];
  return null;
}

function resolveTargetAccount() {
  const accounts = loadAccounts(process.env, PROJECT_ROOT);
  if (accounts.length === 0) {
    throw new ChromeImportError(
      'Nenhuma conta configurada. Defina ALI_USER (e ALI_PASSWORD) no credentials.env.'
    );
  }
  const accountArg = getAccountArg();
  if (!accountArg) return accounts[0];
  const target =
    accounts.find((a) => a.index === Number(accountArg)) ||
    accounts.find((a) => a.user.toLowerCase() === String(accountArg).trim().toLowerCase());
  if (!target) {
    throw new ChromeImportError(`Conta "${accountArg}" não encontrada no credentials.env.`);
  }
  return target;
}

/**
 * Runs the import.
 * @param {object} [options={}]
 * @param {boolean} [options.dryRun]
 * @param {string} [options.profile]
 * @param {string} [options.cookiesDb]
 * @returns {Promise<{user: string, profile: string, cookieCount: number, authCount: number, dryRun: boolean}>}
 */
async function importChromeSession(options = {}) {
  if (process.platform !== 'darwin') {
    throw new ChromeImportError(
      'Este importador usa o Keychain do macOS e só funciona no macOS. ' +
        'Em outros sistemas use ./run_all.sh --manual-login uma vez e depois export_session.js/import_session.js.'
    );
  }
  if (!commandExists('sqlite3')) {
    throw new ChromeImportError('O binário "sqlite3" não foi encontrado no PATH.');
  }

  const account = resolveTargetAccount();
  const password = getChromeSafeStoragePassword();

  const cookiesDbArg = options.cookiesDb || parseArgValue(process.argv.slice(2), '--cookies-db');
  let candidates = [];

  if (cookiesDbArg) {
    const resolved = path.resolve(cookiesDbArg);
    if (!fs.existsSync(resolved)) {
      throw new ChromeImportError(`Arquivo de cookies não encontrado: ${resolved}`);
    }
    const raw = withCookiesDbCopy(resolved, readAliExpressCookieRows);
    candidates.push({ profile: path.basename(path.dirname(resolved)), rows: raw, lastAccess: 0 });
  } else {
    const profileArg = options.profile || parseArgValue(process.argv.slice(2), '--profile');
    const profiles = profileArg ? [profileArg] : listChromeProfiles();
    if (profiles.length === 0) {
      throw new ChromeImportError(`Nenhum perfil do Chrome com banco de cookies em ${CHROME_DIR}`);
    }
    for (const profile of profiles) {
      const dbPath = path.join(CHROME_DIR, profile, 'Cookies');
      if (!fs.existsSync(dbPath)) {
        logger.warn({ profile }, 'Perfil do Chrome sem banco de cookies; ignorando.');
        continue;
      }
      const rows = withCookiesDbCopy(dbPath, readAliExpressCookieRows);
      const lastAccess = rows.reduce(
        (max, row) => Math.max(max, Number(row.last_access_utc) || 0),
        0
      );
      candidates.push({ profile, rows, lastAccess });
    }
  }

  const built = candidates.map((candidate) => {
    const { cookies, expired, undecryptable } = buildStorageState(candidate.rows, password);
    return { ...candidate, cookies, expired, undecryptable };
  });

  const best = pickBestCandidate(built);
  if (!best) {
    throw new ChromeImportError(
      'Nenhum cookie de autenticação AliExpress encontrado no Chrome. ' +
        'Confirme que você está logado em https://www.aliexpress.com no perfil correto, ' +
        'ou use ./run_all.sh --manual-login.'
    );
  }

  const authCookies = authCookiesOf(best.cookies);
  const keepLocale = options.keepLocale === true || process.argv.slice(2).includes('--keep-locale');
  const storageState = {
    cookies: keepLocale ? best.cookies : forceEnglishLocale(best.cookies),
    origins: []
  };
  const validation = validateSession(storageState, { user: account.user }, account.user);
  if (!validation.valid) {
    throw new ChromeImportError(`Sessão do Chrome inválida: ${validation.reason}`);
  }

  logger.info(
    {
      account: account.maskedUser,
      profile: best.profile,
      stateEntries: storageState.cookies.length,
      authNames: authCookies.map((c) => c.name),
      expiredDiscarded: best.expired
    },
    'Cookies AliExpress encontrados no Chrome.'
  );

  if (options.dryRun) {
    logger.info('[dry-run] Nenhum arquivo foi gravado.');
    return {
      user: account.user,
      profile: best.profile,
      cookieCount: storageState.cookies.length,
      authCount: authCookies.length,
      dryRun: true
    };
  }

  const saved = await saveSession(storageState, account.user, {
    sessionPath: account.sessionPath,
    sessionMetaPath: account.sessionMetaPath,
    sessionTokenPath: undefined,
    freshLogin: true
  });

  if (!saved) {
    throw new ChromeImportError(
      'A sessão não pôde ser salva. Verifique SESSION_SECRET (>= 32 caracteres) e as permissões do projeto.'
    );
  }

  logger.info(
    {
      account: account.maskedUser,
      file: path.basename(`${account.sessionPath}.enc`)
    },
    'Sessão do Chrome importada com sucesso. Rode "npm start -- --check-session" para validar.'
  );

  return {
    user: account.user,
    profile: best.profile,
    cookieCount: storageState.cookies.length,
    authCount: authCookies.length,
    dryRun: false
  };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(
      [
        'Uso: node import_chrome_session.js [opções]',
        '',
        '  --dry-run              Inspeciona o Chrome e mostra o que seria importado (não grava).',
        '  --account=N            Usa a conta N do credentials.env (padrão: conta primária).',
        '  --profile="Default"    Perfil do Chrome (padrão: auto-detecta o perfil logado).',
        '  --cookies-db=CAMINHO   Banco de cookies alternativo (avançado).',
        '  --keep-locale          Mantém o idioma original da conta (o bot só entende PT/EN).',
        '  --help                 Mostra esta ajuda.',
        ''
      ].join('\n')
    );
    flushAndExit(0);
    return;
  }

  importChromeSession({ dryRun: args.includes('--dry-run') })
    .then(() => flushAndExit(0))
    .catch((err) => {
      logger.error({ err: err.message }, 'Falha ao importar a sessão do Chrome.');
      flushAndExit(1);
    });
}

module.exports = {
  ChromeImportError,
  importChromeSession,
  buildStorageState,
  createCookieDecryptor,
  chromeTimeToUnixSeconds,
  forceEnglishLocale,
  setQueryParam
};
