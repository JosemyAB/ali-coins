const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  chromeTimeToUnixSeconds,
  setQueryParam,
  forceEnglishLocale,
  createCookieDecryptor,
  buildStorageState,
  ChromeImportError
} = require('../import_chrome_session');

const TEST_PASSWORD = 'test-keychain-password'; //gitleaks:allow valor fictício de teste

/**
 * Reproduces Chrome's cookie format (v10 + AES-128-CBC on macOS + host hash).
 * @param {string} hostKey
 * @param {string} value
 * @returns {string} encrypted_value as hexadecimal
 */
function encryptChromeCookie(hostKey, value) {
  const key = crypto.pbkdf2Sync(TEST_PASSWORD, 'saltysalt', 1003, 16, 'sha1');
  const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
  const hostHash = crypto.createHash('sha256').update(hostKey).digest();
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.concat([hostHash, Buffer.from(value, 'utf8')])),
    cipher.final()
  ]);
  return Buffer.concat([Buffer.from('v10', 'latin1'), ciphertext]).toString('hex');
}

function makeRow(overrides = {}) {
  return {
    host_key: '.aliexpress.com',
    name: 'xman_us_t',
    value: '',
    encrypted_hex: '',
    path: '/',
    expires_utc: 0,
    is_secure: 1,
    is_httponly: 0,
    samesite: -1,
    last_access_utc: 0,
    ...overrides
  };
}

test('chromeTimeToUnixSeconds - converte época Windows e cookies de sessão', () => {
  assert.equal(chromeTimeToUnixSeconds(0), -1);
  // 13300000000000000 µs desde 1601 -> 1655526400 s Unix
  assert.equal(chromeTimeToUnixSeconds(13300000000000000), 1655526400);
  assert.equal(chromeTimeToUnixSeconds('inválido'), -1);
});

test('setQueryParam - atualiza, adiciona e preserva os demais parâmetros', () => {
  const raw = 'site=esp&b_locale=es_ES&region=ES';
  assert.equal(setQueryParam(raw, 'b_locale', 'en_US'), 'site=esp&b_locale=en_US&region=ES');
  assert.equal(setQueryParam(raw, 'x_locale', 'en_US'), `${raw}&x_locale=en_US`);
  assert.equal(setQueryParam('', 'intl_locale', 'en_US'), 'intl_locale=en_US');
});

test('forceEnglishLocale - normaliza cookies do AliExpress e adiciona intl_locale', () => {
  const cookies = [
    { name: 'aep_usuc_f', value: 'site=esp&b_locale=es_ES&region=ES', domain: '.aliexpress.com' },
    {
      name: 'xman_us_f',
      value: 'x_locale=es_ES&x_user=ES|Jose&intl_locale=es_ES',
      domain: '.aliexpress.com'
    },
    { name: 'aep_usuc_f', value: 'site=us&b_locale=es_ES', domain: '.aliexpress.us' },
    { name: 'session', value: 'keep-me', domain: 'example.com' }
  ];

  const result = forceEnglishLocale(cookies);

  assert.match(result[0].value, /b_locale=en_US/);
  assert.match(result[1].value, /x_locale=en_US/);
  assert.match(result[1].value, /intl_locale=en_US/);
  // Other domains/profiles are untouched
  assert.equal(result[2].value, 'site=us&b_locale=es_ES');
  assert.equal(result[3].value, 'keep-me');
  const intl = result.find((c) => c.name === 'intl_locale');
  assert.equal(intl.value, 'en_US');
  assert.equal(intl.domain, '.aliexpress.com');
  // Does not mutate the original array
  assert.match(cookies[0].value, /b_locale=es_ES/);
});

test('createCookieDecryptor - decifra v10 e remove o hash de domínio', () => {
  const decrypt = createCookieDecryptor(TEST_PASSWORD);
  const encrypted = Buffer.from(
    encryptChromeCookie('.aliexpress.com', 'cookie-secret-value'),
    'hex'
  );
  assert.equal(decrypt(encrypted, '.aliexpress.com'), 'cookie-secret-value');
});

test('createCookieDecryptor - rejeita formato v20 não suportado', () => {
  const decrypt = createCookieDecryptor(TEST_PASSWORD);
  assert.throws(
    () => decrypt(Buffer.from('v20conteudo', 'latin1'), '.aliexpress.com'),
    ChromeImportError
  );
});

test('buildStorageState - monta cookies válidos e descarta expirados', () => {
  const rows = [
    makeRow({ encrypted_hex: encryptChromeCookie('.aliexpress.com', 'auth-value') }),
    makeRow({
      name: 'old_cookie',
      encrypted_hex: encryptChromeCookie('.aliexpress.com', 'old-value'),
      // 01/01/2020 em µs desde 1601
      expires_utc: 13325689248000000
    }),
    makeRow({ name: 'empty_cookie', value: '', encrypted_hex: '' })
  ];

  const result = buildStorageState(rows, TEST_PASSWORD);

  assert.equal(result.expired, 1);
  assert.equal(result.undecryptable, 0);
  assert.equal(result.cookies.length, 1);
  assert.equal(result.cookies[0].name, 'xman_us_t');
  assert.equal(result.cookies[0].value, 'auth-value');
  assert.equal(result.cookies[0].expires, -1);
  assert.equal(result.cookies[0].secure, true);
});
