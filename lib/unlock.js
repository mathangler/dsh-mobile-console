/**
 * dsh-remote-access — the password-protected recovery door.
 *
 * Why it exists: the platform's browser cookie is minted once, when a request
 * carries the process launch token, and `authorizeIndex` never re-mints it on an
 * ordinary authenticated request. So a phone that has been away longer than
 * `cookieMaxAgeDays` needs a *fresh tokenized entry URL*, and the only place to
 * read one used to be the desktop panel at 127.0.0.1. This module gives the
 * plugin its own door: a password, verified by challenge-response, that hands
 * back a fresh entry URL and QR code without touching the computer.
 *
 * The password never crosses the wire. The phone derives a key from it with
 * PBKDF2-SHA256 and answers a single-use nonce with HMAC-SHA256; the host stores
 * only the derived key, and compares in constant time.
 *
 * @module dsh-remote-access/unlock
 */

import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';

/** PBKDF2 work factor. Browser WebCrypto needs the same number. */
export const PBKDF2_ITERATIONS = 600000;

/** Derived key length in bytes. */
export const KEY_BYTES = 32;

/** Salt length in bytes. */
export const SALT_BYTES = 16;

/** Cookie payload version, so a future format can be told apart. */
export const TICKET_VERSION = 1;

/** How long an unlock ticket lasts, in days. */
export const DEFAULT_TICKET_DAYS = 30;

/** The cookie the unlock door sets; scoped to this plugin's route prefix. */
export const UNLOCK_COOKIE = 'mc-unlock';

/**
 * The cookie holding this device's long-lived, plugin-issued token.
 *
 * The platform's own cookie comes from a per-process launch token and lives
 * `cookieMaxAgeDays` (30 by default). This one is issued by the plugin at
 * pairing time, lasts `DEFAULT_DEVICE_DAYS`, slides on every use and is
 * revocable per device — so a phone stays paired across restarts, hostname
 * changes, and the platform cookie's expiry.
 */
export const DEVICE_COOKIE = 'mc-device';

/** How long a device token lasts, in days. Refreshed on every successful use. */
export const DEFAULT_DEVICE_DAYS = 365;

/**
 * Alphabet for pairing codes.
 *
 * No `0/O` and no `1/I/L`: a code gets read aloud, typed from a screenshot, or
 * copied by hand, and those four pairs are the ones people get wrong.
 */
export const PAIR_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

/** Pairing-code length. Eight characters of this alphabet is about 39 bits. */
export const PAIR_CODE_LENGTH = 8;

/** How long a pairing code stays valid, in minutes. */
export const DEFAULT_PAIR_MINUTES = 10;

/** A fresh pairing code. */
export function newPairCode(length = PAIR_CODE_LENGTH) {
  const bytes = randomBytes(length);
  let code = '';
  for (const byte of bytes) code += PAIR_CODE_ALPHABET[byte % PAIR_CODE_ALPHABET.length];
  return code;
}

/**
 * Normalize a typed pairing code: strip separators, uppercase, and reject
 * anything that is not in the alphabet.
 * @param value - what the user typed or the page read from the query string.
 * @returns the canonical code, or undefined when it cannot be one.
 */
export function normalizePairCode(value) {
  if (typeof value !== 'string') return undefined;
  const cleaned = value.toUpperCase().replace(/[\s-]/g, '');
  if (cleaned.length !== PAIR_CODE_LENGTH) return undefined;
  // Strict on purpose: the alphabet leaves out the confusable characters, so a
  // character outside it means the code was mistyped. Guessing at a replacement
  // would silently look up a different code.
  for (const character of cleaned) {
    if (!PAIR_CODE_ALPHABET.includes(character)) return undefined;
  }
  return cleaned;
}

/** The stored fingerprint of a pairing code; the code itself is never stored. */
export function hashPairCode(code) {
  const normalized = normalizePairCode(code);
  return normalized === undefined ? undefined : createHash('sha256').update(normalized).digest('hex');
}

/**
 * Turn a lifetime in days into an absolute expiry.
 * @param days - a positive day count, or null for "never expires".
 * @param now - current time in milliseconds.
 */
export function expiryFromDays(days, now = Date.now()) {
  if (days === null || days === undefined) return null;
  const value = Number(days);
  if (!Number.isFinite(value) || value <= 0) return null;
  return now + Math.round(value) * 24 * 60 * 60 * 1000;
}

/** A fresh device token: 32 random bytes, base64url. */
export function newDeviceToken() {
  return randomBytes(32).toString('base64url');
}

/** The stored fingerprint of a device token; the token itself is never stored. */
export function hashDeviceToken(token) {
  return createHash('sha256').update(String(token)).digest('hex');
}

/**
 * Constant-time comparison of a presented token against a stored fingerprint.
 * @param token - the cookie value.
 * @param hash - the stored sha256 hex digest.
 */
export function deviceTokenMatches(token, hash) {
  if (typeof token !== 'string' || token === '' || typeof hash !== 'string' || hash === '') return false;
  const presented = Buffer.from(hashDeviceToken(token), 'hex');
  const stored = Buffer.from(hash, 'hex');
  if (presented.length === 0 || presented.length !== stored.length) return false;
  return timingSafeEqual(presented, stored);
}

/** Failed attempts allowed per window before a lockout. */
export const ATTEMPT_LIMIT = 5;

/** Length of one rate-limit window, in milliseconds. */
export const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

/** A fresh salt for a new password. */
export function newSalt() {
  return randomBytes(SALT_BYTES).toString('base64');
}

/** A fresh single-use challenge. */
export function newNonce() {
  return randomBytes(24).toString('base64');
}

/**
 * Derive the unlock key. The browser performs the same derivation with
 * WebCrypto, so the server never sees the password.
 * @param password - the typed password.
 * @param saltBase64 - the stored salt.
 * @param iterations - PBKDF2 work factor.
 * @returns the derived key, base64.
 */
export function deriveKey(password, saltBase64, iterations = PBKDF2_ITERATIONS) {
  const salt = Buffer.from(String(saltBase64), 'base64');
  return pbkdf2Sync(String(password), salt, iterations, KEY_BYTES, 'sha256').toString('base64');
}

/** The proof a client must return for a nonce: HMAC-SHA256(key, nonce). */
export function proofFor(keyBase64, nonce) {
  return createHmac('sha256', Buffer.from(String(keyBase64), 'base64')).update(String(nonce)).digest('base64');
}

/**
 * Constant-time proof check.
 * @param keyBase64 - the stored derived key.
 * @param nonce - the challenge that was issued.
 * @param proof - the client's answer.
 * @returns whether the answer is correct.
 */
export function verifyProof(keyBase64, nonce, proof) {
  if (typeof proof !== 'string' || proof === '' || typeof nonce !== 'string' || nonce === '') return false;
  const expected = Buffer.from(proofFor(keyBase64, nonce), 'base64');
  const given = Buffer.from(proof, 'base64');
  if (expected.length === 0 || expected.length !== given.length) return false;
  return timingSafeEqual(expected, given);
}

/**
 * Sign a ticket — the value of the plugin's own cookie.
 * @param secret - the ticket secret.
 * @param payload - the ticket body, including a numeric `exp`.
 * @returns `body.mac`, both base64url.
 */
export function signTicket(secret, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const mac = createHmac('sha256', String(secret)).update(body).digest('base64url');
  return `${body}.${mac}`;
}

/**
 * Verify a ticket.
 * @param secret - the ticket secret.
 * @param value - the cookie value.
 * @param now - current time in milliseconds.
 * @returns the payload, or undefined when the ticket is forged, malformed or expired.
 */
export function verifyTicket(secret, value, now = Date.now()) {
  if (typeof value !== 'string') return undefined;
  const dot = value.lastIndexOf('.');
  if (dot <= 0 || dot === value.length - 1) return undefined;
  const body = value.slice(0, dot);
  const expected = Buffer.from(createHmac('sha256', String(secret)).update(body).digest('base64url'));
  const given = Buffer.from(value.slice(dot + 1));
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload === null || typeof payload !== 'object') return undefined;
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= now) return undefined;
    return payload;
  } catch {
    return undefined;
  }
}

/**
 * A fixed-window failure counter, keyed by client address.
 *
 * Kept in memory on purpose: a restart clears it, and the password itself is
 * never weakened by that.
 * @param options - limit, window length and clock.
 */
export function createRateLimiter({ limit = ATTEMPT_LIMIT, windowMs = ATTEMPT_WINDOW_MS, now = Date.now } = {}) {
  const seen = new Map();
  return {
    /**
     * @param key - client address.
     * @returns whether another attempt may be made now.
     */
    allowed(key) {
      const entry = seen.get(key);
      if (entry === undefined) return true;
      if (now() - entry.startedAt >= windowMs) {
        seen.delete(key);
        return true;
      }
      return entry.count < limit;
    },
    /** Record one failure. */
    fail(key) {
      const stamp = now();
      const entry = seen.get(key);
      if (entry === undefined || stamp - entry.startedAt >= windowMs) seen.set(key, { startedAt: stamp, count: 1 });
      else entry.count += 1;
    },
    /** Clear a client's failures after a success. */
    reset(key) {
      seen.delete(key);
    },
    /** Forget every client (a password change or a clear). */
    clear() {
      seen.clear();
    },
    /** Milliseconds until this client may try again, 0 when it may try now. */
    retryAfterMs(key) {
      const entry = seen.get(key);
      if (entry === undefined) return 0;
      const elapsed = now() - entry.startedAt;
      return elapsed >= windowMs ? 0 : windowMs - elapsed;
    },
  };
}

/** The languages this page renders in. Anything else falls back. */
export const PAGE_LOCALES = ['zh', 'en'];

/** The locale used when neither the setting nor the request decides. */
export const FALLBACK_LOCALE = 'en';

/** A BCP 47-style tag; the same shape the locale plugin accepts as a value. */
const LANGUAGE_TAG_RE = /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/;

/**
 * Decide which language to render in.
 *
 * The durable preference wins over the request: a phone opening a recovery link
 * should read what the desktop that configured this machine reads, not whatever
 * language the phone's browser happens to advertise. Only an exact `zh`/`en`
 * preference decides — a missing, malformed or unrecognised one hands the
 * decision to `Accept-Language`, whose *first* tag is the browser's own order of
 * preference (`zh` or `zh-…` means Chinese, anything else means English).
 *
 * @param preference - the `locale.preference` settings value, when one is set.
 * @param acceptLanguage - the request's `Accept-Language` header.
 * @returns `'zh'` or `'en'`, never undefined.
 */
export function pickLocale(preference, acceptLanguage) {
  const chosen = typeof preference === 'string' ? preference.trim().toLowerCase() : '';
  if (chosen === 'zh' || chosen === 'en') return chosen;
  const header = Array.isArray(acceptLanguage) ? acceptLanguage[0] : acceptLanguage;
  const primary = typeof header === 'string' ? header.split(',')[0].split(';')[0].trim().toLowerCase() : '';
  return primary === 'zh' || primary.startsWith('zh-') ? 'zh' : FALLBACK_LOCALE;
}

/**
 * The page's own language, read from the live Web UI settings for one request.
 *
 * `settings` is looked up lazily rather than injected: the host has no `locale`
 * service, and a composition without `settings` must still activate and still
 * serve this page. The value is read per request on purpose — the Web UI
 * language can change while the process runs — and every step is guarded, so a
 * missing service, a missing entry or a throwing one only means "fall back".
 *
 * @param ctx - Host context; only `get` is used.
 * @param req - the incoming request, for its `Accept-Language` header.
 * @returns `'zh'` or `'en'`.
 */
export function requestLocale(ctx, req) {
  let preference;
  try {
    const descriptors = ctx?.get?.('settings')?.describe?.();
    const entry = Array.isArray(descriptors) ? descriptors.find((row) => row?.ns === 'locale') : undefined;
    preference = entry?.value?.preference;
  } catch {
    preference = undefined;
  }
  const header = req?.headers?.['accept-language'];
  return pickLocale(preference, Array.isArray(header) ? header[0] : header);
}

/**
 * Every word this page can show, in both languages.
 *
 * The text lives here rather than in the panel's `lib/client.js`: the panel is a
 * translated browser bundle, while this table is read by the host on the way to
 * a plain HTML response. The two locales must keep exactly the same keys, and
 * two of the keys carry a variant each — see `pageStrings` for which one a
 * render picks.
 */
export const PAGE_STRINGS = {
  en: {
    title: 'dsh · Remote access recovery',
    subtitleConfigured:
      'Enter the recovery password to get a fresh entry link. The password never leaves this phone: this page derives a key with PBKDF2 and answers a one-time challenge with HMAC.',
    subtitleMissing: 'No recovery password is set on this machine.',
    missingPaired:
      'No recovery password is set on this machine. If you paired on a device before, open this address there and it recovers on its own; otherwise set a password on the computer under Settings → Remote Access → Advanced.',
    missingUnpaired:
      'No recovery password is set on this machine. Set one on the computer under Settings → Remote Access → Advanced, or pair again by scanning a QR code.',
    passwordLabel: 'Recovery password',
    buttonLabel: 'Get the entry link',
    wrongLabel: 'That password is not correct.',
    throttledLabel: 'Too many attempts. Wait a few minutes, then try again.',
    failedLabel: 'Something went wrong. Reload this page and try again.',
    successLabel: 'Unlocked. Scan the QR code below with the phone, or open this link to finish pairing:',
    openLabel: 'Open',
    qrLabel: 'QR code for the entry link',
  },
  zh: {
    title: 'dsh · 远程访问恢复',
    subtitleConfigured:
      '输入恢复密码取回入口链接。密码不会离开这台手机：本页用 PBKDF2 派生密钥，再用 HMAC 应答一次性挑战。',
    subtitleMissing: '这台机器没有设置恢复密码。',
    missingPaired:
      '这台机器没有设置恢复密码。如果你曾在某台设备上配对过，用那台设备打开即可自动恢复；否则请在电脑上打开「设置 → 远程访问 → 高级」设置密码。',
    missingUnpaired:
      '这台机器没有设置恢复密码。请在电脑上打开「设置 → 远程访问 → 高级」设置密码，或扫码重新配对。',
    passwordLabel: '恢复密码',
    buttonLabel: '取回入口链接',
    wrongLabel: '密码不正确。',
    throttledLabel: '尝试次数过多。请等几分钟再试。',
    failedLabel: '出了点问题。请刷新本页后重试。',
    successLabel: '已解锁。用手机扫描下面的二维码，或打开这个链接完成配对：',
    openLabel: '打开',
    qrLabel: '入口链接二维码',
  },
};

/**
 * The flat table one render passes to `unlockPageHtml`.
 *
 * @param locale - `'zh'` or `'en'`; anything else renders English.
 * @param kind - `'configured'` (a password is stored), `'missing-paired'` (no
 *   password, but this machine remembers a paired device) or `'missing-unpaired'`
 *   (no password and nothing remembered). An unknown kind is treated as the
 *   latter: it promises the least.
 * @returns every string that render can show, all of them present.
 */
export function pageStrings(locale, kind = 'configured') {
  const text = locale === 'zh' ? PAGE_STRINGS.zh : PAGE_STRINGS.en;
  return {
    title: text.title,
    subtitle: kind === 'configured' ? text.subtitleConfigured : text.subtitleMissing,
    passwordLabel: text.passwordLabel,
    buttonLabel: text.buttonLabel,
    wrongLabel: text.wrongLabel,
    throttledLabel: text.throttledLabel,
    failedLabel: text.failedLabel,
    successLabel: text.successLabel,
    openLabel: text.openLabel,
    qrLabel: text.qrLabel,
    missingLabel: kind === 'missing-paired' ? text.missingPaired : text.missingUnpaired,
  };
}

/**
 * The unlock page: one self-contained document, no external requests.
 *
 * The inline script derives the key with WebCrypto and answers the nonce, so
 * the password is never sent — not even to the Cloudflare edge that terminates
 * TLS in front of this machine. Every word the page or its script can show is
 * passed in, so the host decides the language once per request and the document
 * carries nothing untranslated.
 * @param options - page strings, the document language and the route prefix.
 */
export function unlockPageHtml({
  prefix,
  configured,
  lang,
  title,
  subtitle,
  passwordLabel,
  buttonLabel,
  wrongLabel,
  throttledLabel = PAGE_STRINGS.en.throttledLabel,
  failedLabel = PAGE_STRINGS.en.failedLabel,
  missingLabel,
  successLabel,
  openLabel = PAGE_STRINGS.en.openLabel,
  qrLabel = PAGE_STRINGS.en.qrLabel,
}) {
  const documentLang = typeof lang === 'string' && LANGUAGE_TAG_RE.test(lang) ? lang : FALLBACK_LOCALE;
  const body = configured
    ? `<form id="f">
      <label for="p">${passwordLabel}</label>
      <input id="p" type="password" autocomplete="current-password" required autofocus />
      <button id="go" type="submit">${buttonLabel}</button>
      <p id="msg" role="status"></p>
    </form>
    <div id="done" hidden>
      <p>${successLabel}</p>
      <p><a id="entry" href="#"></a></p>
      <div id="qr"></div>
    </div>`
    : `<p id="msg" role="status">${missingLabel}</p>`;

  return `<!doctype html>
<html lang="${documentLang}">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="referrer" content="no-referrer" />
<title>${title}</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         font: 15px/1.5 system-ui, -apple-system, "Segoe UI", "Noto Sans SC", sans-serif; padding: 24px; }
  main { width: 100%; max-width: 26rem; }
  h1 { font-size: 1.15rem; margin: 0 0 .35rem; }
  p.sub { margin: 0 0 1.1rem; opacity: .72; }
  form { display: grid; gap: .6rem; }
  label { font-size: .9rem; opacity: .8; }
  input { padding: .6rem .7rem; font: inherit; border: 1px solid color-mix(in srgb, currentColor 25%, transparent);
          border-radius: .5rem; background: transparent; color: inherit; }
  button { padding: .6rem .7rem; font: inherit; border: 0; border-radius: .5rem; background: #4d6bfe; color: #fff; cursor: pointer; }
  button[disabled] { opacity: .55; cursor: default; }
  #msg { min-height: 1.3em; margin: .2rem 0 0; font-size: .9rem; }
  #msg.err { color: #e5484d; }
  #qr { margin-top: .8rem; }
  #qr svg { width: 12rem; height: 12rem; background: #fff; border-radius: .5rem; padding: .5rem; }
  a { color: #4d6bfe; word-break: break-all; }
</style>
</head>
<body>
<main>
  <h1>${title}</h1>
  <p class="sub">${subtitle}</p>
  ${body}
</main>
<script>
(function () {
  var PREFIX = ${JSON.stringify(prefix)};
  // Every word this script can show, chosen on the host for this request's
  // language. The script itself never authors user-visible text.
  var TEXT = ${JSON.stringify({ wrongLabel, throttledLabel, failedLabel, openLabel, qrLabel }).replace(/</g, '\\u003c')};
  var form = document.getElementById('f');
  var input = document.getElementById('p');
  var button = document.getElementById('go');
  var msg = document.getElementById('msg');
  function say(text, bad) { msg.textContent = text; msg.className = bad ? 'err' : ''; }
  // ── Best-effort invalidation of a one-time link ────────────────────────────
  // When this page hands out a link that carries *our* temp token (drt_…), this
  // page is the only place that token exists in the clear. If the page then goes
  // away without the link being opened, that link is a live credential nobody is
  // looking at, so the page tells the host to burn it. The 15-minute expiry is
  // still the real control; this only shortens the window when the page really
  // closes.
  //
  // Rules this code keeps: it never blocks the navigation, never throws, never
  // shows anything, fires at most once, sends the token in a JSON *body* (never
  // in a URL), and does nothing at all unless a link was minted on this page.
  var pendingToken = null;
  var beaconSent = false;
  function closeLink() {
    if (beaconSent || !pendingToken) return;
    beaconSent = true;
    var payload = JSON.stringify({ token: pendingToken });
    var url = PREFIX + '/page-close';
    // sendBeacon is the one request that survives page teardown; the JSON blob
    // is what makes the host accept it (a text/plain body is refused).
    try {
      if (navigator.sendBeacon && navigator.sendBeacon(url, new Blob([payload], { type: 'application/json' }))) return;
    } catch (error) {}
    try {
      fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: payload, keepalive: true, credentials: 'same-origin' });
    } catch (error) {}
  }
  function armClose(url) {
    try {
      if (pendingToken || typeof url !== 'string') return;
      var token = new URL(url, window.location.href).searchParams.get('token') || '';
      // Only our own one-time links: the platform's launch token is not ours to
      // burn, and a clean URL means no link was minted here at all.
      if (token.indexOf('drt_') !== 0) return;
      pendingToken = token;
      window.addEventListener('pagehide', closeLink);
      // Fallback for browsers that skip pagehide when a tab is discarded.
      document.addEventListener('visibilitychange', function () {
        if (document.visibilityState === 'hidden') closeLink();
      });
    } catch (error) {}
  }
  function b64(buf) { var s = ''; new Uint8Array(buf).forEach(function (b) { s += String.fromCharCode(b); }); return btoa(s); }
  function fromB64(text) { var raw = atob(text); var out = new Uint8Array(raw.length); for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i); return out; }
  // An answer is { ok: true, value } or { ok: false, error: { code, message } }.
  function value(answer) {
    if (!answer || answer.ok !== true) return undefined;
    return answer.value && typeof answer.value === 'object' ? answer.value : {};
  }
  // The refusal *code* picks the text, never the wire message: the host answers
  // in one language and this page renders in another.
  function reason(answer) {
    var code = answer && answer.error && answer.error.code;
    if (code === 'remote-access/recovery-denied') return TEXT.wrongLabel;
    if (code === 'remote-access/recovery-throttled') return TEXT.throttledLabel;
    return TEXT.failedLabel;
  }
  async function ask(path, body) {
    var answer = await (await fetch(PREFIX + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body })).json();
    return { answer: answer, value: value(answer) };
  }
  // The host answers with the same { size, bits } matrix the panel renders; this
  // page turns it into the SVG it shows. A string answer (an older host) is
  // passed through untouched, so either shape renders.
  function qrMarkup(qr) {
    if (typeof qr === 'string') return qr;
    var size = qr && qr.size;
    var bits = qr && qr.bits;
    if (!size || typeof bits !== 'string' || bits.length !== size * size) return '';
    var quiet = 4;
    var total = size + quiet * 2;
    var path = '';
    for (var y = 0; y < size; y += 1) {
      for (var x = 0; x < size; x += 1) {
        if (bits[y * size + x] === '1') path += 'M' + (x + quiet) + ' ' + (y + quiet) + 'h1v1h-1z';
      }
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + total + ' ' + total + '" shape-rendering="crispEdges" role="img" aria-label="' + TEXT.qrLabel + '"><rect width="' + total + '" height="' + total + '" fill="#fff"/><path d="' + path + '" fill="#000"/></svg>';
  }
  // Show the entry link and its QR, and arm the close beacon if that link is a
  // one-time link this page just minted.
  function showEntry(entry) {
    if (form) form.hidden = true;
    var done = document.getElementById('done');
    if (done) done.hidden = false;
    var link = document.getElementById('entry');
    if (link) { link.href = entry.url; link.textContent = entry.url; link.setAttribute('aria-label', TEXT.openLabel); }
    var qr = document.getElementById('qr');
    if (qr) qr.innerHTML = qrMarkup(entry.qr);
    armClose(entry.url);
  }
  // Show the entry link, then go there. The URL carries this plugin's own
  // one-time token (or, for a device that already has a credential, no token at
  // all), so following it lands inside the app — which is the whole point of a
  // one-time link. The link and its QR stay on screen underneath, so a blocked
  // navigation is still usable, and a second device can scan it.
  function enter(entry) {
    showEntry(entry);
    try { window.location.replace(entry.url); } catch (error) {}
  }
  // The pairing door. It exists for a device that has no session at all, so it
  // must work with no password armed — and when it is reached from a QR code,
  // the code is in this page's own query string.
  async function redeemPairCode(code) {
    try {
      var got = await ask('/unlock/pair', JSON.stringify({ code: code }));
      if (got.value === undefined || typeof got.value.url !== 'string') { say(reason(got.answer), true); return; }
      enter(got.value);
    } catch (error) {
      say(String(error && error.message ? error.message : error), true);
    }
  }
  if (form) form.addEventListener('submit', async function (event) {
    event.preventDefault();
    button.disabled = true;
    say('');
    try {
      var asked = await ask('/unlock/challenge', '{}');
      var challenge = asked.value;
      if (!challenge || typeof challenge.salt !== 'string' || typeof challenge.nonce !== 'string' || typeof challenge.iterations !== 'number') throw new Error(reason(asked.answer));
      var material = await crypto.subtle.importKey('raw', new TextEncoder().encode(input.value), 'PBKDF2', false, ['deriveBits']);
      var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: fromB64(challenge.salt), iterations: challenge.iterations, hash: 'SHA-256' }, material, 256);
      var hmac = await crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      var proof = b64(await crypto.subtle.sign('HMAC', hmac, fromB64(challenge.nonce)));
      var verified = await ask('/unlock/verify', JSON.stringify({ nonce: challenge.nonce, proof: proof }));
      if (verified.value === undefined) { say(reason(verified.answer), true); button.disabled = false; return; }
      input.value = '';
      // The verify answer already carries the one-time link; /unlock/entry is the
      // fallback for a host that answers without one.
      var entry = typeof verified.value.url === 'string' ? verified.value : undefined;
      if (entry === undefined) {
        var got = await ask('/unlock/entry', '{}');
        entry = got.value;
      }
      if (!entry || typeof entry.url !== 'string') { say(reason(verified.answer), true); button.disabled = false; return; }
      showEntry(entry);
    } catch (error) {
      say(String(error && error.message ? error.message : error), true);
      button.disabled = false;
    }
  });
  // A code in the query string is the QR path: redeem it and go in. This runs
  // whether or not a password is armed — with none, there is no form at all, and
  // the page would otherwise just say so while the phone stays outside.
  var code = '';
  try { code = new URLSearchParams(window.location.search).get('code') || ''; } catch (error) { code = ''; }
  if (code) redeemPairCode(code);
})();
</script>
</body>
</html>`;
}

/**
 * Render a QR code as a standalone SVG.
 *
 * Takes the same `{ size, bits }` shape the panel renders: `bits` is a row-major
 * string of '0'/'1', one character per module.
 * @param qr - the encoder's output.
 * @param options - quiet-zone width in modules and an accessible label.
 */
export function qrSvg(qr, { quiet = 4, label = 'QR' } = {}) {
  const size = qr?.size;
  const bits = qr?.bits;
  if (!Number.isSafeInteger(size) || size <= 0 || typeof bits !== 'string' || bits.length !== size * size) return '';
  const total = size + quiet * 2;
  let path = '';
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      if (bits[y * size + x] === '1') path += `M${x + quiet} ${y + quiet}h1v1h-1z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges" role="img" aria-label="${label}"><rect width="${total}" height="${total}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
}
