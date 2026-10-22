/**
 * dsh-mobile-console — the password-protected recovery door.
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
 * @module dsh-mobile-console/unlock
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

/**
 * The unlock page: one self-contained document, no external requests.
 *
 * The inline script derives the key with WebCrypto and answers the nonce, so
 * the password is never sent — not even to the Cloudflare edge that terminates
 * TLS in front of this machine.
 * @param options - page strings and the route prefix.
 */
export function unlockPageHtml({ prefix, configured, title, subtitle, passwordLabel, buttonLabel, wrongLabel, missingLabel, successLabel, openLabel }) {
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
<html lang="zh">
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
  var form = document.getElementById('f');
  if (!form) return;
  var input = document.getElementById('p');
  var button = document.getElementById('go');
  var msg = document.getElementById('msg');
  function say(text, bad) { msg.textContent = text; msg.className = bad ? 'err' : ''; }
  function b64(buf) { var s = ''; new Uint8Array(buf).forEach(function (b) { s += String.fromCharCode(b); }); return btoa(s); }
  function fromB64(text) { var raw = atob(text); var out = new Uint8Array(raw.length); for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i); return out; }
  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    button.disabled = true;
    say('');
    try {
      var challenge = await (await fetch(PREFIX + '/unlock/challenge', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).json();
      if (!challenge || challenge.ok !== true) throw new Error((challenge && challenge.message) || 'challenge failed');
      var material = await crypto.subtle.importKey('raw', new TextEncoder().encode(input.value), 'PBKDF2', false, ['deriveBits']);
      var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: fromB64(challenge.salt), iterations: challenge.iterations, hash: 'SHA-256' }, material, 256);
      var hmac = await crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      var proof = b64(await crypto.subtle.sign('HMAC', hmac, fromB64(challenge.nonce)));
      var result = await (await fetch(PREFIX + '/unlock/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nonce: challenge.nonce, proof: proof }) })).json();
      if (!result || result.ok !== true) { say((result && result.message) || ${JSON.stringify(wrongLabel)}, true); button.disabled = false; return; }
      input.value = '';
      var entry = await (await fetch(PREFIX + '/unlock/entry', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).json();
      if (!entry || entry.ok !== true) { say((entry && entry.message) || 'entry failed', true); button.disabled = false; return; }
      document.getElementById('f').hidden = true;
      var done = document.getElementById('done');
      done.hidden = false;
      var link = document.getElementById('entry');
      link.href = entry.url;
      link.textContent = entry.url;
      document.getElementById('qr').innerHTML = entry.qr;
    } catch (error) {
      say(String(error && error.message ? error.message : error), true);
      button.disabled = false;
    }
  });
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
