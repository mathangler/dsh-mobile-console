/**
 * dsh-remote-access — access keys and one-time temp tokens.
 *
 * Two credentials live here, and both are pure: nothing in this module touches
 * a socket, a credential store or the clock unless the caller passes one in.
 *
 *  - An **access key** is a durable secret a person creates in the panel and
 *    types (or pastes) on a browser that has lost its platform cookie. It is 32
 *    random bytes in base64url behind a short readable prefix, so a key is
 *    recognisable in a log or a screenshot without giving anything away. Only
 *    its sha256 fingerprint is ever stored.
 *  - A **temp token** is the single-use ticket inside the one-time entry link
 *    the password door and the access-key door hand back. It is redeemable
 *    exactly once at the root gate, and it stops working 15 minutes after it
 *    was minted whether or not it was used.
 *
 * The prefix is not a secret and is not a checksum: it exists so that a value
 * offered where a key belongs can be recognised as "not a key" before any
 * comparison happens, and so the two credential kinds can never be confused for
 * one another.
 *
 * Nothing here duplicates `lib/unlock.js`: the pairing-code alphabet, the ticket
 * signer and the day-to-expiry arithmetic stay there, and the host half imports
 * them from it.
 *
 * @module dsh-remote-access/accesskey
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** The readable prefix every access key carries. */
export const ACCESS_KEY_PREFIX = 'dra_';

/** Random bytes behind that prefix. 32 bytes is 256 bits, 43 base64url chars. */
export const ACCESS_KEY_BYTES = 32;

/**
 * The shape of the random part of a key or a temp token.
 *
 * Generous on length on purpose — this is an admission test, not a parser: a
 * short or padded value is simply not a credential this plugin ever minted, and
 * refusing it here keeps it out of the comparison loop.
 */
export const CREDENTIAL_BODY_RE = /^[A-Za-z0-9_-]{16,}$/;

/** The readable prefix every temp token carries. */
export const TEMP_TOKEN_PREFIX = 'drt_';

/** Random bytes inside a temp token. */
export const TEMP_TOKEN_BYTES = 32;

/** How long a temp token stays redeemable. */
export const TEMP_TOKEN_MINUTES = 15;

/** The same lifetime in milliseconds. */
export const TEMP_TOKEN_TTL_MS = TEMP_TOKEN_MINUTES * 60 * 1000;

/** Unguessable random text, base64url so it survives a URL and a QR code. */
function randomToken(bytes) {
  return randomBytes(bytes).toString('base64url');
}

/** The stored fingerprint of one credential; the credential itself is never stored. */
function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

/**
 * Constant-time comparison of a value against a stored fingerprint.
 *
 * The hash of the presented value is what is compared, so the comparison is
 * over two 32-byte digests and leaks nothing about the secret. A malformed
 * stored fingerprint is a miss, never a throw.
 */
function matchesFingerprint(value, hash) {
  if (typeof value !== 'string' || value === '' || typeof hash !== 'string' || !/^[0-9a-f]{64}$/i.test(hash)) return false;
  const presented = Buffer.from(fingerprint(value), 'hex');
  const stored = Buffer.from(hash, 'hex');
  if (presented.length === 0 || presented.length !== stored.length) return false;
  return timingSafeEqual(presented, stored);
}

/** A fresh access key, e.g. `dra_9f3c…`. The caller must show it once and store only its hash. */
export function newAccessKey() {
  return `${ACCESS_KEY_PREFIX}${randomToken(ACCESS_KEY_BYTES)}`;
}

/**
 * Normalize a typed or pasted access key.
 *
 * Whitespace is stripped — a key read off a screen arrives wrapped, hyphenated
 * or with a stray space — and the prefix is required exactly as minted. Nothing
 * is case-folded: base64url is case-sensitive, so "fixing" case here would
 * silently look up a different key.
 * @param value - what the page sent.
 * @returns the canonical key, or undefined when it cannot be one.
 */
export function normalizeAccessKey(value) {
  if (typeof value !== 'string') return undefined;
  const cleaned = value.replace(/\s+/g, '');
  if (cleaned === '' || !cleaned.startsWith(ACCESS_KEY_PREFIX)) return undefined;
  return CREDENTIAL_BODY_RE.test(cleaned.slice(ACCESS_KEY_PREFIX.length)) ? cleaned : undefined;
}

/** Whether one value has the shape of an access key. */
export function isAccessKey(value) {
  return normalizeAccessKey(value) !== undefined;
}

/** The stored fingerprint of an access key; the key itself is never stored. */
export function hashAccessKey(key) {
  const normalized = normalizeAccessKey(key);
  return normalized === undefined ? undefined : fingerprint(normalized);
}

/**
 * Constant-time comparison of a presented access key against a stored fingerprint.
 * @param presented - the key from the request body.
 * @param hash - the stored sha256 hex digest.
 */
export function accessKeyMatches(presented, hash) {
  const normalized = normalizeAccessKey(presented);
  return normalized === undefined ? false : matchesFingerprint(normalized, hash);
}

/** A fresh single-use temp token, e.g. `drt_…`. */
export function newTempToken() {
  return `${TEMP_TOKEN_PREFIX}${randomToken(TEMP_TOKEN_BYTES)}`;
}

/** Normalize a temp token; same rules as an access key, different prefix. */
export function normalizeTempToken(value) {
  if (typeof value !== 'string') return undefined;
  const cleaned = value.trim();
  if (!cleaned.startsWith(TEMP_TOKEN_PREFIX)) return undefined;
  return CREDENTIAL_BODY_RE.test(cleaned.slice(TEMP_TOKEN_PREFIX.length)) ? cleaned : undefined;
}

/** Whether one value has the shape of a temp token. */
export function isTempToken(value) {
  return normalizeTempToken(value) !== undefined;
}

/** The stored fingerprint of a temp token; the token itself is never stored. */
export function hashTempToken(token) {
  const normalized = normalizeTempToken(token);
  return normalized === undefined ? undefined : fingerprint(normalized);
}

/** Constant-time comparison of a presented temp token against a stored fingerprint. */
export function tempTokenMatches(presented, hash) {
  const normalized = normalizeTempToken(presented);
  return normalized === undefined ? false : matchesFingerprint(normalized, hash);
}

/** When a temp token minted now stops working. */
export function tempTokenExpiry(now = Date.now()) {
  return now + TEMP_TOKEN_TTL_MS;
}

/**
 * A fresh record id.
 *
 * Deliberately random rather than a slice of the credential's fingerprint: the
 * id is returned to every client, and a fingerprint prefix would publish the
 * first 16 hex digits of the one value that must never leave the host.
 */
export function newRecordId() {
  return randomBytes(8).toString('hex');
}
