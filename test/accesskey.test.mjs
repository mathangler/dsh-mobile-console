// Access-key, one-time-link and authorized-device tests: key minting and
// timing-safe matching, the temp-token bookkeeping, the legacy -> v2 row
// migration, the derived status, and the "never delete a still-valid row" rule.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACCESS_KEY_PREFIX,
  CREDENTIAL_BODY_RE,
  TEMP_TOKEN_MINUTES,
  TEMP_TOKEN_PREFIX,
  TEMP_TOKEN_TTL_MS,
  accessKeyMatches,
  hashAccessKey,
  hashTempToken,
  isAccessKey,
  isTempToken,
  newAccessKey,
  newRecordId,
  newTempToken,
  normalizeAccessKey,
  normalizeTempToken,
  tempTokenExpiry,
  tempTokenMatches,
} from '../lib/accesskey.js';
import {
  UNLOCK_COOKIE,
  deriveKey,
  expiryFromDays,
  newNonce,
  newSalt,
  proofFor,
  signTicket,
  unlockPageHtml,
  verifyProof,
} from '../lib/unlock.js';
import {
  ACCESS_KEYS_RECORD_KEY,
  DEVICES_V2_RECORD_KEY,
  DEVICE_RECORD_KEY,
  ENTRY_LINK_DAYS,
  apply,
  CHANNEL,
  deviceDeletable,
  deviceStatus,
  localDialTarget,
  migrateLegacyDeviceRows,
  modeFromBindHost,
  parseDeviceRows,
  patchRowConfig,
  publicDeviceRow,
  publicKeyRow,
  reachabilityOf,
  readRowConfigList,
  resolveLinkBase,
  storablePayload,
} from '../lib/index.js';

const DAY = 24 * 60 * 60 * 1000;

test('mints access keys with a readable prefix and stores only a fingerprint', () => {
  const key = newAccessKey();
  assert.ok(key.startsWith(ACCESS_KEY_PREFIX), 'a key is recognisable at a glance');
  assert.equal(key.length, ACCESS_KEY_PREFIX.length + 43, '32 random bytes in base64url');
  assert.match(key.slice(ACCESS_KEY_PREFIX.length), /^[A-Za-z0-9_-]+$/);
  assert.notEqual(key, newAccessKey(), 'every key is unique');
  assert.equal(isAccessKey(key), true);

  const hash = hashAccessKey(key);
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.ok(!hash.includes(key), 'the key cannot be recovered from its fingerprint');
  assert.equal(hashAccessKey(key), hash, 'hashing is deterministic');
  assert.notEqual(hashAccessKey(newAccessKey()), hash);
  assert.equal(hashAccessKey('not-a-key'), undefined);
  assert.equal(hashAccessKey(''), undefined);
  assert.equal(hashAccessKey(undefined), undefined);
});

test('matches an access key in constant time and rejects everything else', () => {
  const key = newAccessKey();
  const hash = hashAccessKey(key);
  assert.equal(accessKeyMatches(key, hash), true);
  assert.equal(accessKeyMatches(`${key}x`, hash), false, 'a longer key is a different key');
  assert.equal(accessKeyMatches(key.slice(0, -1), hash), false);
  assert.equal(accessKeyMatches(key, hashAccessKey(newAccessKey())), false);
  assert.equal(accessKeyMatches(key, 'not-a-fingerprint'), false, 'a malformed stored hash is a miss, not a throw');
  assert.equal(accessKeyMatches(key, ''), false);
  assert.equal(accessKeyMatches('', hash), false);
  assert.equal(accessKeyMatches(undefined, hash), false);
  assert.equal(accessKeyMatches(null, hash), false);
  assert.equal(accessKeyMatches(42, hash), false);
  // Whitespace is the one thing that may be tidied: a key gets read off a screen.
  assert.equal(accessKeyMatches(`  ${key.slice(0, 20)}\n${key.slice(20)} `, hash), true);
  assert.equal(accessKeyMatches(key.toUpperCase().replace(ACCESS_KEY_PREFIX, ACCESS_KEY_PREFIX), hash), false);
  // The prefix is required: a bare body is not a key this plugin minted.
  assert.equal(accessKeyMatches(key.slice(ACCESS_KEY_PREFIX.length), hash), false);
});

test('normalizes a pasted key without ever case-folding it', () => {
  const key = newAccessKey();
  assert.equal(normalizeAccessKey(key), key);
  assert.equal(normalizeAccessKey(` ${key} `), key);
  assert.equal(normalizeAccessKey(key.replace(/(.{10})/, '$1 ')), key, 'a line break in the middle is stripped');
  assert.equal(normalizeAccessKey(undefined), undefined);
  assert.equal(normalizeAccessKey(null), undefined);
  assert.equal(normalizeAccessKey(''), undefined);
  assert.equal(normalizeAccessKey('   '), undefined);
  assert.equal(normalizeAccessKey('dra_'), undefined, 'a prefix with no body is not a key');
  assert.equal(normalizeAccessKey('dra_short'), undefined);
  assert.equal(normalizeAccessKey('DRA_abcdefghijklmnopqrstuvwxyz0123456789abc'), undefined, 'the prefix is not case-folded');
  assert.equal(normalizeAccessKey('xyz_abcdefghijklmnopqrstuvwxyz0123456789abc'), undefined, 'the prefix is required');
  assert.ok(CREDENTIAL_BODY_RE.test('a'.repeat(16)));
});

test('mints single-use temp tokens that expire in fifteen minutes', () => {
  const token = newTempToken();
  assert.ok(token.startsWith(TEMP_TOKEN_PREFIX));
  assert.equal(token.length, TEMP_TOKEN_PREFIX.length + 43);
  assert.notEqual(token, newTempToken());
  assert.equal(isTempToken(token), true);
  // The two credential kinds can never be confused for one another.
  assert.equal(isTempToken(newAccessKey()), false);
  assert.equal(isAccessKey(token), false);

  assert.equal(normalizeTempToken(token), token);
  assert.equal(normalizeTempToken(` ${token} `), token);
  assert.equal(normalizeTempToken(''), undefined);
  assert.equal(normalizeTempToken(undefined), undefined);
  assert.equal(normalizeTempToken(newAccessKey()), undefined);

  const hash = hashTempToken(token);
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(tempTokenMatches(token, hash), true);
  assert.equal(tempTokenMatches(`${token}x`, hash), false);
  assert.equal(tempTokenMatches(token, hashTempToken(newTempToken())), false);
  assert.equal(tempTokenMatches('', hash), false);
  assert.equal(tempTokenMatches(undefined, hash), false);
  assert.equal(tempTokenMatches(token, undefined), false);
  assert.equal(hashTempToken('nonsense'), undefined);

  assert.equal(TEMP_TOKEN_MINUTES, 15);
  assert.equal(TEMP_TOKEN_TTL_MS, 15 * 60 * 1000);
  assert.equal(tempTokenExpiry(1_000_000), 1_000_000 + TEMP_TOKEN_TTL_MS);
});

test('turns a day count into an absolute expiry, and null into never', () => {
  const now = 1_700_000_000_000;
  assert.equal(expiryFromDays(null, now), null, 'null means never expires');
  assert.equal(expiryFromDays(undefined, now), null);
  assert.equal(expiryFromDays(30, now), now + 30 * DAY);
  assert.equal(expiryFromDays('30', now), now + 30 * DAY, 'a form value arrives as a string');
  assert.equal(expiryFromDays(1, now), now + DAY);
  // Zero, negative and unparsable day counts are "never", never "already expired".
  assert.equal(expiryFromDays(0, now), null);
  assert.equal(expiryFromDays(-3, now), null);
  assert.equal(expiryFromDays('soon', now), null);
});

test('derives one status from a row, with no sliding renewal anywhere', () => {
  const now = 5_000_000;
  assert.equal(deviceStatus({ expiresAt: null }, now), 'never');
  assert.equal(deviceStatus({}, now), 'never');
  assert.equal(deviceStatus({ expiresAt: undefined }, now), 'never');
  assert.equal(deviceStatus({ expiresAt: Number.NaN }, now), 'never');
  assert.equal(deviceStatus({ expiresAt: now + 1 }, now), 'valid');
  assert.equal(deviceStatus({ expiresAt: now + 30 * DAY }, now), 'valid');
  assert.equal(deviceStatus({ expiresAt: now }, now), 'expired', 'the instant itself is already past');
  assert.equal(deviceStatus({ expiresAt: now - 1 }, now), 'expired');
  // Reading a row never changes it: the expiry is what was set, not what was used.
  const row = { expiresAt: now + DAY };
  deviceStatus(row, now + 2 * DAY);
  assert.equal(row.expiresAt, now + DAY);
  assert.deepEqual(row, { expiresAt: now + DAY });
});

test('never lets a still-valid device be deleted', () => {
  const now = 5_000_000;
  assert.equal(deviceDeletable({ expiresAt: now - 1 }, now), true, 'an expired row is tidy-up');
  assert.equal(deviceDeletable({ expiresAt: now }, now), true);
  assert.equal(deviceDeletable({ expiresAt: now + 1 }, now), false, 'a live row must be revoked first');
  assert.equal(deviceDeletable({ expiresAt: null }, now), false, 'a never-expiring row is valid forever');
  assert.equal(deviceDeletable({}, now), false);
});

test('hands the panel every device field except the fingerprint', () => {
  const now = 5_000_000;
  const row = {
    id: 'a1',
    name: 'iPhone',
    source: 'access-key',
    temporary: true,
    createdAt: new Date(now).toISOString(),
    lastUsedAt: null,
    lastUsedIp: '10.0.0.9',
    expiresAt: now + 15 * 60 * 1000,
    days: null,
    hash: 'f'.repeat(64),
  };
  const shown = publicDeviceRow(row, now);
  assert.ok(!('hash' in shown), 'the fingerprint must never cross the wire');
  assert.equal(JSON.stringify(shown).includes('f'.repeat(64)), false);
  assert.equal(shown.id, 'a1');
  assert.equal(shown.source, 'access-key');
  assert.equal(shown.temporary, true);
  assert.equal(shown.lastUsedIp, '10.0.0.9');
  assert.equal(shown.status, 'valid');
  assert.equal(row.hash, 'f'.repeat(64), 'the stored row is untouched');

  const key = { id: 'k1', name: 'Phone', hash: 'a'.repeat(64), createdAt: 'x', expiresAt: null, days: null, lastUsedAt: null };
  const shownKey = publicKeyRow(key, now);
  assert.deepEqual(shownKey, { id: 'k1', name: 'Phone', createdAt: 'x', expiresAt: null, days: null, status: 'never', lastUsedAt: null });
  assert.ok(!('hash' in shownKey));
});

test('reads only well-formed rows out of a stored payload', () => {
  assert.deepEqual(parseDeviceRows(undefined), []);
  assert.deepEqual(parseDeviceRows({ version: 2 }), []);
  assert.deepEqual(parseDeviceRows({ devices: 'nope' }), []);
  assert.deepEqual(parseDeviceRows({ devices: [null, 'x', {}, { id: 'a' }, { hash: 'h' }, { id: 'a', hash: 'h' }] }), [{ id: 'a', hash: 'h' }]);
});

test('migrates the legacy token rows into v2, once, without touching them', () => {
  const now = 10_000_000;
  const legacy = [
    { id: 'abc123', hash: 'h1', label: 'iPhone · Safari', createdAt: new Date(now - DAY).toISOString(), lastUsedAt: new Date(now - 1000).toISOString(), expiresAt: now + 365 * DAY, days: 365 },
    // No id: the old code minted the id from the fingerprint, so the same value
    // is derived here and a second run cannot duplicate the row.
    { hash: 'h2'.padEnd(64, '0'), name: 'Named', days: null, expiresAt: null },
    // Malformed rows are skipped rather than invented.
    null,
    { id: 'no-hash' },
  ];
  const first = migrateLegacyDeviceRows([], legacy, now);
  assert.equal(first.added, 2);
  assert.equal(first.rows.length, 2);
  const [a, b] = first.rows;
  assert.equal(a.id, 'abc123');
  assert.equal(a.name, 'iPhone · Safari', 'the v1 label becomes the v2 name');
  assert.equal(a.source, 'entry-link');
  assert.equal(a.temporary, false);
  assert.equal(a.hash, 'h1');
  assert.equal(a.days, 365);
  assert.equal(a.expiresAt, now + 365 * DAY);
  assert.equal(b.id, 'h2'.padEnd(64, '0').slice(0, 16), 'the id is derived deterministically from the fingerprint');
  assert.equal(b.name, 'Named');
  assert.equal(b.days, null);
  assert.equal(b.expiresAt, null, 'a null expiry stays "never"');
  assert.equal(b.createdAt, new Date(now).toISOString(), 'a missing stamp is filled in, not invented as garbage');

  // Idempotent: running again over the result adds nothing.
  const second = migrateLegacyDeviceRows(first.rows, legacy, now);
  assert.equal(second.added, 0);
  assert.deepEqual(second.rows, first.rows);

  // A newer row under the same fingerprint or id is never overwritten.
  const current = [{ id: 'abc123', hash: 'h1', name: 'Renamed by the user', source: 'device-code', temporary: false, createdAt: 'then', lastUsedAt: 'then', expiresAt: null, days: null }];
  const third = migrateLegacyDeviceRows(current, legacy, now);
  assert.equal(third.added, 1, 'the unseen row is added');
  assert.equal(third.rows.find((row) => row.id === 'abc123').name, 'Renamed by the user');
  assert.equal(third.rows.find((row) => row.id === 'abc123').source, 'device-code');
  assert.equal(third.rows.find((row) => row.id === 'abc123').expiresAt, null);
  // An empty legacy record changes nothing at all.
  assert.deepEqual(migrateLegacyDeviceRows(current, [], now), { rows: current, added: 0 });
  assert.deepEqual(migrateLegacyDeviceRows(current, undefined, now).added, 0);
});

test('derives the mode from the address the listener is bound to', () => {
  assert.equal(modeFromBindHost('127.0.0.1'), 'public');
  assert.equal(modeFromBindHost('127.0.0.1:3080'), 'public');
  assert.equal(modeFromBindHost('localhost'), 'public');
  assert.equal(modeFromBindHost('::1'), 'public');
  assert.equal(modeFromBindHost('[::1]'), 'public');
  assert.equal(modeFromBindHost('0.0.0.0'), 'public', 'a wildcard is never a LAN bind');
  assert.equal(modeFromBindHost('::'), 'public');
  assert.equal(modeFromBindHost('10.0.161.47'), 'lan');
  assert.equal(modeFromBindHost('192.168.1.20'), 'lan');
  assert.equal(modeFromBindHost(' 10.0.161.47 '), 'lan');
  assert.equal(modeFromBindHost(''), 'public');
  assert.equal(modeFromBindHost(undefined), 'public');
});

test('resolves link authorities in order, and says how far they reach', () => {
  const lan = { bindHost: '10.0.161.47', port: 3080, requestHost: '10.0.161.47:3080', requestScheme: 'http', tunnelRunning: true };
  const loopback = { bindHost: '127.0.0.1', port: 3080, requestHost: '127.0.0.1:3080', requestScheme: 'http', tunnelRunning: true };

  // (a) An advertised public URL wins over everything, scheme as configured.
  assert.deepEqual(resolveLinkBase({ ...loopback, publicUrl: 'https://dsh.example.com/', tunnelHost: 'other.example.com' }), {
    base: 'dsh.example.com',
    scheme: 'https',
    reachable: 'public',
  });
  assert.deepEqual(resolveLinkBase({ ...lan, publicUrl: 'https://dsh.example.com:8443/mount' }), {
    base: 'dsh.example.com:8443',
    scheme: 'https',
    reachable: 'public',
  });
  // An advertised URL that only names this machine is reported as such, so the
  // panel can warn instead of printing a link a phone cannot open.
  assert.deepEqual(resolveLinkBase({ publicUrl: 'http://127.0.0.1:3080/' }), {
    base: '127.0.0.1:3080',
    scheme: 'http',
    reachable: 'loopback-only',
  });
  assert.equal(resolveLinkBase({ publicUrl: 'http://10.0.161.47:3080', tunnelRunning: true }).reachable, 'lan');
  // A scheme-less advertised name is a public one, so it gets https.
  assert.deepEqual(resolveLinkBase({ publicUrl: 'dsh.example.com', tunnelRunning: true }), {
    base: 'dsh.example.com',
    scheme: 'https',
    reachable: 'public',
  });

  // (b) No advertised URL: the configured tunnel hostname, always https.
  assert.deepEqual(resolveLinkBase({ ...loopback, tunnelHost: 'dsh.example.com' }), {
    base: 'dsh.example.com',
    scheme: 'https',
    reachable: 'public',
  });
  assert.deepEqual(resolveLinkBase({ tunnelHost: 'dsh.example.com:8443', tunnelRunning: true }), {
    base: 'dsh.example.com:8443',
    scheme: 'https',
    reachable: 'public',
  });
  // A hostname that cannot be an authority is skipped rather than emitted.
  assert.equal(resolveLinkBase({ ...loopback, tunnelHost: 'https://dsh.example.com/x' }).base, '127.0.0.1:3080');

  // (c) No tunnel: a non-loopback bind is LAN mode, so the LAN address beats the
  // request's own Host — which is exactly the desktop-panel case.
  assert.deepEqual(resolveLinkBase({ ...lan, requestHost: '127.0.0.1:3080' }), {
    base: '10.0.161.47:3080',
    scheme: 'http',
    reachable: 'lan',
  });
  assert.deepEqual(resolveLinkBase({ bindHost: 'fe80::1', port: 3080 }), {
    base: '[fe80::1]:3080',
    scheme: 'http',
    reachable: 'lan',
  });

  // (d) Last resort: the request's own Host and scheme.
  assert.deepEqual(resolveLinkBase({ ...loopback, requestHost: 'dsh.example.com', requestScheme: 'https' }), {
    base: 'dsh.example.com',
    scheme: 'https',
    reachable: 'public',
  });
  assert.equal(resolveLinkBase({ ...loopback, requestHost: '10.0.161.32:3080' }).reachable, 'lan');
  assert.deepEqual(resolveLinkBase({ ...loopback, requestHost: '', requestScheme: 'https' }), {
    base: '127.0.0.1:3080',
    scheme: 'https',
    reachable: 'loopback-only',
  });
  assert.deepEqual(resolveLinkBase({}), { base: '127.0.0.1:3080', scheme: 'http', reachable: 'loopback-only' });
  assert.equal(resolveLinkBase({ bindHost: '10.0.161.47', port: Number.NaN }).base, '10.0.161.47:3080', 'a nonsense port falls back');
  assert.equal(resolveLinkBase({ bindHost: '10.0.161.47', port: 0 }).base, '10.0.161.47:3080');
});

test('names the authority it can serve, and says how far that authority reaches', () => {
  const tunnel = 'dsh.example.com';
  const lanBind = '10.0.161.47';
  // The verdict has to describe the URL that came with it: a link the plugin
  // calls `loopback-only` while its own QR encodes a tunnel host is a link the
  // panel warns about for no reason — or stays quiet about when it matters.
  const agrees = (input, base, reachable) => {
    const resolved = resolveLinkBase(input);
    assert.equal(resolved.base, base, `base for ${JSON.stringify(input)}`);
    assert.equal(resolved.reachable, reachable, `verdict for ${JSON.stringify(input)}`);
    assert.equal(reachabilityOf(resolved.base), resolved.reachable, 'the verdict matches the authority named');
    return resolved;
  };

  // A configured public base is the link only while something serves it.
  agrees({ tunnelHost: tunnel, tunnelRunning: true }, tunnel, 'public');
  agrees({ publicUrl: `https://${tunnel}/`, tunnelRunning: true }, tunnel, 'public');
  // Down, it is not the link at all: the URL names what can actually answer.
  agrees({ tunnelHost: tunnel, tunnelRunning: false }, '127.0.0.1:3080', 'loopback-only');
  agrees({ publicUrl: `https://${tunnel}/`, tunnelRunning: false }, '127.0.0.1:3080', 'loopback-only');
  agrees({ tunnelHost: tunnel, tunnelRunning: false, bindHost: lanBind }, `${lanBind}:3080`, 'lan');
  agrees({ publicUrl: `https://${tunnel}/`, tunnelRunning: false, bindHost: '192.168.31.186' }, '192.168.31.186:3080', 'lan');
  agrees({ tunnelHost: tunnel }, '127.0.0.1:3080', 'loopback-only');
  // The request's own authority is never gated: being answered on it is proof.
  agrees({ tunnelHost: tunnel, tunnelRunning: false, requestHost: lanBind, requestScheme: 'http' }, lanBind, 'lan');
  agrees({ tunnelHost: tunnel, tunnelRunning: false, requestHost: tunnel, requestScheme: 'https' }, tunnel, 'public');
  // And LAN mode keeps its own answer with no tunnel in the picture.
  agrees({ bindHost: lanBind, port: 3080, tunnelRunning: false }, `${lanBind}:3080`, 'lan');
  agrees({ bindHost: '192.168.31.186', port: 3199, requestHost: '127.0.0.1:3199', tunnelRunning: false }, '192.168.31.186:3199', 'lan');
});

test('dials the listener it is actually bound to', () => {
  assert.deepEqual(localDialTarget('127.0.0.1', 3080), { host: '127.0.0.1', port: 3080 });
  assert.deepEqual(localDialTarget('10.0.161.47', 3199), { host: '10.0.161.47', port: 3199 }, 'LAN mode dials the LAN address, not loopback');
  assert.deepEqual(localDialTarget('192.168.31.186', 3080), { host: '192.168.31.186', port: 3080 });
  assert.deepEqual(localDialTarget('::1', 3080), { host: '::1', port: 3080 });
  assert.deepEqual(localDialTarget('fe80::1%12', 3080), { host: 'fe80::1%12', port: 3080 });
  // A wildcard binds every interface, loopback included, so loopback is right.
  assert.deepEqual(localDialTarget('0.0.0.0', 3080), { host: '127.0.0.1', port: 3080 });
  assert.deepEqual(localDialTarget('::', 3080), { host: '127.0.0.1', port: 3080 });
  assert.deepEqual(localDialTarget('', 3080), { host: '127.0.0.1', port: 3080 });
  assert.deepEqual(localDialTarget(undefined, undefined), { host: '127.0.0.1', port: 3080 });
  assert.deepEqual(localDialTarget('not-an-address', 3080), { host: '127.0.0.1', port: 3080 });
  assert.deepEqual(localDialTarget('10.0.161.47', 0), { host: '10.0.161.47', port: 3080 });
});

test('keeps the new records under the plugin scope, apart from the legacy ones', () => {
  assert.equal(DEVICES_V2_RECORD_KEY, 'dsh-remote-access/devices-v2');
  assert.equal(ACCESS_KEYS_RECORD_KEY, 'dsh-remote-access/access-keys');
  assert.equal(DEVICE_RECORD_KEY, 'dsh-remote-access/devices', 'the heartbeat view keeps its own record');
  assert.notEqual(DEVICES_V2_RECORD_KEY, DEVICE_RECORD_KEY);
  assert.equal(ENTRY_LINK_DAYS, 30, 'an entry link is 30 days, not a silent year');
});

test('gives every record a fresh id that is not part of a fingerprint', () => {
  const id = newRecordId();
  assert.match(id, /^[0-9a-f]{16}$/);
  assert.notEqual(id, newRecordId());
  const hash = hashAccessKey(newAccessKey());
  assert.equal(id.length, 16);
  assert.notEqual(id, hash.slice(0, 16), 'an id is random, never a slice of the fingerprint');
});

// ── The endpoints, driven through the routes the plugin really registers ────
//
// No server and no sockets: the prefix handler and the root gate are called with
// a minimal request/response pair, exactly as the webserver calls them. Only
// paths that answer without proxying the platform index are exercised here.

/** A host context with just enough of the seam for the endpoint map. */
// The listener port is deliberately a *closed* one: a test that reaches the
// index-forward path must fail closed rather than dial whatever is running on
// the developer's machine. Tests that care about the reported port set it.
function hostCtx({ records = new Map(), secrets = new Map(), config, editor, connection, port = 9, documentPath } = {}) {
  const routes = { prefix: [], exact: new Map() };
  // The real store refuses a payload it cannot spell, with its own error, *at
  // write time* — so a double that accepts anything hides exactly the bug class
  // that killed `device-link`. These are the store's rules, verbatim.
  const assertStorable = (where, value, seen = new Set()) => {
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
    if (typeof value === 'number') {
      if (Number.isFinite(value)) return;
      throw new TypeError(`credentials-local: ${where} holds a non-finite number`);
    }
    if (typeof value === 'object') {
      if (seen.has(value)) throw new TypeError(`credentials-local: ${where} is cyclic`);
      if (Object.getPrototypeOf(value) === Object.prototype || Array.isArray(value)) {
        seen.add(value);
        for (const nested of Object.values(value)) assertStorable(where, nested, seen);
        seen.delete(value);
        return;
      }
    }
    throw new TypeError(`credentials-local: ${where} holds a value JSON cannot represent`);
  };
  // Updates to one key are serialized, like the real credential store's atomic
  // update: a double that let two `modifyRecord` callbacks read the same value
  // would make a compare-and-swap look unnecessary.
  const chains = new Map();
  const credentials = {
    readRecord: async (key) => records.get(key),
    modifyRecord: async (key, mutate) => {
      const previous = chains.get(key) ?? Promise.resolve();
      const next = previous.then(async () => {
        const value = await mutate(records.get(key));
        if (value === undefined) return value;
        if (value.kind === 'grant') assertStorable(`record "${key}" payload`, value.payload);
        records.set(key, value);
        return value;
      });
      chains.set(key, next.then(() => undefined, () => undefined));
      return next;
    },
    deleteRecord: async (key) => records.delete(key),
    resolve: async (key) => (secrets.has(key) ? { value: secrets.get(key) } : undefined),
    set: async (key, value) => secrets.set(key, value),
    unset: async (key) => secrets.delete(key),
  };
  const rows = editor ?? [];
  const configEditor = {
    rows,
    edits: [],
    documentPath,
    entries: () => rows.map((row) => row.entry),
    configuration: () => rows,
    edit: async (entry, mutate) => {
      const next = await mutate(entry.options.config ?? {});
      configEditor.edits.push({ id: entry.options.id, next });
      entry.options.config = next;
      return next;
    },
  };
  const ctx = {
    records,
    secrets,
    routes,
    configEditor,
    /** Every write the plugin made to one configuration row, oldest first. */
    editsFor: (id) => configEditor.edits.filter((entry) => entry.id === id),
    effect: (fn) => fn(),
    get: (name) =>
      name === 'credentials'
        ? credentials
        : name === 'subprocess'
          ? undefined
          : name === 'configEditor'
            ? configEditor
            : name === 'connection'
              ? (connection ?? {
                  // Enough of the fence for both callers. Its trust probe is a
                  // synthetic request with no socket and is answered "trusted"; a
                  // real request to a plugin endpoint passes; a real root request
                  // is turned away like any unauthenticated browser (401), and an
                  // authority the fence actually refuses is 403 — which is the
                  // distinction the gate's redirect refusal turns on.
                  requestRejection: (request) => {
                    const url = String(request?.url ?? '/');
                    if (url.startsWith(CHANNEL)) return undefined;
                    if (request?.socket === undefined) return undefined;
                    const host = String(request?.headers?.host ?? '');
                    if (host === '' || host.startsWith('evil.')) return 403;
                    return 401;
                  },
                  // The platform's own exchange, as the real connection service
                  // offers it: a launch token becomes a cookie, server-side.
                  authenticatedUrl: (base) => `${base}?token=launch-token`,
                  authorizeIndex: (request, response) => {
                    const url = new URL(String(request?.url ?? '/'), 'http://dsh.invalid');
                    if (request?.method === 'GET' && url.pathname === '/' && url.searchParams.get('token') === 'launch-token') {
                      response.writeHead(303, { location: './', 'set-cookie': 'dsh-session=ok; Path=/; HttpOnly' });
                      response.end();
                      return false;
                    }
                    response.writeHead(401, {});
                    response.end();
                    return false;
                  },
                })
              : undefined,
    webServer: {
      host: '127.0.0.1',
      port,
      register: (route) => {
        if (route.kind === 'prefix') routes.prefix.push(route.handler);
        else routes.exact.set(route.path, route.handler);
        return () => {};
      },
      tapIndex: () => () => {},
    },
  };
  apply(ctx, config);
  // Exposed so a test can make the store refuse, or inspect what was written.
  ctx.credentials = credentials;
  return ctx;
}

/** A configEditor preloaded with the rows `set-mode` writes. */
function webServerRows(host = '127.0.0.1') {
  return [
    { entry: { options: { id: 'webserver', config: { host, port: 3080 } } }, override: { host, port: 3080 } },
    { entry: { options: { id: 'connection', config: {} } }, override: {} },
    { entry: { options: { id: 'remote-access-panel', config: {} } }, override: {} },
  ];
}

/** The request shape the webserver hands a handler: two arguments, no more. */
function fakeRequest(body, { url = '/', remoteAddress = '203.0.113.9', headers = {}, method = 'POST' } = {}) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  let index = 0;
  return {
    method,
    url,
    headers: { host: 'dsh.example.com', 'content-type': 'application/json', ...headers },
    socket: { remoteAddress },
    // Only `forwardIndex` pipes a request; ending the upstream is what makes the
    // forward observable, and a forward to a closed port simply fails closed.
    pipe(target) {
      target.end();
      return target;
    },
    // The forwarder watches for a client that goes away.
    on() {
      return this;
    },
    once() {
      return this;
    },
    [Symbol.asyncIterator]: () => ({
      next: async () => (index < chunks.length ? { value: chunks[index++], done: false } : { done: true }),
    }),
  };
}

/** Wait for asynchronous work the handler started (a forwarded answer). */
async function waitFor(predicate, steps = 200) {
  for (let attempt = 0; attempt < steps; attempt += 1) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return false;
}

function fakeResponse() {
  const listeners = new Map();
  const chunks = [];
  const res = {
    statusCode: 200,
    headers: {},
    writableEnded: false,
    destroyed: false,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    writeHead(status, headers) {
      this.statusCode = status;
      Object.assign(this.headers, headers);
    },
    // Enough of a writable stream for `answer.pipe(res)` to drive it.
    write(chunk) {
      if (chunk !== undefined) chunks.push(Buffer.from(String(chunk)));
      return true;
    },
    end(body) {
      if (body !== undefined) chunks.push(Buffer.from(String(body)));
      this.body = chunks.length === 0 ? undefined : Buffer.concat(chunks).toString('utf8');
      this.writableEnded = true;
    },
    destroy() {
      this.destroyed = true;
    },
    // The forwarder listens for the client leaving, and for a deadline; a test
    // drives that by emitting `close` itself.
    on(name, listener) {
      const list = listeners.get(name) ?? [];
      list.push(listener);
      listeners.set(name, list);
      return this;
    },
    once(name, listener) {
      return this.on(name, listener);
    },
    listenerCount(name) {
      return (listeners.get(name) ?? []).length;
    },
    emit(name, ...args) {
      for (const listener of listeners.get(name) ?? []) listener(...args);
      return this;
    },
  };
  return res;
}

/** POST one JSON endpoint and return `{ status, value, error }`. */
async function endpoint(ctx, name, body, options) {
  const res = fakeResponse();
  await ctx.routes.prefix[0](fakeRequest(body, { ...options, url: `${CHANNEL}/${name}` }), res);
  const payload = res.body === undefined ? undefined : JSON.parse(res.body);
  return { status: res.statusCode, ok: payload?.ok, value: payload?.value, error: payload?.error, res };
}

/** Call one route by its full path, for the self-authenticating ones. */
async function route(ctx, path, body, options) {
  const res = fakeResponse();
  await ctx.routes.prefix[0](fakeRequest(body, { ...options, url: path }), res);
  let payload;
  try {
    payload = res.body === undefined ? undefined : JSON.parse(res.body);
  } catch {
    payload = undefined;
  }
  return { status: res.statusCode, ok: payload?.ok, value: payload?.value, error: payload?.error, body: res.body, res };
}

test('mints, lists, resets and revokes a key through the endpoint map', async () => {
  const ctx = hostCtx();
  const created = await endpoint(ctx, 'key-create', { name: 'Laptop', days: 30 });
  assert.equal(created.ok, true);
  const key = created.value.key;
  assert.ok(key.startsWith(ACCESS_KEY_PREFIX));
  assert.equal(created.value.days, 30);
  assert.ok(created.value.expiresAt > Date.now());
  // Only the fingerprint is stored, and the plaintext appears nowhere in it.
  const stored = JSON.stringify(ctx.records.get(ACCESS_KEYS_RECORD_KEY));
  assert.ok(!stored.includes(key), 'the plaintext key is never persisted');
  assert.equal(hashAccessKey(key), ctx.records.get(ACCESS_KEYS_RECORD_KEY).payload.keys[0].hash);

  const listed = await endpoint(ctx, 'key-list', {});
  assert.equal(listed.value.keys.length, 1);
  assert.equal(listed.value.keys[0].status, 'valid');
  assert.ok(!('hash' in listed.value.keys[0]), 'a fingerprint never crosses the wire');

  const reset = await endpoint(ctx, 'key-reset', { id: created.value.id });
  assert.notEqual(reset.value.key, key, 'a reset always mints a new secret');
  assert.equal(accessKeyMatches(key, ctx.records.get(ACCESS_KEYS_RECORD_KEY).payload.keys[0].hash), false);
  assert.equal(accessKeyMatches(reset.value.key, ctx.records.get(ACCESS_KEYS_RECORD_KEY).payload.keys[0].hash), true);

  const revoked = await endpoint(ctx, 'key-revoke', { id: created.value.id });
  assert.equal(revoked.value.revoked, true);
  assert.equal((await endpoint(ctx, 'key-revoke', { id: created.value.id })).value.revoked, false, 'revoking twice is safe');
  assert.equal((await endpoint(ctx, 'key-list', {})).value.keys.length, 0);
});

test('the access-key door mints a single-use link and burns it at the gate', async () => {
  const ctx = hostCtx();
  const created = await endpoint(ctx, 'key-create', { name: 'Phone' });
  const key = created.value.key;

  const minted = await endpoint(ctx, 'token', { key });
  assert.equal(minted.ok, true, JSON.stringify(minted.error));
  assert.equal(minted.value.expiresAt - Date.now() <= TEMP_TOKEN_TTL_MS, true);
  const url = new URL(minted.value.url);
  const token = url.searchParams.get('token');
  assert.ok(isTempToken(token), `the link carries a temp token, got ${url.search}`);
  assert.ok(Number.isInteger(minted.value.qr?.size), 'the qr is a matrix');

  // The row it recorded is a 15-minute, single-use, access-key device.
  const rows = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].source, 'access-key');
  assert.equal(rows[0].temporary, true);
  assert.equal(rows[0].expiresAt - Date.now() <= TEMP_TOKEN_TTL_MS, true);
  assert.equal(JSON.stringify(rows).includes(token), false, 'only the fingerprint is stored');

  const list = await endpoint(ctx, 'device-list', {});
  assert.equal(list.value.devices[0].status, 'valid');
  assert.equal(list.value.devices[0].lastUsedAt, null);
  assert.ok(!('hash' in list.value.devices[0]));

  // Redeem it at the root gate: a redirect, and the row is gone.
  const root = ctx.routes.exact.get('/');
  const first = fakeResponse();
  await root(fakeRequest(undefined, { url: `/?token=${token}`, headers: { 'user-agent': 'Mozilla/5.0 (iPhone)' } }), first);
  assert.equal(first.statusCode, 303, 'a live one-time link redirects into the app');
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 0, 'and burns itself');

  const second = fakeResponse();
  await root(fakeRequest(undefined, { url: `/?token=${token}` }), second);
  assert.notEqual(second.statusCode, 303, 'it cannot be replayed');
  assert.equal(second.headers['set-cookie'], undefined, 'a spent link mints nothing on the way back');
});

test('the page-close beacon is idempotent and never throws', async () => {
  const ctx = hostCtx();
  for (const body of [{ token: 'nonsense' }, {}, undefined, { token: newTempToken() }]) {
    const answer = await endpoint(ctx, 'page-close', body);
    assert.equal(answer.status, 200);
    assert.equal(answer.ok, true);
    assert.equal(answer.value.closed, false);
  }
  // A real link whose page closes itself is invalidated before it is ever used.
  const created = await endpoint(ctx, 'key-create', { name: 'Phone' });
  const minted = await endpoint(ctx, 'token', { key: created.value.key });
  const token = new URL(minted.value.url).searchParams.get('token');
  assert.equal((await endpoint(ctx, 'page-close', { token })).value.closed, true);
  assert.equal((await endpoint(ctx, 'page-close', { token })).value.closed, false);
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 0);

  // A late beacon is the normal case, not an error: the link expired, or the
  // page closed after the phone had already used it. Both answer the same shape.
  const late = hostCtx();
  const lateKey = await endpoint(late, 'key-create', { name: 'Phone' });
  const lateLink = await endpoint(late, 'token', { key: lateKey.value.key });
  const lateToken = new URL(lateLink.value.url).searchParams.get('token');
  late.records.get(DEVICES_V2_RECORD_KEY).payload.devices[0].expiresAt = Date.now() - 1000;
  const expired = await endpoint(late, 'page-close', { token: lateToken });
  assert.equal(expired.status, 200, 'an expired link answers, never throws');
  assert.equal(expired.ok, true);
  assert.equal(expired.value.closed, true, 'and the dead row is cleaned up');
  assert.equal((await endpoint(late, 'page-close', { token: lateToken })).value.closed, false, 'a second beacon is a no-op');
});

test('accepts the proof a real browser signs, and rejects the text-signed variant', async () => {
  // The defect this locks shut: the host HMAC'd the base64 *text* of the nonce
  // while the page signs the decoded *bytes* — so every real browser was denied,
  // and a host-side test that signed the way the host does could never notice.
  // This reproduces the page's algorithm with the real WebCrypto implementation.
  const { subtle } = (await import('node:crypto')).webcrypto;
  const toBytes = (text) => new Uint8Array(Buffer.from(text, 'base64'));
  const toB64 = (buffer) => Buffer.from(new Uint8Array(buffer)).toString('base64');

  const password = 'correct horse battery staple';
  const salt = newSalt();
  const iterations = 1000;
  const key = deriveKey(password, salt, iterations);
  const nonce = newNonce();

  const material = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'PBKDF2', salt: toBytes(salt), iterations, hash: 'SHA-256' }, material, 256);
  const hmac = await subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const browserProof = toB64(await subtle.sign('HMAC', hmac, toBytes(nonce)));
  assert.equal(verifyProof(key, nonce, browserProof), true, 'the browser’s proof verifies');
  assert.equal(browserProof, proofFor(key, nonce), 'and it is byte-for-byte what the host computes');

  // The old scheme: signing the base64 text instead of the bytes it stands for.
  const textProof = toB64(await subtle.sign('HMAC', hmac, new TextEncoder().encode(nonce)));
  assert.notEqual(textProof, browserProof, 'the two schemes really do differ');
  assert.equal(verifyProof(key, nonce, textProof), false, 'the text-signed variant is refused');

  // The page's own sign call must be the byte form.
  const script = unlockPageHtml({
    prefix: CHANNEL,
    configured: true,
    title: 't',
    subtitle: 's',
    passwordLabel: 'p',
    buttonLabel: 'b',
    wrongLabel: 'w',
    throttledLabel: 'th',
    failedLabel: 'f',
    missingLabel: 'm',
    successLabel: 'ok',
    openLabel: 'o',
    qrLabel: 'qr',
  }).split('<script>')[1].split('</script>')[0];
  assert.doesNotThrow(() => new Function(script), 'the inline script parses');
  assert.match(script, /subtle\.sign\('HMAC', hmac, fromB64\(challenge\.nonce\)\)/, 'the page signs the decoded nonce bytes');
  assert.match(script, /subtle\.deriveBits\(\{ name: 'PBKDF2', salt: fromB64\(challenge\.salt\), iterations: challenge\.iterations, hash: 'SHA-256' \}, material, 256\)/);

  // A malformed nonce is a miss, never a throw.
  assert.equal(proofFor(key, 'not base64 at all!'), undefined);
  assert.equal(proofFor(key, 'abc'), undefined, 'a nonce that is not whole base64 is not signed');
  assert.equal(proofFor(key, ''), undefined);
  assert.equal(proofFor(key, undefined), undefined);
  assert.equal(verifyProof(key, 'not base64 at all!', browserProof), false);
  assert.equal(verifyProof(key, '', browserProof), false);
  assert.equal(verifyProof(key, nonce, undefined), false);
});

test('the served page arms a close beacon for the link it hands out', () => {
  const html = unlockPageHtml({
    prefix: CHANNEL,
    configured: true,
    title: 't',
    subtitle: 's',
    passwordLabel: 'p',
    buttonLabel: 'b',
    wrongLabel: 'w',
    throttledLabel: 'th',
    failedLabel: 'f',
    missingLabel: 'm',
    successLabel: 'ok',
    openLabel: 'o',
    qrLabel: 'qr',
  });
  const script = html.split('<script>')[1].split('</script>')[0];
  // It compiles: a template literal that breaks the page is the failure mode
  // that no amount of string matching would catch.
  assert.doesNotThrow(() => new Function(script), 'the inline script parses');

  assert.match(script, /addEventListener\('pagehide', closeLink\)/, 'pagehide is the primary signal');
  assert.match(script, /addEventListener\('visibilitychange'/, 'and visibilitychange is the fallback');
  assert.match(script, /document\.visibilityState === 'hidden'/, 'which fires when the page is hidden');
  assert.match(script, /navigator\.sendBeacon\(url, new Blob\(\[payload\], \{ type: 'application\/json' \}\)\)/, 'sendBeacon carries a JSON blob');
  assert.match(script, /keepalive: true/, 'and the fetch fallback keeps the request alive');
  assert.match(script, /PREFIX \+ '\/page-close'/, 'posted to the close endpoint');
  // The token is only ever in the body: no URL, no query string.
  const beacon = script.slice(script.indexOf('function closeLink'), script.indexOf('function armClose'));
  assert.ok(!beacon.includes('?token='), 'the token never reaches a URL');
  assert.match(beacon, /JSON\.stringify\(\{ token: pendingToken \}\)/, 'it travels in the JSON body');
  // Arming is conditional: a page that minted nothing never beacons.
  assert.match(script, /token\.indexOf\('drt_'\) !== 0\) return;/, 'only our own one-time links arm it');
  assert.match(script, /if \(beaconSent \|\| !pendingToken\) return;/, 'and it fires at most once');
  // The link the page shows is handed to the arming helper on both paths.
  assert.match(script, /function showEntry\(entry\)[\s\S]*?armClose\(entry\.url\)/, 'showing a link arms the beacon');
});

test('refuses a wrong key, and throttles per client and globally', async () => {
  const ctx = hostCtx();
  await endpoint(ctx, 'key-create', { name: 'Phone' });

  // No key stored at all behaves as if the door did not exist.
  const empty = hostCtx();
  assert.equal((await endpoint(empty, 'token', { key: 'dra_' + 'a'.repeat(43) })).status, 404);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const answer = await endpoint(ctx, 'token', { key: 'dra_' + 'a'.repeat(43) });
    assert.equal(answer.status, 200, `attempt ${attempt} is answered, not leaked`);
    assert.equal(answer.error.code, 'remote-access/key-denied');
  }
  const throttled = await endpoint(ctx, 'token', { key: 'dra_' + 'a'.repeat(43) });
  assert.equal(throttled.status, 429, 'the sixth failure from one client is refused');
  assert.equal(throttled.error.code, 'remote-access/key-throttled');

  // The budget is also counted across every client, so one address cannot hide.
  const global = hostCtx();
  await endpoint(global, 'key-create', { name: 'Phone' });
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await endpoint(global, 'token', { key: 'dra_' + 'b'.repeat(43) }, { remoteAddress: `10.0.0.${attempt + 1}` });
  }
  const other = await endpoint(global, 'token', { key: 'dra_' + 'b'.repeat(43) }, { remoteAddress: '10.0.0.99' });
  assert.equal(other.status, 429, 'a fresh client is still stopped by the global budget');
});

test('changes one device expiry, and refuses to delete a live row', async () => {
  const ctx = hostCtx();
  const created = await endpoint(ctx, 'key-create', { name: 'Phone' });
  await endpoint(ctx, 'token', { key: created.value.key });
  const row = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices[0];

  const named = await endpoint(ctx, 'device-rename', { id: row.id, name: 'My phone' });
  assert.equal(named.value.name, 'My phone');

  const never = await endpoint(ctx, 'device-expiry', { id: row.id, days: null });
  assert.equal(never.value.days, null);
  assert.equal(never.value.expiresAt, null);
  assert.equal(never.value.status, 'never');

  const until = new Date(Date.now() + 3600_000).toISOString();
  const dated = await endpoint(ctx, 'device-expiry', { id: row.id, days: 5, until });
  assert.equal(dated.value.expiresAt, Date.parse(until), 'until wins over days');
  assert.equal(dated.value.status, 'valid');

  const refused = await endpoint(ctx, 'device-delete', { id: row.id });
  assert.equal(refused.ok, false, 'a valid row is never deleted');
  assert.match(refused.error.message, /revoke/);

  // Expire it, and deletion becomes the tidy-up it is meant to be.
  const past = await endpoint(ctx, 'device-expiry', { id: row.id, until: new Date(Date.now() - 1000).toISOString() });
  assert.equal(past.value.status, 'expired');
  const deleted = await endpoint(ctx, 'device-delete', { id: row.id });
  assert.equal(deleted.value.deleted, true);
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 0);

  // The legacy aliases answer with their old shapes over the new record.
  const revoked = await endpoint(ctx, 'token-revoke', { id: 'nope' });
  assert.equal(revoked.value.revoked, 0);
  assert.equal((await endpoint(ctx, 'token-expiry', { id: 'nope' })).ok, false);
  assert.equal((await endpoint(ctx, 'tokens-clear', {})).value.revoked, 0);
});

test('exchanges a launch token for the platform cookie, keeping ours', async () => {
  // A stand-in for the platform's own index authorizer: it mints its cookie for
  // a launch-token GET on `/`, and answers 401 for anything else. This is the
  // exchange the plugin must trigger itself, because it owns `/`.
  const platform = {
    requestRejection: (request) => (String(request?.headers?.cookie ?? '').includes('dsh-session=ok') ? undefined : 401),
    authorizeIndex: (req, res) => {
      const url = new URL(String(req.url ?? '/'), 'http://dsh.invalid');
      if (req.method === 'GET' && url.pathname === '/' && url.searchParams.get('token') === 'launch-token') {
        res.writeHead(303, { location: './', 'set-cookie': 'dsh-session=ok; Path=/; HttpOnly' });
        res.end();
        return false;
      }
      res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('unauthorized');
      return false;
    },
  };
  const ctx = hostCtx({ connection: platform });
  const root = ctx.routes.exact.get('/');

  // The pairing visit: one entry-link row, our 30-day credential merged into the
  // platform's own set-cookie, and a redirect into the app.
  const first = fakeResponse();
  await root(fakeRequest(undefined, { method: 'GET', url: '/?token=launch-token' }), first);
  assert.equal(first.statusCode, 303);
  const cookies = [].concat(first.headers['set-cookie']);
  assert.ok(cookies.some((cookie) => cookie.startsWith('dsh-session=ok')), 'the platform cookie is handed over');
  const device = cookies.find((cookie) => cookie.startsWith('mc-device='));
  assert.ok(device !== undefined, 'our device credential rides along in the same answer');
  const rows = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].source, 'entry-link');
  assert.equal(rows[0].temporary, true);
  assert.ok(Math.abs(rows[0].expiresAt - Date.now() - ENTRY_LINK_DAYS * 24 * 60 * 60 * 1000) < 10_000);

  // A return visit that only re-exchanges a lapsed platform cookie must not pile
  // up a fresh row (and fresh cookie) every time.
  const token = decodeURIComponent(device.slice('mc-device='.length).split(';')[0].trim());
  const second = fakeResponse();
  await root(
    fakeRequest(undefined, { method: 'GET', url: '/?token=launch-token', headers: { cookie: `mc-device=${encodeURIComponent(token)}` } }),
    second,
  );
  assert.equal(second.statusCode, 303);
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'a known device is not re-recorded');

  // A launch token the platform refuses is not a key: the visit falls through to
  // the ordinary answer, and no credential is attached to it. (Live, that
  // ordinary answer is the platform's own 401; here the index dial is closed on
  // purpose, so what is asserted is the invariant — nothing of ours rides along.)
  const refused = fakeResponse();
  await root(fakeRequest(undefined, { method: 'GET', url: '/?token=stale-token' }), refused);
  assert.equal(refused.headers['set-cookie'], undefined, 'a refused token mints nothing');
  assert.ok(!String(refused.headers['content-type'] ?? '').includes('text/html'), 'and never our page');
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'still only the one real row');

  // The platform's verdict comes first: an accepted caller is forwarded, never
  // bounced through a fresh launch token — the loop that would otherwise never
  // end, since the token visit redirects back to `/`.
  const forwarded = hostCtx({ connection: { requestRejection: () => undefined }, port: 9 });
  const answer = fakeResponse();
  await forwarded.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/', headers: { cookie: 'mc-device=whatever' } }),
    answer,
  );
  assert.notEqual(answer.statusCode, 303, 'an accepted caller is never redirected through a launch token');
  assert.equal(await waitFor(() => answer.body !== undefined), true, 'the index forward ran');
  assert.equal(answer.statusCode, 502, 'and failed closed, because nothing listens on that port');
});

test('bootstraps a loopback launch-token visit through the platform authorizer', async () => {
  // The desktop opens the printed `?token=` URL at 127.0.0.1. The platform only
  // mints its cookie for a path of exactly `/`, and the index proxy below asks
  // for `/index.html`, so the gate must run the authorizer itself here too.
  const platform = {
    requestRejection: () => 401,
    authorizeIndex: (req, res) => {
      const url = new URL(String(req.url ?? '/'), 'http://dsh.invalid');
      if (req.method === 'GET' && url.pathname === '/' && url.searchParams.get('token') === 'launch-token') {
        res.writeHead(303, { location: './', 'set-cookie': 'dsh-session=ok; Path=/; HttpOnly' });
        res.end();
        return false;
      }
      res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('unauthorized');
      return false;
    },
  };
  const ctx = hostCtx({ connection: platform });
  const root = ctx.routes.exact.get('/');
  const local = { url: '/?token=launch-token', headers: { host: '127.0.0.1:3080' }, remoteAddress: '127.0.0.1', method: 'GET' };

  const first = fakeResponse();
  await root(fakeRequest(undefined, local), first);
  assert.equal(first.statusCode, 303, 'a fresh local browser bootstraps instead of getting a 401');
  const cookies = [].concat(first.headers['set-cookie']);
  assert.ok(cookies.some((cookie) => cookie.startsWith('dsh-session=ok')), 'the platform cookie is handed over');
  assert.ok(cookies.some((cookie) => cookie.startsWith('mc-device=')), 'and our device credential too');
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices[0].source, 'entry-link');

  // A stale token is not a key and not an oracle: the visit falls through to the
  // ordinary answer, and nothing is minted for it.
  const stale = fakeResponse();
  await root(fakeRequest(undefined, { ...local, url: '/?token=stale' }), stale);
  assert.equal(stale.headers['set-cookie'], undefined, 'a stale token buys no credential');
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'still the one row from the real bootstrap');
  const plain = hostCtx({ connection: { requestRejection: () => undefined }, port: 9 });
  const forwarded = fakeResponse();
  await plain.routes.exact.get('/')(fakeRequest(undefined, { url: '/', headers: { host: '127.0.0.1:3080' }, remoteAddress: '127.0.0.1', method: 'GET' }), forwarded);
  assert.equal(await waitFor(() => forwarded.body !== undefined), true);
  assert.equal(forwarded.statusCode, 502, 'a loopback visit with no token is proxied to the index, as before');
});

test('serves the pairing door with or without a password, and stays quiet otherwise', async () => {
  const ctx = hostCtx();
  const minted = await endpoint(ctx, 'pair-code', { days: 30 });
  const code = minted.value.code;

  // No password is stored at all: the page and the password endpoints behave as
  // if they did not exist...
  assert.equal((await route(ctx, `${CHANNEL}/unlock`, undefined, { method: 'GET' })).status, 404);
  assert.equal((await route(ctx, `${CHANNEL}/unlock/challenge`, {}, { method: 'POST' })).status, 404);
  assert.equal((await route(ctx, `${CHANNEL}/unlock/verify`, {}, { method: 'POST' })).status, 404);

  // ...but a pairing code still redeems, because the panel can mint one without
  // a password and the code is its own single-use, rate-limited credential.
  const redeemed = await route(ctx, `${CHANNEL}/unlock/pair`, { code }, { method: 'POST' });
  assert.equal(redeemed.ok, true, JSON.stringify(redeemed.error));
  assert.equal(redeemed.value.days, 30);
  assert.match(String(redeemed.res.headers['set-cookie']), /mc-device=/);
  assert.equal((await route(ctx, `${CHANNEL}/unlock/pair`, { code }, { method: 'POST' })).ok, false, 'the code is single use');

  // With a password armed, the page and the challenge come back.
  await endpoint(ctx, 'recovery-set', { password: 'a very long password' });
  assert.equal((await route(ctx, `${CHANNEL}/unlock`, undefined, { method: 'GET' })).status, 200);
  assert.equal((await route(ctx, `${CHANNEL}/unlock/challenge`, {}, { method: 'POST' })).ok, true);
  const second = await endpoint(ctx, 'pair-code', { days: null });
  assert.equal((await route(ctx, `${CHANNEL}/unlock/pair`, { code: second.value.code }, { method: 'POST' })).ok, true, 'and the pairing door keeps working');
});

test('refuses to mint a credential for a token the platform has not accepted', async () => {
  // The bypass this locks shut: `?token=<anything>` used to mint a valid 30-day
  // device credential *before* the platform judged the token, and the platform's
  // 401 was then forwarded with our Set-Cookie still attached — so a stranger
  // who asked for `?token=1` held a device credential, and that credential was
  // worth a platform cookie through the reentry path.
  const shapes = ['1', 'A'.repeat(200), 'x'.repeat(43), ' ', '%20', 'drt_' + 'y'.repeat(43), 'undefined', 'null'];
  for (const shape of shapes) {
    const ctx = hostCtx();
    const res = fakeResponse();
    await ctx.routes.exact.get('/')(
      fakeRequest(undefined, {
        method: 'GET',
        url: `/?token=${encodeURIComponent(shape)}`,
        headers: { host: 'dsh.example.com' },
        remoteAddress: '203.0.113.9',
      }),
      res,
    );
    const label = JSON.stringify(shape.slice(0, 12));
    const cookies = [].concat(res.headers['set-cookie'] ?? []);
    assert.equal(cookies.length, 0, `${label}: nothing was minted`);
    assert.ok(!cookies.some((value) => String(value).startsWith('mc-device=')), `${label}: no device credential`);
    assert.ok(!cookies.some((value) => String(value).startsWith('dsh-session=')), `${label}: no platform cookie`);
    assert.ok(!String(res.body ?? '').includes('__DSH_BOOT__'), `${label}: not an app response`);
    assert.equal(
      (ctx.records.get(DEVICES_V2_RECORD_KEY)?.payload?.devices ?? []).length,
      0,
      `${label}: no row was created either`,
    );
  }

  // An empty token is simply no token: it behaves like a bare `GET /`.
  const bare = hostCtx();
  const withEmpty = fakeResponse();
  await bare.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/?token=', headers: { host: 'dsh.example.com' }, remoteAddress: '203.0.113.9' }),
    withEmpty,
  );
  const withoutAny = fakeResponse();
  await bare.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/', headers: { host: 'dsh.example.com' }, remoteAddress: '203.0.113.9' }),
    withoutAny,
  );
  assert.equal(withEmpty.statusCode, withoutAny.statusCode, '?token= and a bare GET / answer the same');
  assert.deepEqual(withEmpty.headers, withoutAny.headers, 'with the same headers, and no cookie either way');

  // A refusal from the platform is forwarded as-is: no plugin cookie rides along.
  const refusing = hostCtx({
    connection: {
      requestRejection: () => 401,
      authenticatedUrl: (base) => `${base}?token=launch-token`,
      authorizeIndex: (request, response) => {
        response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('nope');
        return false;
      },
    },
  });
  const refused = fakeResponse();
  await refusing.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/?token=launch-token', headers: { host: 'dsh.example.com' }, remoteAddress: '203.0.113.9' }),
    refused,
  );
  assert.equal(refused.headers['set-cookie'], undefined, 'a refused exchange carries no cookie of ours');
  assert.ok(!String(refused.headers['content-type'] ?? '').includes('text/html'), 'and never our page');
  assert.equal((refusing.records.get(DEVICES_V2_RECORD_KEY)?.payload?.devices ?? []).length, 0, 'and nothing was minted for it');

  // The platform's own launch token still pairs, in one answer.
  const pairing = hostCtx();
  const boot = fakeResponse();
  await pairing.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/?token=launch-token', headers: { host: 'dsh.example.com' }, remoteAddress: '203.0.113.9' }),
    boot,
  );
  const bootCookies = [].concat(boot.headers['set-cookie'] ?? []).map(String);
  assert.equal(boot.statusCode, 303, 'the printed URL is answered by the platform exchange');
  assert.ok(bootCookies.some((value) => value.startsWith('dsh-session=')), 'with its cookie');
  assert.ok(bootCookies.some((value) => value.startsWith('mc-device=')), 'and ours, in the same answer');
  assert.equal(pairing.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'one row, for a proven token');
});

test('keeps both doors quiet while no password is armed', async () => {
  // The two doors have to agree: with nothing armed, `/` is the platform's own
  // 401 and `/remote-access/unlock` says nothing exists. A page on one and a 404
  // on the other announces the plugin from the door nobody is watching.
  const ctx = hostCtx();
  const remote = { host: 'dsh.example.com' };
  const gate = async (url) => {
    const res = fakeResponse();
    await ctx.routes.exact.get('/')(
      fakeRequest(undefined, { method: 'GET', url, headers: remote, remoteAddress: '203.0.113.9' }),
      res,
    );
    return res;
  };

  for (const url of ['/', '/?token=1', '/?token=']) {
    const res = await gate(url);
    // Live this is the platform's own 401; the index dial is closed here, so
    // what is asserted is the silence: no page of ours, no credential, and no
    // app — the plugin never announces the recovery door it is not serving.
    assert.ok(!String(res.headers['content-type'] ?? '').includes('text/html'), `${url}: not our HTML`);
    assert.ok(!String(res.body ?? '').includes('__DSH_BOOT__'), `${url}: no app`);
    assert.ok(!String(res.body ?? '').includes('Remote access recovery'), `${url}: no recovery page`);
    assert.equal(res.headers['set-cookie'], undefined, `${url}: and no credential`);
  }

  // A refused redemption is the same answer, not a page.
  const refused = await gate(`/?token=drt_${'z'.repeat(43)}`);
  assert.ok(!String(refused.body ?? '').includes('Remote access recovery'), 'a refused link serves no page');
  assert.equal(refused.headers['set-cookie'], undefined);

  // The other door agrees.
  const page = await route(ctx, `${CHANNEL}/unlock`, {}, { method: 'GET' });
  assert.equal(page.status, 404, 'the page route does not exist while nothing is armed');

  // With a password armed the page *is* the answer, so the silence above is
  // about the armed state and not about the branch being dead.
  const armedCtx = hostCtx({ connection: { requestRejection: () => 401 } });
  armedCtx.records.set('dsh-remote-access/recovery', {
    kind: 'grant',
    payload: { version: 1, key: 'k', salt: 's', secret: 'secret', iterations: 1000 },
  });
  const armed = fakeResponse();
  await armedCtx.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/', headers: remote, remoteAddress: '203.0.113.9' }),
    armed,
  );
  assert.equal(armed.statusCode, 200, 'armed: the page is served');
  assert.ok(String(armed.headers['content-type']).includes('text/html'));
});

test('hands out URLs whose authority matches the reachability it reports', async () => {
  // Every QR-bearing answer, checked against the verdict in the same response.
  const ctx = hostCtx({ documentPath: undefined });
  const agrees = (label, value) => {
    assert.equal(typeof value.url, 'string', `${label} has a URL`);
    const authority = new URL(value.url).host;
    assert.equal(reachabilityOf(authority), value.reachable, `${label}: ${authority} vs ${value.reachable}`);
    return value;
  };

  const code = await endpoint(ctx, 'pair-code', { days: null });
  agrees('pair-code', code.value);
  const key = await endpoint(ctx, 'key-create', { name: 'Phone' });
  agrees('/remote-access/token', (await endpoint(ctx, 'token', { key: key.value.key })).value);
  const devices = await endpoint(ctx, 'device-list', {});
  agrees('device-link', (await endpoint(ctx, 'device-link', { id: devices.value.devices[0].id })).value);
  agrees('/unlock/pair', (await route(ctx, `${CHANNEL}/unlock/pair`, { code: code.value.code }, { method: 'POST' })).value);
  agrees('renew-session', (await endpoint(ctx, 'renew-session', {})).value);

  // The same verdict the state reports, so the panel's warning and the QR cannot
  // disagree about the same link.
  const state = await endpoint(ctx, 'state', {});
  assert.equal(state.value.linksReachable, reachabilityOf(new URL(code.value.url).host));
});

test('lets exactly one of many concurrent pairing redemptions win', async () => {
  const ctx = hostCtx();
  const minted = await endpoint(ctx, 'pair-code', { days: 30 });
  const code = minted.value.code;

  // Twelve at once, the way a script would. A read/splice/write cycle lets every
  // one of them read the same rows and win; the compare-and-swap lets one.
  const attempts = await Promise.all(
    Array.from({ length: 12 }, () => route(ctx, `${CHANNEL}/unlock/pair`, { code }, { method: 'POST' })),
  );
  const won = attempts.filter((attempt) => attempt.status === 200 && attempt.ok === true);
  const lost = attempts.filter((attempt) => attempt.status === 200 && attempt.ok === false);
  assert.equal(won.length, 1, `exactly one winner, got ${won.length}`);
  assert.equal(lost.length, 11, 'and eleven refusals');
  for (const attempt of lost) assert.equal(attempt.error.code, 'remote-access/pair-denied');

  // One code, one device row — not twelve.
  const devices = (await endpoint(ctx, 'device-list', {})).value.devices;
  assert.equal(devices.length, 1, 'one device was authorized');
  assert.equal(devices[0].source, 'device-code');
  const codes = ctx.records.get('dsh-remote-access/pair-codes')?.payload?.codes ?? [];
  assert.equal(codes.length, 0, 'and the code is gone');
});

test('refuses a cross-site POST at every public door', async () => {
  // The public doors skip the platform's browser check by design, so they carry
  // its cross-site half themselves. Each case is a real cross-site shape:
  // `sec-fetch-site`, a foreign `Origin`, and `Origin: null`.
  const crossSite = [
    { 'sec-fetch-site': 'cross-site' },
    { origin: 'http://evil.example' },
    { origin: 'null' },
    { origin: 'http://dsh.example.com.evil.example' },
  ];
  const ctx = hostCtx();
  const code = (await endpoint(ctx, 'pair-code', { days: 30 })).value.code;
  const key = (await endpoint(ctx, 'key-create', { name: 'Phone' })).value.key;

  for (const headers of crossSite) {
    const pair = await route(ctx, `${CHANNEL}/unlock/pair`, { code }, { method: 'POST', headers });
    assert.equal(pair.status, 403, `pair is refused for ${JSON.stringify(headers)}`);
    assert.equal(pair.res.headers['set-cookie'], undefined, 'and sets no cookie');
    const token = await route(ctx, `${CHANNEL}/token`, { key }, { method: 'POST', headers });
    assert.equal(token.status, 403, `the key door is refused for ${JSON.stringify(headers)}`);
    const close = await route(ctx, `${CHANNEL}/page-close`, { token: newTempToken() }, { method: 'POST', headers });
    assert.equal(close.status, 403, `the beacon is refused for ${JSON.stringify(headers)}`);
  }
  assert.equal((await endpoint(ctx, 'device-list', {})).value.devices.length, 0, 'nothing was authorized');
  assert.equal(ctx.records.get('dsh-remote-access/pair-codes').payload.codes.length, 1, 'and no code was burned');

  // Same-origin, and the desktop workflow with no Origin at all, still work.
  const sameOrigin = await route(ctx, `${CHANNEL}/unlock/pair`, { code }, { method: 'POST', headers: { origin: 'http://dsh.example.com', 'sec-fetch-site': 'same-origin' } });
  assert.equal(sameOrigin.ok, true, JSON.stringify(sameOrigin.error));
  assert.equal((await endpoint(ctx, 'device-list', {})).value.devices.length, 1, 'the same-origin pairing went through');

  // And the body has to be the JSON the API speaks.
  const again = (await endpoint(ctx, 'pair-code', { days: 30 })).value.code;
  const wrongType = await route(ctx, `${CHANNEL}/unlock/pair`, { code: again }, { method: 'POST', headers: { 'content-type': 'text/plain' } });
  assert.equal(wrongType.status, 415, 'a form-shaped body is refused');
  const noType = await route(ctx, `${CHANNEL}/unlock/pair`, { code: again }, { method: 'POST', headers: { 'content-type': '' } });
  assert.equal(noType.status, 415, 'and so is a body with no type at all');
  assert.equal((await endpoint(ctx, 'device-list', {})).value.devices.length, 1, 'neither one authorized anything');
});

test('counts a client by its socket, not by a header it can invent', async () => {
  const ctx = hostCtx();
  // Twelve wrong codes, a fresh forwarding header on each, one socket: a
  // spoofable key turned the per-client budget into no budget.
  let throttled = 0;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const answer = await route(
      ctx,
      `${CHANNEL}/unlock/pair`,
      { code: 'ABCDEFGH' },
      { method: 'POST', headers: { 'x-forwarded-for': `203.0.113.${attempt + 1}` }, remoteAddress: '198.51.100.7' },
    );
    if (answer.status === 429) throttled += 1;
  }
  assert.ok(throttled > 0, 'the budget bites even though every request claimed a new address');
  assert.equal(throttled, 7, 'five attempts allowed, seven refused');

  // From the loopback proxy the header *is* the client, so each address gets its
  // own budget — that is what cloudflared looks like.
  const behindProxy = hostCtx();
  const statuses = [];
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const answer = await route(
      behindProxy,
      `${CHANNEL}/unlock/pair`,
      { code: 'ABCDEFGH' },
      { method: 'POST', headers: { 'cf-connecting-ip': `203.0.113.${attempt + 1}` }, remoteAddress: '127.0.0.1' },
    );
    statuses.push(answer.status);
  }
  assert.deepEqual(statuses, [200, 200, 200, 200], 'four distinct edge clients are four budgets');
});

test('does not let failed proofs lock the owner out of the door', async () => {
  const ctx = hostCtx();
  ctx.records.set('dsh-remote-access/recovery', {
    kind: 'grant',
    payload: { version: 1, key: 'k', salt: 'c2FsdA==', secret: 'sec', iterations: 1000 },
  });
  // One attacker burns its own budget...
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await route(ctx, `${CHANNEL}/unlock/verify`, { nonce: 'nope', proof: 'nope' }, { method: 'POST', remoteAddress: '198.51.100.9' });
  }
  const attacker = await route(ctx, `${CHANNEL}/unlock/verify`, { nonce: 'nope', proof: 'nope' }, { method: 'POST', remoteAddress: '198.51.100.9' });
  assert.equal(attacker.status, 429, 'the attacker is throttled');

  // ...and the owner, from another address, still gets a challenge: the global
  // budget is a backstop, not five failures away from a lockout.
  const owner = await route(ctx, `${CHANNEL}/unlock/challenge`, {}, { method: 'POST', remoteAddress: '203.0.113.50' });
  assert.equal(owner.status, 200, 'the owner is not locked out by someone else’s failures');
  assert.equal(owner.ok, true, JSON.stringify(owner.error));
});

test('revoke-temporary clears exactly the temporary rows', async () => {
  const ctx = hostCtx();

  // Two durable devices: an access key redeemed to a *durable* device row, and a
  // pairing code redeemed the same way. These must survive the broom.
  const durableKey = await endpoint(ctx, 'key-create', { name: 'Laptop' });
  const durableToken = (await endpoint(ctx, 'token', { key: durableKey.value.key })).value;
  const durableJar = {};
  // Redeem the one-time link: that row is temporary and *is* one of the ones the
  // broom takes, so the durable device it authorizes is what we then keep.
  await ctx.routes.exact.get('/')(
    fakeRequest(undefined, {
      method: 'GET',
      url: `/?token=${new URL(durableToken.url).searchParams.get('token')}`,
      headers: { host: 'dsh.example.com', cookie: 'mc-device=' + new URL(durableToken.url).searchParams.get('token') },
      remoteAddress: '203.0.113.9',
    }),
    fakeResponse(),
  );
  const code = await endpoint(ctx, 'pair-code', { days: null });
  const paired = await route(ctx, `${CHANNEL}/unlock/pair`, { code: code.value.code }, { method: 'POST' });
  assert.equal(paired.ok, true, JSON.stringify(paired.error));
  const durableCookie = [].concat(paired.res.headers['set-cookie'] ?? []).map(String).find((value) => value.startsWith('mc-device='));
  assert.ok(durableCookie !== undefined, 'the durable device holds its credential');
  const deviceCookie = durableCookie.split(';')[0];

  // Now some temporary rows: an outstanding one-time link, and a link minted for
  // that durable device (which is temporary and carries a parentId).
  const durable = (await endpoint(ctx, 'device-list', {})).value.devices.find((row) => row.source === 'device-code');
  assert.ok(durable !== undefined, 'the durable device is listed');
  const link = await endpoint(ctx, 'token', { key: durableKey.value.key });
  assert.equal(link.ok, true, JSON.stringify(link.error));
  const child = await endpoint(ctx, 'device-link', { id: durable.id });
  assert.equal(child.ok, true, JSON.stringify(child.error));

  const before = (await endpoint(ctx, 'device-list', {})).value.devices;
  const temporaryIds = before.filter((row) => row.temporary === true).map((row) => row.id);
  const durableIds = before.filter((row) => row.temporary !== true).map((row) => row.id);
  assert.ok(temporaryIds.length >= 2, `expected temporary rows to clear, got ${temporaryIds.length}`);
  assert.ok(durableIds.length >= 1, 'and at least one durable row to keep');

  const swept = await endpoint(ctx, 'revoke-temporary', {});
  assert.equal(swept.ok, true, JSON.stringify(swept.error));
  assert.equal(swept.value.revoked, temporaryIds.length, 'the count is exactly the temporary rows');

  const after = (await endpoint(ctx, 'device-list', {})).value.devices;
  assert.equal(after.length, durableIds.length, 'only durable rows are left');
  for (const id of durableIds) assert.ok(after.some((row) => row.id === id), `durable ${id} survived`);

  // The durable device's credential still works: the gate sends it into the app.
  const gate = fakeResponse();
  await ctx.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/', headers: { host: 'dsh.example.com', cookie: deviceCookie }, remoteAddress: '203.0.113.9' }),
    gate,
  );
  assert.equal(gate.statusCode, 303, 'the durable device still gets in');

  // The swept links are dead, and a repeat call is a no-op.
  const sweptToken = new URL(link.value.url).searchParams.get('token');
  const refused = fakeResponse();
  await ctx.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: `/?token=${sweptToken}`, headers: { host: 'dsh.example.com' }, remoteAddress: '203.0.113.9' }),
    refused,
  );
  assert.notEqual(refused.statusCode, 303, 'a swept link no longer opens anything');
  assert.equal((await endpoint(ctx, 'revoke-temporary', {})).value.revoked, 0, 'a repeat call revokes nothing');
});

test('every credential payload survives a JSON round trip', async () => {
  // The store rejects a payload it cannot spell — `undefined` in a row, a Date, a
  // class instance — and it rejects it *at write time*, so the request that
  // happened to be writing dies with the store's error. This asserts the property
  // directly, for every record shape the plugin builds, so the class cannot come
  // back a third time.
  const roundTrips = (label, payload) => {
    assert.ok(payload !== undefined, `${label}: something was written`);
    assert.deepEqual(JSON.parse(JSON.stringify(payload)), payload, `${label}: round-trips losslessly`);
  };
  const ctx = hostCtx();

  const key = await endpoint(ctx, 'key-create', { name: 'Phone', days: 30 });
  roundTrips('access-keys', ctx.records.get(ACCESS_KEYS_RECORD_KEY).payload);

  // A one-time link row, and the device it authorizes.
  await endpoint(ctx, 'token', { key: key.value.key });
  roundTrips('devices-v2 (access-key link)', ctx.records.get(DEVICES_V2_RECORD_KEY).payload);
  const device = (await endpoint(ctx, 'device-list', {})).value.devices.find((row) => row.source === 'access-key');

  // A link row *with* `parentId`, which is the field the cascade fix added.
  const linked = await endpoint(ctx, 'device-link', { id: device.id });
  assert.equal(linked.ok, true, JSON.stringify(linked.error));
  roundTrips('devices-v2 (device-link, with parentId)', ctx.records.get(DEVICES_V2_RECORD_KEY).payload);

  // A pairing code, and the durable device row redeeming it produces.
  const code = await endpoint(ctx, 'pair-code', { days: null });
  roundTrips('pair-codes', ctx.records.get('dsh-remote-access/pair-codes').payload);
  await route(ctx, `${CHANNEL}/unlock/pair`, { code: code.value.code }, { method: 'POST' });
  roundTrips('devices-v2 (device-code)', ctx.records.get(DEVICES_V2_RECORD_KEY).payload);

  // A device the gate has touched, so `lastUsedAt`/`lastUsedIp` are written too.
  const cookie = (await endpoint(ctx, 'device-list', {})).value.devices.find((row) => row.source === 'device-code');
  const used = await endpoint(ctx, 'device-rename', { id: cookie.id, name: 'Renamed' });
  assert.equal(used.ok, true, JSON.stringify(used.error));
  roundTrips('devices-v2 (renamed)', ctx.records.get(DEVICES_V2_RECORD_KEY).payload);

  // The password record, and the legacy activity record a device row passes
  // through on the migration path.
  const armed = hostCtx();
  armed.records.set('dsh-remote-access/recovery', {
    kind: 'grant',
    payload: { version: 1, key: 'k', salt: 'c2FsdA==', secret: 'sec', iterations: 1000 },
  });
  roundTrips('recovery', armed.records.get('dsh-remote-access/recovery').payload);
  roundTrips('devices', ctx.records.get(DEVICE_RECORD_KEY)?.payload ?? { version: 1, devices: [] });
});

test('reports a structured refusal when a write is rejected', async () => {
  // The store refusing a payload must not take the request down with its own
  // error: the panel needs a code it can branch on.
  const failing = hostCtx();
  failing.records.set(DEVICES_V2_RECORD_KEY, {
    kind: 'grant',
    payload: { version: 2, devices: [{ id: 'row-1', name: 'Phone', source: 'device-code', temporary: false, createdAt: new Date().toISOString(), lastUsedAt: null, expiresAt: null, days: null, hash: 'a'.repeat(64) }] },
  });
  const original = failing.credentials.modifyRecord;
  failing.credentials.modifyRecord = async (key, mutate) => {
    if (key === DEVICES_V2_RECORD_KEY) {
      throw new TypeError('credentials-local: record "dsh-remote-access/devices-v2" payload holds a value JSON cannot represent');
    }
    return original(key, mutate);
  };
  const answer = await endpoint(failing, 'device-link', { id: 'row-1' });
  assert.equal(answer.ok, false, 'the endpoint answers a refusal');
  assert.equal(answer.status, 200, 'and not a 500');
  assert.match(String(answer.error?.code), /^remote-access\//, 'with a code the panel can branch on');
  assert.match(String(answer.error?.message), /cannot represent|store/, 'and a message that says what happened');
});

test('never waits forever on the index forward', async () => {
  // The defect: a declared `Content-Length` with no body left both ends waiting
  // for bytes that never came — 300 seconds of nothing, which over a tunnel is a
  // Cloudflare 502/524 with no log line. Three guards, one assertion each.
  const http = await import('node:http');
  const seen = [];
  const answering = http.createServer((req, res) => {
    seen.push({ length: req.headers['content-length'], method: req.method });
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<html>__DSH_BOOT__</html>');
  });
  const silent = http.createServer(() => {});
  let aborted = 0;
  let reached;
  const arrived = new Promise((resolve) => {
    reached = resolve;
  });
  const stalled = http.createServer((req) => {
    reached();
    req.on('aborted', () => {
      aborted += 1;
    });
    req.socket.on('close', () => {
      aborted += 1;
    });
  });
  const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  await listen(answering);
  await listen(silent);
  await listen(stalled);
  const stop = async (server) => {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  };
  const ctxFor = (port, timeoutMs) =>
    hostCtx({ port, connection: { requestRejection: () => undefined }, config: { forwardTimeoutMs: timeoutMs } });
  const drive = async (ctx, options = {}) => {
    const res = fakeResponse();
    await ctx.routes.exact.get('/')(
      fakeRequest(undefined, { method: 'GET', url: '/', headers: { host: '127.0.0.1:3080' }, remoteAddress: '127.0.0.1', ...options }),
      res,
    );
    return res;
  };

  try {
    // (a) A body-length header is never forwarded on a request with no body, so a
    //     lying `Content-Length` cannot hang anything: the answer just arrives.
    const lying = await drive(ctxFor(answering.address().port), { headers: { host: '127.0.0.1:3080', 'content-length': '50' } });
    assert.equal(await waitFor(() => lying.body !== undefined), true, 'the answer arrives instead of hanging');
    assert.equal(lying.statusCode, 200);
    assert.equal(seen.at(-1).length, undefined, 'and the upstream was told no body was coming');

    // (b) A silent upstream gets a deadline, and the client is told 504.
    const started = Date.now();
    const quiet = await drive(ctxFor(silent.address().port, 150));
    assert.equal(await waitFor(() => quiet.body !== undefined, 100), true, 'the deadline answers');
    assert.equal(quiet.statusCode, 504, 'with 504, not a hang');
    assert.ok(Date.now() - started < 5000, 'well inside the configured deadline');
    assert.match(String(quiet.body), /did not answer in time/);

    // (c) A client that goes away takes the upstream with it, rather than pinning
    //     the socket until the deadline.
    const gone = fakeResponse();
    const pending = ctxFor(stalled.address().port, 5000).routes.exact.get('/')(
      fakeRequest(undefined, { method: 'GET', url: '/', headers: { host: '127.0.0.1:3080' }, remoteAddress: '127.0.0.1' }),
      gone,
    );
    // Wait until the upstream really has the request, so the destroy below is
    // what drops the socket rather than a race with the connect.
    await arrived;
    assert.ok(gone.listenerCount('close') > 0, 'the forwarder watches for the client leaving');
    gone.emit('close');
    await pending;
    assert.equal(await waitFor(() => aborted > 0, 100), true, 'the upstream socket was dropped with the client');
    assert.equal(gone.body, undefined, 'and nothing was written to a client that had left');

    // (d) A HEAD request still ends cleanly, with the upstream drained.
    const head = await drive(ctxFor(answering.address().port), { method: 'HEAD' });
    assert.equal(await waitFor(() => head.writableEnded === true, 100), true, 'HEAD ends');
    assert.equal(head.statusCode, 200);
    assert.equal(head.body, undefined, 'with no body');
  } finally {
    await stop(answering);
    await stop(silent);
    await stop(stalled);
  }
});

test('serves the pairing page only for a code that could be real', async () => {
  // With no password armed, `?code=` used to be enough to make the recovery page
  // appear — and that page states whether a password is set.
  const ctx = hostCtx();
  const shapes = ['', ' ', 'abc', 'ABCDEFG', 'ABCDEFGHI', 'ABCDEFG!', 'ABCDEFG0', 'ABCDEFGL', 'ABCDEFGO'];
  for (const shape of shapes) {
    const page = await route(ctx, `${CHANNEL}/unlock?code=${encodeURIComponent(shape)}`, {}, { method: 'GET' });
    assert.equal(page.status, 404, `code ${JSON.stringify(shape)} is not a page`);
  }
  // 'ABCDEFGH' is in the alphabet and the right length, so it is a *shape* the
  // page may serve even though no such code was minted: the redemption is what
  // rejects it, and a refusal shows the page rather than a success.
  const shaped = await route(ctx, `${CHANNEL}/unlock?code=ABCDEFGH`, {}, { method: 'GET' });
  assert.equal(shaped.status, 200, 'a well-formed but unknown code shows the page');
  assert.equal(shaped.res.headers['set-cookie'], undefined, 'and buys no credential');
  assert.equal((await endpoint(ctx, 'device-list', {})).value.devices.length, 0, 'and authorizes nothing');
});

test('lands a pairing code in the app without any page script', async () => {
  const ctx = hostCtx();
  const mint = async () => (await endpoint(ctx, 'pair-code', { days: 30 })).value.code;

  // (1) A browser navigation: the GET itself redeems and redirects into the app,
  //     with the device cookie on that same 303. No script runs anywhere.
  const code = await mint();
  const navigation = await route(ctx, `${CHANNEL}/unlock?code=${code}`, {}, { method: 'GET', headers: { accept: 'text/html,application/xhtml+xml' } });
  assert.equal(navigation.status, 303, 'the navigation is redirected, not shown a page');
  assert.equal(navigation.res.headers.location, 'http://dsh.example.com/', 'straight to the entry URL');
  const cookies = [].concat(navigation.res.headers['set-cookie'] ?? []).map(String);
  assert.ok(cookies.some((value) => value.startsWith('mc-device=')), 'and the device cookie rides on the redirect');
  assert.equal((await endpoint(ctx, 'device-list', {})).value.devices.filter((row) => row.source === 'device-code').length, 1, 'one device was authorized');

  // That cookie is what the root gate turns into a session on the next request.
  const deviceCookie = cookies.find((value) => value.startsWith('mc-device=')).split(';')[0];
  const landed = fakeResponse();
  await ctx.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/', headers: { host: 'dsh.example.com', cookie: deviceCookie }, remoteAddress: '203.0.113.9' }),
    landed,
  );
  assert.equal(landed.statusCode, 303, 'and the gate sends it into the app');
  assert.equal(landed.headers.location, '/', 'with no token in the URL');
  assert.ok(String([].concat(landed.headers['set-cookie']).join(';')).includes('dsh-session='), 'a session cookie is minted server-side');

  // (2) The page's own fetch asks for JSON and gets exactly what it renders.
  const pageCode = await mint();
  const asJson = await route(ctx, `${CHANNEL}/unlock/pair`, { code: pageCode }, { method: 'POST', headers: { accept: 'application/json' } });
  assert.equal(asJson.ok, true, JSON.stringify(asJson.error));
  assert.equal(typeof asJson.value.url, 'string');
  assert.ok(Number.isInteger(asJson.value.qr?.size), 'with the QR the page shows');
  assert.equal(asJson.res.headers.location, undefined, 'never both shapes in one answer');

  // (3) A form-shaped POST from a browser is landed the same way as the GET.
  const formCode = await mint();
  const asHtml = await route(ctx, `${CHANNEL}/unlock/pair`, { code: formCode }, { method: 'POST', headers: { accept: 'text/html' } });
  assert.equal(asHtml.status, 303, 'an HTML POST is redirected');
  assert.equal(asHtml.res.headers.location, 'http://dsh.example.com/');
  assert.ok([].concat(asHtml.res.headers['set-cookie'] ?? []).map(String).some((value) => value.startsWith('mc-device=')));

  // (4) A script with no Accept at all keeps the JSON it has always had, and can
  //     ask for either shape explicitly.
  const scriptCode = await mint();
  const script = await route(ctx, `${CHANNEL}/unlock/pair`, { code: scriptCode }, { method: 'POST', headers: { accept: '*/*' } });
  assert.equal(script.ok, true, 'a plain client still gets JSON');
  const forcedJson = await route(ctx, `${CHANNEL}/unlock?code=${await mint()}&format=json`, {}, { method: 'GET', headers: { accept: 'text/html' } });
  assert.equal(forcedJson.ok, true, 'and ?format=json forces the JSON answer');
  const forcedPage = await route(ctx, `${CHANNEL}/unlock?code=${await mint()}&format=page`, {}, { method: 'GET', headers: { accept: 'text/html' } });
  assert.equal(forcedPage.status, 200, 'while ?format=page asks for the page');
  assert.match(String(forcedPage.res.body), /'\/unlock\/pair'/, 'and that page can still redeem the code itself');

  // (5) A second redemption is refused in both shapes.
  const once = await mint();
  assert.equal((await route(ctx, `${CHANNEL}/unlock?code=${once}`, {}, { method: 'GET', headers: { accept: 'text/html' } })).status, 303);
  const again = await route(ctx, `${CHANNEL}/unlock/pair`, { code: once }, { method: 'POST', headers: { accept: 'application/json' } });
  assert.equal(again.ok, false, 'the code is spent for the JSON shape too');
  assert.equal(again.error.code, 'remote-access/pair-denied');
  const againHtml = await route(ctx, `${CHANNEL}/unlock/pair`, { code: once }, { method: 'POST', headers: { accept: 'text/html' } });
  assert.notEqual(againHtml.status, 303, 'and for the HTML shape');

  // (6) A prefetch never burns a code: a link preview must not spend it.
  const previewed = await mint();
  const preview = await route(ctx, `${CHANNEL}/unlock?code=${previewed}`, {}, { method: 'GET', headers: { accept: 'text/html', purpose: 'prefetch' } });
  assert.equal(preview.status, 200, 'a prefetch gets the page, not the landing');
  assert.equal(preview.res.headers['set-cookie'], undefined, 'and no credential');
  assert.equal((await route(ctx, `${CHANNEL}/unlock?code=${previewed}`, {}, { method: 'GET', headers: { accept: 'text/html' } })).status, 303, 'the code is still good for the person');

  // (7) A rejected code on the GET door is a refusal in the shape that was asked
  //     for — both for a burned code and for one that never existed. Each attempt
  //     comes from its own address so the refusal budget is not the thing under
  //     test here.
  const burned = await mint();
  await route(ctx, `${CHANNEL}/unlock?code=${burned}`, {}, { method: 'GET', headers: { accept: 'text/html' } });
  let client = 0;
  const from = () => `198.51.100.${(client += 1)}`;
  for (const [label, code] of [['burned', burned], ['unknown', 'ABCDEFGH']]) {
    const asJson = await route(ctx, `${CHANNEL}/unlock?code=${code}`, {}, { method: 'GET', headers: { accept: 'application/json' }, remoteAddress: from() });
    assert.equal(asJson.ok, false, `${label}: the JSON shape is refused`);
    assert.equal(asJson.error.code, 'remote-access/pair-denied', `${label}: with the same code the POST door uses`);
    assert.equal(asJson.res.headers.location, undefined, `${label}: and no redirect`);
    assert.ok(!String(asJson.res.body).includes('<!doctype'), `${label}: and never the page`);

    const forced = await route(ctx, `${CHANNEL}/unlock?code=${code}&format=json`, {}, { method: 'GET', headers: { accept: 'text/html' }, remoteAddress: from() });
    assert.equal(forced.ok, false, `${label}: ?format=json is refused the same way`);

    const asPage = await route(ctx, `${CHANNEL}/unlock?code=${code}`, {}, { method: 'GET', headers: { accept: 'text/html' }, remoteAddress: from() });
    assert.equal(asPage.status, 200, `${label}: the HTML shape gets the page`);
    assert.match(String(asPage.res.body), /<!doctype html>/, `${label}: which is the recovery page`);
    assert.equal(asPage.res.headers['set-cookie'], undefined, `${label}: with no credential`);
  }
});

test('offers a plain anchor into the app, and asks for JSON itself', () => {
  const html = unlockPageHtml({
    prefix: CHANNEL,
    configured: true,
    title: 't',
    subtitle: 's',
    passwordLabel: 'p',
    buttonLabel: 'b',
    wrongLabel: 'w',
    throttledLabel: 'th',
    failedLabel: 'f',
    missingLabel: 'm',
    successLabel: 'ok',
    openLabel: 'Open the app',
    qrLabel: 'qr',
  });
  const script = html.split('<script>')[1].split('</script>')[0];
  // The way in that needs nothing from the page: an ordinary anchor, built from
  // the URL the host returned.
  assert.match(html, /<a id="open" href="#" role="button"><\/a>/, 'the page carries a plain link');
  assert.match(script, /open\.href = entry\.url/, 'pointed at the entry URL');
  assert.match(script, /open\.textContent = TEXT\.openLabel/, 'and labelled from the host strings');
  // Its own fetch must say JSON: the default Accept would get the redirect.
  assert.match(script, /headers: \{ 'content-type': 'application\/json', accept: 'application\/json' \}/, 'the page asks for the JSON answer');
  assert.doesNotThrow(() => new Function(script), 'and the script parses');
});

test('adds Secure only when the browser really is on https', async () => {
  // Wrong in the unsafe direction drops the cookie: a `Secure` cookie delivered
  // over http is discarded, while one without `Secure` is accepted over https.
  const navigate = async (ctx, headers, remoteAddress = '203.0.113.9') => {
    const code = (await endpoint(ctx, 'pair-code', { days: 30 })).value.code;
    return route(ctx, `${CHANNEL}/unlock?code=${code}`, {}, { method: 'GET', headers: { accept: 'text/html', ...headers }, remoteAddress });
  };
  const secureOf = (res) => [].concat(res.res.headers['set-cookie'] ?? []).map(String).join('; ').includes('Secure');

  // A LAN visit, tunnel or not: http, so no Secure — the cookie survives.
  const lan = hostCtx({ editor: webServerRows('192.168.31.186'), port: 3080 });
  assert.equal(secureOf(await navigate(lan, { host: '192.168.31.186:3080' })), false, 'a LAN http visit gets no Secure');

  // The local proxy says the browser is on https: that is the one caller allowed
  // to speak for the client, because it is the one terminating TLS.
  const proxied = hostCtx();
  assert.equal(secureOf(await navigate(proxied, { host: 'dsh.example.com', 'x-forwarded-proto': 'https' }, '127.0.0.1')), true, 'the loopback proxy may say https');
  // The same header from anywhere else changes nothing.
  const spoofed = hostCtx();
  assert.equal(secureOf(await navigate(spoofed, { host: 'dsh.example.com', 'x-forwarded-proto': 'https' })), false, 'a stranger may not');

  // The request arrived on the advertised public authority: https by config.
  const advertised = hostCtx({ config: { publicUrl: 'https://dsh-win.mathangler.site/' } });
  assert.equal(secureOf(await navigate(advertised, { host: 'dsh-win.mathangler.site' })), true, 'the advertised tunnel authority is https');
  // But the same instance visited over its LAN address is still http.
  const advertisedLan = hostCtx({ config: { publicUrl: 'https://dsh-win.mathangler.site/' }, editor: webServerRows('192.168.31.186'), port: 3080 });
  assert.equal(secureOf(await navigate(advertisedLan, { host: '192.168.31.186:3080' })), false, 'and the LAN address of that instance is not');
});

test('decides Secure from configuration, not from a header a caller sets', async () => {
  // `x-forwarded-proto` decided whether the plugin's cookies carried `Secure`,
  // which let any caller choose the transport attributes of a credential.
  const plain = hostCtx();
  const plainCode = (await endpoint(plain, 'pair-code', { days: 30 })).value.code;
  const claimed = await route(plain, `${CHANNEL}/unlock/pair`, { code: plainCode }, { method: 'POST', headers: { 'x-forwarded-proto': 'https' } });
  assert.equal(claimed.ok, true, JSON.stringify(claimed.error));
  const cookie = [].concat(claimed.res.headers['set-cookie'] ?? []).join('; ');
  assert.ok(!cookie.includes('Secure'), 'a header claim does not add Secure');

  // A configured public URL is what says https, and it is read from the config.
  const advertised = hostCtx({ config: { publicUrl: 'https://dsh.example.com/' } });
  const advertisedCode = (await endpoint(advertised, 'pair-code', { days: 30 })).value.code;
  const secure = await route(advertised, `${CHANNEL}/unlock/pair`, { code: advertisedCode }, { method: 'POST' });
  assert.equal(secure.ok, true, JSON.stringify(secure.error));
  assert.ok([].concat(secure.res.headers['set-cookie'] ?? []).join('; ').includes('Secure'), 'the configured https base does');
});

test('a flood of entry links cannot evict a real device, and is rate limited', async () => {
  const ctx = hostCtx();
  // Three real paired devices, as a household would have.
  const real = [];
  for (let index = 0; index < 3; index += 1) {
    const key = await endpoint(ctx, 'key-create', { name: `Phone ${index}` });
    await endpoint(ctx, 'token', { key: key.value.key });
  }
  for (const row of ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices) real.push(row.id);
  assert.equal(real.length, 3);

  // Now a flood of launch-token visits — the shape that used to add fifty rows
  // and push every real device out of the capped list.
  const gate = ctx.routes.exact.get('/');
  const mintedCookies = [];
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const res = fakeResponse();
    await gate(
      fakeRequest(undefined, {
        method: 'GET',
        url: '/?token=launch-token',
        headers: { host: 'dsh.example.com' },
        remoteAddress: '198.51.100.44',
      }),
      res,
    );
    assert.equal(res.statusCode, 303, 'the platform exchange still answers');
    const cookies = [].concat(res.headers['set-cookie'] ?? []).map(String);
    assert.ok(cookies.some((value) => value.startsWith('dsh-session=')), 'with the platform cookie');
    if (cookies.some((value) => value.startsWith('mc-device='))) mintedCookies.push(attempt);
  }

  const rows = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices;
  for (const id of real) {
    assert.ok(rows.some((row) => row.id === id), `the real device ${id} is still authorized`);
  }
  const entryLinks = rows.filter((row) => row.source === 'entry-link');
  assert.ok(entryLinks.length <= 3, `entry links are capped, got ${entryLinks.length}`);
  // Five mints per client per quarter hour: the flood gets no more than that,
  // and it can never reach MAX_DEVICES.
  assert.equal(mintedCookies.length, 5, 'the mint budget is five per client');
  assert.equal(mintedCookies[0], 0, 'the first visit mints');
  assert.equal(mintedCookies[4], 4, 'the fifth mints');
  assert.equal(rows.length, 3 + entryLinks.length, 'and nothing else was added');
});

test('refuses a token visit, and a redirect, from an authority the fence rejects', async () => {
  // F7: the gate used to accept a device credential even when the fence said
  // 403, and then build a redirect from that Host — which handed the refused
  // authority a URL carrying the process launch token.
  const ctx = hostCtx();
  const gate = ctx.routes.exact.get('/');
  const key = await endpoint(ctx, 'key-create', { name: 'Phone' });
  const linked = await endpoint(ctx, 'token', { key: key.value.key });
  const token = new URL(linked.value.url).searchParams.get('token');
  const device = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices[0];
  const cookie = { cookie: `mc-device=${device.hash}` };

  for (const attempt of [
    { url: '/', headers: { host: 'evil.example', ...cookie } },
    { url: '/?token=launch-token', headers: { host: 'evil.example' } },
    { url: `/?token=${token}`, headers: { host: 'evil.example' } },
    { url: '/', headers: { host: 'evil.example', cookie: 'mc-unlock=whatever' } },
  ]) {
    const res = fakeResponse();
    await gate(fakeRequest(undefined, { method: 'GET', remoteAddress: '203.0.113.9', ...attempt }), res);
    assert.equal(res.statusCode, 403, `${attempt.url} on a refused Host is refused`);
    assert.equal(res.headers.location, undefined, 'and no redirect is built for it');
    assert.equal(res.headers['set-cookie'], undefined, 'and nothing is minted');
  }
  // No row was created for a refused authority.
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'the only row is the one the panel minted');
});

test('mints a one-time link for an existing device without touching it', async () => {
  const ctx = hostCtx();
  const created = await endpoint(ctx, 'key-create', { name: 'Phone' });
  await endpoint(ctx, 'token', { key: created.value.key });
  const before = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices;
  assert.equal(before.length, 1);
  const source = before[0];
  const snapshot = JSON.stringify(source);

  const linked = await endpoint(ctx, 'device-link', { id: source.id });
  assert.equal(linked.ok, true, JSON.stringify(linked.error));
  // The answer identifies the LINK row — the one the panel can see and revoke —
  // and says which device it was minted for.
  assert.notEqual(linked.value.id, source.id, 'the link row, not the source row');
  assert.equal(linked.value.parentId, source.id);
  assert.ok(isTempToken(new URL(linked.value.url).searchParams.get('token')), 'the link carries a temp token');
  assert.ok(Number.isInteger(linked.value.qr?.size));
  assert.ok(Math.abs(linked.value.expiresAt - Date.now() - TEMP_TOKEN_TTL_MS) < 5000, 'fifteen minutes, as promised');

  const rows = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices;
  assert.equal(rows.length, 2, 'a new row, not a rewritten one');
  const added = rows.find((row) => row.id === linked.value.id);
  assert.ok(added !== undefined, 'the returned id is a row that exists');
  assert.equal(added.parentId, source.id, 'and it remembers its device');
  assert.equal(added.temporary, true);
  assert.equal(added.source, source.source, 'the source is copied');
  assert.match(added.name, /· 链接$/);
  assert.notEqual(added.hash, source.hash, 'and the device keeps its own credential');
  // The source row is byte-for-byte what it was.
  assert.equal(JSON.stringify(rows.find((row) => row.id === source.id)), snapshot);
  // The panel can revoke exactly what it was handed.
  assert.equal((await endpoint(ctx, 'device-revoke', { id: linked.value.id })).value.revoked, true);
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'the link row is the one that went away');
  assert.equal(JSON.stringify(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices[0]), snapshot, 'and the device survived');

  // Unknown id: a dedicated refusal the panel can branch on, and nothing minted.
  const missing = await endpoint(ctx, 'device-link', { id: 'nope' });
  assert.equal(missing.ok, false);
  assert.equal(missing.error.code, 'remote-access/device-not-found');
  assert.match(missing.error.message, /no authorized device with id "nope"/);
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'a failed link adds no row');

  // And it is rate limited like the other mint operations: the mint above was
  // the first of five, so four more are allowed and the sixth is refused.
  for (let attempt = 0; attempt < 4; attempt += 1) {
    assert.equal((await endpoint(ctx, 'device-link', { id: source.id })).ok, true, `mint ${attempt + 2}`);
  }
  const throttled = await endpoint(ctx, 'device-link', { id: source.id });
  assert.equal(throttled.ok, false);
  assert.match(throttled.error.message, /too many links/);
});

test('a device link dies with the device it was minted for', async () => {
  const visit = async (ctx, token) => {
    const res = fakeResponse();
    await ctx.routes.exact.get('/')(
      fakeRequest(undefined, { method: 'GET', url: `/?token=${token}`, headers: { host: 'dsh.example.com' }, remoteAddress: '203.0.113.9' }),
      res,
    );
    return res;
  };
  const linkFor = async (ctx, deviceId) => {
    const linked = await endpoint(ctx, 'device-link', { id: deviceId });
    return { rowId: linked.value.id, token: new URL(linked.value.url).searchParams.get('token') };
  };
  const pairedCtx = async () => {
    const ctx = hostCtx();
    const key = await endpoint(ctx, 'key-create', { name: 'Phone' });
    await endpoint(ctx, 'token', { key: key.value.key });
    const device = (await endpoint(ctx, 'device-list', {})).value.devices[0];
    return { ctx, device };
  };

  // A live device: revoking the DEVICE takes its outstanding link with it.
  const first = await pairedCtx();
  const revokedLink = await linkFor(first.ctx, first.device.id);
  assert.ok(revokedLink.rowId !== undefined);
  assert.equal((await endpoint(first.ctx, 'device-revoke', { id: first.device.id })).value.removed, 2, 'the device and its link both go');
  assert.equal(first.ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 0, 'nothing is left to redeem');
  assert.notEqual((await visit(first.ctx, revokedLink.token)).statusCode, 303, 'and the link no longer opens anything');

  // Revoking only the parent (the cascade is tested above; this checks the
  // redemption-time parent rule on its own).
  const second = await pairedCtx();
  const lateLink = await linkFor(second.ctx, second.device.id);
  assert.equal((await visit(second.ctx, lateLink.token)).statusCode, 303, 'it works while the device is live');
  const third = await pairedCtx();
  const orphanLink = await linkFor(third.ctx, third.device.id);
  third.ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices = third.ctx.records
    .get(DEVICES_V2_RECORD_KEY)
    .payload.devices.filter((row) => row.id !== third.device.id);
  assert.notEqual((await visit(third.ctx, orphanLink.token)).statusCode, 303, 'a link whose parent is gone is refused');

  // A parent that has merely expired is refused too.
  const fourth = await pairedCtx();
  const expiringLink = await linkFor(fourth.ctx, fourth.device.id);
  fourth.ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.find((row) => row.id === fourth.device.id).expiresAt = Date.now() - 1000;
  assert.notEqual((await visit(fourth.ctx, expiringLink.token)).statusCode, 303, 'a link whose parent expired is refused');
});

test('refuses a one-time link whose row was revoked, and one that expired', async () => {
  const root = (ctx) => ctx.routes.exact.get('/');
  const visit = async (ctx, token) => {
    const res = fakeResponse();
    await root(ctx)(fakeRequest(undefined, { method: 'GET', url: `/?token=${token}`, headers: { host: 'dsh.example.com' }, remoteAddress: '203.0.113.9' }), res);
    return res;
  };

  // A live link redirects into the app...
  const live = hostCtx();
  const created = await endpoint(live, 'key-create', { name: 'Phone' });
  const minted = await endpoint(live, 'token', { key: created.value.key });
  const token = new URL(minted.value.url).searchParams.get('token');
  assert.equal((await visit(live, token)).statusCode, 303, 'a live link works');

  // ...revoking its row stops it dead, with nothing left to burn.
  const revoked = hostCtx();
  const key = await endpoint(revoked, 'key-create', { name: 'Phone' });
  const link = await endpoint(revoked, 'token', { key: key.value.key });
  const linkToken = new URL(link.value.url).searchParams.get('token');
  const row = revoked.records.get(DEVICES_V2_RECORD_KEY).payload.devices[0];
  assert.equal((await endpoint(revoked, 'device-revoke', { id: row.id })).value.revoked, true);
  assert.equal(revoked.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 0);
  assert.notEqual((await visit(revoked, linkToken)).statusCode, 303, 'a revoked link cannot be redeemed');

  // An expired row is refused too (and burned, so it cannot linger).
  const stale = hostCtx();
  const staleKey = await endpoint(stale, 'key-create', { name: 'Phone' });
  const staleLink = await endpoint(stale, 'token', { key: staleKey.value.key });
  const staleToken = new URL(staleLink.value.url).searchParams.get('token');
  stale.records.get(DEVICES_V2_RECORD_KEY).payload.devices[0].expiresAt = Date.now() - 1000;
  assert.notEqual((await visit(stale, staleToken)).statusCode, 303, 'an expired link cannot be redeemed');
  assert.equal(stale.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 0, 'and the attempt burns it');

  // Pasting the token into the device cookie must not turn a single-use link
  // into a fifteen-minute session: the link is only ever redeemed through the
  // one door that burns it.
  const smuggled = hostCtx();
  const smuggledKey = await endpoint(smuggled, 'key-create', { name: 'Phone' });
  const smuggledLink = await endpoint(smuggled, 'token', { key: smuggledKey.value.key });
  const smuggledToken = new URL(smuggledLink.value.url).searchParams.get('token');
  const gate = fakeResponse();
  await smuggled.routes.exact.get('/')(
    fakeRequest(undefined, {
      method: 'GET',
      url: '/',
      headers: { host: 'dsh.example.com', cookie: `mc-device=${smuggledToken}` },
      remoteAddress: '203.0.113.9',
    }),
    gate,
  );
  assert.notEqual(gate.statusCode, 303, 'the device cookie door refuses a one-time token');
  assert.equal(smuggled.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'and the link is still intact for its own door');
  assert.equal((await visit(smuggled, smuggledToken)).statusCode, 303, 'while its real door still works once');
});

test('never hands the platform launch token back to a client', async () => {
  const ctx = hostCtx();
  const secret = 'clean-secret';
  ctx.records.set('dsh-remote-access/recovery', {
    kind: 'grant',
    payload: { version: 1, key: 'k', salt: 's', secret, iterations: 1000 },
  });
  const tokenFree = (label, url) => {
    assert.equal(typeof url, 'string', `${label} has a URL`);
    assert.equal(new URL(url).searchParams.has('token'), false, `${label} carries no token`);
    assert.ok(!url.includes('launch-token'), `${label} does not leak the launch token`);
  };

  // Every URL-bearing answer the plugin gives out.
  tokenFree('pair-code', (await endpoint(ctx, 'pair-code', { days: null })).value.url);
  tokenFree('renew-session', (await endpoint(ctx, 'renew-session', {})).value.url);
  const code = (await endpoint(ctx, 'pair-code', { days: null })).value.code;
  const pair = await route(ctx, `${CHANNEL}/unlock/pair`, { code }, { method: 'POST' });
  tokenFree('/unlock/pair', pair.value.url);
  const phone = {};
  const pairCookie = [].concat(pair.res.headers['set-cookie'] ?? []);
  assert.ok(pairCookie.some((value) => String(value).startsWith('mc-device=')));
  const deviceCookie = String(pairCookie.find((value) => String(value).startsWith('mc-device='))).split(';')[0];
  phone.cookie = deviceCookie;

  const ticket = signTicket(secret, { v: 1, exp: Date.now() + 60_000, row: 'row-9' });

  // And no redirect the plugin writes may carry one either.
  const redirects = [];
  const gate = async (headers, url = '/') => {
    const res = fakeResponse();
    await ctx.routes.exact.get('/')(fakeRequest(undefined, { method: 'GET', url, headers: { host: 'dsh.example.com', ...headers }, remoteAddress: '203.0.113.9' }), res);
    if (res.statusCode === 303) redirects.push({ location: res.headers.location, tokens: res.headers['set-cookie'] ?? [] });
    return res;
  };
  // A device credential, while its pairing row is still the only row.
  const byDevice = await gate(phone);
  assert.equal(byDevice.statusCode, 303, 'the device credential re-enters');

  // Then a ticket, for which its row has to exist in the record.
  ctx.records.set(DEVICES_V2_RECORD_KEY, {
    kind: 'grant',
    payload: {
      version: 2,
      devices: [
        {
          id: 'row-9',
          name: 'Phone',
          source: 'device-code',
          temporary: false,
          createdAt: new Date().toISOString(),
          lastUsedAt: null,
          expiresAt: null,
          days: null,
          hash: 'c'.repeat(64),
        },
      ],
    },
  });
  const entry = await route(ctx, `${CHANNEL}/unlock/entry`, {}, { method: 'POST', headers: { cookie: `${UNLOCK_COOKIE}=${ticket}` } });
  tokenFree('/unlock/entry', entry.value.url);
  const byTicket = await gate({ cookie: `${UNLOCK_COOKIE}=${ticket}` });
  assert.equal(byTicket.statusCode, 303, 'the ticket re-enters');

  // And a one-time link, from the access-key door.
  const created = await endpoint(ctx, 'key-create', { name: 'Phone' });
  const minted = await endpoint(ctx, 'token', { key: created.value.key });
  const byLink = await gate({}, `/?token=${new URL(minted.value.url).searchParams.get('token')}`);
  assert.equal(byLink.statusCode, 303, 'the one-time link re-enters');

  assert.equal(redirects.length, 3, 'all three credential kinds redirected');
  for (const redirect of redirects) {
    assert.equal(redirect.location, '/', 'the redirect is a bare path, not a tokenized URL');
    assert.ok(!String(redirect.location).includes('token'), 'and it carries no token parameter');
    assert.ok(
      redirect.tokens.some((value) => String(value).startsWith('dsh-session=')),
      'the session arrives as a cookie from the server-side exchange',
    );
  }
});

test('backs the unlock ticket with its row, so revoking the row revokes it', async () => {
  const ctx = hostCtx();
  const secret = 'ticket-secret';
  ctx.records.set('dsh-remote-access/recovery', {
    kind: 'grant',
    payload: { version: 1, key: 'k', salt: 's', secret, iterations: 1000 },
  });
  const now = Date.now();
  const row = {
    id: 'row-1',
    name: 'Phone',
    source: 'password',
    temporary: true,
    createdAt: new Date(now).toISOString(),
    lastUsedAt: null,
    expiresAt: now + 15 * 60 * 1000,
    days: null,
    hash: 'b'.repeat(64),
  };
  ctx.records.set(DEVICES_V2_RECORD_KEY, { kind: 'grant', payload: { version: 2, devices: [row] } });

  const cookie = (payload) => ({ cookie: `${UNLOCK_COOKIE}=${signTicket(secret, payload)}` });
  const ticket = { v: 1, exp: now + 15 * 60 * 1000, iat: now, row: row.id };
  const entry = await route(ctx, `${CHANNEL}/unlock/entry`, {}, { method: 'POST', headers: cookie(ticket) });
  assert.equal(entry.status, 200, 'a live row lets its ticket through');

  // Revoke the row: the ticket it minted stops working, on the endpoint...
  ctx.records.set(DEVICES_V2_RECORD_KEY, { kind: 'grant', payload: { version: 2, devices: [] } });
  assert.equal((await route(ctx, `${CHANNEL}/unlock/entry`, {}, { method: 'POST', headers: cookie(ticket) })).status, 401);

  // ...and on the root gate's redirect path, which is the one that matters.
  const gate = fakeResponse();
  await ctx.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/', headers: { host: 'dsh.example.com', ...cookie(ticket) }, remoteAddress: '203.0.113.9' }),
    gate,
  );
  assert.notEqual(gate.statusCode, 303, 'a ticket whose row is gone cannot re-enter');

  // A ticket with no row at all — anything minted before this rule — is refused
  // rather than grandfathered in.
  ctx.records.set(DEVICES_V2_RECORD_KEY, { kind: 'grant', payload: { version: 2, devices: [row] } });
  const legacy = await route(ctx, `${CHANNEL}/unlock/entry`, {}, { method: 'POST', headers: cookie({ v: 1, exp: now + 60_000 }) });
  assert.equal(legacy.status, 401, 'a row-less ticket buys nothing');
});

test('answers every QR-bearing door with the same matrix shape', async () => {
  const ctx = hostCtx();
  const matrix = (qr, where) => {
    assert.ok(Number.isInteger(qr?.size) && typeof qr?.bits === 'string', `${where} carries { size, bits }`);
    assert.equal(qr.bits.length, qr.size * qr.size, `${where} carries a full matrix`);
  };

  // The pairing-code door hands back a URL to navigate to, not just a day count.
  const code = await endpoint(ctx, 'pair-code', { days: 30 });
  matrix(code.value.qr, 'pair-code');
  assert.equal(typeof code.value.url, 'string');

  const pair = await route(ctx, `${CHANNEL}/unlock/pair`, { code: code.value.code }, { method: 'POST' });
  assert.equal(pair.ok, true, JSON.stringify(pair.error));
  assert.equal(typeof pair.value.url, 'string', 'the page has somewhere to go');
  assert.equal(pair.value.days, 30);
  assert.ok(pair.value.expiresAt > Date.now());
  matrix(pair.value.qr, '/unlock/pair');

  // The access-key and device-link doors.
  const key = await endpoint(ctx, 'key-create', { name: 'Phone' });
  matrix((await endpoint(ctx, 'token', { key: key.value.key })).value.qr, '/remote-access/token');
  const devices = await endpoint(ctx, 'device-list', {});
  matrix((await endpoint(ctx, 'device-link', { id: devices.value.devices[0].id })).value.qr, 'device-link');

  // And /unlock/entry, which used to be the odd one out with an SVG string.
  const secret = 'entry-secret';
  ctx.records.set('dsh-remote-access/recovery', { kind: 'grant', payload: { version: 1, key: 'k', salt: 's', secret, iterations: 1000 } });
  const row = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices[0];
  const ticket = signTicket(secret, { v: 1, exp: Date.now() + 60_000, row: row.id });
  const entry = await route(ctx, `${CHANNEL}/unlock/entry`, {}, { method: 'POST', headers: { cookie: `${UNLOCK_COOKIE}=${ticket}` } });
  assert.equal(entry.ok, true);
  matrix(entry.value.qr, '/unlock/entry');
});

test('renders a page that can redeem a pairing code without a password', () => {
  // The QR the panel prints encodes the code in this page's own query string,
  // and the phone that opens it may have no password armed at all — so the
  // script must run with no form, redeem the code, and go into the app.
  const bare = unlockPageHtml({ prefix: CHANNEL, configured: false, title: 't', subtitle: 's', passwordLabel: 'p', buttonLabel: 'b', wrongLabel: 'w', missingLabel: 'no-password-yet', successLabel: 'ok', openLabel: 'o', qrLabel: 'qr' });
  assert.ok(!bare.includes('<form id="f">'), 'still no form without a password');
  assert.match(bare, /'\/unlock\/pair'/, 'the page can redeem a code');
  assert.match(bare, /location\.search/, 'and it reads the code from its own query string');
  assert.match(bare, /location\.replace\(/, 'then navigates into the app');
  assert.match(bare, /'\/unlock\/entry'/, 'the password path keeps its entry fallback');
  // The matrix → SVG conversion lives in the page, so one shape reaches both.
  assert.match(bare, /function qrMarkup/, 'the page renders the matrix itself');
  assert.match(bare, /shape-rendering="crispEdges"/);
});

test('reports the mode and switches the bind without starting a tunnel', async () => {
  const ctx = hostCtx({ port: 3080 });
  const status = await endpoint(ctx, 'mode-status', {});
  assert.equal(status.value.mode, 'public', 'the shipped bind is loopback');
  assert.equal(status.value.port, 3080);
  assert.equal(status.value.tunnelRunning, false);
  assert.equal(status.value.publicUrl, null);
  assert.ok(Array.isArray(status.value.addresses));
  for (const address of status.value.addresses) {
    assert.equal(typeof address.address, 'string');
    assert.equal(typeof address.label, 'string');
  }

  // Without the configEditor service the switch cannot write, and must say so.
  const refused = await endpoint(ctx, 'set-mode', { mode: 'lan', host: '10.0.161.47' });
  assert.equal(refused.ok, false);
  const nonsense = await endpoint(ctx, 'set-mode', { mode: 'sideways' });
  assert.equal(nonsense.ok, false);
  assert.match(nonsense.error.message, /'lan' or 'public'/);
});

test('rewrites only the named keys of one profile row', () => {
  const patch = [
    '# a comment that must survive',
    '- id: webserver',
    '  name: "@deepseek-ai/dsh-host-webserver"',
    '  config:',
    '    host: 127.0.0.1',
    '    port: !!js ctx.webStartup.port ?? 3080',
    '    tls: !!js ctx.webStartup.tls',
    '    compression: gzip',
    '- id: connection',
    '  name: "@deepseek-ai/dsh-client-connection"',
    '  config:',
    '    trustedHosts:',
    '      - dsh-win.example.com:443',
    '      - 192.168.31.186:3199',
    '- id: other',
    '  config:',
    '    host: keep-me',
    '',
  ].join('\n');

  const hostChanged = patchRowConfig(patch, 'webserver', { host: '10.0.161.47' });
  assert.ok(hostChanged.includes('    host: 10.0.161.47'));
  assert.ok(hostChanged.includes('    host: keep-me'), 'another row keeps its own host');
  assert.ok(hostChanged.includes('    port: !!js ctx.webStartup.port ?? 3080'), 'the !!js expressions survive');
  assert.ok(hostChanged.includes('    tls: !!js ctx.webStartup.tls'));
  assert.ok(hostChanged.includes('    compression: gzip'));
  assert.ok(hostChanged.includes('      - dsh-win.example.com:443'), 'another row is untouched');
  assert.ok(hostChanged.includes('# a comment that must survive'));
  assert.equal(hostChanged.split('\n').length, patch.split('\n').length, 'a scalar rewrite is one for one');

  // A list is replaced wholesale, and the merge the caller did is what lands.
  const hostsChanged = patchRowConfig(patch, 'connection', { trustedHosts: ['dsh-win.example.com:443', '10.0.161.47:3080'] });
  assert.ok(hostsChanged.includes('    trustedHosts:\n      - dsh-win.example.com:443\n      - 10.0.161.47:3080\n'));
  assert.ok(!hostsChanged.includes('192.168.31.186:3199'), 'the old list is gone, not appended to');
  assert.ok(hostsChanged.includes('    host: 127.0.0.1'), 'the webserver row is untouched');

  // A key the row does not have yet is added, in front of the ones it has.
  const added = patchRowConfig(patch, 'other', { port: 3199 });
  assert.ok(added.includes('- id: other\n  config:\n    port: 3199\n    host: keep-me'), 'the new key goes first');
  // A row with no config block at all gets one.
  const fresh = patchRowConfig('- id: bare\n  name: x\n', 'bare', { host: '127.0.0.1' });
  assert.equal(fresh, '- id: bare\n  name: x\n  config:\n    host: 127.0.0.1\n');
  // A row that is not there at all is appended, with its plugin name, and only
  // when the caller could supply one.
  const appended = patchRowConfig(patch, 'new-row', { host: '127.0.0.1' }, 'dsh-new-row');
  assert.ok(appended.endsWith('- id: new-row\n  name: dsh-new-row\n  config:\n    host: 127.0.0.1\n'));
  assert.equal(patchRowConfig(patch, 'new-row', { host: '127.0.0.1' }), undefined, 'no name, no faithful append');

  // Idempotent: the text comes back unchanged when it already says this.
  assert.equal(patchRowConfig(hostChanged, 'webserver', { host: '10.0.161.47' }), hostChanged);

  // CRLF survives.
  const crlf = patch.replace(/\n/g, '\r\n');
  assert.ok(patchRowConfig(crlf, 'webserver', { host: '10.0.0.9' }).includes('\r\n    host: 10.0.0.9\r\n'));

  // Reading a list back out of the file is what makes a merge safe.
  assert.deepEqual(readRowConfigList(patch, 'connection', 'trustedHosts'), {
    present: true,
    values: ['dsh-win.example.com:443', '192.168.31.186:3199'],
  });
  assert.deepEqual(readRowConfigList(patch, 'webserver', 'trustedHosts'), { present: false, values: [] });
  assert.deepEqual(readRowConfigList('- id: x\n  config:\n    hosts: [a, "b c"]\n', 'x', 'hosts'), { present: true, values: ['a', 'b c'] });
  assert.deepEqual(readRowConfigList(patch, 'nope', 'trustedHosts'), { present: false, values: [] });

  // Refusals, so the caller can fall back rather than guess.
  assert.equal(patchRowConfig('id: not-a-sequence\n', 'webserver', { host: 'x' }), undefined);
  assert.equal(patchRowConfig('- id: webserver\n  config: { host: 127.0.0.1 }\n', 'webserver', { host: 'x' }), undefined);
  assert.equal(patchRowConfig('- id: webserver\n  insert:\n    - id: webserver\n', 'webserver', { host: 'x' }), undefined);
  assert.equal(patchRowConfig('', 'webserver', { host: 'x' }), undefined);
  assert.equal(patchRowConfig(patch, 'webserver', null), undefined);
});

test('never writes a credential value JSON cannot hold', () => {
  const payload = storablePayload({ version: 2, devices: [{ id: 'a', lastUsedIp: undefined, name: 'x' }] }, 'test');
  assert.deepEqual(payload, { version: 2, devices: [{ id: 'a', name: 'x' }] }, 'an absent field is dropped, not written as null');
  assert.equal(JSON.stringify(payload).includes('undefined'), false);
  assert.equal(storablePayload({ a: null, b: false, c: 0, d: '' }, 'test').b, false, 'falsy values are kept');
  assert.throws(() => storablePayload({ a: Number.NaN }, 'test'), /a is NaN/);
  assert.throws(() => storablePayload({ a: Number.POSITIVE_INFINITY }, 'test'), /Infinity/);
  assert.throws(() => storablePayload({ a: () => {} }, 'test'), /function/);
  assert.throws(() => storablePayload({ a: [undefined] }, 'test'), /a\[0\] is undefined/);
  const circular = { id: 'x' };
  circular.self = circular;
  assert.throws(() => storablePayload(circular, 'test'), /circular/);
});

test('switches the bind through the profile patch, merging trusted hosts', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-access-'));
  const path = join(dir, 'cordis.patch.yml');
  const original = [
    '- id: webserver',
    '  name: "@deepseek-ai/dsh-host-webserver"',
    '  config:',
    '    host: 127.0.0.1',
    '    port: !!js ctx.webStartup.port ?? 3080',
    '- id: connection',
    '  name: "@deepseek-ai/dsh-client-connection"',
    '  config:',
    '    trustedHosts:',
    '      - dsh-win.mathangler.site',
    '',
  ].join('\n');
  writeFileSync(path, original);
  try {
    const rows = webServerRows();
    const connected = rows.find((row) => row.entry.options.id === 'connection');
    connected.entry.options.config = { trustedHosts: ['dsh-win.mathangler.site'] };
    const wired = hostCtx({ editor: rows, documentPath: path, port: 3080 });

    const lan = await endpoint(wired, 'set-mode', { mode: 'lan', host: '10.0.161.47' });
    assert.equal(lan.ok, true, JSON.stringify(lan.error));
    assert.equal(lan.value.mode, 'lan');
    assert.equal(lan.value.host, '10.0.161.47');
    assert.equal(lan.value.authority, '10.0.161.47:3080');
    assert.equal(lan.value.restartRequired, true);
    assert.equal(lan.value.appliesImmediately, true, 'a bind write applies as soon as the file changes');
    assert.equal(lan.value.rebindMayDropThisPage, true);

    const afterLan = readFileSync(path, 'utf8');
    assert.ok(afterLan.includes('    host: 10.0.161.47'), 'the bind really changed on disk');
    assert.ok(afterLan.includes('    port: !!js ctx.webStartup.port ?? 3080'), 'the !!js port survives');
    // (D)(i): the existing trusted host is merged, never dropped.
    assert.deepEqual(lan.value.trustedHosts, ['dsh-win.mathangler.site', '10.0.161.47:3080']);
    assert.ok(afterLan.includes('      - dsh-win.mathangler.site\n'), 'the existing entry survives');
    assert.ok(afterLan.includes('      - 10.0.161.47:3080\n'), 'the new authority is added');
    assert.equal(wired.editsFor('connection').length, 0, 'the platform editor is not used for these rows');
    assert.equal(wired.editsFor('webserver').length, 0);

    // A repeated LAN switch changes nothing on disk.
    const repeat = await endpoint(wired, 'set-mode', { mode: 'lan', host: '10.0.161.47' });
    assert.equal(repeat.ok, true);
    assert.equal(readFileSync(path, 'utf8'), afterLan, 'a repeat is a no-op');

    // The file, not the (possibly stale) live row, is what a merge reads: an
    // entry another writer added after the row was built must survive.
    writeFileSync(path, afterLan.replace('      - 10.0.161.47:3080\n', '      - 10.0.161.47:3080\n      - 10.0.97.10:3199\n'));
    const mergedAgain = await endpoint(wired, 'set-mode', { mode: 'lan', host: '10.0.161.47' });
    assert.deepEqual(
      mergedAgain.value.trustedHosts,
      ['dsh-win.mathangler.site', '10.0.161.47:3080', '10.0.97.10:3199'],
      'a host the file holds is never dropped by a later switch',
    );
    assert.ok(readFileSync(path, 'utf8').includes('      - 10.0.97.10:3199\n'));

    // And the way back works — in the same process, which the platform editor
    // could no longer do once its HMR transaction had been nested.
    const restored = await endpoint(wired, 'restore-loopback', {});
    assert.equal(restored.value.mode, 'public');
    assert.equal(restored.value.host, '127.0.0.1');
    assert.equal(restored.value.restartRequired, true);
    assert.equal(restored.value.appliesImmediately, true);
    const afterRestore = readFileSync(path, 'utf8');
    assert.ok(afterRestore.includes('    host: 127.0.0.1'), 'restore-loopback really restores');
    assert.ok(afterRestore.includes('      - 10.0.161.47:3080\n'), '(D) the trusted list is not clobbered by the way back');
    assert.equal(wired.editsFor('webserver').length, 0);

    // Idempotent again, and honest about it.
    const again = await endpoint(wired, 'restore-loopback', {});
    assert.equal(again.value.appliesImmediately, false, 'nothing changed, so nothing is being applied');
    assert.equal(again.value.rebindMayDropThisPage, false);
    assert.equal(readFileSync(path, 'utf8'), afterRestore);

    // No temporary neighbours are left behind by the atomic write.
    assert.deepEqual(readdirSync(dir).filter((name) => name.includes('.tmp')), []);

    // The platform editor is still the fallback when the patch path is unknown.
    const fallback = hostCtx({ editor: webServerRows() });
    const viaEditor = await endpoint(fallback, 'set-mode', { mode: 'lan', host: '10.0.161.47' });
    assert.equal(viaEditor.ok, true);
    assert.equal(fallback.editsFor('webserver').at(-1).next.host, '10.0.161.47');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('reports the Cloudflare Access state and never throws without a token', async () => {
  // No stored token: a short reason and an empty block, not a failed endpoint.
  const bare = hostCtx({ config: { tunnelHost: 'dsh.example.com' } });
  const empty = await endpoint(bare, 'cf-env', {});
  assert.equal(empty.ok, true);
  assert.deepEqual(empty.value.access, { enabled: false, configured: false, apps: [] });
  assert.equal(typeof empty.value.accessError, 'string');
  assert.ok(empty.value.accessError.length > 0);

  // With a token, the state comes from the API through the existing client. The
  // client captures `fetch` when the plugin activates, so each variant needs its
  // own context created while that stub is installed.
  const realFetch = globalThis.fetch;
  const api = (handler) => {
    globalThis.fetch = async (url) => handler(String(url));
  };
  const answering = (apps) => (url) => ({
    status: 200,
    text: async () =>
      JSON.stringify(url.includes('/zones?') ? { success: true, result: [{ id: 'z1', name: 'example.com', account: { id: 'a1', name: 'acct' } }] } : { success: true, result: apps }),
  });
  const cloudCtx = () => {
    const ctx = hostCtx({ config: { tunnelHost: 'dsh.example.com' } });
    ctx.secrets.set('CLOUDFLARE_API_TOKEN', 'cf-token');
    return ctx;
  };
  try {
    api(answering([{ id: 'app1', name: 'dsh', domain: 'dsh.example.com', session_duration: '720h' }]));
    const enabled = await endpoint(cloudCtx(), 'cf-env', {});
    assert.deepEqual(enabled.value.access, {
      enabled: true,
      configured: true,
      apps: [{ id: 'app1', name: 'dsh', domain: 'dsh.example.com', sessionDuration: '720h' }],
    });
    assert.equal('accessError' in enabled.value, false, 'a healthy read carries no error');

    // A readable app list that does not cover the tunnel hostname: the scope is
    // there, the edge gate is not.
    api(answering([{ id: 'other', name: 'other', domain: 'other.example.com' }]));
    const notCovered = await endpoint(cloudCtx(), 'cf-env', {});
    assert.deepEqual(notCovered.value.access, { enabled: false, configured: true, apps: [] });

    // A token without the Access scope, or any other API failure: the block
    // stays empty and the reason is a string, because the panel defaults the
    // whole line to "未启用" when the block is missing or disabled.
    api(() => ({ status: 403, text: async () => JSON.stringify({ success: false, errors: [{ code: 9109, message: 'Unauthorized' }] }) }));
    const denied = await endpoint(cloudCtx(), 'cf-env', {});
    assert.equal(denied.ok, true);
    assert.deepEqual(denied.value.access, { enabled: false, configured: false, apps: [] });
    assert.match(denied.value.accessError, /Unauthorized/);
  } finally {
    globalThis.fetch = realFetch;
  }
});