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
import { expiryFromDays } from '../lib/unlock.js';
import {
  ACCESS_KEYS_RECORD_KEY,
  DEVICES_V2_RECORD_KEY,
  DEVICE_RECORD_KEY,
  ENTRY_LINK_DAYS,
  apply,
  CHANNEL,
  deviceDeletable,
  deviceStatus,
  migrateLegacyDeviceRows,
  modeFromBindHost,
  parseDeviceRows,
  patchRowConfig,
  publicDeviceRow,
  publicKeyRow,
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
  const lan = { bindHost: '10.0.161.47', port: 3080, requestHost: '10.0.161.47:3080', requestScheme: 'http' };
  const loopback = { bindHost: '127.0.0.1', port: 3080, requestHost: '127.0.0.1:3080', requestScheme: 'http' };

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
  assert.equal(resolveLinkBase({ publicUrl: 'http://10.0.161.47:3080' }).reachable, 'lan');
  // A scheme-less advertised name is a public one, so it gets https.
  assert.deepEqual(resolveLinkBase({ publicUrl: 'dsh.example.com' }), {
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
  assert.deepEqual(resolveLinkBase({ tunnelHost: 'dsh.example.com:8443' }), {
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
function hostCtx({ records = new Map(), secrets = new Map(), config, editor, connection, port = 3080, documentPath } = {}) {
  const routes = { prefix: [], exact: new Map() };
  const credentials = {
    readRecord: async (key) => records.get(key),
    modifyRecord: async (key, mutate) => {
      const next = await mutate(records.get(key));
      if (next !== undefined) records.set(key, next);
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
                  // real request to a plugin endpoint passes; a real request to the
                  // root gate is refused, so the gate's fall-through never proxies
                  // the platform index from inside a test.
                  requestRejection: (request) => {
                    const url = String(request?.url ?? '/');
                    if (url.startsWith(CHANNEL)) return undefined;
                    return request?.socket === undefined ? undefined : 403;
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
  return {
    statusCode: 200,
    headers: {},
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    writeHead(status, headers) {
      this.statusCode = status;
      Object.assign(this.headers, headers);
    },
    end(body) {
      this.body = body;
    },
  };
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
  assert.equal(second.statusCode, 403, 'a spent link falls through to the fence’s own answer');
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

  // A launch token the platform refuses is the platform's own 401, and a
  // cookie-less stranger stays a stranger.
  const refused = fakeResponse();
  await root(fakeRequest(undefined, { method: 'GET', url: '/?token=stale-token' }), refused);
  assert.equal(refused.statusCode, 401);

  // The platform's verdict comes first: an accepted caller is forwarded, never
  // bounced through a fresh launch token — the loop that would otherwise never
  // end, since the token visit redirects back to `/`.
  const forwarded = hostCtx({ connection: { requestRejection: () => undefined }, port: 0 });
  const answer = fakeResponse();
  await forwarded.routes.exact.get('/')(
    fakeRequest(undefined, { method: 'GET', url: '/', headers: { cookie: 'mc-device=whatever' } }),
    answer,
  );
  assert.notEqual(answer.statusCode, 303, 'an accepted caller is never redirected through a launch token');
  assert.equal(await waitFor(() => answer.body !== undefined), true, 'the index forward ran');
  assert.equal(answer.statusCode, 502, 'and failed closed, because nothing listens on port 0');
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

  // A stale token is still the platform's own answer, and a plain loopback visit
  // (no token at all) is untouched: it is proxied as before.
  const stale = fakeResponse();
  await root(fakeRequest(undefined, { ...local, url: '/?token=stale' }), stale);
  assert.equal(stale.statusCode, 401);
  const plain = hostCtx({ connection: { requestRejection: () => undefined }, port: 0 });
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
  assert.equal(linked.value.id, source.id);
  assert.ok(isTempToken(new URL(linked.value.url).searchParams.get('token')), 'the link carries a temp token');
  assert.ok(Number.isInteger(linked.value.qr?.size));
  assert.ok(Math.abs(linked.value.expiresAt - Date.now() - TEMP_TOKEN_TTL_MS) < 5000, 'fifteen minutes, as promised');

  const rows = ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices;
  assert.equal(rows.length, 2, 'a new row, not a rewritten one');
  const added = rows.find((row) => row.id !== source.id);
  assert.equal(added.temporary, true);
  assert.equal(added.source, source.source, 'the source is copied');
  assert.match(added.name, /· 链接$/);
  assert.notEqual(added.hash, source.hash, 'and the device keeps its own credential');
  // The source row is byte-for-byte what it was.
  assert.equal(JSON.stringify(rows.find((row) => row.id === source.id)), snapshot);

  // Unknown id: a clear error, and nothing minted.
  const missing = await endpoint(ctx, 'device-link', { id: 'nope' });
  assert.equal(missing.ok, false);
  assert.match(missing.error.message, /no authorized device with id "nope"/);
  assert.equal(ctx.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 2, 'a failed link adds no row');

  // And it is rate limited like the other mint operations.
  for (let attempt = 0; attempt < 4; attempt += 1) {
    assert.equal((await endpoint(ctx, 'device-link', { id: source.id })).ok, true, `mint ${attempt + 2}`);
  }
  const throttled = await endpoint(ctx, 'device-link', { id: source.id });
  assert.equal(throttled.ok, false);
  assert.match(throttled.error.message, /too many links/);
});

test('reports the mode and switches the bind without starting a tunnel', async () => {
  const ctx = hostCtx();
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
    const wired = hostCtx({ editor: rows, documentPath: path });

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
