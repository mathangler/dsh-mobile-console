// Access-key, one-time-link and authorized-device tests: key minting and
// timing-safe matching, the temp-token bookkeeping, the legacy -> v2 row
// migration, the derived status, and the "never delete a still-valid row" rule.
import { test } from 'node:test';
import assert from 'node:assert/strict';
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
  publicDeviceRow,
  publicKeyRow,
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
function hostCtx({ records = new Map(), secrets = new Map(), config, editor, connection, port = 3080 } = {}) {
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

  // With the editor present, LAN mode binds the chosen address, trusts the very
  // authority the browser will use, stops any tunnel, and reports the mode back.
  const wired = hostCtx({ editor: webServerRows() });
  const lan = await endpoint(wired, 'set-mode', { mode: 'lan', host: '10.0.161.47' });
  assert.equal(lan.ok, true, JSON.stringify(lan.error));
  assert.equal(lan.value.mode, 'lan');
  assert.equal(lan.value.host, '10.0.161.47');
  assert.equal(lan.value.authority, '10.0.161.47:3080');
  assert.deepEqual(lan.value.trustedHosts, ['10.0.161.47:3080']);
  assert.equal(lan.value.restartRequired, true);
  assert.equal(wired.editsFor('webserver').at(-1).next.host, '10.0.161.47');
  assert.equal((await endpoint(wired, 'mode-status', {})).value.mode, 'lan');
  assert.equal((await endpoint(wired, 'mode-status', {})).value.host, '10.0.161.47');

  // Back to loopback: the same write as `public`, and the tunnel is never started.
  const restored = await endpoint(wired, 'restore-loopback', {});
  assert.equal(restored.ok, true, JSON.stringify(restored.error));
  assert.deepEqual(restored.value, { mode: 'public', host: '127.0.0.1', restartRequired: true });
  assert.equal(wired.editsFor('webserver').at(-1).next.host, '127.0.0.1');
  assert.equal((await endpoint(wired, 'mode-status', {})).value.mode, 'public');

  // Idempotent: already loopback means success with no further write.
  const writes = wired.editsFor('webserver').length;
  const again = await endpoint(wired, 'restore-loopback', {});
  assert.deepEqual(again.value, { mode: 'public', host: '127.0.0.1', restartRequired: true });
  assert.equal(wired.editsFor('webserver').length, writes, 'nothing is rewritten when nothing changes');
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
