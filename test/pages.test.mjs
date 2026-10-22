// The recovery page's language: which locale wins, that both tables carry the
// same keys, what the rendered document contains, and that the host really
// serves it in the Web UI's configured language — per request, and without ever
// letting a missing settings service take the page (or activation) down.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { apply, CHANNEL } from '../lib/index.js';
import {
  FALLBACK_LOCALE,
  PAGE_LOCALES,
  PAGE_STRINGS,
  UNLOCK_COOKIE,
  pageStrings,
  pickLocale,
  requestLocale,
  signTicket,
  unlockPageHtml,
} from '../lib/unlock.js';

/** Any CJK ideograph, so a render can be proved free of one script or the other. */
const CJK_RE = /[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]/;

/** The keys a render's table must carry, whatever the language. */
const PAGE_KEYS = [
  'buttonLabel',
  'failedLabel',
  'missingLabel',
  'openLabel',
  'passwordLabel',
  'qrLabel',
  'subtitle',
  'successLabel',
  'throttledLabel',
  'title',
  'wrongLabel',
];

const CONFIGURED_KEYS = ['title', 'subtitle', 'passwordLabel', 'buttonLabel', 'wrongLabel', 'throttledLabel', 'failedLabel', 'successLabel', 'openLabel'];

/** Render one page the way the host does: table in, document language in. */
function render(locale, kind) {
  return unlockPageHtml({
    prefix: CHANNEL,
    configured: kind === 'configured',
    lang: locale,
    ...pageStrings(locale, kind),
  });
}

test('picks the language from the settings preference before the browser header', () => {
  // The durable preference is the Web UI's own language and outranks the request.
  assert.equal(pickLocale('zh', 'en-US,en;q=0.9'), 'zh');
  assert.equal(pickLocale('en', 'zh-CN,zh;q=0.9'), 'en');
  assert.equal(pickLocale(' ZH ', undefined), 'zh', 'case and padding are tidied');
  assert.equal(pickLocale('en', undefined), 'en');
  // Only an exact known value decides; anything else hands over to the header.
  assert.equal(pickLocale('de', 'zh-Hant'), 'zh', 'an unknown preference does not decide');
  assert.equal(pickLocale('', 'en-GB,en;q=0.9'), 'en');
  assert.equal(pickLocale(undefined, 'zh-CN,zh;q=0.9,en;q=0.8'), 'zh');
  // The header is read from its first tag, which is the browser's own order.
  assert.equal(pickLocale(undefined, 'zh'), 'zh');
  assert.equal(pickLocale(undefined, 'en-GB,en;q=0.9'), 'en');
  assert.equal(pickLocale(undefined, 'fr-FR,fr;q=0.9'), 'en', 'a language this page does not speak falls back');
  assert.equal(pickLocale(undefined, ['zh-TW,zh;q=0.9']), 'zh', 'a repeated header is read from its first value');
  assert.equal(pickLocale(undefined, undefined), 'en');
  assert.equal(pickLocale(undefined, ''), 'en');
  assert.equal(pickLocale(null, 42), 'en', 'a non-string header is not a language');
  assert.equal(pickLocale({}, []), 'en');
  // Both rendered languages are also valid document languages, and the fallback
  // is the one the whole helper chain ends on.
  assert.deepEqual(PAGE_LOCALES, ['zh', 'en']);
  assert.equal(FALLBACK_LOCALE, 'en');
});

test('reads the live settings service, and survives every missing step', () => {
  const localeCtx = (settings) => ({ get: (name) => (name === 'settings' ? settings : undefined) });
  const header = { headers: { 'accept-language': 'en-US,en;q=0.9' } };

  assert.equal(requestLocale(localeCtx({ describe: () => [{ ns: 'locale', value: { preference: 'zh' } }] }), header), 'zh');
  assert.equal(requestLocale(localeCtx({ describe: () => [{ ns: 'other', value: { preference: 'zh' } }] }), header), 'en', 'another namespace does not decide');
  assert.equal(requestLocale(localeCtx({ describe: () => [{ ns: 'locale' }] }), header), 'en');
  assert.equal(requestLocale(localeCtx({ describe: () => [{ ns: 'locale', value: { preference: 7 } }] }), header), 'en');
  assert.equal(requestLocale(localeCtx({ describe: () => undefined }), { headers: { 'accept-language': 'zh-CN' } }), 'zh', 'a non-list describes nothing');
  assert.equal(requestLocale(localeCtx(undefined), { headers: { 'accept-language': 'zh' } }), 'zh', 'no settings service at all');
  assert.equal(requestLocale(localeCtx({ describe: () => { throw new Error('no settings'); } }), { headers: { 'accept-language': 'zh' } }), 'zh', 'a throwing service falls back');
  assert.equal(requestLocale({ get: () => { throw new Error('no context'); } }, { headers: { 'accept-language': 'zh' } }), 'zh', 'a throwing context falls back');
  assert.equal(requestLocale(undefined, undefined), 'en');
  assert.equal(requestLocale(localeCtx({}), undefined), 'en', 'no describe method');
});

test('both language tables carry exactly the same keys', () => {
  const en = Object.keys(PAGE_STRINGS.en).sort();
  const zh = Object.keys(PAGE_STRINGS.zh).sort();
  assert.deepEqual(zh, en, 'a key in one table and not the other is an untranslated string');
  assert.equal(en.length, 13);

  const kinds = ['configured', 'missing-paired', 'missing-unpaired'];
  for (const kind of kinds) {
    for (const locale of PAGE_LOCALES) {
      const table = pageStrings(locale, kind);
      assert.deepEqual(Object.keys(table).sort(), PAGE_KEYS, `${locale}/${kind} carries the whole table`);
      for (const [key, value] of Object.entries(table)) {
        assert.equal(typeof value, 'string', `${locale}/${kind}/${key} is a string`);
        assert.ok(value.trim().length > 0, `${locale}/${kind}/${key} is not empty`);
      }
    }
    assert.deepEqual(Object.keys(pageStrings('en', kind)).sort(), Object.keys(pageStrings('zh', kind)).sort());
  }

  // The variants really vary, and an unknown locale or kind still renders.
  assert.notEqual(pageStrings('en', 'configured').subtitle, pageStrings('en', 'missing-unpaired').subtitle);
  assert.notEqual(pageStrings('en', 'missing-paired').missingLabel, pageStrings('en', 'missing-unpaired').missingLabel);
  assert.equal(pageStrings('en', 'missing-paired').subtitle, pageStrings('en', 'missing-unpaired').subtitle);
  assert.deepEqual(pageStrings('fr', 'configured'), pageStrings('en', 'configured'), 'an unknown locale renders English');
  assert.deepEqual(pageStrings('zh', 'bogus'), pageStrings('zh', 'missing-unpaired'), 'an unknown kind promises the least');
  assert.deepEqual(pageStrings('en'), pageStrings('en', 'configured'), 'a configured door is the default');
  assert.notEqual(pageStrings('en', 'configured').missingLabel, pageStrings('zh', 'configured').missingLabel);
});

test('each table is written in its own language', () => {
  for (const [key, value] of Object.entries(PAGE_STRINGS.en)) {
    assert.ok(!CJK_RE.test(value), `the English ${key} carries no Chinese: ${value}`);
  }
  for (const [key, value] of Object.entries(PAGE_STRINGS.zh)) {
    assert.ok(CJK_RE.test(value), `the Chinese ${key} is actually Chinese: ${value}`);
  }
});

test('renders neither a form nor an input when no password is stored', () => {
  for (const kind of ['missing-paired', 'missing-unpaired']) {
    for (const locale of PAGE_LOCALES) {
      const html = render(locale, kind);
      assert.ok(!html.includes('<input'), `${locale}/${kind} renders no input`);
      assert.ok(!/<form[\s>]/.test(html), `${locale}/${kind} renders no form`);
      assert.ok(!html.includes('id="p"'), `${locale}/${kind} renders no password field`);
      assert.ok(!html.includes('id="go"'), `${locale}/${kind} renders no button`);
      assert.ok(html.includes(pageStrings(locale, kind).missingLabel), `${locale}/${kind} shows why`);
      assert.match(html, new RegExp(`<html lang="${locale}">`), `${locale}/${kind} declares its language`);
      assert.match(html, /<meta name="referrer" content="no-referrer"/);
    }
  }
});

test('renders the password field and every label when a password is stored', () => {
  for (const locale of PAGE_LOCALES) {
    const html = render(locale, 'configured');
    const table = pageStrings(locale, 'configured');
    assert.match(html, /<form id="f">/);
    assert.match(html, /<input id="p" type="password" autocomplete="current-password" required autofocus \/>/);
    assert.match(html, /<button id="go" type="submit">/);
    assert.match(html, new RegExp(`<html lang="${locale}">`));
    for (const key of CONFIGURED_KEYS) {
      assert.ok(html.includes(table[key]), `${locale} renders its own ${key}`);
    }
    // The script's own words come from the same table, so it can always get one.
    assert.match(html, /var TEXT = \{"wrongLabel":/);
    assert.ok(html.includes('remote-access/recovery-denied'));
    assert.ok(html.includes('remote-access/recovery-throttled'));
  }
});

test('never leaks one language into the other render', () => {
  for (const kind of ['configured', 'missing-paired', 'missing-unpaired']) {
    const en = render('en', kind);
    const zh = render('zh', kind);
    assert.ok(!CJK_RE.test(en), `the English ${kind} page carries no Chinese character at all`);
    assert.ok(!zh.includes('Recovery password'), `the Chinese ${kind} page carries no English label`);
    assert.ok(!en.includes('恢复密码'), `the English ${kind} page carries no Chinese label`);
  }
  const en = render('en', 'configured');
  const zh = render('zh', 'configured');
  assert.ok(en.includes('Recovery password'));
  assert.ok(en.includes('Get the entry link'));
  assert.ok(zh.includes('恢复密码'));
  assert.ok(zh.includes('取回入口链接'));
  assert.ok(!en.includes('取回入口链接'));
  assert.ok(!zh.includes('Get the entry link'));
});

// ── The host, driven through the route the plugin really registers ───────────
//
// No server and no sockets: the prefix handler is called with a minimal
// request/response pair, exactly as the webserver calls it.

const RECOVERY_KEY = 'dsh-remote-access/recovery';

/** A settings stub whose preference can be changed between requests. */
function settingsFor(preference) {
  return {
    preference,
    describe() {
      return [{ ns: 'locale', value: { preference: this.preference } }];
    },
  };
}

/** A host context with just enough of the seam to serve the recovery page. */
function hostCtx({ settings, records = new Map() } = {}) {
  const credentials = {
    readRecord: async (key) => records.get(key),
    modifyRecord: async (key, mutate) => {
      const next = await mutate(records.get(key));
      if (next !== undefined) records.set(key, next);
      return next;
    },
    deleteRecord: async (key) => records.delete(key),
    resolve: async () => undefined,
    set: async () => {},
    unset: async () => {},
  };
  const routes = { prefix: [], exact: new Map() };
  const ctx = {
    records,
    routes,
    effect: (fn) => fn(),
    get: (name) =>
      name === 'credentials'
        ? credentials
        : name === 'settings'
          ? settings
          : name === 'connection'
            ? { requestRejection: () => undefined }
            : undefined,
    webServer: {
      host: '127.0.0.1',
      port: 3080,
      register: (route) => {
        if (route.kind === 'prefix') routes.prefix.push(route.handler);
        else routes.exact.set(route.path, route.handler);
        return () => {};
      },
      tapIndex: () => () => {},
    },
  };
  apply(ctx, undefined);
  return ctx;
}

/** The request shape the webserver hands a handler: two arguments, no more. */
function fakeRequest({ url = '/', method = 'GET', headers = {} } = {}) {
  return {
    method,
    url,
    // The page's own script posts JSON (`headers: { 'content-type': 'application/json' }`),
    // and the host requires it on the public doors; the double has to match.
    headers: { host: 'dsh.example.com', ...(method === 'POST' ? { 'content-type': 'application/json' } : {}), ...headers },
    socket: { remoteAddress: '203.0.113.9' },
    pipe(target) {
      target.end();
      return target;
    },
    [Symbol.asyncIterator]: () => ({ next: async () => ({ done: true }) }),
  };
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

/** One request through the plugin's own prefix route. */
async function request(ctx, path, { method = 'GET', headers = {} } = {}) {
  const res = fakeResponse();
  await ctx.routes.prefix[0](fakeRequest({ url: path, method, headers }), res);
  return res;
}

/** A context with a password armed, so the recovery door is open. */
function armedCtx(options = {}) {
  const records = new Map([[RECOVERY_KEY, { kind: 'grant', payload: { version: 1, key: 'k', salt: 's', secret: 'sec', iterations: 1000 } }]]);
  return hostCtx({ ...options, records });
}

test('serves the recovery page in the Web UI language, read once per request', async () => {
  const settings = settingsFor('zh');
  const ctx = armedCtx({ settings });

  const zh = await request(ctx, `${CHANNEL}/unlock`, { headers: { 'accept-language': 'en-US,en;q=0.9' } });
  assert.equal(zh.statusCode, 200);
  assert.equal(zh.headers['content-type'], 'text/html; charset=utf-8');
  assert.equal(zh.headers['cache-control'], 'no-store', 'the page is never cached');
  assert.equal(zh.headers['referrer-policy'], 'no-referrer');
  assert.match(String(zh.body), /<html lang="zh">/);
  assert.ok(String(zh.body).includes('恢复密码'));
  assert.ok(String(zh.body).includes('<input id="p" type="password"'));

  // The preference is re-read every request: the next page follows the change.
  settings.preference = 'en';
  const en = await request(ctx, `${CHANNEL}/unlock`, { headers: { 'accept-language': 'zh-CN,zh;q=0.9' } });
  assert.match(String(en.body), /<html lang="en">/);
  assert.ok(!CJK_RE.test(String(en.body)), 'an English page carries no Chinese');
  assert.ok(String(en.body).includes('Recovery password'));

  const head = await request(ctx, `${CHANNEL}/unlock`, { method: 'HEAD' });
  assert.equal(head.statusCode, 200);
  assert.equal(head.body, '', 'a HEAD answer carries the headers and no body');
});

test('still renders the page when the settings service is absent or broken', async () => {
  const bare = armedCtx();
  const fromHeader = await request(bare, `${CHANNEL}/unlock`, { headers: { 'accept-language': 'zh-CN,zh;q=0.9' } });
  assert.equal(fromHeader.statusCode, 200);
  assert.match(String(fromHeader.body), /<html lang="zh">/, 'with no settings service the header decides');

  const broken = armedCtx({ settings: { describe: () => { throw new Error('no settings'); } } });
  const survived = await request(broken, `${CHANNEL}/unlock`, { headers: { 'accept-language': 'en-GB' } });
  assert.equal(survived.statusCode, 200);
  assert.match(String(survived.body), /<html lang="en">/);
});

test('refuses the whole recovery route while no password is stored', async () => {
  const ctx = hostCtx();
  const page = await request(ctx, `${CHANNEL}/unlock`);
  assert.equal(page.statusCode, 404, 'an unarmed door is indistinguishable from a missing one');
  assert.equal(page.body, undefined);

  const challenge = await request(ctx, `${CHANNEL}/unlock/challenge`, { method: 'POST' });
  assert.equal(challenge.statusCode, 404, 'fail-closed: no password means no challenge');
  assert.equal(challenge.body, undefined);

  const verify = await request(ctx, `${CHANNEL}/unlock/verify`, { method: 'POST' });
  assert.equal(verify.statusCode, 404, 'fail-closed: no password means no verify either');
});

test('answers the page in the envelope its own script unwraps, in the page language', async () => {
  const settings = settingsFor('zh');
  const ctx = armedCtx({ settings });

  const challenge = await request(ctx, `${CHANNEL}/unlock/challenge`, { method: 'POST' });
  assert.equal(challenge.statusCode, 200);
  const answered = JSON.parse(String(challenge.body));
  assert.equal(answered.ok, true);
  assert.equal(typeof answered.value.nonce, 'string');
  assert.equal(typeof answered.value.salt, 'string');
  assert.equal(answered.value.iterations, 1000, 'the stored work factor rides along');
  assert.match(render('zh', 'configured'), /answer\.value/, 'and the page reads that envelope, not bare fields');

  // An unlock ticket buys the entry link and its QR. The ticket names the
  // authorized-device row it was minted for, so that row is the single source of
  // truth: revoke it and the ticket stops working at once.
  settings.preference = 'en';
  const row = {
    id: 'row-1',
    name: 'Phone',
    source: 'password',
    temporary: true,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    expiresAt: Date.now() + 60_000,
    days: null,
    hash: 'a'.repeat(64),
  };
  ctx.records.set('dsh-remote-access/devices-v2', { kind: 'grant', payload: { version: 2, devices: [row] } });
  const ticket = signTicket('sec', { v: 1, exp: Date.now() + 60_000, row: row.id });
  const entry = await request(ctx, `${CHANNEL}/unlock/entry`, { method: 'POST', headers: { cookie: `${UNLOCK_COOKIE}=${ticket}` } });
  assert.equal(entry.statusCode, 200);
  const fresh = JSON.parse(String(entry.body));
  assert.equal(fresh.ok, true);
  assert.equal(typeof fresh.value.url, 'string');
  // Every QR-bearing answer carries the same shape, the module matrix.
  assert.ok(Number.isInteger(fresh.value.qr.size), 'the entry answer carries the matrix');
  assert.ok(typeof fresh.value.qr.bits === 'string');
  // The row disappears (the panel revoked it) and the ticket is worth nothing.
  ctx.records.set('dsh-remote-access/devices-v2', { kind: 'grant', payload: { version: 2, devices: [] } });
  const afterRevoke = await request(ctx, `${CHANNEL}/unlock/entry`, { method: 'POST', headers: { cookie: `${UNLOCK_COOKIE}=${ticket}` } });
  assert.equal(afterRevoke.statusCode, 401, 'revoking the row revokes the ticket it minted');
});
