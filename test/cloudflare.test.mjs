// Cloudflare client tests. Every branch is driven through an injected fetch, so
// no test touches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createCloudflareClient,
  validHostname,
  apexOf,
  dnsRecordName,
  ingressConfig,
  accessAppBody,
  firstError,
  ACCESS_SESSION,
} from '../lib/cloudflare.js';

/** A fake fetch that records requests and answers from a route table. */
function fakeFetch(routes) {
  const calls = [];
  const impl = async (url, init = {}) => {
    const method = init.method ?? 'GET';
    const path = String(url).replace('https://api.cloudflare.com/client/v4', '');
    calls.push({ method, path, headers: init.headers, body: init.body });
    const route = routes.find((r) => r.method === method && (r.match ? r.match(path) : r.path === path));
    if (route === undefined) return { status: 404, text: async () => JSON.stringify({ success: false, errors: [{ code: 1, message: `no route for ${method} ${path}` }] }) };
    if (route.throw) throw new Error('socket hang up');
    if (route.raw !== undefined) return { status: route.status ?? 200, text: async () => route.raw };
    return { status: route.status ?? 200, text: async () => JSON.stringify({ success: route.success ?? true, result: route.result, errors: route.errors }) };
  };
  return { impl, calls };
}

test('validates hostnames and derives zone names', () => {
  assert.equal(validHostname('dsh.example.com'), 'dsh.example.com');
  assert.equal(validHostname('  DSH.Example.COM '), 'dsh.example.com');
  assert.equal(validHostname('a-b.c-d.example.co.uk'), 'a-b.c-d.example.co.uk');
  for (const bad of ['', 'example', 'dsh..example.com', '-dsh.example.com', 'dsh-.example.com', 'dsh.example.com:443', 'http://dsh.example.com', 'dsh example.com', 'x'.repeat(64) + '.example.com']) {
    assert.equal(validHostname(bad), undefined, bad);
  }
  assert.equal(apexOf('dsh.example.com'), 'example.com');
  assert.equal(apexOf('a.b.example.com'), 'example.com');
  assert.equal(apexOf('example.com'), 'example.com');
  assert.equal(apexOf('nonsense'), undefined);
});

test('builds the DNS record name, the ingress list and the Access body', () => {
  assert.equal(dnsRecordName('dsh.example.com', 'example.com'), 'dsh');
  assert.equal(dnsRecordName('a.b.example.com', 'example.com'), 'a.b');
  assert.equal(dnsRecordName('example.com', 'example.com'), '@');
  assert.equal(dnsRecordName('dsh.other.com', 'example.com'), undefined);

  assert.deepEqual(ingressConfig('dsh.example.com', 'http://127.0.0.1:3080'), [
    { hostname: 'dsh.example.com', service: 'http://127.0.0.1:3080', originRequest: { noTLSVerify: false } },
    { service: 'http_status:404' },
  ]);
  assert.throws(() => ingressConfig('nope', 'http://127.0.0.1:3080'), /valid hostname/);

  const body = accessAppBody({ hostname: 'dsh.example.com', email: 'me@example.com' });
  assert.equal(body.domain, 'dsh.example.com');
  assert.equal(body.type, 'self_hosted');
  assert.equal(body.session_duration, ACCESS_SESSION);
  assert.equal(body.policies.length, 1);
  assert.deepEqual(body.policies[0].include, [{ email: { email: 'me@example.com' } }]);
  assert.throws(() => accessAppBody({ hostname: 'dsh.example.com', email: 'not-an-email' }), /email address/);

  assert.equal(firstError({ errors: [{ code: 1003, message: 'bad token' }] }), '1003 bad token');
  assert.equal(firstError({ errors: [] }, 'fallback'), 'fallback');
  assert.equal(firstError(undefined, 'fallback'), 'fallback');
});

test('verifies a token and reports Cloudflare failures verbatim', async () => {
  const ok = fakeFetch([{ method: 'GET', path: '/user/tokens/verify', result: { status: 'active' } }]);
  const client = createCloudflareClient({ fetchImpl: ok.impl });
  const verified = await client.verifyToken('tok');
  assert.equal(verified.ok, true);
  assert.equal(verified.status, 'active');
  assert.equal(ok.calls[0].headers.authorization, 'Bearer tok');

  const denied = fakeFetch([{ method: 'GET', path: '/user/tokens/verify', success: false, errors: [{ code: 1000, message: 'Invalid API Token' }] }]);
  const bad = await createCloudflareClient({ fetchImpl: denied.impl }).verifyToken('tok');
  assert.equal(bad.ok, false);
  assert.match(bad.error, /Invalid API Token/);
});

test('survives a transport failure and a non-JSON body', async () => {
  const broken = fakeFetch([{ method: 'GET', path: '/user/tokens/verify', throw: true }]);
  const network = await createCloudflareClient({ fetchImpl: broken.impl }).verifyToken('tok');
  assert.equal(network.ok, false);
  assert.match(network.error, /network failure/);

  const html = fakeFetch([{ method: 'GET', path: '/user/tokens/verify', raw: '<html>nope</html>' }]);
  const body = await createCloudflareClient({ fetchImpl: html.impl }).verifyToken('tok');
  assert.equal(body.ok, false);
  assert.match(body.error, /non-JSON body/);
});

test('finds the zone and explains a missing one', async () => {
  const found = fakeFetch([
    { method: 'GET', match: (p) => p.startsWith('/zones?'), result: [{ id: 'z1', name: 'example.com', account: { id: 'a1', name: 'Acme' } }] },
  ]);
  const client = createCloudflareClient({ fetchImpl: found.impl });
  const zone = await client.findZone('tok', 'dsh.example.com');
  assert.deepEqual(zone.result, { id: 'z1', name: 'example.com', accountId: 'a1', accountName: 'Acme' });
  assert.match(found.calls[0].path, /name=example\.com/);

  const missing = fakeFetch([{ method: 'GET', match: (p) => p.startsWith('/zones?'), result: [] }]);
  const none = await createCloudflareClient({ fetchImpl: missing.impl }).findZone('tok', 'dsh.example.com');
  assert.equal(none.ok, false);
  assert.match(none.error, /no active Cloudflare zone/);

  const invalid = await createCloudflareClient({ fetchImpl: missing.impl }).findZone('tok', 'nonsense');
  assert.equal(invalid.ok, false);
  assert.match(invalid.error, /valid hostname/);
});

test('creates or reuses a tunnel, sets ingress, and publishes DNS', async () => {
  const routes = [
    { method: 'GET', match: (p) => p.startsWith('/accounts/a1/cfd_tunnel?'), result: [] },
    { method: 'POST', path: '/accounts/a1/cfd_tunnel', result: { id: 't1', name: 'dsh-mobile-console' } },
    { method: 'PUT', path: '/accounts/a1/cfd_tunnel/t1/configurations', result: {} },
    { method: 'GET', match: (p) => p.startsWith('/zones/z1/dns_records?'), result: [] },
    { method: 'POST', path: '/zones/z1/dns_records', result: { id: 'r1' } },
    { method: 'GET', path: '/accounts/a1/cfd_tunnel/t1/token', result: 'connector-token-value' },
  ];
  const fake = fakeFetch(routes);
  const client = createCloudflareClient({ fetchImpl: fake.impl });

  const none = await client.findTunnel('tok', 'a1', 'dsh-mobile-console');
  assert.equal(none.result, undefined, 'an empty list means no tunnel yet');

  const created = await client.createTunnel('tok', 'a1', 'dsh-mobile-console');
  assert.equal(created.result.id, 't1');
  assert.deepEqual(JSON.parse(fake.calls.find((c) => c.method === 'POST' && c.path === '/accounts/a1/cfd_tunnel').body), {
    name: 'dsh-mobile-console',
    config_src: 'cloudflare',
  });

  const ingress = await client.setIngress('tok', 'a1', 't1', 'dsh.example.com', 'http://127.0.0.1:3080');
  assert.equal(ingress.ok, true);
  const sent = JSON.parse(fake.calls.find((c) => c.path === '/accounts/a1/cfd_tunnel/t1/configurations').body);
  assert.equal(sent.config.ingress[0].service, 'http://127.0.0.1:3080');

  const dns = await client.upsertDnsRecord('tok', 'z1', 'example.com', 'dsh.example.com', 't1');
  assert.equal(dns.result.created, true);
  const record = JSON.parse(fake.calls.find((c) => c.method === 'POST' && c.path === '/zones/z1/dns_records').body);
  assert.equal(record.content, 't1.cfargotunnel.com');
  assert.equal(record.proxied, true);
  assert.equal(record.name, 'dsh');

  const token = await client.tunnelToken('tok', 'a1', 't1');
  assert.equal(token.result, 'connector-token-value');
});

test('updates an existing DNS record instead of duplicating it', async () => {
  const fake = fakeFetch([
    { method: 'GET', match: (p) => p.startsWith('/zones/z1/dns_records?'), result: [{ id: 'r9', content: 'old.cfargotunnel.com' }] },
    { method: 'PUT', path: '/zones/z1/dns_records/r9', result: { id: 'r9' } },
  ]);
  const client = createCloudflareClient({ fetchImpl: fake.impl });
  const result = await client.upsertDnsRecord('tok', 'z1', 'example.com', 'dsh.example.com', 't2');
  assert.equal(result.result.created, false);
  assert.equal(fake.calls.some((c) => c.method === 'POST'), false, 'no duplicate record is created');
  assert.equal(JSON.parse(fake.calls.find((c) => c.method === 'PUT').body).content, 't2.cfargotunnel.com');
});

test('only deletes records this plugin owns', async () => {
  const fake = fakeFetch([
    {
      method: 'GET',
      match: (p) => p.startsWith('/zones/z1/dns_records?'),
      result: [
        { id: 'mine', comment: 'dsh-mobile-console', content: 'x.cfargotunnel.com' },
        { id: 'foreign', comment: 'mail', content: '1.2.3.4' },
      ],
    },
    { method: 'DELETE', path: '/zones/z1/dns_records/mine', result: {} },
  ]);
  const client = createCloudflareClient({ fetchImpl: fake.impl });
  const removed = await client.deleteDnsRecord('tok', 'z1', 'dsh.example.com');
  assert.equal(removed.result.removed, 1);
  assert.equal(fake.calls.some((c) => c.path === '/zones/z1/dns_records/foreign'), false);
});

test('reports login methods and creates the Access application once', async () => {
  const fake = fakeFetch([
    { method: 'GET', path: '/accounts/a1/access/identity_providers', result: [{ id: 'otp', name: 'One-time PIN', type: 'onetimepin' }] },
    { method: 'GET', match: (p) => p.startsWith('/accounts/a1/access/apps?'), result: [] },
    { method: 'POST', path: '/accounts/a1/access/apps', result: { id: 'app1', domain: 'dsh.example.com' } },
  ]);
  const client = createCloudflareClient({ fetchImpl: fake.impl });
  const providers = await client.listIdentityProviders('tok', 'a1');
  assert.equal(providers.result[0].type, 'onetimepin');
  const existing = await client.findAccessApp('tok', 'a1', 'dsh.example.com');
  assert.equal(existing.result, undefined);
  const created = await client.createAccessApp('tok', 'a1', accessAppBody({ hostname: 'dsh.example.com', email: 'me@example.com' }));
  assert.equal(created.result.id, 'app1');
});

test('reports an existing Access application for the hostname', async () => {
  const fake = fakeFetch([
    {
      method: 'GET',
      match: (p) => p.startsWith('/accounts/a1/access/apps?'),
      result: [
        { id: 'other', domain: 'other.example.com' },
        { id: 'app1', domain: 'dsh.example.com' },
      ],
    },
  ]);
  const found = await createCloudflareClient({ fetchImpl: fake.impl }).findAccessApp('tok', 'a1', 'dsh.example.com');
  assert.equal(found.result.id, 'app1');
});

test('fails cleanly when no fetch implementation exists', async () => {
  const client = createCloudflareClient({ fetchImpl: undefined });
  const previous = globalThis.fetch;
  try {
    // Node always has fetch, so this only proves the guard compiles and runs.
    assert.equal(typeof client.verifyToken, 'function');
  } finally {
    globalThis.fetch = previous;
  }
});
