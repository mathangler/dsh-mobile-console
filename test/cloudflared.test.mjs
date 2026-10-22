// cloudflared CLI helper tests: output parsing, config rendering, install hints.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  cloudflaredDir,
  certPemPath,
  tunnelConfigPath,
  credentialsPath,
  parseLoginUrl,
  parseTunnelId,
  findTunnelInList,
  renderTunnelConfig,
  tunnelRunArgs,
  tunnelTokenArgs,
  installHint,
  environmentSummary,
} from '../lib/cloudflared.js';

const ENV = { USERPROFILE: 'C:\\Users\\tester', HOME: '/home/tester' };

test('derives the cloudflared paths from the platform home', () => {
  assert.equal(cloudflaredDir({ USERPROFILE: 'C:\\Users\\tester' }), 'C:\\Users\\tester\\.cloudflared');
  // `node:path` joins with the running platform's separator, so compare both
  // spellings rather than assuming POSIX.
  assert.equal(cloudflaredDir({ HOME: '/home/tester' }).replace(/\\/g, '/'), '/home/tester/.cloudflared');
  assert.equal(certPemPath(ENV), 'C:\\Users\\tester\\.cloudflared\\cert.pem');
  assert.equal(tunnelConfigPath(ENV), 'C:\\Users\\tester\\.cloudflared\\dsh-mobile-console.yml');
  assert.match(credentialsPath('6ff42ae2-765d-4adf-9cd0-1b1a1c2f2a3b', ENV), /6ff42ae2-765d-4adf-9cd0-1b1a1c2f2a3b\.json$/);
});

test('extracts the authorization URL from login output', () => {
  const url = 'https://dash.cloudflare.com/argotunnel?aud=&callback=https%3A%2F%2Flocalhost%3A9000';
  assert.equal(parseLoginUrl(`Please open the following URL and log in:\n\n\t${url}\n\n`), url);
  assert.equal(parseLoginUrl('nothing here'), undefined);
  assert.equal(parseLoginUrl(undefined), undefined);
  // Trailing punctuation must not be swallowed into the URL.
  assert.equal(parseLoginUrl(`open ${url}. done`), url);
});

test('extracts the tunnel id from create output', () => {
  const id = '6ff42ae2-765d-4adf-9cd0-1b1a1c2f2a3b';
  assert.equal(parseTunnelId(`Created tunnel dsh-win with id ${id}`), id);
  assert.equal(parseTunnelId(`Tunnel credentials written to C:\\Users\\t\\.cloudflared\\${id}.json`), id);
  assert.equal(parseTunnelId('no uuid here'), undefined);
});

test('finds a live tunnel in the JSON list, ignoring deleted ones', () => {
  const list = [
    { id: 'a', name: 'dsh-win' },
    { id: 'b', name: 'dsh-win', deleted_at: '2026-01-01T00:00:00Z' },
    { id: 'c', name: 'other' },
  ];
  assert.deepEqual(findTunnelInList(JSON.stringify(list), 'dsh-win'), { id: 'a', name: 'dsh-win' });
  assert.deepEqual(findTunnelInList({ tunnels: list }, 'other'), { id: 'c', name: 'other' });
  assert.equal(findTunnelInList(JSON.stringify(list), 'missing'), undefined);
  assert.equal(findTunnelInList('not json', 'dsh-win'), undefined);
});

test('renders a tunnel config with a forward-slashed credentials path', () => {
  const text = renderTunnelConfig({
    tunnelId: '6ff42ae2-765d-4adf-9cd0-1b1a1c2f2a3b',
    hostname: 'dsh.example.com',
    service: 'http://127.0.0.1:3080',
    env: ENV,
  });
  assert.match(text, /^# Written by dsh-mobile-console/);
  assert.match(text, /tunnel: 6ff42ae2-765d-4adf-9cd0-1b1a1c2f2a3b/);
  assert.match(text, /credentials-file: C:\/Users\/tester\/\.cloudflared\/6ff42ae2-765d-4adf-9cd0-1b1a1c2f2a3b\.json/);
  assert.match(text, /- hostname: dsh\.example\.com\n {4}service: http:\/\/127\.0\.0\.1:3080/);
  assert.match(text, /- service: http_status:404/);
  assert.throws(() => renderTunnelConfig({ tunnelId: 'nope', hostname: 'dsh.example.com', service: 'http://x', env: ENV }), /UUID/);
  assert.throws(() => renderTunnelConfig({ tunnelId: '6ff42ae2-765d-4adf-9cd0-1b1a1c2f2a3b', hostname: '', service: 'http://x', env: ENV }), /hostname/);
});

test('builds the run arguments for both tunnel modes', () => {
  assert.deepEqual(tunnelRunArgs({ configPath: 'C:\\c.yml', tunnelName: 'dsh-win' }), [
    'tunnel',
    '--no-autoupdate',
    '--config',
    'C:\\c.yml',
    'run',
    'dsh-win',
  ]);
  assert.deepEqual(tunnelTokenArgs('secret-token'), ['tunnel', '--no-autoupdate', 'run', '--token', 'secret-token']);
});

test('offers a per-platform install command', () => {
  assert.match(installHint('win32').command, /winget install/);
  assert.match(installHint('darwin').command, /brew install/);
  assert.match(installHint('linux').command, /apt/);
  assert.equal(installHint('win32').platform, 'windows');
});

test('summarizes what still blocks setup', () => {
  assert.deepEqual(
    environmentSummary({ cloudflaredFound: false, certPresent: false, apiTokenStored: false, hostname: undefined }),
    { ready: false, missing: ['cloudflared', 'authentication', 'hostname'] },
  );
  assert.deepEqual(
    environmentSummary({ cloudflaredFound: true, certPresent: true, apiTokenStored: false, hostname: 'dsh.example.com' }),
    { ready: true, missing: [] },
  );
  assert.deepEqual(
    environmentSummary({ cloudflaredFound: true, certPresent: false, apiTokenStored: true, hostname: 'dsh.example.com' }),
    { ready: true, missing: [] },
  );
});
