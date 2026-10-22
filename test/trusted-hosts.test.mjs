// Host-half unit tests: config normalization, bind-address admission, the trust
// probe, and the device view's pure helpers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  normalizeConfig,
  deviceLabel,
  isLoopbackAuthority,
  validBindAddress,
  probeTrust,
  upsertDevice,
  pruneDevices,
  classifyRequestOrigin,
  isPrivateAddress,
  sameLan,
  absentText,
  suggestedLabelFor,
  SECRET_REF_RE,
  SECRET_REFS,
  apply,
  CHANNEL,
  HEARTBEAT_PATH,
  DEVICE_RECORD_KEY,
  DEVICES_V2_RECORD_KEY,
  ROW_ID,
} from '../lib/index.js';
import { skillRegistration, SKILL_NAME } from '../lib/skill.js';

test('normalizes the row config with defaults and rejects nonsense', () => {
  const defaults = normalizeConfig(undefined);
  assert.equal(defaults.narrowEnhance, true);
  assert.equal(defaults.deviceRetentionDays, 180);
  assert.equal(defaults.tunnelHost, undefined);
  assert.equal(defaults.cloudflared, undefined);

  const configured = normalizeConfig({
    tunnelHost: '  dsh.example.com ',
    publicUrl: 'https://dsh.example.com',
    lanHost: '10.0.161.47',
    narrowEnhance: false,
    deviceRetentionDays: '30',
    cloudflared: { command: 'cloudflared', args: ['tunnel', 'run', 'dsh-mobile'] },
  });
  assert.equal(configured.tunnelHost, 'dsh.example.com');
  assert.equal(configured.publicUrl, 'https://dsh.example.com');
  assert.equal(configured.lanHost, '10.0.161.47');
  assert.equal(configured.narrowEnhance, false);
  assert.equal(configured.deviceRetentionDays, 30);
  assert.deepEqual(configured.cloudflared, { command: 'cloudflared', args: ['tunnel', 'run', 'dsh-mobile'] });

  // A bare cloudflared object still gets a command.
  assert.equal(normalizeConfig({ cloudflared: {} }).cloudflared.command, 'cloudflared');
  // A non-positive or unparsable retention falls back to the default.
  assert.equal(normalizeConfig({ deviceRetentionDays: -5 }).deviceRetentionDays, 180);
  assert.equal(normalizeConfig({ deviceRetentionDays: 'soon' }).deviceRetentionDays, 180);
  // Empty strings read as absent.
  assert.equal(normalizeConfig({ tunnelHost: '   ' }).tunnelHost, undefined);
});

test('admits one concrete bind literal and refuses wildcards', () => {
  assert.equal(validBindAddress('10.0.161.47'), '10.0.161.47');
  assert.equal(validBindAddress(' 192.168.1.20 '), '192.168.1.20');
  assert.equal(validBindAddress('::1'), '::1');
  assert.equal(validBindAddress('fe80::1%12'), 'fe80::1%12');
  // Wildcards are refused by the platform itself, so they are refused here too.
  assert.equal(validBindAddress('0.0.0.0'), undefined);
  assert.equal(validBindAddress('::'), undefined);
  assert.equal(validBindAddress('[::]'), undefined);
  // Out-of-range octets and prose are not literals.
  assert.equal(validBindAddress('999.1.1.1'), undefined);
  assert.equal(validBindAddress('dsh.example.com'), undefined);
  assert.equal(validBindAddress(''), undefined);
  assert.equal(validBindAddress(undefined), undefined);
});

test('classifies loopback authorities, with or without a port', () => {
  assert.equal(isLoopbackAuthority('127.0.0.1'), true);
  assert.equal(isLoopbackAuthority('127.0.0.1:3080'), true);
  assert.equal(isLoopbackAuthority('localhost:3080'), true);
  assert.equal(isLoopbackAuthority('[::1]:3080'), true);
  assert.equal(isLoopbackAuthority('10.0.161.47:3080'), false);
  assert.equal(isLoopbackAuthority('dsh.example.com'), false);
});

test('reads the platform fence the way the panel needs it', () => {
  // 403 means the Host fence refused the authority outright.
  assert.equal(probeTrust({ requestRejection: () => 403 }, 'dsh.example.com'), 'refused');
  // 401 means the fence accepted the Host and only authentication is missing.
  assert.equal(probeTrust({ requestRejection: () => 401 }, 'dsh.example.com'), 'trusted');
  // undefined means the whole request was acceptable.
  assert.equal(probeTrust({ requestRejection: () => undefined }, '127.0.0.1:3080'), 'trusted');
  // A throwing fence is reported as unknown rather than crashing the panel.
  assert.equal(
    probeTrust(
      {
        requestRejection: () => {
          throw new Error('fence exploded');
        },
      },
      'dsh.example.com',
    ),
    'unknown',
  );
  assert.equal(probeTrust(undefined, 'dsh.example.com'), 'unknown');
  // The probe must hand the fence a Host header, which is what it reads.
  let seen;
  probeTrust(
    {
      requestRejection: (request) => {
        seen = request;
        return 403;
      },
    },
    'dsh.example.com:443',
  );
  assert.equal(seen.headers.host, 'dsh.example.com:443');
});

test('labels devices from their user agent', () => {
  assert.equal(
    deviceLabel('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1'),
    'iPhone · Safari',
  );
  assert.equal(
    deviceLabel('Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36'),
    'Android · Chrome',
  );
  assert.equal(deviceLabel('Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 CriOS/131.0 Mobile/15E148 Safari/604.1'), 'iPad · Chrome');
  assert.equal(deviceLabel(''), 'Unknown · Browser');
  assert.equal(deviceLabel(undefined), 'Unknown · Browser');
});

test('upserts and prunes device rows', () => {
  const t0 = 1_000_000;
  const IPHONE =
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
  const ANDROID =
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36';
  const first = upsertDevice([], { id: 'a', ua: IPHONE, ip: '10.0.0.9', now: t0 });
  assert.equal(first.length, 1);
  assert.equal(first[0].id, 'a');
  assert.equal(first[0].name, 'iPhone · Safari');
  assert.equal(first[0].firstSeenAt, t0);
  assert.equal(first[0].lastSeenAt, t0);
  assert.equal(first[0].hits, 1);

  const second = upsertDevice(first, { id: 'a', ua: IPHONE, ip: '10.0.0.10', now: t0 + 5000 });
  assert.equal(second.length, 1);
  assert.equal(second[0].firstSeenAt, t0, 'first sighting is preserved');
  assert.equal(second[0].lastSeenAt, t0 + 5000);
  assert.equal(second[0].lastIp, '10.0.0.10');
  assert.equal(second[0].hits, 2);
  assert.equal(first[0].hits, 1, 'the input array is not mutated');

  const two = upsertDevice(second, { id: 'b', ua: ANDROID, ip: '10.0.0.11', now: t0 + 9000 });
  assert.equal(two[0].id, 'b', 'newest sighting sorts first');

  // Retention keeps recent rows and drops stale ones.
  const day = 24 * 60 * 60 * 1000;
  // A cutoff between the two sightings (t0+5000 and t0+9000) keeps only the newer.
  const kept = pruneDevices(two, 1, t0 + day + 7000);
  assert.equal(kept.length, 1);
  assert.equal(kept[0].id, 'b');
  assert.equal(pruneDevices(two, 30, t0 + day + 7000).length, 2);

  // The cap keeps the newest rows.
  let many = [];
  for (let i = 0; i < 60; i++) many = upsertDevice(many, { id: `d${i}`, ua: 'Android Chrome', now: t0 + i });
  assert.equal(many.length, 50);
  assert.equal(many[0].id, 'd59');
});

test('classifies where a request came from', () => {
  // cloudflared runs on this machine, so a tunnelled request arrives over
  // loopback and carries Cloudflare's client-IP header.
  assert.deepEqual(classifyRequestOrigin({ 'cf-connecting-ip': '203.0.113.7' }, '127.0.0.1'), {
    via: 'tunnel',
    clientIp: '203.0.113.7',
  });
  assert.deepEqual(classifyRequestOrigin({ 'x-forwarded-for': '203.0.113.7, 10.0.0.1' }, '127.0.0.1'), {
    via: 'tunnel',
    clientIp: '203.0.113.7',
  });
  // A phone on the same Wi-Fi reaches the listener with its own address.
  assert.deepEqual(classifyRequestOrigin({}, '10.0.161.23'), { via: 'lan', clientIp: '10.0.161.23' });
  assert.deepEqual(classifyRequestOrigin({}, '::ffff:192.168.1.9'), { via: 'lan', clientIp: '192.168.1.9' });
  // The desktop on this machine.
  assert.deepEqual(classifyRequestOrigin({}, '127.0.0.1'), { via: 'local', clientIp: '127.0.0.1' });
  assert.deepEqual(classifyRequestOrigin({}, '::1'), { via: 'local', clientIp: '::1' });
  // A public peer with no proxy header is unusual but must not be called local.
  assert.deepEqual(classifyRequestOrigin({}, '203.0.113.7'), { via: 'direct', clientIp: '203.0.113.7' });
  assert.deepEqual(classifyRequestOrigin({}, undefined), { via: 'unknown', clientIp: undefined });
  // Empty headers are ignored rather than treated as a proxy.
  assert.equal(classifyRequestOrigin({ 'cf-connecting-ip': '  ' }, '10.0.0.5').via, 'lan');
});

test('recognizes private addresses and the machine’s own subnet', () => {
  for (const address of ['10.0.0.1', '10.255.255.254', '172.16.0.1', '172.31.255.1', '192.168.1.1', 'fd00::1']) {
    assert.equal(isPrivateAddress(address), true, address);
  }
  for (const address of ['172.15.0.1', '172.32.0.1', '8.8.8.8', '203.0.113.7', '2001:db8::1', '', 'nonsense']) {
    assert.equal(isPrivateAddress(address), false, address);
  }
  const mine = [{ address: '10.0.161.47', interface: 'WLAN' }];
  assert.equal(sameLan('10.0.161.23', mine), true, 'same /24');
  assert.equal(sameLan('10.0.68.140', mine), false, 'different /24');
  assert.equal(sameLan('8.8.8.8', mine), false, 'public address is never the LAN');
  assert.equal(sameLan(undefined, mine), false);
});

test('keeps the last-seen route on a device row', () => {
  const t0 = 2_000_000;
  const first = upsertDevice([], { id: 'p', ua: 'iPhone', ip: '203.0.113.7', via: 'tunnel', now: t0 });
  assert.equal(first[0].lastVia, 'tunnel');
  const second = upsertDevice(first, { id: 'p', ua: 'iPhone', ip: '10.0.161.23', via: 'lan', now: t0 + 1000 });
  assert.equal(second[0].lastVia, 'lan');
  assert.equal(second[0].lastIp, '10.0.161.23');
  assert.equal(second[0].firstSeenAt, t0);
});

test('suggests a hostname label from the machine platform', () => {
  // A Mac must not be handed the Windows example: the panel renders this label
  // into the hostname, tunnel-name and advertised-URL placeholders.
  assert.equal(suggestedLabelFor('darwin'), 'dsh-mac');
  assert.equal(suggestedLabelFor('win32'), 'dsh-win');
  assert.equal(suggestedLabelFor('linux'), 'dsh-lin');
  assert.equal(suggestedLabelFor('freebsd'), 'dsh-freebsd');
  assert.equal(suggestedLabelFor(''), 'dsh');
  assert.equal(suggestedLabelFor(undefined), 'dsh');
  for (const platform of ['darwin', 'win32', 'linux']) {
    assert.match(suggestedLabelFor(platform), /^[a-z][a-z0-9-]*$/, 'a label is a legal hostname label');
  }
});

test('every stored secret ref can be parsed back at startup', () => {
  // The credentials document is validated against this pattern when it loads, so
  // a name that does not match fails the *next startup*, not the call that wrote
  // it. That is exactly how "dsh-remote-access/unlock-secret" once bricked a
  // boot: the plugin called set() with a slash and the file became unloadable.
  for (const ref of SECRET_REFS) {
    assert.match(ref, SECRET_REF_RE, `${ref} must be a legal env-style credential ref`);
  }
  assert.ok(SECRET_REFS.length >= 2, 'the Cloudflare token and the connector token are both stored');
  assert.ok(!SECRET_REF_RE.test('dsh-remote-access/unlock-secret'), 'a slashed ref is rejected');
  assert.ok(!SECRET_REF_RE.test('1LEADING_DIGIT'), 'a leading digit is rejected');
  assert.ok(!SECRET_REF_RE.test(''), 'an empty ref is rejected');
  assert.ok(SECRET_REF_RE.test('CLOUDFLARE_API_TOKEN'));
});

test('treats every browser spelling of absent as not set', () => {
  // `String(null)` from a stale input draft used to write the literal "null"
  // into a hostname, producing a config that looked set but could never work.
  for (const junk of ['null', 'NULL', ' null ', 'undefined', 'nil', '', '   ']) {
    assert.equal(absentText(junk), undefined, `${JSON.stringify(junk)} means not set`);
  }
  assert.equal(absentText(undefined), undefined);
  assert.equal(absentText(null), undefined);
  assert.equal(absentText(42), undefined);
  assert.equal(absentText('dsh-win.example.com'), 'dsh-win.example.com');
  assert.equal(absentText('  dsh-win.example.com  '), 'dsh-win.example.com');
});

test('registers the setup skill with all three platforms covered', () => {
  const skill = skillRegistration('remote-access');
  assert.equal(skill.name, SKILL_NAME);
  assert.equal(skill.source, 'runtime');
  assert.equal(skill.provider, 'remote-access');
  assert.deepEqual(skill.invocation, { modelInvocable: true, userInvocable: true });
  assert.equal(skill.resourceBase.kind, 'opaque');
  assert.ok(skill.description.length > 40, 'the catalog needs a real description');
  assert.ok(skill.whenToUse.length > 20);

  // The body must be usable on Windows, macOS and Linux: install commands per
  // platform, both cloudflared directory spellings, both env-var spellings, and
  // the service story for each.
  for (const needle of [
    'Windows',
    'macOS',
    'Linux',
    'winget install',
    'brew install',
    'apt install',
    'dnf install',
    '%USERPROFILE%',
    '~/.cloudflared',
    '$env:DSH_HOME',
    'systemd',
    'launchd',
  ]) {
    assert.ok(skill.content.includes(needle), `skill body mentions ${needle}`);
  }
  // It must state the manual step, the upload ceiling and the restart rule
  // rather than leaving them to be discovered.
  assert.match(skill.content, /Add a site/);
  assert.match(skill.content, /100 MB/);
  assert.match(skill.content, /重启 dsh/);
});

test('routes and record keys live under the renamed plugin scope', () => {
  assert.equal(CHANNEL, '/remote-access');
  assert.equal(HEARTBEAT_PATH, '/remote-access/heartbeat.js');
  assert.equal(DEVICE_RECORD_KEY, 'dsh-remote-access/devices');
  assert.ok(!CHANNEL.includes('mobile-console'), 'no route embeds the old plugin name');
});

test('the package patch row keeps the collision-free row id', () => {
  // `dsh-base` already owns `id: remote-access` for `@deepseek-ai/dsh-api-remote-access`,
  // and the Loader dedupes rows by id with the last one winning and no diagnostic:
  // reusing that id would silently drop the shipped row, so the id carries the
  // `-panel` suffix and the code that rewrites its own row uses the same value.
  assert.equal(ROW_ID, 'remote-access-panel');
  const yaml = readFileSync(new URL('../cordis.patch.yml', import.meta.url), 'utf8');
  assert.match(yaml, /- id: remote-access-panel\n +name: dsh-remote-access/);
  assert.ok(!/^\s*- id: remote-access\s*$/m.test(yaml), 'the shipped row id is never reused');
});

/** Minimal host ctx: enough for `apply` to register its routes and effects. */
function hostCtx(credentials) {
  const routes = [];
  return {
    routes,
    effect: (fn) => fn(),
    get: (name) => (name === 'credentials' ? credentials : undefined),
    webServer: {
      register: (route) => {
        routes.push(route);
        return () => {};
      },
      tapIndex: () => () => {},
    },
  };
}

/** A credentials store good enough for the record half of the seam. */
function credentialStore(initial = []) {
  const records = new Map(initial);
  return {
    records,
    readRecord: async (key) => records.get(key),
    modifyRecord: async (key, mutate) => {
      const next = await mutate(records.get(key));
      if (next !== undefined) records.set(key, next);
      return next;
    },
  };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

test('copies legacy credential records into the new scope, once, without deleting them', async () => {
  const legacy = {
    'dsh-mobile-console/devices': { kind: 'grant', payload: { version: 1, devices: [{ id: 'd1' }] } },
    'dsh-mobile-console/recovery': { kind: 'grant', payload: { version: 1, salt: 's', key: 'k', secret: 'x' } },
    'dsh-mobile-console/device-tokens': { kind: 'grant', payload: { version: 1, tokens: [{ hash: 'h' }] } },
    'dsh-mobile-console/pair-codes': { kind: 'grant', payload: { version: 1, codes: [] } },
  };
  const credentials = credentialStore(Object.entries(legacy));
  apply(hostCtx(credentials), undefined);
  await tick();

  for (const [oldKey, record] of Object.entries(legacy)) {
    const newKey = oldKey.replace('dsh-mobile-console', 'dsh-remote-access');
    assert.deepEqual(credentials.records.get(newKey), record, `${newKey} was copied`);
    assert.deepEqual(credentials.records.get(oldKey), record, `${oldKey} is kept as the rollback path`);
  }

  // A newer record under the new key is never overwritten by a second run.
  credentials.records.set('dsh-remote-access/recovery', { kind: 'grant', payload: { version: 1, salt: 'newer' } });
  apply(hostCtx(credentials), undefined);
  await tick();
  assert.equal(credentials.records.get('dsh-remote-access/recovery').payload.salt, 'newer');
  assert.ok(!credentials.records.has('dsh-remote-access/nothing'), 'no record is invented');
});

test('converts the legacy device tokens into the unified record on activation', async () => {
  // The chain a real upgrade walks: the mobile-console record is copied into the
  // current scope, then its rows are converted into the v2 authorized-device
  // record. Both legacy records stay exactly where they were, and a second
  // activation changes nothing.
  const legacyTokens = {
    kind: 'grant',
    payload: {
      version: 1,
      tokens: [{ id: 'abc123', hash: 'f'.repeat(64), label: 'iPhone · Safari', createdAt: 'then', lastUsedAt: 'then', expiresAt: null, days: null }],
    },
  };
  const credentials = credentialStore([['dsh-mobile-console/device-tokens', legacyTokens]]);
  apply(hostCtx(credentials), undefined);
  await tick();

  assert.deepEqual(credentials.records.get('dsh-remote-access/device-tokens'), legacyTokens, 'the v1 record is copied, not moved');
  const v2 = credentials.records.get(DEVICES_V2_RECORD_KEY);
  assert.equal(v2.payload.version, 2);
  assert.equal(v2.payload.devices.length, 1);
  assert.equal(v2.payload.devices[0].id, 'abc123');
  assert.equal(v2.payload.devices[0].hash, 'f'.repeat(64), 'the fingerprint is carried over');
  assert.equal(v2.payload.devices[0].name, 'iPhone · Safari');
  assert.equal(v2.payload.devices[0].source, 'entry-link');
  assert.deepEqual(credentials.records.get('dsh-mobile-console/device-tokens'), legacyTokens, 'the original is untouched');

  apply(hostCtx(credentials), undefined);
  await tick();
  assert.equal(credentials.records.get(DEVICES_V2_RECORD_KEY).payload.devices.length, 1, 'a second activation adds nothing');
});

test('a broken credential store cannot stop activation', async () => {
  const refusing = {
    readRecord: async () => {
      throw new Error('the store is locked');
    },
    modifyRecord: async () => {
      throw new Error('the store is locked');
    },
  };
  assert.doesNotThrow(() => apply(hostCtx(refusing), undefined));
  await tick();
  assert.doesNotThrow(() => apply(hostCtx(undefined), undefined));
  await tick();
});
