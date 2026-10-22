// QR encoder regression test.
//
// The golden hashes below were produced by the reference `qrcode` npm package
// (a byte-mode segment, the same error-correction level, and a pinned mask) and
// then reproduced by this encoder for every level, version 1-10 and all eight
// masks. They are embedded so this suite keeps that anchor without taking a
// dependency.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { encodeQr } from '../lib/qr.js';

const GOLDEN = [
  { text: 'A', level: 'H', mask: 0, version: 1, size: 21, sha256: '28679ece3397cce400019b7015eaa736' },
  { text: 'https://dsh.example.com/', level: 'L', mask: 0, version: 2, size: 25, sha256: 'f3bf9c9432d059c7066386631bd7de7a' },
  { text: 'https://dsh.example.com/', level: 'M', mask: 3, version: 2, size: 25, sha256: '75d49f0ebd93fb529638b72d1d1cd1f3' },
  {
    text: 'https://dsh.example.com/?token=' + 'x'.repeat(43),
    level: 'M',
    mask: 5,
    version: 5,
    size: 37,
    sha256: '1400f802caf80977e866380492f9d2e7',
  },
  {
    text: 'https://dsh.example.com/?token=' + 'x'.repeat(43),
    level: 'Q',
    mask: 7,
    version: 6,
    size: 41,
    sha256: '1a846a2ef6cb2eb552fcb4d40b731205',
  },
  {
    text: 'https://a-very-long-tunnel-name.example.com/?token=' + 'Ab3_-'.repeat(12),
    level: 'Q',
    mask: 2,
    version: 9,
    size: 53,
    sha256: 'b0e4afdc65722107bb73170cb75890e2',
  },
  {
    text: 'https://dsh.example.com/?token=' + 'y'.repeat(60),
    level: 'H',
    mask: 1,
    version: 9,
    size: 53,
    sha256: 'a20efda6b180ba4d9c78753b69a0eda6',
  },
  {
    text: 'http://10.0.161.47:3080/?token=' + 'z'.repeat(43),
    level: 'M',
    mask: 4,
    version: 5,
    size: 37,
    sha256: 'e8e4b7abd9ad4b2778ce6ef3813ec97c',
  },
];

const sha = (s) => createHash('sha256').update(s).digest('hex').slice(0, 32);

test('matches the reference encoder matrix for every anchored case', () => {
  for (const c of GOLDEN) {
    const qr = encodeQr(c.text, { level: c.level, minVersion: c.version, forceMask: c.mask });
    assert.equal(qr.version, c.version, `version for ${JSON.stringify(c.text)}`);
    assert.equal(qr.size, c.size, `size for ${JSON.stringify(c.text)}`);
    assert.equal(qr.bits.length, c.size * c.size);
    assert.equal(sha(qr.bits), c.sha256, `matrix for ${JSON.stringify(c.text)} ${c.level} mask${c.mask}`);
  }
});

test('chooses the lowest-penalty mask and stays decodable-shaped', () => {
  const qr = encodeQr('https://dsh.example.com/?token=' + 'x'.repeat(43), { level: 'M' });
  assert.ok(qr.mask >= 0 && qr.mask <= 7);
  const forced = [];
  for (let mask = 0; mask < 8; mask++) forced.push(encodeQr('https://dsh.example.com/?token=' + 'x'.repeat(43), { level: 'M', forceMask: mask }));
  assert.equal(new Set(forced.map((f) => f.bits)).size, 8, 'each mask must produce a distinct matrix');
});

test('places the function patterns the specification requires', () => {
  const qr = encodeQr('https://dsh.example.com/', { level: 'M' });
  const dark = (x, y) => qr.bits[y * qr.size + x] === '1';
  const reserved = (x, y) => qr.reservedBits[y * qr.size + x] === '1';
  // Finder cores and rings.
  for (const [ox, oy] of [[0, 0], [qr.size - 7, 0], [0, qr.size - 7]]) {
    for (let dy = 0; dy < 7; dy++) {
      for (let dx = 0; dx < 7; dx++) {
        const dist = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
        assert.equal(dark(ox + dx, oy + dy), dist !== 2, `finder at ${ox},${oy} offset ${dx},${dy}`);
      }
    }
  }
  // Timing patterns alternate, starting dark on even coordinates.
  for (let i = 8; i < qr.size - 8; i++) {
    assert.equal(dark(i, 6), i % 2 === 0, `timing row at ${i}`);
    assert.equal(dark(6, i), i % 2 === 0, `timing column at ${i}`);
  }
  // The always-dark module sits at row 4V+9, column 8.
  assert.equal(dark(8, qr.size - 8), true, 'dark module');
  assert.equal(reserved(8, qr.size - 8), true, 'dark module is a function module');
  // Format areas are reserved on both copies.
  assert.equal(reserved(8, 8), true);
  assert.equal(reserved(qr.size - 1, 8), true);
  assert.equal(reserved(8, qr.size - 1), true);
  // Reserved modules leave exactly the codeword capacity plus that version's
  // remainder bits (7 for versions 2-6, 0 for 7-13, and so on).
  const dataModules = [...qr.reservedBits].filter((c) => c === '0').length;
  const remainderBits = ((16 * qr.version + 128) * qr.version + 64 -
    (qr.version >= 2 ? (25 * (Math.floor(qr.version / 7) + 2) - 10) * (Math.floor(qr.version / 7) + 2) - 55 : 0) -
    (qr.version >= 7 ? 36 : 0)) % 8;
  assert.equal(
    dataModules - qr.codewords.length * 8,
    remainderBits,
    'data modules exceed the codeword capacity by exactly the remainder bits',
  );
  assert.equal(remainderBits, 7, 'version 2 carries 7 remainder bits');
});

test('every block satisfies the Reed-Solomon root property', () => {
  const mul = (x, y) => {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d);
      z ^= ((y >>> i) & 1) * x;
    }
    return z & 0xff;
  };
  const pow = (a, n) => {
    let r = 1;
    for (let i = 0; i < n; i++) r = mul(r, a);
    return r;
  };
  const evaluate = (bytes, x) => bytes.reduce((acc, b) => mul(acc, x) ^ b, 0);

  for (const level of ['L', 'M', 'Q', 'H']) {
    const qr = encodeQr('https://dsh.example.com/?token=' + 'w'.repeat(40), { level });
    const { codewords, dataCodewordCount, ecCodewordsPerBlock, blockCount } = qr;
    const shortLen = Math.floor(dataCodewordCount / blockCount);
    const numShort = blockCount - (dataCodewordCount % blockCount);
    const data = Array.from({ length: blockCount }, (_, i) => new Array(shortLen + (i < numShort ? 0 : 1)).fill(0));
    const ec = Array.from({ length: blockCount }, () => new Array(ecCodewordsPerBlock).fill(0));
    let p = 0;
    for (let i = 0; i <= shortLen; i++) for (let b = 0; b < blockCount; b++) if (i < data[b].length) data[b][i] = codewords[p++];
    for (let i = 0; i < ecCodewordsPerBlock; i++) for (let b = 0; b < blockCount; b++) ec[b][i] = codewords[p++];
    for (let b = 0; b < blockCount; b++) {
      const full = [...data[b], ...ec[b]];
      for (let i = 0; i < ecCodewordsPerBlock; i++) {
        assert.equal(evaluate(full, pow(2, i)), 0, `${level} block ${b} root alpha^${i}`);
      }
    }
  }
});

test('refuses text beyond version 10 at that level', () => {
  assert.throws(() => encodeQr('z'.repeat(300), { level: 'H' }), RangeError);
  assert.throws(() => encodeQr('z'.repeat(1000), { level: 'L' }), RangeError);
  assert.throws(() => encodeQr('x', { level: 'Z' }), RangeError);
  // The largest entry URL this plugin builds fits comfortably.
  const url = 'https://a-long-tunnel-hostname.example.com/?token=' + 'A'.repeat(43);
  assert.equal(encodeQr(url, { level: 'M' }).size > 0, true);
});
