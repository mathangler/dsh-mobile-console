// Recovery-door tests: key derivation, challenge-response, ticket signing,
// rate limiting, and the QR SVG the unlock page hands back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PBKDF2_ITERATIONS,
  createRateLimiter,
  deriveKey,
  newNonce,
  newSalt,
  proofFor,
  qrSvg,
  signTicket,
  unlockPageHtml,
  verifyProof,
  verifyTicket,
} from '../lib/unlock.js';

const PAGE = {
  prefix: '/mobile-console',
  title: 't',
  subtitle: 's',
  passwordLabel: 'p',
  buttonLabel: 'b',
  wrongLabel: 'w',
  missingLabel: 'no-password-yet',
  successLabel: 'ok',
  openLabel: 'o',
};

test('derives a key that answers a nonce, and rejects everything else', () => {
  const salt = newSalt();
  const key = deriveKey('correct horse battery staple', salt, 1000);
  assert.equal(key, deriveKey('correct horse battery staple', salt, 1000), 'derivation is deterministic');
  assert.notEqual(key, deriveKey('correct horse battery stapl', salt, 1000), 'a one-character difference changes the key');
  assert.notEqual(key, deriveKey('correct horse battery staple', newSalt(), 1000), 'a different salt changes the key');
  assert.ok(key.length >= 40);

  const nonce = newNonce();
  const proof = proofFor(key, nonce);
  assert.equal(verifyProof(key, nonce, proof), true);
  assert.equal(verifyProof(deriveKey('a different password', salt, 1000), nonce, proof), false);
  assert.equal(verifyProof(key, newNonce(), proof), false, 'the nonce is part of the answer');
  assert.equal(verifyProof(key, nonce, ''), false);
  assert.equal(verifyProof(key, nonce, 'not base64 at all'), false);
  assert.equal(verifyProof(key, nonce, undefined), false);
});

test('uses a work factor strong enough to make guessing expensive', () => {
  assert.ok(PBKDF2_ITERATIONS >= 600000, `expected at least 600k iterations, got ${PBKDF2_ITERATIONS}`);
});

test('signs tickets that cannot be forged, tampered with or outlived', () => {
  const secret = 'ticket-secret';
  const ticket = signTicket(secret, { v: 1, exp: Date.now() + 60_000 });
  assert.equal(verifyTicket(secret, ticket)?.v, 1);
  assert.equal(verifyTicket('another-secret', ticket), undefined, 'a different secret cannot verify it');
  assert.equal(verifyTicket(secret, `${ticket}x`), undefined, 'a tampered mac fails');
  assert.equal(verifyTicket(secret, `x${ticket}`), undefined, 'a tampered body fails');
  assert.equal(verifyTicket(secret, signTicket(secret, { v: 1, exp: Date.now() - 1 })), undefined, 'expired');
  assert.equal(verifyTicket(secret, signTicket(secret, { v: 1 })), undefined, 'a payload without exp is refused');
  assert.equal(verifyTicket(secret, 'no-dot-here'), undefined);
  assert.equal(verifyTicket(secret, undefined), undefined);
  assert.equal(verifyTicket(secret, ''), undefined);
});

test('limits failures per client and forgets them on success or reset', () => {
  let clock = 0;
  const limiter = createRateLimiter({ limit: 3, windowMs: 1000, now: () => clock });
  for (let attempt = 0; attempt < 3; attempt += 1) {
    assert.equal(limiter.allowed('1.2.3.4'), true);
    limiter.fail('1.2.3.4');
  }
  assert.equal(limiter.allowed('1.2.3.4'), false, 'the fourth attempt in the window is blocked');
  assert.equal(limiter.allowed('5.6.7.8'), true, 'another client is unaffected');
  assert.ok(limiter.retryAfterMs('1.2.3.4') > 0);
  assert.equal(limiter.retryAfterMs('5.6.7.8'), 0);

  clock = 1001;
  assert.equal(limiter.allowed('1.2.3.4'), true, 'the window rolls over');
  limiter.fail('1.2.3.4');
  limiter.reset('1.2.3.4');
  assert.equal(limiter.retryAfterMs('1.2.3.4'), 0);
  limiter.fail('1.2.3.4');
  limiter.clear();
  assert.equal(limiter.allowed('1.2.3.4'), true);
});

test('renders a challenge-response page, and nothing to attack without a password', () => {
  const configured = unlockPageHtml({ ...PAGE, configured: true });
  assert.match(configured, /crypto\.subtle\.importKey/);
  assert.match(configured, /crypto\.subtle\.deriveBits/);
  assert.match(configured, /name: 'PBKDF2'/);
  assert.match(configured, /crypto\.subtle\.sign/);
  // The page builds its URLs as PREFIX + suffix, so assert both halves.
  assert.match(configured, /PREFIX = "\/mobile-console"/);
  assert.match(configured, /'\/unlock\/challenge'/);
  assert.match(configured, /'\/unlock\/verify'/);
  assert.match(configured, /'\/unlock\/entry'/);
  assert.match(configured, /<meta name="referrer" content="no-referrer"/);

  const missing = unlockPageHtml({ ...PAGE, configured: false });
  assert.match(missing, /no-password-yet/);
  // Nothing to attack: no form, no input. The inline script is present but
  // returns immediately when there is no form to drive.
  assert.ok(!missing.includes('<form id="f">'), 'an unconfigured door renders no form');
  assert.ok(!missing.includes('id="p"'), 'an unconfigured door renders no password input');
  assert.ok(!missing.includes('id="go"'), 'an unconfigured door renders no button');
});

test('renders a QR svg and refuses malformed input', () => {
  const svg = qrSvg({ size: 2, bits: '1001' });
  assert.match(svg, /^<svg /);
  assert.match(svg, /viewBox="0 0 10 10"/, '2 modules plus a 4-module quiet zone on each side');
  assert.equal(qrSvg({ size: 3, bits: '1' }), '');
  assert.equal(qrSvg({ size: 0, bits: '' }), '');
  assert.equal(qrSvg(undefined), '');
});
