/**
 * dsh-remote-access — host half.
 *
 * Route A: the phone uses the shipped Web UI over a Cloudflare named tunnel
 * (optionally behind Cloudflare Access). The platform already authenticates that
 * traffic — a per-process launch token exchanged for a signed, authority-bound
 * cookie, plus a Host/Origin fence — so this plugin never re-implements login.
 * What it adds is everything around that:
 *
 *  - `/remote-access/state` and friends: the entry URLs (with the process's
 *    fresh launch token), a QR matrix for each, the trust verdict for the tunnel
 *    authority, the cloudflared child process, the devices that recently
 *    connected, and the platform cookie lifetime.
 *  - `/remote-access/heartbeat`: the phone-side ping behind the injected
 *    script, which is how a device list exists at all (the platform keeps no
 *    per-device state for browser cookies, so this is a view, not an authority).
 *  - `deployment-apply`: writes the tunnel authority into the shipped
 *    `connection` row's `trustedHosts` through `ctx.configEditor`, which
 *    persists into the user's own profile patch layer and reconciles through the
 *    normal Loader path. No command-line flag is required.
 *  - `tunnel-start` / `tunnel-stop`: a managed cloudflared child process.
 *  - `revoke-platform-sessions`: deletes the platform's browser-session
 *    credential record, so every paired browser loses access at the next start.
 *
 * Security: every request goes through the composition's
 * `connection.requestRejection(req)` first — the platform's Host/Origin fence
 * and its login-token/cookie check — exactly as the shipped open-in-app plugin
 * does. Nothing is hand-rolled.
 *
 * The plugin has no dependencies: no `@deepseek-ai/*` imports, no zod Config
 * schema (the row's `config` is normalized defensively below), no bundler.
 *
 * @module dsh-remote-access
 */
import { networkInterfaces } from 'node:os';
import { encodeQr } from './qr.js';
import { createCloudflareClient, accessAppBody, validHostname, REQUIRED_TOKEN_SCOPES } from './cloudflare.js';
import {
  certPemPath,
  tunnelConfigPath,
  parseLoginUrl,
  parseTunnelId,
  findTunnelInList,
  renderTunnelConfig,
  tunnelRunArgs,
  tunnelTokenArgs,
  installHint,
  CLOUDFLARED_RELEASES,
  environmentSummary,
} from './cloudflared.js';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { skillRegistration } from './skill.js';
import { randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import {
  TEMP_TOKEN_MINUTES,
  accessKeyMatches,
  fingerprintsMatch,
  hashAccessKey,
  hashTempToken,
  isTempToken,
  newAccessKey,
  newRecordId,
  newTempToken,
  normalizeAccessKey,
  tempTokenExpiry,
  tempTokenMatches,
} from './accesskey.js';
import {
  PBKDF2_ITERATIONS,
  UNLOCK_COOKIE,
  DEVICE_COOKIE,
  DEFAULT_TICKET_DAYS,
  DEFAULT_DEVICE_DAYS,
  DEFAULT_PAIR_MINUTES,
  PAIR_CODE_LENGTH,
  createRateLimiter,
  deriveKey,
  deviceTokenMatches,
  expiryFromDays,
  hashDeviceToken,
  hashPairCode,
  newDeviceToken,
  newNonce,
  newPairCode,
  newSalt,
  normalizePairCode,
  pageStrings,
  requestLocale,
  signTicket,
  unlockPageHtml,
  verifyProof,
  verifyTicket,
} from './unlock.js';

/** Cordis plugin name reported to the loader. */
const name = 'remote-access';

/**
 * This plugin's own row id, as the profile patch layer addresses it.
 *
 * Deliberately not `remote-access`: the shipped `dsh-base` bundle already owns
 * that id for `@deepseek-ai/dsh-api-remote-access`, and the Loader dedupes rows
 * by id with the last one winning and no diagnostic — reusing it would silently
 * drop the shipped row. The plugin's own `cordis.patch.yml` declares the same id.
 */
const ROW_ID = 'remote-access-panel';

/**
 * `webServer` is a hard dependency: without a route there is nothing to serve.
 * `connection`, `credentials`, `configEditor`, `subprocess`, `webApp` and
 * `webStartup` are read through `ctx.get`, so this plugin still activates in a
 * composition that mounts only some of them.
 */
const inject = ['webServer'];

/** Absolute route prefix owned by this plugin; must match the client half. */
const CHANNEL = '/remote-access';

/** Public static asset injected into the SPA index; holds no secret. */
const HEARTBEAT_PATH = '/remote-access/heartbeat.js';

/** Credential record holding the device view, under this plugin's own scope. */
const DEVICE_RECORD_KEY = 'dsh-remote-access/devices';

/**
 * Credential record holding the unified authorized-device rows.
 *
 * This replaces the old device-token rows. `-v2` is in the key because the row
 * shape changed rather than only the plugin's name: a v1 row carries no
 * `source`, no `temporary` and no `lastUsedIp`, so a record written by the old
 * code cannot be read as a v2 one. The legacy record is read once at activation
 * and copied into this one; it is never deleted.
 */
const DEVICES_V2_RECORD_KEY = 'dsh-remote-access/devices-v2';

/** Credential record holding the access keys, under the same scope. */
const ACCESS_KEYS_RECORD_KEY = 'dsh-remote-access/access-keys';

/** The one-time entry link the root gate mints for `?token=` visitors, in days. */
const ENTRY_LINK_DAYS = 30;

/** Key rows kept in the store. */
const MAX_KEYS = 50;

/** The key the "every client together" rate limit is counted against. */
const GLOBAL_LIMIT_KEY = '*';

/** The platform's browser-session record, addressed to revoke every pairing. */
const PLATFORM_SESSION_KEY = 'client-connection/browser-session';

/**
 * Credential keys the automatic Cloudflare setup stores its secrets under. The
 * platform's credential store keeps them out of configuration and out of every
 * response this plugin sends.
 */
const CF_API_TOKEN_KEY = 'CLOUDFLARE_API_TOKEN';

const CF_TUNNEL_TOKEN_KEY = 'CLOUDFLARE_TUNNEL_TOKEN';

/**
 * The shape every env-style credential ref must have.
 *
 * `credentials.set` / `resolve` / `unset` accept any string, but the credentials
 * document is validated against this pattern when it is parsed — so a ref that
 * does not match becomes a failed *startup* instead of a failed call. Records
 * (`readRecord` / `modifyRecord` / `deleteRecord`) are a separate namespace and
 * may contain a slash; env-style secrets may not.
 */
export const SECRET_REF_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Every env-style secret this plugin stores. Each must match SECRET_REF_RE. */
export const SECRET_REFS = [CF_API_TOKEN_KEY, CF_TUNNEL_TOKEN_KEY];

/** Default name of the remotely-managed tunnel this plugin creates. */
const DEFAULT_TUNNEL_NAME = 'dsh-remote-access';

/** Panel requests are small JSON objects; anything larger is hostile. */
const MAX_BODY_BYTES = 64 * 1024;

/**
 * How many mints one client may spend through the fenced panel per quarter hour.
 *
 * The public doors keep the strict five, which is what stops guessing; the panel
 * is used by the person who already holds the session, and five clicks in a
 * quarter hour made the panel fight its own user ("retry in 796s").
 */
const PANEL_LIMIT = 30;

/**
 * The record that switches the two credential channels on and off.
 *
 * Kept apart from the rows themselves on purpose: switching a channel off must
 * refuse its credentials without deleting anything, so switching it back on
 * restores access with no re-pairing and no new link.
 */
const ACCESS_POLICY_RECORD_KEY = 'dsh-remote-access/access-policy';

/** Both channels are on unless the record says otherwise. */
const DEFAULT_ACCESS_POLICY = { temporaryAccess: true, deviceAccess: true };

/**
 * How long the index forward waits for the platform before giving up.
 *
 * Node's own `requestTimeout` is 300 seconds, which over a tunnel is a
 * Cloudflare 524 long before anything is logged. Half a minute is longer than
 * any real page render and short enough to be a diagnosis.
 */
const FORWARD_TIMEOUT_MS = 30 * 1000;

/** Device rows kept in the view. */
const MAX_DEVICES = 50;

/**
 * Entry-link rows kept, in a bucket of their own.
 *
 * Deliberately tiny and separate: these are the rows a `?token=` visit creates,
 * so they are the only ones an unauthenticated stranger can add to. Capping them
 * inside `MAX_DEVICES` let a flood of them evict every real paired device.
 */
const MAX_ENTRY_LINKS = 3;

/** Default retention for a device row that stops appearing. */
const RETENTION_DEFAULT_DAYS = 180;

/** Endpoint segment: the names this module exports, and nothing else. */
const ENDPOINT_RE = /^[A-Za-z0-9_$.-]+$/;

/** IPv4 or IPv6 literal, the only shape the webserver row accepts as a bind. */
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const WILDCARD_RE = /^(?:0\.0\.0\.0|::|\[::\]|::0\.0\.0\.0)$/;

const ok = (value) => ({ ok: true, value });
const fail = (code, message, details = {}) => ({ ok: false, error: { code, message, details } });

/** JSON response; every answer is a live fact about this machine. */
function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(payload));
}

/** Collect a bounded request body as UTF-8 text; null past the ceiling. */
async function readBoundedBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.byteLength;
    if (size > MAX_BODY_BYTES) {
      req.resume();
      return null;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size).toString('utf8');
}

/** Call a function, returning `undefined` instead of throwing. */
function attempt(fn) {
  try {
    return fn();
  } catch {
    return undefined;
  }
}

/**
 * The value as the credential store can hold it.
 *
 * The store refuses a payload that holds a value JSON cannot represent — and it
 * does so *at write time*, which turns a stray `undefined` field into a bare 400
 * from the webserver instead of a diagnosable error. Two rules, then:
 *
 *  - `undefined` means "absent", so the key is dropped rather than written as
 *    `null` (which would change what the row says);
 *  - anything else JSON cannot represent — a non-finite number, a function, a
 *    circular reference — fails loudly, naming the path that caused it.
 *
 * Every credential write goes through here, so a future field added with the
 * wrong value is a clear error at the call site instead of a silent 400 later.
 * @param value - the payload about to be stored.
 * @param path - where the value came from, for the error message.
 */
export function storablePayload(value, path = 'payload') {
  const seen = new Set();
  const walk = (node, where, inArray) => {
    if (node === undefined) {
      if (inArray) throw new Error(`${where} is undefined, which JSON cannot represent`);
      return undefined;
    }
    if (node === null || typeof node === 'string' || typeof node === 'boolean') return node;
    if (typeof node === 'number') {
      if (!Number.isFinite(node)) throw new Error(`${where} is ${String(node)}, which JSON cannot represent`);
      return node;
    }
    if (typeof node !== 'object') throw new Error(`${where} is a ${typeof node}, which JSON cannot represent`);
    if (seen.has(node)) throw new Error(`${where} is circular`);
    seen.add(node);
    let out;
    if (Array.isArray(node)) {
      out = node.map((item, index) => walk(item, `${where}[${index}]`, true));
    } else {
      out = {};
      for (const [key, item] of Object.entries(node)) {
        const next = walk(item, `${where}.${key}`, false);
        if (next !== undefined) out[key] = next;
      }
    }
    seen.delete(node);
    return out;
  };
  return walk(value, path, false);
}

/** Await a call, returning `undefined` instead of rejecting. */
async function attemptAsync(fn) {
  try {
    return await fn();
  } catch {
    return undefined;
  }
}

/** Normalize one optional string field. */
function text(value) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

/**
 * Normalize the row's `config`. The plugin declares no Config schema, so this
 * is the single place that decides defaults and rejects nonsense.
 * @param raw - the row's config, as the Loader resolved it.
 * @returns the effective configuration.
 */
export function normalizeConfig(raw) {
  const c = raw !== null && typeof raw === 'object' ? raw : {};
  const cloudflaredRaw = c.cloudflared !== null && typeof c.cloudflared === 'object' ? c.cloudflared : undefined;
  const days = Number(c.deviceRetentionDays);
  return {
    tunnelHost: text(c.tunnelHost),
    publicUrl: text(c.publicUrl),
    lanHost: text(c.lanHost),
    tunnelName: text(c.tunnelName) ?? DEFAULT_TUNNEL_NAME,
    accessEmail: text(c.accessEmail),
    cloudflared: cloudflaredRaw
      ? {
          command: text(cloudflaredRaw.command) ?? 'cloudflared',
          args: Array.isArray(cloudflaredRaw.args) ? cloudflaredRaw.args.map(String) : [],
        }
      : undefined,
    narrowEnhance: c.narrowEnhance !== false,
    deviceRetentionDays: Number.isFinite(days) && days > 0 ? Math.floor(days) : RETENTION_DEFAULT_DAYS,
    // How long the index forward waits for the platform before answering 504. A
    // knob because a slow machine legitimately needs longer, and a test needs it
    // shorter.
    forwardTimeoutMs:
      Number.isFinite(Number(c.forwardTimeoutMs)) && Number(c.forwardTimeoutMs) > 0 ? Number(c.forwardTimeoutMs) : FORWARD_TIMEOUT_MS,
  };
}

/** A short human label for a user agent, for the device view. */
export function deviceLabel(userAgent) {
  const s = String(userAgent ?? '');
  const platform = /iPhone/.test(s)
    ? 'iPhone'
    : /iPad/.test(s)
      ? 'iPad'
      : /Android/.test(s)
        ? 'Android'
        : /Macintosh|Mac OS X/.test(s)
          ? 'Mac'
          : /Windows/.test(s)
            ? 'Windows'
            : /Linux/.test(s)
              ? 'Linux'
              : 'Unknown';
  const browser = /Edg\//.test(s)
    ? 'Edge'
    : /CriOS\//.test(s) || /Chrome\//.test(s)
      ? 'Chrome'
      : /FxiOS\//.test(s) || /Firefox\//.test(s)
        ? 'Firefox'
        : /Safari\//.test(s)
          ? 'Safari'
          : 'Browser';
  return `${platform} · ${browser}`;
}

/** Every non-loopback IPv4 literal of a local interface, best effort. */
function localAddresses() {
  const out = [];
  const interfaces = attempt(() => networkInterfaces()) ?? {};
  for (const [name_, entries] of Object.entries(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.family !== 'IPv4' || entry.internal) continue;
      out.push({ address: entry.address, interface: name_ });
    }
  }
  return out;
}

/**
 * Treat every spelling of "absent" a browser can produce as absent.
 *
 * `String(null)` in the panel yields the literal text "null"; writing that into
 * a hostname or URL field produces a config that looks set but can never work.
 * @param value - the raw field value.
 * @returns the trimmed text, or undefined when it means "not set".
 */
export function absentText(value) {
  const trimmed = typeof value === 'string' ? value.trim() : undefined;
  if (trimmed === undefined || trimmed === '') return undefined;
  return /^(null|undefined|nil)$/i.test(trimmed) ? undefined : trimmed;
}

/**
 * The hostname label this machine should suggest.
 *
 * One name per machine, and the machine's own platform is the only sane
 * default: a Mac must not be told to use the Windows example. The panel renders
 * it into every placeholder and example.
 * @param platform - a `process.platform` value.
 */
export function suggestedLabelFor(platform) {
  if (platform === 'darwin') return 'dsh-mac';
  if (platform === 'win32') return 'dsh-win';
  if (platform === 'linux') return 'dsh-lin';
  const raw = typeof platform === 'string' && platform !== '' ? platform.toLowerCase().replace(/[^a-z0-9]/g, '') : '';
  return raw === '' ? 'dsh' : `dsh-${raw}`;
}

/**
 * Whether an authority (host[:port], with or without brackets) names this
 * machine's loopback. A bare IPv6 literal is checked before the URL parser,
 * which requires brackets around it.
 */
export function isLoopbackAuthority(authority) {
  const value = String(authority ?? '').trim();
  if (value === '') return false;
  if (value === 'localhost' || value === '::1' || value.startsWith('::1%')) return true;
  let host;
  try {
    // WHATWG `hostname` keeps the brackets on an IPv6 literal.
    host = new URL(value.includes('://') ? value : `http://${value}`).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return false;
  }
  return host === 'localhost' || host === '::1' || host.startsWith('::1%') || /^127\./.test(host);
}

/**
 * Whether one text is a bind address the shipped webserver row accepts: a
 * concrete IPv4 or IPv6 literal, never a wildcard (the platform refuses those
 * at load, because binding every interface would expose the Harness).
 * @returns the literal, or `undefined` when it is not usable.
 */
export function validBindAddress(value) {
  const literal = String(value ?? '').trim();
  if (literal === '' || WILDCARD_RE.test(literal)) return undefined;
  const ipv4 = IPV4_RE.test(literal) && literal.split('.').every((part) => Number(part) <= 255);
  const ipv6 = literal.includes(':') && /^[0-9a-fA-F:.%]+$/.test(literal);
  return ipv4 || ipv6 ? literal : undefined;
}

/**
 * Classify where one request came from, which is the honest half of "detect the
 * local network". A phone cannot be routed to the LAN automatically — its DNS
 * already answered with the tunnel — but the host can say how the request
 * actually arrived, and the panel shows it per device.
 *
 * `cloudflared` runs on this same machine, so a tunnelled request reaches the
 * listener over loopback and carries Cloudflare's client-IP header, while a
 * direct LAN request arrives from the phone's own address with no such header.
 *
 * @param headers - request headers (node lower-cases them).
 * @param remoteAddress - the socket's peer address.
 * @returns `{ via, clientIp }`, where `via` is
 *   `'tunnel' | 'lan' | 'local' | 'direct' | 'unknown'`.
 */
export function classifyRequestOrigin(headers, remoteAddress) {
  const get = (name) => {
    const value = headers?.[name];
    return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
  };
  const forwarded = get('cf-connecting-ip') ?? get('x-forwarded-for')?.split(',')[0].trim();
  const peer = typeof remoteAddress === 'string' ? remoteAddress.replace(/^::ffff:/, '') : undefined;
  if (forwarded !== undefined) return { via: 'tunnel', clientIp: forwarded };
  if (peer === undefined || peer === '') return { via: 'unknown', clientIp: undefined };
  if (isLoopbackAuthority(peer)) return { via: 'local', clientIp: peer };
  if (isPrivateAddress(peer)) return { via: 'lan', clientIp: peer };
  return { via: 'direct', clientIp: peer };
}

/** Whether an IPv4 literal is in a private range (or IPv6 unique-local). */
export function isPrivateAddress(address) {
  const value = String(address ?? '').replace(/^::ffff:/, '');
  if (value.includes(':')) return /^f[cd][0-9a-f]{2}:/i.test(value);
  const parts = value.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

/**
 * Whether one client address shares a /24 with any address of this machine —
 * the "is this phone on my network" test behind the panel's LAN badge.
 */
export function sameLan(clientIp, localAddresses) {
  const value = String(clientIp ?? '').replace(/^::ffff:/, '');
  if (!value.includes('.') || !isPrivateAddress(value)) return false;
  const prefix = value.split('.').slice(0, 3).join('.');
  return localAddresses.some((entry) => {
    const address = String(entry?.address ?? '');
    return address.includes('.') && address.split('.').slice(0, 3).join('.') === prefix;
  });
}

/**
 * Insert or refresh one device row, newest first, capped at {@link MAX_DEVICES}.
 * @param devices - existing rows.
 * @param input - `{ id, ua, ip, via, now }`.
 * @returns a new array; the input is not mutated.
 */
export function upsertDevice(devices, input) {
  const now = Number(input.now ?? Date.now());
  const index = devices.findIndex((d) => d.id === input.id);
  const next = devices.slice();
  if (index >= 0) {
    const existing = devices[index];
    next[index] = {
      ...existing,
      ua: input.ua,
      lastSeenAt: now,
      lastIp: input.ip ?? existing.lastIp,
      lastVia: input.via ?? existing.lastVia,
      hits: Number(existing.hits ?? 0) + 1,
    };
  } else {
    next.push({
      id: input.id,
      name: deviceLabel(input.ua),
      ua: input.ua,
      firstSeenAt: now,
      lastSeenAt: now,
      lastIp: input.ip,
      lastVia: input.via,
      hits: 1,
    });
  }
  return next.sort((a, b) => Number(b.lastSeenAt ?? 0) - Number(a.lastSeenAt ?? 0)).slice(0, MAX_DEVICES);
}

/**
 * Drop rows that have not been seen inside the retention window.
 * @param devices - device rows.
 * @param days - retention window in days.
 * @param now - reference instant, for tests.
 * @returns the rows to keep.
 */
export function pruneDevices(devices, days, now = Date.now()) {
  const cutoff = now - days * 24 * 60 * 60 * 1000;
  return devices.filter((d) => Number(d.lastSeenAt ?? 0) >= cutoff);
}

// ── Authorized-device rows (the `-v2` record) ───────────────────────────────
//
// One row per credential this machine handed out, whatever door it came
// through: an entry link, the recovery password, an access key, or a pairing
// code. The v1 record kept the same idea under a thinner shape (id, hash,
// label, createdAt, lastUsedAt, expiresAt, days); the helpers below are pure so
// the panel's rules — "is this still valid", "may this be deleted" — can be
// tested without a credential store or a socket.

/**
 * Whether a row's credential still works.
 *
 * `expiresAt: null` (or any non-number) is the explicit, stored choice "never
 * expires"; a number is an absolute instant. There is no sliding renewal
 * anywhere in this plugin: a row expires exactly when it says it does.
 * @param row - one authorized-device row.
 * @param now - reference instant, for tests.
 * @returns `'valid' | 'expired' | 'never'`.
 */
export function deviceStatus(row, now = Date.now()) {
  const expiresAt = row?.expiresAt;
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) return 'never';
  return expiresAt > now ? 'valid' : 'expired';
}

/**
 * Whether a row may be deleted outright.
 *
 * Deletion is for expired rows only. A row that is valid — including one that
 * never expires — has to be revoked first, so a stray click can never silently
 * drop a device that is still in use.
 */
export function deviceDeletable(row, now = Date.now()) {
  return deviceStatus(row, now) === 'expired';
}

/**
 * One row as the client sees it: the fingerprint removed, the status derived.
 *
 * `hash` is the sha256 of a live credential and must never cross the wire; this
 * is the only shape the panel ever receives.
 */
export function publicDeviceRow(row, now = Date.now()) {
  const { hash, ...rest } = row ?? {};
  return { ...rest, status: deviceStatus(row, now) };
}

/** One key row as the client sees it: no fingerprint, derived status. */
export function publicKeyRow(row, now = Date.now()) {
  return {
    id: row?.id,
    name: row?.name,
    createdAt: row?.createdAt,
    expiresAt: typeof row?.expiresAt === 'number' && Number.isFinite(row.expiresAt) ? row.expiresAt : null,
    days: row?.days === undefined ? null : row.days,
    status: deviceStatus(row, now),
    lastUsedAt: row?.lastUsedAt ?? null,
  };
}

/**
 * A stored number as a plain number.
 *
 * The credential document is YAML, and a YAML integer can come back as a
 * `BigInt` — which JSON cannot serialize and this store refuses to write. A
 * record holding one would otherwise be unwritable forever, so numbers are
 * normalized as they are read.
 */
export function storedNumber(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'bigint') {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : null;
  }
  return null;
}

/** A stored timestamp as an ISO string, whatever the document spelled it as. */
function storedStamp(value) {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.toISOString() : undefined;
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** The rows out of one record payload, ignoring anything malformed. */
export function parseDeviceRows(payload) {
  if (payload === null || typeof payload !== 'object' || !Array.isArray(payload.devices)) return [];
  return payload.devices
    .filter((row) => row !== null && typeof row === 'object' && typeof row.id === 'string' && typeof row.hash === 'string')
    .map((row) => {
      // Only values the document spelled in a way JSON cannot hold are rewritten;
      // everything else keeps the exact shape it was stored with.
      const next = { ...row };
      for (const [key, value] of Object.entries(next)) {
        if (typeof value === 'bigint') next[key] = key === 'createdAt' || key === 'lastUsedAt' ? storedStamp(value) : storedNumber(value);
        else if (value instanceof Date) next[key] = key === 'createdAt' || key === 'lastUsedAt' ? storedStamp(value) : storedNumber(value);
      }
      return next;
    });
}

/** An ISO string from a stored stamp, or `now` when it is missing or unparsable. */
function isoOr(value, now) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : new Date(now).toISOString();
}

/**
 * Convert the legacy device-token rows into v2 rows, without ever replacing one.
 *
 * Copy-only and idempotent, in that order of importance:
 *
 *  - a legacy row is copied, never moved — the v1 record stays on disk as the
 *    rollback path;
 *  - a row whose fingerprint *or* id is already present is skipped, so a second
 *    run adds nothing and a row that has since been renamed, re-scoped or
 *    re-expired keeps its newer values;
 *  - ids are derived deterministically (the legacy id, else the fingerprint's
 *    first 16 hex digits, which is exactly what the old code minted), so two
 *    runs produce the same rows and cannot duplicate them.
 *
 * A legacy row's `label` becomes the v2 `name`, and its origin is unknown — the
 * old code minted the same token shape from both the entry link and a pairing
 * code — so it is recorded as an entry link, which is the common case.
 *
 * @param current - the v2 rows already stored.
 * @param legacy - the v1 rows, as read from the old record.
 * @param now - reference instant for a missing timestamp, for tests.
 * @returns `{ rows, added }`; `added === 0` means nothing changed.
 */
export function migrateLegacyDeviceRows(current, legacy, now = Date.now()) {
  const rows = Array.isArray(current) ? current.slice() : [];
  const seen = new Set();
  for (const row of rows) {
    if (typeof row?.hash === 'string') seen.add(row.hash);
    if (typeof row?.id === 'string') seen.add(row.id);
  }
  let added = 0;
  for (const row of Array.isArray(legacy) ? legacy : []) {
    if (row === null || typeof row !== 'object' || typeof row.hash !== 'string' || row.hash === '') continue;
    const id = typeof row.id === 'string' && row.id !== '' ? row.id : row.hash.slice(0, 16);
    if (seen.has(row.hash) || seen.has(id)) continue;
    const days = row.days === null || row.days === undefined ? null : Number(row.days);
    rows.push({
      id,
      name: typeof row.name === 'string' && row.name !== '' ? row.name : typeof row.label === 'string' ? row.label : 'Paired device',
      source: 'entry-link',
      temporary: false,
      createdAt: isoOr(row.createdAt, now),
      lastUsedAt: isoOr(row.lastUsedAt, now),
      expiresAt: typeof row.expiresAt === 'number' && Number.isFinite(row.expiresAt) ? row.expiresAt : null,
      days: Number.isFinite(days) ? days : null,
      hash: row.hash,
      // A missing `lastUsedIp` is dropped rather than written as `undefined`,
      // which the credential store refuses outright.
      ...(typeof row.lastUsedIp === 'string' ? { lastUsedIp: row.lastUsedIp } : {}),
    });
    seen.add(row.hash);
    seen.add(id);
    added += 1;
  }
  return { rows, added };
}

/**
 * Which mode one bind host means.
 *
 * A loopback literal (or a wildcard, which the platform refuses to bind anyway)
 * means the listener is only reachable through a tunnel — `public`. Anything
 * concrete means it is reachable on the local network — `lan`. An unknown host
 * is reported as `public`, which is the honest answer for the shipped default.
 */
export function modeFromBindHost(host) {
  const value = typeof host === 'string' ? host.trim() : '';
  if (value === '' || WILDCARD_RE.test(value) || isLoopbackAuthority(value)) return 'public';
  return 'lan';
}

/**
 * The address this process should dial to reach its own listener.
 *
 * Not loopback by default: in LAN mode the listener is bound to one concrete
 * interface and nothing answers on `127.0.0.1`, so dialling loopback made every
 * page request fail with `ECONNREFUSED` while the JSON endpoints kept working.
 * Loopback is the fallback only where it is also the bind — an empty or wildcard
 * address, or a value that is not a usable literal.
 *
 * @param host - the listener's configured bind address.
 * @param port - the listening port.
 * @returns `{ host, port }` for one local request.
 */
export function localDialTarget(host, port) {
  const literal = String(host ?? '').trim();
  const usable = literal !== '' && !WILDCARD_RE.test(literal) && (IPV4_RE.test(literal) || literal.includes(':'));
  const value = Number(port);
  return {
    host: usable ? literal : '127.0.0.1',
    port: Number.isFinite(value) && value > 0 && value < 65536 ? value : 3080,
  };
}

// ── Direct profile-patch writes ────────────────────────────────────────────
//
// Why not `configEditor.edit`: every `edit` runs inside the HMR service's
// exclusive transaction, and a config change that reloads the webserver
// recreates its listener *inside* that transaction. The replacement listener
// inherits the transaction's async context, so every later `configEditor.edit`
// — from any request, for the rest of the process — is refused with
// "HMR transactions cannot be nested". A LAN switch therefore made
// `restore-loopback` impossible until the process restarted.
//
// The two rows a mode switch touches (`webserver.host` and
// `connection.trustedHosts`) are therefore written straight into the profile
// patch file, which is what the editor ultimately does anyway; the file watcher
// then reconciles the change through the normal Loader path, exactly as it does
// for a hand edit. The transformation below is pure, and deliberately refuses
// anything it does not fully understand, so the caller can fall back to the
// platform editor rather than guess.

/** A YAML plain scalar when one is unambiguous, a quoted string otherwise. */
function yamlScalar(value) {
  const text = String(value);
  if (text === '') return "''";
  const plain = /^[A-Za-z0-9_./:@%+-]+$/.test(text) && !/^(?:true|false|null|yes|no|on|off|~)$/i.test(text);
  return plain ? text : JSON.stringify(text);
}

/** The bare value of a scalar: quotes and trailing comment removed. */
function yamlBareValue(value) {
  const text = String(value).trim();
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) return text.slice(1, -1);
  return text;
}

/** The indentation width of one line. */
function indentWidth(line) {
  return (/^[ \t]*/.exec(line) ?? [''])[0].length;
}

/**
 * The list one row's config key holds, as the file itself spells it.
 *
 * Read from the patch text rather than from the live row on purpose: the
 * in-memory config lags a change by however long the Loader takes to reconcile,
 * and merging against a stale list silently drops entries the file still has.
 *
 * @returns `{ present, values }`; `present: false` means the row or the key is
 *   not in this text at all.
 */
export function readRowConfigList(text, id, key) {
  const source = String(text ?? '');
  const rowId = String(id ?? '');
  const lines = source.split(/\r?\n/);
  const starts = [];
  lines.forEach((line, index) => {
    if (/^-(\s|$)/.test(line)) starts.push(index);
  });
  const items = starts.map((start, index) => ({ start, end: index + 1 < starts.length ? starts[index + 1] : lines.length }));
  const idOf = (item) => {
    const inline = /^-[ \t]+id:[ \t]*(\S.*)$/.exec(lines[item.start]);
    if (inline !== null) return yamlBareValue(inline[1]);
    for (let i = item.start + 1; i < item.end; i += 1) {
      const match = /^[ \t]+id:[ \t]*(\S.*)$/.exec(lines[i]);
      if (match !== null) return yamlBareValue(match[1]);
    }
    return undefined;
  };
  const target = items.filter((item) => idOf(item) === rowId).pop();
  if (target === undefined) return { present: false, values: [] };

  const keyIndent = indentWidth(lines[target.start] ?? '') + 2;
  const pattern = new RegExp(`^[ \\t]{${keyIndent + 2}}${String(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:(.*)$`);
  for (let i = target.start; i < target.end; i += 1) {
    const match = pattern.exec(lines[i]);
    if (match === null) continue;
    const inline = match[1].trim();
    if (inline !== '') {
      const inner = inline.startsWith('[') && inline.endsWith(']') ? inline.slice(1, -1) : inline;
      return { present: true, values: inner.split(',').map((part) => yamlBareValue(part)).filter((part) => part !== '') };
    }
    const values = [];
    for (let j = i + 1; j < target.end; j += 1) {
      const line = lines[j];
      if (line.trim() === '') continue;
      // A sequence item may sit right under the key or one level deeper; both
      // spellings are the same list.
      if (indentWidth(line) > keyIndent + 2 && line.trimStart().startsWith('-')) {
        values.push(yamlBareValue(line.trimStart().replace(/^-[ \t]*/, '')));
        continue;
      }
      break;
    }
    return { present: true, values };
  }
  return { present: false, values: [] };
}

/**
 * Set top-level keys inside one row's `config:` block of a profile patch file.
 *
 * Pure and surgical: only the lines that hold the named keys are rewritten, and
 * every other line — other rows, `!!js` expressions, comments, blank lines — is
 * preserved byte for byte. Values are one scalar or a list of scalars, which is
 * all a bind address and a trusted-host list ever are.
 *
 * @param text - the whole patch file, as read.
 * @param id - the row id to edit; the *last* plain row with that id wins, which
 *   is the row the config editor would also address.
 * @param values - `{ key: scalar | scalar[] }` to set in that row's config.
 * @param name - the row's plugin name, needed only when the row must be appended.
 * @returns the new text (identical when nothing needed changing), or
 *   `undefined` when this file is not one this function can safely edit.
 */
export function patchRowConfig(text, id, values, name) {
  const source = String(text ?? '');
  const rowId = String(id ?? '');
  if (source === '' || rowId === '' || values === null || typeof values !== 'object') return undefined;
  if (!/^-(\s|$)/m.test(source)) return undefined;

  const eol = source.includes('\r\n') ? '\r\n' : '\n';
  const lines = source.split(/\r?\n/);
  const starts = [];
  lines.forEach((line, index) => {
    if (/^-(\s|$)/.test(line)) starts.push(index);
  });
  if (starts.length === 0) return undefined;
  const items = starts.map((start, index) => ({ start, end: index + 1 < starts.length ? starts[index + 1] : lines.length }));

  const idOf = (item) => {
    const inline = /^-[ \t]+id:[ \t]*(\S.*)$/.exec(lines[item.start]);
    if (inline !== null) return yamlBareValue(inline[1]);
    for (let i = item.start + 1; i < item.end; i += 1) {
      const match = /^[ \t]+id:[ \t]*(\S.*)$/.exec(lines[i]);
      if (match !== null) return yamlBareValue(match[1]);
    }
    return undefined;
  };
  const inserts = new Set();
  for (const item of items) {
    if (lines.slice(item.start, item.end).some((line) => /^[ \t]+insert:/.test(line))) inserts.add(item);
  }
  const matching = items.filter((item) => idOf(item) === rowId);
  // A row that only exists inside an `insert:` list is not ours to rewrite: a
  // top-level row with the same id would be a different row entirely.
  if (matching.some((item) => inserts.has(item))) return undefined;
  const target = matching[matching.length - 1];

  // A row that is not in this file yet is appended the way the platform editor
  // appends one. Without its plugin name there is nothing faithful to write, so
  // the caller falls back instead.
  if (target === undefined) {
    if (typeof name !== 'string' || name === '') return undefined;
    const pad = '  ';
    const additions = [`- id: ${yamlScalar(rowId)}`, `${pad}name: ${yamlScalar(name)}`, `${pad}config:`];
    for (const [key, value] of Object.entries(values)) {
      if (Array.isArray(value)) additions.push(`${pad}  ${key}:`, ...value.map((entry) => `${pad}    - ${yamlScalar(entry)}`));
      else additions.push(`${pad}  ${key}: ${yamlScalar(value)}`);
    }
    const appended = lines.slice();
    let insertAt = appended.length;
    while (insertAt > 0 && appended[insertAt - 1].trim() === '') insertAt -= 1;
    appended.splice(insertAt, 0, ...additions);
    return appended.join(eol);
  }

  const keyIndent = indentWidth(lines[target.start] ?? '') + 2;
  const configPad = ' '.repeat(keyIndent);
  const keyPad = ' '.repeat(keyIndent + 2);
  const valuePad = ' '.repeat(keyIndent + 4);

  let configIndex = -1;
  for (let i = target.start; i < target.end; i += 1) {
    const match = /^([ \t]+)config:[ \t]*(.*)$/.exec(lines[i]);
    if (match !== null && match[1].length === keyIndent) {
      configIndex = i;
      break;
    }
  }

  /** The lines one key and its value occupy, as this file already spells them. */
  const replacementFor = (key, value) => {
    if (Array.isArray(value)) {
      return [`${keyPad}${key}:`, ...value.map((entry) => `${valuePad}- ${yamlScalar(entry)}`)];
    }
    return [`${keyPad}${key}: ${yamlScalar(value)}`];
  };

  const next = lines.slice();

  if (configIndex < 0) {
    // No `config:` block yet: add one at the end of the row's own lines.
    const additions = [`${configPad}config:`];
    for (const [key, value] of Object.entries(values)) additions.push(...replacementFor(key, value));
    // The row ends at the next item, but the blank lines before it belong to the
    // file's spacing, not to this row: insert ahead of them so the trailing
    // newline stays where it was.
    let insertAt = target.end;
    while (insertAt > target.start && lines[insertAt - 1].trim() === '') insertAt -= 1;
    next.splice(insertAt, 0, ...additions);
    return next.join(eol);
  }

  const inline = /^([ \t]+)config:[ \t]*(.*)$/.exec(lines[configIndex])[2].trim();
  if (inline !== '' && inline !== '{}' && inline !== '~' && inline !== 'null') {
    // A flow-style config (or a `!!js` expression) is not something a line edit
    // can be trusted with.
    return undefined;
  }
  next[configIndex] = `${configPad}config:`;

  // The block ends at the row's next key (same indent as `config:`).
  let blockEnd = target.end;
  for (let i = configIndex + 1; i < target.end; i += 1) {
    if (lines[i].trim() === '') continue;
    if (indentWidth(lines[i]) <= keyIndent) {
      blockEnd = i;
      break;
    }
  }
  const block = lines.slice(configIndex + 1, blockEnd);
  const escape = (key) => key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patternFor = (key) => new RegExp(`^[ \\t]{${keyIndent + 2}}${escape(key)}\\s*:`);
  const remaining = new Map(Object.entries(values));
  const rewritten = [];
  for (let i = 0; i < block.length; i += 1) {
    const key = [...remaining.keys()].find((candidate) => patternFor(candidate).test(block[i]));
    if (key === undefined) {
      rewritten.push(block[i]);
      continue;
    }
    rewritten.push(...replacementFor(key, remaining.get(key)));
    remaining.delete(key);
    // Drop the lines that spelled the old value: anything deeper than the key,
    // or a `- ` item at the key's own indent.
    let stop = i + 1;
    while (stop < block.length) {
      const line = block[stop];
      const deeper = indentWidth(line) > keyIndent + 2;
      const sequenceAtKey = indentWidth(line) === keyIndent + 2 && line.trimStart().startsWith('-');
      if (!deeper && !sequenceAtKey) break;
      stop += 1;
    }
    i = stop - 1;
  }
  // Keys the row did not have yet go first, so the block reads in one order.
  const additions = [];
  for (const [key, value] of remaining) additions.push(...replacementFor(key, value));
  next.splice(configIndex + 1, block.length, ...additions, ...rewritten);

  const before = lines.filter((line) => /^-(\s|$)/.test(line)).length;
  const after = next.filter((line) => /^-(\s|$)/.test(line)).length;
  if (before !== after) return undefined;
  return next.join(eol);
}

// ── Link resolution ────────────────────────────────────────────────────────
//
// Every link and QR this plugin hands out is built on one resolved authority.
// The request's own `Host` is the wrong default: a pairing code generated from
// the desktop panel is generated at `127.0.0.1:3080`, and a phone cannot open
// that. The four sources below are tried in order, most authoritative first,
// and the answer carries how far it reaches so the panel can warn instead of
// printing a link that only works on this machine.

/** The authority inside one URL or bare host, or undefined when it cannot be one. */
function authorityFrom(value) {
  const raw = text(value);
  if (raw === undefined) return undefined;
  try {
    const url = new URL(raw.includes('://') ? raw : `http://${raw}`);
    if (url.host === '') return undefined;
    // A scheme-less value is a public name unless it names this machine's own
    // loopback or a private address, which are the spellings a LAN or desktop
    // URL actually uses.
    const scheme = raw.includes('://')
      ? url.protocol === 'https:'
        ? 'https'
        : 'http'
      : isLoopbackAuthority(url.host) || isPrivateAddress(url.hostname)
        ? 'http'
        : 'https';
    return { base: url.host, scheme };
  } catch {
    return undefined;
  }
}

/** The host part of one authority, without brackets or port. */
function hostOf(base) {
  const value = String(base ?? '').trim();
  if (value === '') return '';
  try {
    return new URL(value.includes('://') ? value : `http://${value}`).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return value;
  }
}

/** How far one authority reaches: this machine only, the local network, or the internet. */
function reachabilityOf(base) {
  if (isLoopbackAuthority(base)) return 'loopback-only';
  const host = hostOf(base);
  // `isPrivateAddress` covers RFC1918 and IPv6 unique-local; an IPv6 link-local
  // bind (`fe80::/10`) is just as much a local-network address, so it is called
  // one here too.
  return isPrivateAddress(host) || /^fe80:/i.test(host) ? 'lan' : 'public';
}

/** Bracket an IPv6 literal so it can carry a port. */
function withPort(host, port) {
  const value = String(host ?? '').trim();
  const literal = value.includes(':') && !value.startsWith('[') ? `[${value}]` : value;
  return `${literal}:${port}`;
}

/**
 * Resolve the authority every user-facing link is built from.
 *
 * The rule is one sentence: **the URL names the authority the plugin can serve
 * right now, and `reachable` describes exactly that authority.** A link that
 * names a host nothing answers on is not a link, and a verdict that disagrees
 * with the URL it was returned beside makes the panel's warning fire on a
 * perfectly good link — or stay silent on a useless one.
 *
 * Order, and why:
 *  1. the advertised public URL (`web-runtime.publicUrl`) or the configured
 *     tunnel hostname — but only while the tunnel is actually running, because
 *     that is when something serves that name;
 *  2. the LAN bind — a non-loopback listener address plus its port, `http://`;
 *  3. the request's own `Host` — being answered on that authority is itself the
 *     evidence that it serves, so this one is not gated on anything;
 *  4. loopback, which is honest about being reachable from this machine only.
 *
 * A configured public base that is not being served therefore does not appear
 * in the URL at all; its state is reported separately (`tunnel.running`,
 * `configuredPublicUrl()`), which is where "configured but down" belongs.
 *
 * @param input - `{ publicUrl, tunnelHost, bindHost, port, requestHost, requestScheme, tunnelRunning }`.
 * @returns `{ base, scheme, reachable }`, where `base` is a bare authority
 *   (`host` or `host:port`, bracketed for IPv6) and `reachable` is
 *   `'public' | 'lan' | 'loopback-only'`.
 */
export function resolveLinkBase(input = {}) {
  const { publicUrl, tunnelHost, bindHost, requestHost, requestScheme, tunnelRunning } = input;
  const port = Number.isFinite(Number(input.port)) && Number(input.port) > 0 ? Number(input.port) : 3080;

  const advertised = authorityFrom(publicUrl);
  if (advertised !== undefined && tunnelRunning === true) {
    return { ...advertised, reachable: reachabilityOf(advertised.base) };
  }

  const tunnel = text(tunnelHost);
  if (tunnel !== undefined && !/[/\s]/.test(tunnel) && tunnelRunning === true) {
    return { base: tunnel, scheme: 'https', reachable: reachabilityOf(tunnel) };
  }

  const bind = text(bindHost);
  if (bind !== undefined && modeFromBindHost(bind) === 'lan') {
    const base = withPort(bind, port);
    return { base, scheme: 'http', reachable: reachabilityOf(base) };
  }

  const fallback = text(requestHost) ?? (bind !== undefined ? withPort(bind, port) : withPort('127.0.0.1', port));
  return { base: fallback, scheme: requestScheme === 'https' ? 'https' : 'http', reachable: reachabilityOf(fallback) };
}


/**
 * Ask the platform's own fence what it thinks of one authority. The fence
 * answers 403 for an authority it refuses and 401 (or nothing) once the Host is
 * accepted but the caller is unauthenticated, which is exactly the distinction
 * the panel needs to explain a tunnel that loads but cannot call `/api`.
 * @returns `'trusted' | 'refused' | 'unknown'`.
 */
export function probeTrust(connection, authority) {
  if (connection === undefined || typeof connection.requestRejection !== 'function') return 'unknown';
  let status;
  try {
    status = connection.requestRejection({ method: 'GET', url: '/', headers: { host: String(authority) } });
  } catch {
    // A fence that cannot answer is not a fence that said yes.
    return 'unknown';
  }
  if (status === undefined) return 'trusted';
  if (status === 403) return 'refused';
  return 'trusted';
}

/** Build a QR payload for one URL, or `undefined` when it cannot be encoded. */
function qrFor(url) {
  try {
    const qr = encodeQr(url, { level: 'M' });
    return { size: qr.size, bits: qr.bits, version: qr.version };
  } catch {
    return undefined;
  }
}

/**
 * Host plugin body.
 * @param ctx - Host Cordis context.
 * @param rawConfig - the row's config, normalized here.
 */
function apply(ctx, rawConfig) {
  const config = normalizeConfig(rawConfig);
  /** Managed cloudflared child, when the panel started one. */
  let tunnel = null;

  const getConnection = () => ctx.get('connection');
  const getCredentials = () => ctx.get('credentials');
  const getConfigEditor = () => ctx.get('configEditor');
  const getSubprocess = () => ctx.get('subprocess');

  /** The listener's own facts, best effort. */
  function listenerFacts() {
    return {
      host: attempt(() => ctx.webServer.host),
      port: attempt(() => ctx.webServer.port),
      protocol: attempt(() => ctx.webServer.protocol),
      origin: attempt(() => ctx.webServer.getOrigin()),
      advertised: attempt(() => ctx.get('webApp')?.getAdvertisedUrl?.()),
    };
  }

  /** Add the process's launch token to an entry URL when the platform offers it. */
  function tokenized(base) {
    const connection = getConnection();
    const url = attempt(() => connection?.authenticatedUrl?.(base));
    return typeof url === 'string' && url !== '' ? url : base;
  }

  /** Entry URLs the phone can use, each with its trust verdict and QR. */
  function buildEntries() {
    const facts = listenerFacts();
    const port = Number.isFinite(facts.port) ? facts.port : 3080;
    const connection = getConnection();
    const entries = [];

    if (config.tunnelHost !== undefined) {
      const authority = config.tunnelHost;
      const base = `https://${authority}/`;
      const url = tokenized(base);
      entries.push({
        id: 'tunnel',
        kind: 'tunnel',
        label: 'Cloudflare tunnel',
        authority,
        base,
        url,
        trust: probeTrust(connection, authority),
        qr: qrFor(url),
      });
    }

    const bindHost = typeof facts.host === 'string' ? facts.host : undefined;
    const boundToLan = bindHost !== undefined && !isLoopbackAuthority(bindHost) && !WILDCARD_RE.test(bindHost);
    const lanAuthority = config.lanHost ?? (boundToLan ? `${bindHost}:${port}` : undefined);
    if (lanAuthority !== undefined) {
      const base = `http://${lanAuthority}/`;
      const url = tokenized(base);
      entries.push({
        id: 'lan',
        kind: 'lan',
        label: 'Local network',
        authority: lanAuthority,
        base,
        url,
        trust: probeTrust(connection, lanAuthority),
        qr: qrFor(url),
        bound: boundToLan || isLoopbackAuthority(lanAuthority),
      });
    }

    return entries;
  }

  // ── Mode ──────────────────────────────────────────────────────────────────
  //
  // `mode` is never stored: it is derived from the address the listener is
  // actually bound to. That way the switch cannot disagree with reality — if
  // the bind was changed by hand, or by the platform, the panel still says what
  // is true rather than what was last requested.

  /** The authority the LAN entry would use, when there is one. */
  function lanAuthority() {
    const facts = listenerFacts();
    const port = Number.isFinite(facts.port) ? facts.port : 3080;
    const bindHost = typeof facts.host === 'string' ? facts.host : undefined;
    const boundToLan = bindHost !== undefined && !isLoopbackAuthority(bindHost) && !WILDCARD_RE.test(bindHost);
    return config.lanHost ?? (boundToLan ? `${bindHost}:${port}` : undefined);
  }

  /** The host the listener is bound to, row first, live value as the fallback. */
  function configuredBindHost() {
    const fromRow = attempt(() => findEntry('webserver')?.options?.config?.host);
    const value = absentText(fromRow);
    if (value !== undefined) return value;
    const live = attempt(() => ctx.webServer.host);
    return absentText(live);
  }

  /**
   * The mode, the address book, the tunnel's verdict, and how far a link reaches.
   *
   * `mode` is what is configured; `auto` is what this machine would choose by
   * itself (a configured tunnel hostname means this instance is meant to be
   * published; otherwise a real LAN address means it is meant to be local).
   * The two differ exactly when the panel should say so.
   */
  function modeStatus(req) {
    const facts = listenerFacts();
    const addresses = localAddresses();
    const host = configuredBindHost();
    const mode = modeFromBindHost(host);
    return {
      mode,
      auto: config.tunnelHost !== undefined ? 'public' : addresses.length > 0 ? 'lan' : 'public',
      host: host ?? null,
      port: Number.isFinite(facts.port) ? facts.port : 3080,
      tunnelRunning: tunnel !== null && tunnel.exited !== true,
      publicUrl: config.publicUrl ?? (config.tunnelHost !== undefined ? `https://${config.tunnelHost}/` : null),
      lanHost: lanAuthority() ?? null,
      addresses: addresses.map((entry) => ({ address: entry.address, label: entry.interface ?? entry.address })),
      /** How far a link generated for this request reaches. */
      linksReachable: linkBase(req).reachable,
    };
  }

  /** The advertised public URL: the web-runtime row first, then our own field. */
  function configuredPublicUrl() {
    const fromRow = attempt(() => findEntry('web-runtime')?.options?.config?.publicUrl);
    return absentText(fromRow) ?? config.publicUrl;
  }

  /** The listener's port, with the shipped default as the fallback. */
  function listenerPort() {
    const facts = listenerFacts();
    return Number.isFinite(facts.port) ? facts.port : 3080;
  }

  /**
   * The authority this request's links should be built on.
   *
   * Gathered here and resolved by the pure {@link resolveLinkBase}, so the order
   * can be tested without a composition.
   */
  function linkBase(req) {
    return resolveLinkBase({
      publicUrl: configuredPublicUrl(),
      tunnelHost: config.tunnelHost,
      bindHost: configuredBindHost(),
      port: listenerPort(),
      requestHost: String(req?.headers?.host ?? ''),
      requestScheme: requestScheme(req),
      tunnelRunning: tunnel !== null && tunnel.exited !== true,
    });
  }

  // ── Activity view (the heartbeat's own record) ────────────────────────────
  //
  // Not an authorization list: this is the browser-side ping behind the
  // injected script, which is the only way a "recently connected" panel exists
  // at all, since the platform keeps no per-device state. It is a *view*.
  // Authorized credentials live in the `-v2` record below.

  /** Read the activity rows; an absent or malformed record reads as empty. */
  async function readDevices() {
    const credentials = getCredentials();
    if (credentials === undefined) return [];
    const record = await attempt(() => credentials.readRecord(DEVICE_RECORD_KEY));
    const payload = record?.payload;
    if (payload === null || typeof payload !== 'object' || !Array.isArray(payload.devices)) return [];
    return payload.devices.filter((d) => d !== null && typeof d === 'object' && typeof d.id === 'string');
  }

  /**
   * The one place a credential record is written.
   *
   * Every payload goes through `storablePayload` *here*, so no call site can
   * reintroduce a value the store cannot spell — which is what killed
   * `device-link` once (an `undefined` in a freshly built row) and would have
   * done it again for the next optional field. The guard runs before the store
   * sees anything, so a rejected payload never leaves a half-written record, and
   * the refusal reaches the caller as `remote-access/unstorable-payload` with the
   * field path in its message.
   *
   * Returning `undefined` from `mutate` means "nothing to do": the store skips
   * both validation and the write, which is also what keeps a record that already
   * holds an unspellable value from failing a no-op read-modify-write.
   *
   * @param key - the credential record key.
   * @param mutate - receives the record as the store holds it, returns the next
   *   *payload*, or undefined to leave the record untouched.
   */
  async function modifyRecordGuarded(key, mutate) {
    const credentials = getCredentials();
    if (credentials === undefined) throw new Error('the credentials service is unavailable in this composition');
    return credentials.modifyRecord(key, async (previous) => {
      const next = await mutate(previous);
      if (next === undefined) return undefined;
      let payload;
      try {
        payload = storablePayload(next, key);
      } catch (error) {
        throw refusal('remote-access/unstorable-payload', error instanceof Error ? error.message : String(error));
      }
      return { kind: 'grant', payload };
    });
  }

  /** Persist the activity rows under this plugin's own credential scope. */
  async function writeDevices(devices) {
    const kept = devices
      .slice()
      .sort((a, b) => Number(b.lastSeenAt ?? 0) - Number(a.lastSeenAt ?? 0))
      .slice(0, MAX_DEVICES);
    await modifyRecordGuarded(DEVICE_RECORD_KEY, async () => ({ version: 1, devices: kept }));
    return kept;
  }

  // ── Authorized-device record ──────────────────────────────────────────────
  //
  // One record for every credential this machine handed out, whichever door it
  // came through. The fingerprint is the only thing stored; the credential
  // itself was shown once, at the moment it was minted.

  /** Read the authorized-device rows; an absent or malformed record reads as empty. */
  async function readDeviceRows() {
    const credentials = getCredentials();
    if (credentials === undefined) return [];
    const record = await attempt(() => credentials.readRecord(DEVICES_V2_RECORD_KEY));
    return parseDeviceRows(record?.payload);
  }

  /**
   * Persist the authorized-device rows, newest first and capped.
   *
   * Entry links live in their own small bucket. They are the one row kind a
   * stranger can cause — every launch-token visit the platform accepts adds one
   * — so they must never be able to push a real paired device out of the list:
   * a flood of entry links that evicts the owner's phone is a lockout dressed up
   * as a rate limit.
   */
  async function writeDeviceRows(rows) {
    const newestFirst = (a, b) =>
      Number(Date.parse(String(b.createdAt ?? '')) || 0) - Number(Date.parse(String(a.createdAt ?? '')) || 0);
    const isEntryLink = (row) => row.temporary === true && row.source === 'entry-link';
    const entryLinks = rows.filter(isEntryLink).sort(newestFirst).slice(0, MAX_ENTRY_LINKS);
    const devices = rows.filter((row) => !isEntryLink(row)).sort(newestFirst).slice(0, MAX_DEVICES);
    const kept = [...entryLinks, ...devices].sort(newestFirst);
    await modifyRecordGuarded(DEVICES_V2_RECORD_KEY, async () => ({ version: 2, devices: kept }));
    return kept;
  }

  /**
   * Take one row out of the record and hand it back.
   *
   * The match-and-remove happens inside `modifyRecord`'s callback, against the
   * record's current value, so a one-time link cannot be redeemed twice by two
   * requests that read the same rows and both believe they were first.
   * @param predicate - called with each row; the first match is removed.
   * @returns the removed row, or undefined when nothing matched.
   */
  async function takeDeviceRow(predicate) {
    let taken;
    await modifyRecordGuarded(DEVICES_V2_RECORD_KEY, async (previous) => {
      const rows = parseDeviceRows(previous?.payload);
      const index = rows.findIndex(predicate);
      // Nothing matched: leave the record alone rather than handing the store
      // back the very value it may have refused to spell.
      if (index < 0) return undefined;
      taken = rows[index];
      rows.splice(index, 1);
      return { version: 2, devices: rows };
    });
    return taken;
  }

  /**
   * Remove one row and everything minted from it.
   *
   * A one-time link is a way in *as* the device it was minted for, so it cannot
   * outlive that device: leaving a child behind would let the panel say
   * "revoked" while a link it handed out still opens the door. Children are
   * found by `parentId`, transitively, so a chain cannot keep itself alive.
   *
   * @returns `{ removed, ids }`; `removed: 0` means the id was not there.
   */
  async function removeDeviceRows(id) {
    const rows = await readDeviceRows();
    const doomed = new Set([id]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const row of rows) {
        if (doomed.has(row.id)) continue;
        const parentId = absentText(row.parentId);
        if (parentId !== undefined && doomed.has(parentId)) {
          doomed.add(row.id);
          grew = true;
        }
      }
    }
    const kept = rows.filter((row) => !doomed.has(row.id));
    if (kept.length === rows.length) return { removed: 0, ids: [] };
    await writeDeviceRows(kept);
    return { removed: rows.length - kept.length, ids: rows.filter((row) => doomed.has(row.id)).map((row) => row.id) };
  }

  // ── Access keys ───────────────────────────────────────────────────────────

  /** Read the access-key rows; an absent or malformed record reads as empty. */
  async function readKeyRows() {
    const credentials = getCredentials();
    if (credentials === undefined) return [];
    const record = await attempt(() => credentials.readRecord(ACCESS_KEYS_RECORD_KEY));
    const payload = record?.payload;
    if (payload === null || typeof payload !== 'object' || !Array.isArray(payload.keys)) return [];
    return payload.keys.filter(
      (row) => row !== null && typeof row === 'object' && typeof row.id === 'string' && typeof row.hash === 'string',
    );
  }

  /** Persist the access-key rows. */
  async function writeKeyRows(keys) {
    await modifyRecordGuarded(ACCESS_KEYS_RECORD_KEY, async () => ({ version: 1, keys: keys.slice(0, MAX_KEYS) }));
    return keys.slice(0, MAX_KEYS);
  }

  /** Drop activity rows that have not been seen inside the retention window. */
  function prune(devices) {
    return pruneDevices(devices, config.deviceRetentionDays);
  }

  // ── Tunnel child process ───────────────────────────────────────────────────

  /** Last collected lines of the child's output, for the panel. */
  function tunnelOutput() {
    if (tunnel === null) return { lines: [], url: undefined, lossy: false };
    const read = attempt(() => tunnel.stdout?.readFrom(tunnel.stdoutOffset ?? 0));
    if (read !== undefined && typeof read.text === 'string' && read.text !== '') {
      tunnel.stdoutOffset = read.nextOffset;
      const lines = read.text.split(/\r?\n/).filter((l) => l.trim() !== '');
      tunnel.lines = [...(tunnel.lines ?? []), ...lines].slice(-40);
      const match = read.text.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
      if (match !== null) tunnel.url = match[0];
      tunnel.lossy = read.lossy === true;
    }
    const err = attempt(() => tunnel.stderr?.readFrom(tunnel.stderrOffset ?? 0));
    if (err !== undefined && typeof err.text === 'string' && err.text !== '') {
      tunnel.stderrOffset = err.nextOffset;
      const lines = err.text.split(/\r?\n/).filter((l) => l.trim() !== '');
      tunnel.lines = [...(tunnel.lines ?? []), ...lines].slice(-40);
    }
    return { lines: tunnel.lines ?? [], url: tunnel.url, lossy: tunnel.lossy === true };
  }

  /**
   * Describe the managed child for the panel.
   *
   * `configured` must cover every way a tunnel can be ready — a stored
   * connector token (API setup), the written certificate config (guided login),
   * or the row's own command — otherwise the panel disables Start on a machine
   * that is in fact fully set up.
   * @param connectorStored - whether a connector token is in the credential store.
   */
  function tunnelStatus(connectorStored = false) {
    const output = tunnelOutput();
    const certMode = existsSync(tunnelConfigPath());
    const modes = [];
    if (connectorStored) modes.push('token');
    if (certMode) modes.push('certificate');
    if (config.cloudflared !== undefined) modes.push('args');
    const command =
      modes.length === 0
        ? undefined
        : modes[0] === 'token'
          ? 'cloudflared tunnel run --token <stored>'
          : modes[0] === 'certificate'
            ? `cloudflared tunnel --config ${tunnelConfigPath()} run ${config.tunnelName}`
            : [config.cloudflared.command, ...config.cloudflared.args].join(' ');
    return {
      configured: modes.length > 0,
      modes,
      mode: tunnel?.mode ?? modes[0],
      command,
      running: tunnel !== null && tunnel.exited !== true,
      startedAt: tunnel?.startedAt,
      exit: tunnel?.exit,
      url: output.url,
      lines: output.lines.slice(-20),
      lossy: output.lossy,
      available: getSubprocess() !== undefined,
    };
  }

  /**
   * Start cloudflared as a managed child.
   *
   * With a connector token from the automatic setup, the command is
   * `cloudflared tunnel run --token <token>` — no `cert.pem`, no browser login.
   * Otherwise the row's own `cloudflared.args` are used, which is the path for a
   * tunnel you manage yourself.
   */
  async function tunnelStart() {
    if (tunnel !== null && tunnel.exited !== true) return { started: false, reason: 'already-running' };
    const subprocess = getSubprocess();
    if (subprocess === undefined) throw new Error('the subprocess service is unavailable in this composition');
    const connector = await readSecret(CF_TUNNEL_TOKEN_KEY);
    const command = config.cloudflared?.command ?? 'cloudflared';
    let args;
    let mode;
    if (connector !== undefined) {
      args = tunnelTokenArgs(connector);
      mode = 'token';
    } else if (existsSync(tunnelConfigPath())) {
      args = tunnelRunArgs({ configPath: tunnelConfigPath(), tunnelName: config.tunnelName });
      mode = 'certificate';
    } else if (config.cloudflared !== undefined) {
      args = config.cloudflared.args;
      mode = 'args';
    } else {
      throw new Error(
        'no tunnel to start: run the automatic Cloudflare setup, complete the guided cloudflared login, or configure config.cloudflared with your own command',
      );
    }
    const resolved = await subprocess.resolveExecutable(command);
    const handle = subprocess.spawn({
      argv: [resolved, ...args],
      cwd: process.cwd(),
      stdio: {
        stdin: 'ignore',
        stdout: { maxBytes: 64 * 1024, spill: { maxBytes: 512 * 1024 } },
        stderr: { maxBytes: 64 * 1024, spill: { maxBytes: 512 * 1024 } },
      },
      graceMs: 5000,
    });
    tunnel = {
      handle,
      mode,
      startedAt: Date.now(),
      stdout: handle.collected?.stdout,
      stderr: handle.collected?.stderr,
      stdoutOffset: 0,
      stderrOffset: 0,
      lines: [],
      exited: false,
      exit: undefined,
    };
    Promise.resolve(handle.done).then(
      (outcome) => {
        if (tunnel?.handle === handle) {
          tunnel.exited = true;
          tunnel.exit = outcome;
        }
      },
      (error) => {
        if (tunnel?.handle === handle) {
          tunnel.exited = true;
          tunnel.exit = { error: error instanceof Error ? error.message : String(error) };
        }
      },
    );
    return { started: true, resolved, mode };
  }

  /** Stop the managed child, if any. */
  function tunnelStop() {
    if (tunnel === null) return { stopped: false, reason: 'not-running' };
    attempt(() => tunnel.handle?.terminate?.());
    tunnel.exited = true;
    tunnel = null;
    return { stopped: true };
  }

  // ── Platform session revocation ────────────────────────────────────────────

  /**
   * The platform holds its cookie-signing secret in memory and keeps only the
   * record on disk. Deleting the record therefore invalidates every existing
   * cookie at the next start, not immediately — the panel says so plainly.
   */
  async function revokePlatformSessions() {
    const credentials = getCredentials();
    if (credentials === undefined) throw new Error('the credentials service is unavailable in this composition');
    const record = await attempt(() => credentials.readRecord(PLATFORM_SESSION_KEY));
    await credentials.deleteRecord(PLATFORM_SESSION_KEY);
    return { deleted: record !== undefined, restartRequired: true };
  }

  // ── Configuration writes ───────────────────────────────────────────────────

  /** The live configuration rows the panel may write, by patch id. */
  function findEntry(id) {
    const editor = getConfigEditor();
    if (editor === undefined) return undefined;
    const rows = editor.entries();
    return rows.find((entry) => entry?.options?.id === id);
  }

  /** The platform's configured browser-cookie lifetime, in days. */
  function cookieMaxAgeDays() {
    const editor = getConfigEditor();
    const rows = attempt(() => editor?.configuration()) ?? [];
    const row = rows.find((r) => r?.entry?.options?.id === 'connection');
    const value = row?.entry?.options?.config?.cookieMaxAgeDays;
    return Number.isFinite(Number(value)) ? Number(value) : 30;
  }

  /**
   * The raw config this row already has in the user's own patch layer, if any.
   *
   * `edit`'s callback receives the *evaluated* config, which would freeze
   * `!!js` expressions (a row written with `port: !!js ctx.webStartup.port`
   * would come back as the literal number). Extending the raw layer value
   * instead preserves whatever expressions the user wrote; the Config Editor
   * serializes `{ __jsExpr }` maps back into `!!js` scalars on write.
   * @returns the raw override, or `{}` when this row has none.
   */
  function rawOverride(id) {
    const editor = getConfigEditor();
    const rows = attempt(() => editor?.configuration()) ?? [];
    const row = rows.find((r) => r?.entry?.options?.id === id);
    const override = row?.override;
    return override !== null && typeof override === 'object' ? override : {};
  }

  /** Base config for a write: the user's raw row when present, else the live one. */
  function baseConfig(id, current) {
    const raw = rawOverride(id);
    return Object.keys(raw).length > 0 ? { ...raw } : { ...current };
  }

  /**
   * Write one file atomically: a temporary neighbour, then a rename over it.
   *
   * The profile patch is the file the whole harness boots from, so it is never
   * written in place — a crash mid-write would cost the user their profile.
   */
  async function writeFileAtomic(path, contents) {
    const temporary = `${path}.${process.pid}.tmp`;
    await writeFile(temporary, contents, { mode: 0o600 });
    try {
      await rename(temporary, path);
    } catch (error) {
      await attemptAsync(() => unlink(temporary));
      throw error;
    }
  }

  /**
   * Set several rows' config keys in one atomic patch write.
   *
   * One write matters: a write is what makes the Loader reconcile, and a
   * reconcile is what rebinds a listener. Doing a LAN switch as two writes would
   * rebind twice, and every rebind is a window in which the old socket may still
   * hold the port.
   *
   * @param edits - `[{ id, values, mergeKeys }]`, applied to one text.
   * @returns `{ changed, path, values }` keyed by row id, or `undefined` when
   *   the file cannot be edited this way and the caller must fall back.
   */
  async function writeRowsConfigDirect(edits) {
    const path = attempt(() => getConfigEditor()?.documentPath);
    if (typeof path !== 'string' || path === '') return undefined;
    const before = await attemptAsync(() => readFile(path, 'utf8'));
    if (typeof before !== 'string') return undefined;
    let after = before;
    const values = {};
    for (const edit of edits) {
      const effective = { ...edit.values };
      for (const key of edit.mergeKeys ?? []) {
        const existing = readRowConfigList(after, edit.id, key).values;
        const given = Array.isArray(effective[key]) ? effective[key] : [effective[key]].filter((entry) => entry !== undefined);
        effective[key] = [...new Set([...existing, ...given].filter(Boolean))];
      }
      const name = attempt(() => findEntry(edit.id)?.options?.name);
      const next = patchRowConfig(after, edit.id, effective, name);
      if (next === undefined) return undefined;
      after = next;
      values[edit.id] = effective;
    }
    if (after === before) return { changed: false, path, values };
    await writeFileAtomic(path, after);
    return { changed: true, path, values };
  }

  /**
   * Set one row's config keys straight into the profile patch file.
   *
   * @returns `{ changed, path, values }` when the file was written (or already
   *   said the same thing), or `undefined` when this composition cannot be
   *   written this way and the caller should use the platform editor instead.
   */
  async function writeRowConfigDirect(id, values, mergeKeys = []) {
    const result = await writeRowsConfigDirect([{ id, values, mergeKeys }]);
    if (result === undefined) return undefined;
    return { changed: result.changed, path: result.path, values: result.values[id] };
  }

  /**
   * Write the tunnel authority into the shipped `connection` row's
   * `trustedHosts`.
   *
   * The list is *merged*, never rebuilt: whatever the row already trusted, and
   * whatever `--trusted-host` supplied on the command line, survives. Dropping
   * an entry here would silently lock a working authority out of the fence.
   */
  async function writeTrustedHosts(authority) {
    const fromCli = attempt(() => ctx.get('webStartup')?.trustedHosts) ?? [];
    const fromRow = attempt(() => findEntry('connection')?.options?.config?.trustedHosts) ?? [];
    const merged = [
      ...new Set([...(Array.isArray(fromCli) ? fromCli : []), ...(Array.isArray(fromRow) ? fromRow : []), authority].filter(Boolean)),
    ];
    const direct = await writeRowConfigDirect('connection', { trustedHosts: merged }, ['trustedHosts']);
    if (direct !== undefined) {
      return { trustedHosts: direct.values.trustedHosts, trust: probeTrust(getConnection(), authority), wrote: direct.changed };
    }
    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry('connection');
    if (entry === undefined) throw new Error('the profile has no "connection" row to write');
    await editor.edit(entry, (current) => {
      const live = Array.isArray(current?.trustedHosts) ? current.trustedHosts : [];
      const next = [...new Set([...merged, ...live].filter(Boolean))];
      return { ...baseConfig('connection', current), trustedHosts: next };
    });
    return { trustedHosts: merged, trust: probeTrust(getConnection(), authority), wrote: true };
  }

  /**
   * Bind the listener to one concrete local interface.
   *
   * Only `host` is rewritten: the shipped `webserver` row also carries `port`,
   * `tls` and the compression settings, and a `!!js` expression there must
   * survive untouched, which is exactly what a line-level edit guarantees.
   * @returns `{ host, wrote }`, where `wrote: false` means it already said so.
   */
  async function writeLanHost(host) {
    const literal = validBindAddress(host);
    if (literal === undefined) {
      throw new Error('a bind address must be one concrete IPv4 or IPv6 literal; wildcards are refused by the platform');
    }
    const direct = await writeRowConfigDirect('webserver', { host: literal });
    if (direct !== undefined) return { host: literal, wrote: direct.changed };
    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry('webserver');
    if (entry === undefined) throw new Error('the profile has no "webserver" row to write');
    await editor.edit(entry, (current) => ({ ...baseConfig('webserver', current), host: literal }));
    return { host: literal, wrote: true };
  }

  /**
   * The answer one mode switch gives.
   *
   * Deliberately not "restartRequired: true and nothing else": the Loader
   * applies a bind change as soon as the file changes, so the honest answer is
   * that it applies now, and that this very response may not make it back.
   * `appliesImmediately: false` means the write changed nothing.
   */
  function modeAnswer(written, mode, changed = written.wrote === true) {
    return {
      mode,
      host: written.host,
      restartRequired: true,
      appliesImmediately: changed === true,
      rebindMayDropThisPage: changed === true,
    };
  }

  /** Advertise the tunnel root as the application URL. */
  async function writePublicUrl(url) {
    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry('web-runtime');
    if (entry === undefined) throw new Error('the profile has no "web-runtime" row to write');
    await editor.edit(entry, (current) => ({ ...baseConfig('web-runtime', current), publicUrl: String(url) }));
    return { publicUrl: String(url) };
  }

  /**
   * Drop the advertised URL again, so the instance goes back to advertising its
   * own listener origin (`http://127.0.0.1:3080`) instead of the tunnel
   * hostname. The row config is replaced wholesale, so omitting the key removes
   * it; the raw `!!js` overrides are preserved by `baseConfig`.
   */
  async function clearPublicUrl() {
    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry('web-runtime');
    if (entry === undefined) throw new Error('the profile has no "web-runtime" row to write');
    await editor.edit(entry, (current) => {
      const next = { ...baseConfig('web-runtime', current) };
      delete next.publicUrl;
      return next;
    });
    return { cleared: true };
  }

  // ── Automatic Cloudflare setup ────────────────────────────────────────────
  //
  // Deliberately does NOT write this plugin's own row: that write reloads this
  // fiber, and a reload disposes the managed tunnel child. The panel instead
  // saves the row config (tunnelHost and friends) and starts the tunnel as two
  // further calls, each landing on the reloaded fiber.

  const cloudflare = createCloudflareClient();

  /** Read one stored secret from the platform credential store. */
  async function readSecret(key) {
    const credentials = getCredentials();
    if (credentials === undefined) return undefined;
    const resolved = await attemptAsync(() => credentials.resolve(key));
    return typeof resolved?.value === 'string' && resolved.value !== '' ? resolved.value : undefined;
  }

  /**
   * Store one secret; it never appears in a response.
   *
   * The credentials service accepts any ref here and validates it against
   * `SECRET_REF_RE` only when it next parses the credentials document — which
   * turns a bad name into a *startup failure* rather than a call-site error.
   * That is how `dsh-remote-access/unlock-secret` once bricked a start, so the
   * name is checked before it can be written.
   */
  async function writeSecret(key, value) {
    if (!SECRET_REF_RE.test(String(key))) {
      throw new Error(`credential ref ${JSON.stringify(String(key))} must match ${String(SECRET_REF_RE)}`);
    }
    const credentials = getCredentials();
    if (credentials === undefined) throw new Error('the credentials service is unavailable in this composition');
    await credentials.set(key, String(value));
  }

  /** Remove one stored secret. */
  async function clearSecret(key) {
    const credentials = getCredentials();
    if (credentials === undefined) return;
    await attemptAsync(() => credentials.unset(key));
  }

  /** The local origin cloudflared must dial, matching the listener's own bind. */
  function localService() {
    const facts = listenerFacts();
    const port = Number.isFinite(facts.port) ? facts.port : 3080;
    const host = typeof facts.host === 'string' && facts.host !== '' ? facts.host : '127.0.0.1';
    const literal = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    return `http://${literal}:${port}`;
  }

  /**
   * The whole automatic setup, one log line per step: verify the token, find the
   * zone, create or reuse a remotely-managed tunnel, point its ingress at the
   * local listener, publish the proxied CNAME, read the connector token, store
   * it, and add the authority to the platform's trust fence.
   */
  async function cloudflareConnect(input) {
    const steps = [];
    const record = (step, ok, detail) => {
      steps.push({ step, ok, detail });
      return ok;
    };
    const supplied = text(input?.token);
    const token = supplied ?? (await readSecret(CF_API_TOKEN_KEY));
    if (token === undefined) {
      record('token', false, 'no API token is stored yet');
      return { ok: false, steps };
    }
    if (supplied !== undefined) {
      await writeSecret(CF_API_TOKEN_KEY, token);
      record('token', true, 'API token stored in the platform credential store');
    }

    const verify = await cloudflare.verifyToken(token);
    if (!verify.ok) {
      record('verify', false, verify.error);
      return { ok: false, steps };
    }
    record('verify', true, `token status: ${verify.status ?? 'active'}`);

    const hostname = validHostname(input?.hostname) ?? config.tunnelHost;
    if (hostname === undefined) {
      record('hostname', false, 'a hostname such as dsh.example.com is required');
      return { ok: false, steps };
    }
    const zone = await cloudflare.findZone(token, hostname);
    if (!zone.ok) {
      record('zone', false, zone.error);
      return { ok: false, steps };
    }
    record('zone', true, `zone ${zone.result.name} (account ${zone.result.accountName ?? zone.result.accountId})`);

    const name = text(input?.tunnelName) ?? config.tunnelName;
    const found = await cloudflare.findTunnel(token, zone.result.accountId, name);
    if (!found.ok) {
      record('tunnel', false, found.error);
      return { ok: false, steps };
    }
    let tunnelId = found.result?.id;
    if (tunnelId === undefined) {
      const created = await cloudflare.createTunnel(token, zone.result.accountId, name);
      if (!created.ok) {
        record('tunnel', false, created.error);
        return { ok: false, steps };
      }
      tunnelId = created.result.id;
      record('tunnel', true, `created tunnel ${name} (${tunnelId})`);
    } else {
      record('tunnel', true, `reusing tunnel ${name} (${tunnelId})`);
    }

    const service = localService();
    const ingress = await cloudflare.setIngress(token, zone.result.accountId, tunnelId, hostname, service);
    if (!ingress.ok) {
      record('ingress', false, ingress.error);
      return { ok: false, steps };
    }
    record('ingress', true, `${hostname} → ${service}`);

    const dns = await cloudflare.upsertDnsRecord(token, zone.result.id, zone.result.name, hostname, tunnelId);
    if (!dns.ok) {
      record('dns', false, dns.error);
      return { ok: false, steps };
    }
    record('dns', true, dns.result.created ? 'created the proxied CNAME' : 'updated the existing CNAME');

    const connector = await cloudflare.tunnelToken(token, zone.result.accountId, tunnelId);
    if (!connector.ok || typeof connector.result !== 'string' || connector.result === '') {
      record('connector-token', false, connector.error ?? 'Cloudflare returned no connector token');
      return { ok: false, steps };
    }
    await writeSecret(CF_TUNNEL_TOKEN_KEY, connector.result);
    record('connector-token', true, 'connector token stored in the platform credential store');

    const trust = await writeTrustedHosts(hostname);
    record('trust', true, `trustedHosts now accepts ${hostname} (${trust.trust})`);

    return {
      ok: true,
      steps,
      hostname,
      tunnelId,
      tunnelName: name,
      service,
      zone: zone.result.name,
      accountId: zone.result.accountId,
    };
  }

  /** Create the Access application for one hostname, and report the login methods. */
  async function cloudflareAccess(input) {
    const steps = [];
    const record = (step, ok, detail) => {
      steps.push({ step, ok, detail });
      return ok;
    };
    const token = await readSecret(CF_API_TOKEN_KEY);
    if (token === undefined) {
      record('token', false, 'no API token is stored yet');
      return { ok: false, steps };
    }
    const hostname = validHostname(input?.hostname) ?? config.tunnelHost;
    const email = text(input?.email) ?? config.accessEmail;
    if (hostname === undefined) {
      record('hostname', false, 'a hostname is required');
      return { ok: false, steps };
    }
    const zone = await cloudflare.findZone(token, hostname);
    if (!zone.ok) {
      record('zone', false, zone.error);
      return { ok: false, steps };
    }
    const providers = await cloudflare.listIdentityProviders(token, zone.result.accountId);
    if (providers.ok) {
      const oneTimePin = providers.result.some((idp) => /one-?time/i.test(idp.type ?? '') || /one-?time/i.test(idp.name ?? ''));
      record(
        'login-methods',
        providers.result.length > 0,
        providers.result.length === 0
          ? 'the Zero Trust organization has no login method yet — enable One-time PIN in the Cloudflare dashboard first'
          : `${providers.result.length} login method(s)${oneTimePin ? ', including One-time PIN' : ''}`,
      );
    }
    if (email === undefined) {
      record('policy', false, 'an email address is required for the Access policy');
      return { ok: false, steps, hostname };
    }
    const existing = await cloudflare.findAccessApp(token, zone.result.accountId, hostname);
    if (!existing.ok) {
      record('access-app', false, existing.error);
      return { ok: false, steps, hostname };
    }
    if (existing.result !== undefined) {
      record('access-app', true, `an Access application already covers ${hostname}`);
      return { ok: true, steps, hostname, appId: existing.result.id, existing: true };
    }
    const body = accessAppBody({ hostname, email });
    const created = await cloudflare.createAccessApp(token, zone.result.accountId, body);
    if (!created.ok) {
      record('access-app', false, created.error);
      return { ok: false, steps, hostname };
    }
    record('access-app', true, `created an Access application for ${hostname}, allowing ${email}, session 1 month`);
    return { ok: true, steps, hostname, appId: created.result.id };
  }

  /** Remove what this plugin created in Cloudflare. */
  async function cloudflareTeardown() {
    const steps = [];
    const record = (step, ok, detail) => {
      steps.push({ step, ok, detail });
      return ok;
    };
    const token = await readSecret(CF_API_TOKEN_KEY);
    const hostname = config.tunnelHost;
    if (token !== undefined && hostname !== undefined) {
      const zone = await cloudflare.findZone(token, hostname);
      if (zone.ok) {
        const dns = await cloudflare.deleteDnsRecord(token, zone.result.id, hostname);
        record('dns', dns.ok, dns.ok ? `removed ${dns.result.removed} record(s)` : dns.error);
        const found = await cloudflare.findTunnel(token, zone.result.accountId, config.tunnelName);
        if (found.ok && found.result?.id !== undefined) {
          const removed = await cloudflare.deleteTunnel(token, zone.result.accountId, found.result.id);
          record('tunnel', removed.ok, removed.ok ? `deleted tunnel ${config.tunnelName}` : removed.error);
        } else {
          record('tunnel', found.ok, found.ok ? 'no tunnel of that name exists' : found.error);
        }
      } else {
        record('zone', false, zone.error);
      }
    } else {
      record('token', token !== undefined, token === undefined ? 'no API token is stored' : 'no hostname is configured');
    }
    await clearSecret(CF_TUNNEL_TOKEN_KEY);
    record('secrets', true, 'the stored connector token was removed');
    return { ok: steps.every((step) => step.ok), steps };
  }

  // ── cloudflared environment, guided login, certificate-based setup ────────
  //
  // The API-token path above needs no browser. This is the other path the CLI
  // offers: `cloudflared tunnel login` writes cert.pem, then `tunnel create`,
  // `tunnel route dns` and a local config.yml publish the hostname.

  /** Cached `cloudflared --version` per resolved path. */
  const versionCache = new Map();
  /** The `cloudflared tunnel login` child while it waits for authorization. */
  let loginChild = null;

  /** Spawn one short-lived cloudflared command and collect its output. */
  async function runCloudflared(executable, args, timeoutMs = 20000) {
    const subprocess = getSubprocess();
    if (subprocess === undefined) return { exitCode: null, output: '', error: 'the subprocess service is unavailable' };
    let handle;
    try {
      handle = subprocess.spawn({
        argv: [executable, ...args],
        cwd: process.cwd(),
        stdio: {
          stdin: 'ignore',
          stdout: { maxBytes: 256 * 1024 },
          stderr: { maxBytes: 256 * 1024 },
        },
        graceMs: 4000,
      });
    } catch (error) {
      return { exitCode: null, output: '', error: error instanceof Error ? error.message : String(error) };
    }
    const timeout = new Promise((resolve) => setTimeout(resolve, timeoutMs));
    const outcome = await Promise.race([
      Promise.resolve(handle.done).catch((error) => ({ error: error instanceof Error ? error.message : String(error) })),
      timeout,
    ]);
    const read = (reader) => {
      const chunk = attempt(() => reader?.readFrom(0));
      return typeof chunk?.text === 'string' ? chunk.text : '';
    };
    const output = `${read(handle.collected?.stdout)}${read(handle.collected?.stderr)}`;
    if (outcome === undefined) attempt(() => handle.terminate?.());
    return {
      exitCode: typeof outcome?.exitCode === 'number' ? outcome.exitCode : null,
      output,
      timedOut: outcome === undefined,
    };
  }

  /** Resolve cloudflared, and read its version once per binary. */
  async function cloudflaredInfo() {
    const subprocess = getSubprocess();
    const command = config.cloudflared?.command ?? 'cloudflared';
    if (subprocess === undefined) {
      return { found: false, command, reason: 'the subprocess service is unavailable in this composition' };
    }
    let resolved;
    try {
      resolved = await subprocess.resolveExecutable(command);
    } catch (error) {
      return { found: false, command, reason: error instanceof Error ? error.message : String(error) };
    }
    let version = versionCache.get(resolved);
    if (version === undefined) {
      const run = await runCloudflared(resolved, ['--version'], 8000);
      version = (run.output.match(/cloudflared version ([0-9][^\s]*)/i)?.[1] ?? run.output.trim().split('\n')[0] ?? '').slice(0, 40);
      versionCache.set(resolved, version);
    }
    return { found: true, command, resolved, version };
  }

  /** Current state of the login child: authorization URL, exit, certificate. */
  function loginStatus() {
    if (loginChild === null) {
      return { running: false, url: undefined, exit: undefined, certPresent: existsSync(certPemPath()), output: [] };
    }
    const drain = (reader, offsetKey) => {
      const chunk = attempt(() => reader?.readFrom(loginChild[offsetKey] ?? 0));
      if (typeof chunk?.text === 'string' && chunk.text !== '') {
        loginChild[offsetKey] = chunk.nextOffset;
        loginChild.lines = [...(loginChild.lines ?? []), ...chunk.text.split(/\r?\n/).filter((line) => line.trim() !== '')].slice(-40);
      }
    };
    drain(loginChild.stdout, 'stdoutOffset');
    drain(loginChild.stderr, 'stderrOffset');
    const lines = loginChild.lines ?? [];
    return {
      running: loginChild.exited !== true,
      url: parseLoginUrl(lines.join('\n')),
      exit: loginChild.exit,
      certPresent: existsSync(certPemPath()),
      output: lines.slice(-12),
    };
  }

  /** Start `cloudflared tunnel login` and hand back the authorization URL. */
  async function loginStart() {
    const info = await cloudflaredInfo();
    if (!info.found) {
      throw new Error(
        `cloudflared was not found (${info.reason ?? 'not on PATH'}). Install it first: ${installHint().command}`,
      );
    }
    if (loginChild !== null && loginChild.exited !== true) return loginStatus();
    const handle = getSubprocess().spawn({
      argv: [info.resolved, 'tunnel', 'login'],
      cwd: process.cwd(),
      stdio: {
        stdin: 'ignore',
        stdout: { maxBytes: 64 * 1024 },
        stderr: { maxBytes: 64 * 1024 },
      },
      graceMs: 4000,
    });
    loginChild = {
      handle,
      startedAt: Date.now(),
      stdout: handle.collected?.stdout,
      stderr: handle.collected?.stderr,
      stdoutOffset: 0,
      stderrOffset: 0,
      lines: [],
      exited: false,
      exit: undefined,
    };
    Promise.resolve(handle.done).then(
      (outcome) => {
        if (loginChild?.handle === handle) {
          loginChild.exited = true;
          loginChild.exit = outcome;
        }
      },
      (error) => {
        if (loginChild?.handle === handle) {
          loginChild.exited = true;
          loginChild.exit = { error: error instanceof Error ? error.message : String(error) };
        }
      },
    );
    // Give the CLI a moment to print the authorization URL before answering.
    await new Promise((resolve) => setTimeout(resolve, 1200));
    return loginStatus();
  }

  /** Cancel a pending login. */
  function loginCancel() {
    if (loginChild === null) return { cancelled: false };
    attempt(() => loginChild.handle?.terminate?.());
    loginChild = null;
    return { cancelled: true };
  }

  /**
   * Whether Cloudflare Access covers the configured hostname.
   *
   * Read-only and best effort: the panel renders an edge-auth status line from
   * this, and a missing or refused block simply means "not enabled" there. It
   * never throws — a machine with no token, no hostname, no zone or a token
   * without the Access scope all come back as the same empty block plus a short
   * reason, which is what the panel shows behind its own "未启用" default.
   */
  async function accessState() {
    const empty = { enabled: false, configured: false, apps: [] };
    try {
      const token = await readSecret(CF_API_TOKEN_KEY);
      if (token === undefined) return { access: empty, accessError: 'no Cloudflare API token is stored' };
      const hostname = config.tunnelHost;
      if (hostname === undefined) return { access: empty, accessError: 'no tunnel hostname is configured' };
      const zone = await cloudflare.findZone(token, hostname);
      if (!zone.ok) return { access: empty, accessError: zone.error };
      const found = await cloudflare.findAccessApp(token, zone.result.accountId, hostname);
      if (!found.ok) {
        // The usual cause is a token minted without the Access scope, which the
        // API reports as an authorization error on the account's app list.
        return { access: empty, accessError: found.error };
      }
      const app = found.result;
      if (app === undefined) return { access: { enabled: false, configured: true, apps: [] } };
      return {
        access: {
          enabled: true,
          configured: true,
          apps: [{ id: app.id, name: app.name, domain: app.domain, sessionDuration: app.session_duration }],
        },
      };
    } catch (error) {
      return { access: empty, accessError: error instanceof Error ? error.message : String(error) };
    }
  }

  /** Everything the panel's environment checklist needs. */
  async function cloudflareEnv() {
    const info = await cloudflaredInfo();
    const cert = certPemPath();
    const configPath = tunnelConfigPath();
    const certPresent = existsSync(cert);
    const apiTokenStored = (await readSecret(CF_API_TOKEN_KEY)) !== undefined;
    const connectorTokenStored = (await readSecret(CF_TUNNEL_TOKEN_KEY)) !== undefined;
    return {
      cloudflared: info,
      cert: { path: cert, present: certPresent },
      configFile: { path: configPath, present: existsSync(configPath) },
      apiTokenStored,
      connectorTokenStored,
      hostname: config.tunnelHost,
      tunnelName: config.tunnelName,
      login: loginStatus(),
      install: installHint(),
      releases: CLOUDFLARED_RELEASES,
      service: localService(),
      // Read-only Access state, so the panel can say whether the edge itself
      // authenticates before the platform does.
      ...(await accessState()),
      summary: environmentSummary({
        cloudflaredFound: info.found,
        certPresent,
        apiTokenStored,
        hostname: config.tunnelHost,
      }),
    };
  }

  /**
   * The certificate-based setup: `tunnel create`, `tunnel route dns`, a local
   * config.yml, and the platform trust entry. This is the path that follows
   * `cloudflared tunnel login`, for users who prefer the browser authorization
   * over an API token.
   */
  async function cloudflareLoginConfigure(input) {
    const steps = [];
    const record = (step, ok, detail) => {
      steps.push({ step, ok, detail });
      return ok;
    };
    const info = await cloudflaredInfo();
    if (!info.found) {
      record('cloudflared', false, info.reason ?? 'cloudflared was not found');
      return { ok: false, steps };
    }
    record('cloudflared', true, info.version ? `cloudflared ${info.version}` : 'cloudflared found');
    if (!existsSync(certPemPath())) {
      record('login', false, `no certificate at ${certPemPath()} — finish the browser authorization first`);
      return { ok: false, steps };
    }
    record('login', true, 'cert.pem present');

    const hostname = validHostname(input?.hostname) ?? config.tunnelHost;
    if (hostname === undefined) {
      record('hostname', false, 'a hostname such as dsh.example.com is required');
      return { ok: false, steps };
    }
    const name = text(input?.tunnelName) ?? config.tunnelName;
    const service = localService();

    const created = await runCloudflared(info.resolved, ['tunnel', 'create', name], 30000);
    let tunnelId = parseTunnelId(created.output);
    if (tunnelId === undefined) {
      const listed = await runCloudflared(info.resolved, ['tunnel', 'list', '--output', 'json'], 20000);
      const hit = findTunnelInList(listed.output, name);
      if (hit === undefined) {
        record('tunnel', false, (created.output || created.error || 'cloudflared printed no tunnel id').slice(0, 300));
        return { ok: false, steps };
      }
      tunnelId = hit.id;
      record('tunnel', true, `reusing tunnel ${name} (${tunnelId})`);
    } else {
      record('tunnel', true, `tunnel ${name} (${tunnelId})`);
    }

    const routed = await runCloudflared(info.resolved, ['tunnel', 'route', 'dns', name, hostname], 30000);
    const routeOk = routed.exitCode === 0 || /already|exist/i.test(routed.output);
    record('dns', routeOk, routeOk ? `DNS route for ${hostname}` : (routed.output || routed.error || 'route dns failed').slice(0, 300));

    const configPath = tunnelConfigPath();
    try {
      mkdirSync(dirname(configPath), { recursive: true });
      writeFileSync(configPath, renderTunnelConfig({ tunnelId, hostname, service }), { mode: 0o600 });
      record('config', true, `wrote ${configPath}`);
    } catch (error) {
      record('config', false, error instanceof Error ? error.message : String(error));
      return { ok: false, steps };
    }

    const trust = await writeTrustedHosts(hostname);
    record('trust', true, `trustedHosts now accepts ${hostname} (${trust.trust})`);
    return { ok: true, steps, hostname, tunnelId, tunnelName: name, service, configPath, mode: 'certificate' };
  }

  /** Rewrite this plugin's own row config (its fields are all ours). */
  async function writeOwnConfig(patch) {    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry(ROW_ID);
    if (entry === undefined) throw new Error(`the profile has no "${ROW_ID}" row to write`);
    await editor.edit(entry, (current) => ({ ...baseConfig(ROW_ID, current), ...patch }));
    return { ...patch };
  }

  // ── Endpoint map ───────────────────────────────────────────────────────────

  const handlers = {
    /** Everything the panel renders. */
    async state(args, req) {
      // Retries the legacy credential copies when activation ran before the
      // credentials service existed; a no-op once they have run. The second
      // waits for the first: it reads the record the first one writes.
      await migrateLegacyRecords();
      await migrateDeviceRecords();
      const facts = listenerFacts();
      const entries = buildEntries();
      const devices = prune(await readDevices());
      const cookieDays = cookieMaxAgeDays();
      const now = Date.now();
      const addresses = localAddresses();
      const here = classifyRequestOrigin(req?.headers, req?.socket?.remoteAddress);
      const recoveryRecord = await readRecovery();
      const deviceRows = await readDeviceRows();
      const keyRows = await readKeyRows();
      return {
        config,
        /** The name this machine should use: dsh-mac, dsh-win, dsh-lin… */
        suggestedLabel: suggestedLabelFor(process.platform),
        platform: process.platform,
        /** The listener's mode, its address book and the tunnel's verdict. */
        mode: modeStatus(req),
        /** How far a link generated for this very request reaches. */
        linksReachable: linkBase(req).reachable,
        /** The two credential channels, so the panel renders their switches. */
        accessPolicy: await readAccessPolicy(),
        /** The recovery door: whether a password is armed, and the credentials. */
        recovery: {
          configured: recoveryRecord !== undefined,
          createdAt: recoveryRecord?.createdAt,
          ticketDays: DEFAULT_TICKET_DAYS,
          deviceDays: DEFAULT_DEVICE_DAYS,
          /** How long a one-time link lives, in minutes. */
          tempTokenMinutes: TEMP_TOKEN_MINUTES,
          // The fingerprints stay on the host; the panel only needs the metadata.
          tokens: deviceRows.map((row) => publicDeviceRow(row, now)),
        },
        listener: facts,
        entries,
        localAddresses: addresses,
        /** How this very panel request arrived, and whether the fence took it. */
        request: {
          host: req?.headers?.host,
          via: here.via,
          clientIp: here.clientIp,
          trusted: probeTrust(getConnection(), String(req?.headers?.host ?? '')) !== 'refused',
        },
        tunnel: tunnelStatus((await readSecret(CF_TUNNEL_TOKEN_KEY)) !== undefined),
        /** Every credential this machine has handed out, with its status. */
        devices: deviceRows.map((row) => publicDeviceRow(row, now)),
        /** The access keys: metadata only, never a fingerprint. */
        keys: keyRows.map((row) => publicKeyRow(row, now)),
        /** The heartbeat's browser view — a sighting log, not an authorization. */
        activity: devices.map((d) => ({
          ...d,
          name: d.name ?? deviceLabel(d.ua),
          daysLeft: cookieDays - Math.floor((now - Number(d.firstSeenAt ?? now)) / (24 * 60 * 60 * 1000)),
          onLan: d.lastVia === 'lan' || sameLan(d.lastIp, addresses),
        })),
        platform: {
          cookieMaxAgeDays: cookieDays,
          sessionRecordPresent: (await attemptAsync(() => getCredentials()?.readRecord(PLATFORM_SESSION_KEY))) !== undefined,
        },
        cloudflare: {
          apiTokenStored: (await readSecret(CF_API_TOKEN_KEY)) !== undefined,
          connectorTokenStored: (await readSecret(CF_TUNNEL_TOKEN_KEY)) !== undefined,
          tunnelName: config.tunnelName,
          accessEmail: config.accessEmail,
          service: localService(),
          scopes: REQUIRED_TOKEN_SCOPES,
        },
        capabilities: {
          connection: getConnection() !== undefined,
          credentials: getCredentials() !== undefined,
          configEditor: getConfigEditor() !== undefined,
          subprocess: getSubprocess() !== undefined,
          tokenUrls: getConnection() !== undefined,
          /** Whether the `/` recovery gate is actually answering in this process. */
          rootGate: rootGate.ok,
          rootGateError: rootGate.ok ? undefined : rootGate.error,
        },
      };
    },

    /** Phone-side ping from the injected script; feeds the activity view. */
    async heartbeat(args, req) {
      const id = text(args?.id);
      if (id === undefined) throw new Error('heartbeat requires a device id');
      const ua = text(args?.ua) ?? String(req?.headers?.['user-agent'] ?? '');
      const origin = classifyRequestOrigin(req?.headers, req?.socket?.remoteAddress);
      const devices = await readDevices();
      await writeDevices(prune(upsertDevice(devices, { id, ua, ip: origin.clientIp, via: origin.via })));
      return { recorded: true, via: origin.via };
    },

    /** Rename one activity row (a label, never an authorization). */
    async 'activity-rename'(args) {
      const id = text(args?.id);
      const next = text(args?.name);
      if (id === undefined || next === undefined) throw new Error('activity-rename requires id and name');
      const devices = await readDevices();
      const index = devices.findIndex((d) => d.id === id);
      if (index < 0) throw new Error('no such device');
      devices[index] = { ...devices[index], name: next.slice(0, 60) };
      await writeDevices(devices);
      return { id, name: devices[index].name };
    },

    /** Forget one activity row; this is not a security revocation. */
    async 'device-forget'(args) {
      const id = text(args?.id);
      if (id === undefined) throw new Error('device-forget requires id');
      const devices = await readDevices();
      await writeDevices(devices.filter((d) => d.id !== id));
      return { id, forgotten: true };
    },

    /** Clear the activity view. */
    async 'devices-clear'() {
      await writeDevices([]);
      return { cleared: true };
    },

    // ── Mode ──────────────────────────────────────────────────────────────────

    /** The listener's mode, its address book and the tunnel's verdict. */
    async 'mode-status'(args, req) {
      // The channels ride along so the panel renders them without a second call.
      return { ...modeStatus(req), accessPolicy: await readAccessPolicy() };
    },

    /**
     * Choose between the local network and the tunnel.
     *
     * `public` binds loopback only and is deliberately silent about the tunnel:
     * publishing is a separate, explicit decision. `lan` binds the chosen
     * address, makes sure the platform's fence trusts it, and stops any tunnel
     * that is running — a machine that is reachable on the local network must
     * not keep advertising itself to the internet by accident.
     *
     * The write is honest about what it does. Changing a bind address is a
     * listener option, and the Loader applies it the moment the file changes:
     * the answer says so (`appliesImmediately`) and warns that the reply itself
     * may be cut off by the rebind (`rebindMayDropThisPage`) rather than
     * claiming a restart is required while the socket moves underneath the
     * caller. A write that changes nothing reports `appliesImmediately: false`.
     */
    async 'set-mode'(args) {
      const requested = text(args?.mode);
      if (requested !== 'lan' && requested !== 'public') throw new Error("set-mode requires mode 'lan' or 'public'");
      if (requested === 'public') return modeAnswer(await writeLanHost('127.0.0.1'), 'public');
      const chosen = validBindAddress(args?.host) ?? validBindAddress(localAddresses()[0]?.address);
      if (chosen === undefined) {
        throw new Error('no local address was found to bind; pass one explicitly (for example {"mode":"lan","host":"10.0.0.5"})');
      }
      const facts = listenerFacts();
      const port = Number.isFinite(facts.port) ? facts.port : 3080;
      const authority = chosen.includes(':') ? `[${chosen}]:${port}` : `${chosen}:${port}`;
      const fromCli = attempt(() => ctx.get('webStartup')?.trustedHosts) ?? [];
      const fromRow = attempt(() => findEntry('connection')?.options?.config?.trustedHosts) ?? [];
      const hosts = [
        ...new Set([...(Array.isArray(fromCli) ? fromCli : []), ...(Array.isArray(fromRow) ? fromRow : []), authority].filter(Boolean)),
      ];
      // One write, not two: each write is a reconcile, and each reconcile is a
      // rebind of the listener this call is about to move.
      const combined = await writeRowsConfigDirect([
        { id: 'connection', values: { trustedHosts: hosts }, mergeKeys: ['trustedHosts'] },
        { id: 'webserver', values: { host: chosen } },
      ]);
      const stopped = tunnelStop();
      if (combined !== undefined) {
        return {
          ...modeAnswer({ host: chosen, wrote: combined.changed }, 'lan', combined.changed),
          authority,
          trust: probeTrust(getConnection(), authority),
          trustedHosts: combined.values.connection.trustedHosts,
          tunnelStopped: stopped.stopped === true,
        };
      }
      const trust = await writeTrustedHosts(authority);
      const written = await writeLanHost(chosen);
      return {
        ...modeAnswer(written, 'lan', trust.wrote || written.wrote),
        authority,
        trust: trust.trust,
        trustedHosts: trust.trustedHosts,
        tunnelStopped: stopped.stopped === true,
      };
    },

    /**
     * Put the listener back on loopback.
     *
     * The way back from LAN mode, and deliberately tiny: it writes the loopback
     * literal, reports the mode the derivation will now give, and starts
     * nothing.
     *
     * Idempotency is decided by the file, never by the in-memory row: after a
     * LAN switch the live config can still be the old value for as long as the
     * Loader takes to reconcile, and trusting it would make this call a no-op
     * exactly when it is needed most. If the patch already says `127.0.0.1` the
     * write is skipped and the answer says nothing changed.
     */
    async 'restore-loopback'() {
      return modeAnswer(await writeLanHost('127.0.0.1'), 'public');
    },

    // ── Authorized devices ────────────────────────────────────────────────────

    /** Every credential this machine has handed out, with its status. */
    async 'device-list'() {
      const rows = await readDeviceRows();
      const now = Date.now();
      return { devices: rows.map((row) => publicDeviceRow(row, now)) };
    },

    /**
     * Mint a fresh one-time link for an existing authorized device.
     *
     * For the phone that still holds its credential but whose platform cookie
     * has lapsed, and for handing a device a walk-in link without rotating what
     * it already has. The source row is read, never written: this adds a new
     * 15-minute single-use row and leaves the device's own credential exactly as
     * it was.
     *
     * The new row records `parentId` — the device it was minted for — and that
     * is what makes revoking the device take its outstanding links with it. A
     * link is a way in *as* a device, so it cannot outlive it.
     *
     * @returns `{ id, parentId, url, qr, expiresAt }` where `id` is the LINK
     *   row's own id — the row the panel lists and can revoke.
     */
    async 'device-link'(args, req) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('device-link requires an id');
      // The panel's own budget, not the public one: this is a fenced action by
      // the person who already holds the session. Counted when a link is
      // actually minted, so a panel rendering a stale row costs nothing.
      const linkPolicy = await readAccessPolicy();
      if (linkPolicy.temporaryAccess === false) {
        throw refusal('remote-access/temporary-disabled', channelRefusal(linkPolicy).message);
      }
      spendPanelMint(req, 'link requests');
      const rows = await readDeviceRows();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) throw refusal('remote-access/device-not-found', `no authorized device with id ${JSON.stringify(id)}`);
      const name = `${absentText(row.name) ?? 'Device'} · 链接`;
      // The link row remembers whose link it is: revoking the device must take
      // its outstanding links with it, which is what `parentId` is for. The
      // answer identifies the LINK row (the one the panel can see and revoke),
      // never the source it was minted from.
      const minted = await mintTempLink(req, row.source, name, row.id);
      return { id: minted.id, parentId: row.id, url: minted.url, qr: minted.qr, expiresAt: minted.expiresAt, reachable: minted.reachable };
    },

    /**
     * What became of one pairing code.
     *
     * The panel shows a code and then needs to know whether it was used — which
     * used to be indistinguishable from expired or never minted, because the row
     * was deleted on redemption. An unknown id is a normal answer, not an error.
     */
    async 'pair-code-status'(args) {
      const id = absentText(args?.id);
      if (id === undefined) return { state: 'unknown' };
      const rows = await readPairCodes();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) return { state: 'unknown' };
      const expiresAt = typeof row.expiresAt === 'number' && Number.isFinite(row.expiresAt) ? row.expiresAt : undefined;
      if (pairCodeUsed(row)) return { state: 'used', usedAt: row.usedAt, expiresAt };
      if (expiresAt !== undefined && expiresAt <= Date.now()) return { state: 'expired', expiresAt };
      return { state: 'ready', expiresAt };
    },

    /** The two credential channels, as the panel renders them. */
    async 'access-policy'() {
      return await readAccessPolicy();
    },

    /**
     * Switch the temporary-link channel and the authorized-device channel.
     *
     * Idempotent, and it deletes nothing: a channel that is off refuses its
     * credentials (an outstanding one-time link stops working, a paired device
     * stops getting in) and switching it back on restores both at once, with no
     * re-pairing and no new link. Omitted fields keep their current value, and
     * the answer reports what actually changed.
     */
    async 'set-access-policy'(args) {
      const current = await readAccessPolicy();
      const next = {
        temporaryAccess: typeof args?.temporary === 'boolean' ? args.temporary : current.temporaryAccess,
        deviceAccess: typeof args?.device === 'boolean' ? args.device : current.deviceAccess,
      };
      const changed = {};
      if (next.temporaryAccess !== current.temporaryAccess) changed.temporaryAccess = next.temporaryAccess;
      if (next.deviceAccess !== current.deviceAccess) changed.deviceAccess = next.deviceAccess;
      if (Object.keys(changed).length > 0) await writeAccessPolicy(next);
      return { ...next, changed };
    },

    /** Give one authorized device a name of your own. */
    async 'device-rename'(args) {
      const id = absentText(args?.id);
      const name = absentText(args?.name);
      if (id === undefined) throw new Error('device-rename requires an id');
      if (name === undefined) throw new Error('device-rename requires a name');
      const rows = await readDeviceRows();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) throw new Error(`no authorized device with id ${JSON.stringify(id)}`);
      row.name = name.slice(0, 60);
      await writeDeviceRows(rows);
      return { id, name: row.name };
    },

    /**
     * Change one device's expiry.
     *
     * `until` wins when both are given: an exact instant is a different kind of
     * instruction than "N days from now", and the caller that sent both meant
     * the instant. `days: null` with no `until` means never expires.
     */
    async 'device-expiry'(args) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('device-expiry requires an id');
      const until = absentText(args?.until);
      const rawDays = args?.days;
      let days = null;
      if (rawDays !== undefined && rawDays !== null) {
        days = Number(rawDays);
        if (!Number.isFinite(days) || days <= 0) throw new Error('device-expiry requires a positive day count or null');
      }
      let expiresAt;
      if (until !== undefined) {
        expiresAt = Date.parse(until);
        if (!Number.isFinite(expiresAt)) throw new Error('device-expiry requires "until" to be an ISO date-time');
        // An exact instant is not a day count; the status field is what the
        // panel reads, and it is derived from `expiresAt`.
        days = null;
      } else {
        expiresAt = expiryFromDays(days);
      }
      const rows = await readDeviceRows();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) throw new Error(`no authorized device with id ${JSON.stringify(id)}`);
      row.days = days;
      row.expiresAt = expiresAt;
      await writeDeviceRows(rows);
      return { id, days, expiresAt, status: deviceStatus(row) };
    },

    /**
     * Revoke every temporary row in one call.
     *
     * The one-time links are the rows a stranger can cause and the rows that pile
     * up, so this is the broom: temporary rows go, durable devices stay. The same
     * cascade rule as `device-revoke` applies — a row derived from a revoked one
     * goes with it — and a repeat call is a no-op.
     */
    async 'revoke-temporary'() {
      const rows = await readDeviceRows();
      const doomed = new Set(rows.filter((row) => row.temporary === true).map((row) => row.id));
      let grew = true;
      while (grew) {
        grew = false;
        for (const row of rows) {
          if (doomed.has(row.id)) continue;
          const parentId = absentText(row.parentId);
          if (parentId !== undefined && doomed.has(parentId)) {
            doomed.add(row.id);
            grew = true;
          }
        }
      }
      const kept = rows.filter((row) => !doomed.has(row.id));
      if (kept.length === rows.length) return { revoked: 0 };
      await writeDeviceRows(kept);
      return { revoked: rows.length - kept.length };
    },

    /**
     * Revoke one device credential, valid or expired. Idempotent.
     *
     * Cascades to the links minted for this device: they are ways in as it, so
     * they go with it.
     */
    async 'device-revoke'(args) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('device-revoke requires an id');
      const result = await removeDeviceRows(id);
      return { id, revoked: result.removed > 0, removed: result.removed };
    },

    /**
     * Delete an expired row outright.
     *
     * The mirror image of revoke, and deliberately narrow: a row that is still
     * valid — including one that never expires — is refused, so the button that
     * tidies up the list can never drop a device that is still in use. Deleting
     * an expired device takes its expired children with it.
     */
    async 'device-delete'(args) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('device-delete requires an id');
      const rows = await readDeviceRows();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) throw new Error(`no authorized device with id ${JSON.stringify(id)}`);
      if (!deviceDeletable(row)) throw new Error('this device is still valid; revoke it instead of deleting it');
      const result = await removeDeviceRows(id);
      return { id, deleted: true, removed: result.removed };
    },

    // ── Access keys ───────────────────────────────────────────────────────────

    /**
     * Mint an access key.
     *
     * The plaintext key is returned exactly once, in this response, and only its
     * sha256 fingerprint is stored — losing it means resetting it, which is the
     * point. `days` omitted or null means the key never expires.
     */
    async 'key-create'(args, req) {
      spendPanelMint(req, 'access-key requests');
      const name = absentText(args?.name) ?? 'Access key';
      const rawDays = args?.days;
      let days = null;
      if (rawDays !== undefined && rawDays !== null) {
        days = Number(rawDays);
        if (!Number.isFinite(days) || days <= 0) throw new Error('key-create requires a positive day count or null');
      }
      const key = newAccessKey();
      const now = Date.now();
      const row = {
        id: newRecordId(),
        name: name.slice(0, 60),
        hash: hashAccessKey(key),
        createdAt: new Date(now).toISOString(),
        expiresAt: expiryFromDays(days),
        days,
        lastUsedAt: null,
      };
      const rows = await readKeyRows();
      rows.unshift(row);
      await writeKeyRows(rows);
      return { id: row.id, name: row.name, key, createdAt: row.createdAt, expiresAt: row.expiresAt, days: row.days };
    },

    /** The access keys, metadata only. */
    async 'key-list'() {
      const rows = await readKeyRows();
      const now = Date.now();
      return { keys: rows.map((row) => publicKeyRow(row, now)) };
    },

    /** Replace one key's secret; the new one is shown once, and the old one dies. */
    async 'key-reset'(args) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('key-reset requires an id');
      const rows = await readKeyRows();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) throw new Error(`no access key with id ${JSON.stringify(id)}`);
      const key = newAccessKey();
      row.hash = hashAccessKey(key);
      await writeKeyRows(rows);
      return { id, key };
    },

    /** Revoke one access key. Idempotent. */
    async 'key-revoke'(args) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('key-revoke requires an id');
      const rows = await readKeyRows();
      const kept = rows.filter((row) => row.id !== id);
      if (kept.length === rows.length) return { id, revoked: false };
      await writeKeyRows(kept);
      return { id, revoked: true };
    },

    // ── Legacy token aliases ──────────────────────────────────────────────────
    //
    // The panel used to speak of "device tokens" as their own thing. There is
    // now one record of authorized devices, so these stay as thin aliases with
    // their old return shapes, and the old record is left untouched as the
    // rollback path.

    /** Revoke one authorized device; returns how many rows went away. */
    async 'token-revoke'(args) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('token-revoke requires an id');
      const result = await removeDeviceRows(id);
      return { revoked: result.removed };
    },

    /** Rename one authorized device. */
    async 'token-rename'(args) {
      const id = absentText(args?.id);
      const name = absentText(args?.name);
      if (id === undefined) throw new Error('token-rename requires an id');
      if (name === undefined) throw new Error('token-rename requires a name');
      const rows = await readDeviceRows();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) throw new Error(`no device token with id ${JSON.stringify(id)}`);
      row.name = name.slice(0, 60);
      await writeDeviceRows(rows);
      return { id, name: row.name };
    },

    /**
     * Change one device's expiry; null means it never expires.
     *
     * Omitted `days` keeps the historical default of one year — callers that
     * mean "never" say so, exactly as before.
     */
    async 'token-expiry'(args) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('token-expiry requires an id');
      const days = args?.days === null ? null : args?.days === undefined ? DEFAULT_DEVICE_DAYS : Number(args.days);
      if (days !== null && (!Number.isFinite(days) || days <= 0)) throw new Error('token-expiry requires a positive day count or null');
      const rows = await readDeviceRows();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) throw new Error(`no device token with id ${JSON.stringify(id)}`);
      row.days = days;
      row.expiresAt = expiryFromDays(days);
      await writeDeviceRows(rows);
      return { id, days, expiresAt: row.expiresAt };
    },

    /** Revoke every authorized device. */
    async 'tokens-clear'() {
      const rows = await readDeviceRows();
      await writeDeviceRows([]);
      return { revoked: rows.length };
    },

    /** Add one authority to the shipped connection row's trustedHosts. */
    async 'trust-authority'(args) {
      const authority = text(args?.authority);
      if (authority === undefined) throw new Error('trust-authority requires an authority');
      if (/[/\s]/.test(authority)) throw new Error('an authority is a bare host or host:port');
      return await writeTrustedHosts(authority);
    },

    /** Bind the listener to one concrete interface literal. */
    async 'set-lan-host'(args) {
      return await writeLanHost(args?.host);
    },

    /** Advertise a public root URL. */
    async 'set-public-url'(args) {
      const url = text(args?.url);
      if (url === undefined || !/^https?:\/\//.test(url)) throw new Error('set-public-url requires an http(s) URL');
      return await writePublicUrl(url);
    },

    /** Undo the advertised URL: back to the listener's own origin. */
    async 'clear-public-url'() {
      return await clearPublicUrl();
    },

    /** Rewrite this plugin's own row config. */
    async 'set-plugin-config'(args) {
      const patch = {};
      if (typeof args?.narrowEnhance === 'boolean') patch.narrowEnhance = args.narrowEnhance;
      if (absentText(args?.tunnelHost) !== undefined) patch.tunnelHost = absentText(args.tunnelHost);
      if (absentText(args?.publicUrl) !== undefined) patch.publicUrl = absentText(args.publicUrl);
      if (absentText(args?.lanHost) !== undefined) patch.lanHost = absentText(args.lanHost);
      if (absentText(args?.tunnelName) !== undefined) patch.tunnelName = absentText(args.tunnelName);
      if (absentText(args?.accessEmail) !== undefined) patch.accessEmail = absentText(args.accessEmail);
      if (Object.keys(patch).length === 0) throw new Error('set-plugin-config requires at least one field');
      const written = await writeOwnConfig(patch);
      Object.assign(config, normalizeConfig({ ...config, ...patch }));
      return written;
    },

    /** Environment checklist: cloudflared, certificate, stored secrets, hostname. */
    async 'cf-env'() {
      return await cloudflareEnv();
    },

    /** Start the guided browser login and return its authorization URL. */
    async 'cf-login-start'() {
      return await loginStart();
    },

    /** Poll the login child and the certificate it writes. */
    async 'cf-login-status'() {
      return loginStatus();
    },

    /** Abandon a pending login. */
    async 'cf-login-cancel'() {
      return loginCancel();
    },

    /** After authorization: create the tunnel, route DNS, write config.yml, trust. */
    async 'cf-login-configure'(args) {
      return await cloudflareLoginConfigure(args);
    },

    /** Store and verify a Cloudflare API token. */
    async 'cf-set-token'(args) {
      const token = text(args?.token);
      if (token === undefined) throw new Error('cf-set-token requires a token');
      const verify = await cloudflare.verifyToken(token);
      if (!verify.ok) throw new Error(verify.error);
      await writeSecret(CF_API_TOKEN_KEY, token);
      const hostname = text(args?.hostname) ?? config.tunnelHost;
      const zone = hostname === undefined ? undefined : await cloudflare.findZone(token, hostname);
      return {
        stored: true,
        status: verify.status ?? 'active',
        zone: zone?.ok ? zone.result.name : undefined,
        zoneError: zone !== undefined && !zone.ok ? zone.error : undefined,
      };
    },

    /** The full automatic setup: tunnel, ingress, DNS, connector token, trust. */
    async 'cf-connect'(args) {
      return await cloudflareConnect(args);
    },

    /** Create the Access application and report the login methods. */
    async 'cf-access'(args) {
      return await cloudflareAccess(args);
    },

    /** Delete the DNS record and tunnel this plugin created. */
    async 'cf-teardown'() {
      return await cloudflareTeardown();
    },

    /** Forget the stored API token. */
    async 'cf-forget-token'() {
      await clearSecret(CF_API_TOKEN_KEY);
      return { cleared: true };
    },

    /** Start the configured cloudflared child. */
    async 'tunnel-start'() {
      return await tunnelStart();
    },

    /** Stop the managed cloudflared child. */
    async 'tunnel-stop'() {
      return tunnelStop();
    },

    /** Delete the platform's browser-session record. */
    async 'revoke-platform-sessions'() {
      return await revokePlatformSessions();
    },

    /** Whether the password door is armed, and which credentials exist. */
    async 'recovery-status'() {
      const recovery = await readRecovery();
      const now = Date.now();
      const rows = await readDeviceRows();
      const keys = await readKeyRows();
      return {
        configured: recovery !== undefined,
        createdAt: recovery?.createdAt,
        iterations: recovery?.iterations ?? PBKDF2_ITERATIONS,
        ticketDays: DEFAULT_TICKET_DAYS,
        deviceDays: DEFAULT_DEVICE_DAYS,
        tempTokenMinutes: TEMP_TOKEN_MINUTES,
        tokens: rows.map((row) => publicDeviceRow(row, now)),
        keys: keys.map((row) => publicKeyRow(row, now)),
      };
    },

    /** Set or replace the recovery password (the password itself is never stored). */
    async 'recovery-set'(args) {
      const password = typeof args?.password === 'string' ? args.password : '';
      if (password.length < 12) throw new Error('recovery-set requires a password of at least 12 characters');
      const salt = newSalt();
      const record = {
        salt,
        iterations: PBKDF2_ITERATIONS,
        key: deriveKey(password, salt, PBKDF2_ITERATIONS),
        // Rotating the password rotates the ticket secret too, so every ticket
        // the old password minted stops verifying.
        secret: randomBytes(32).toString('base64'),
        createdAt: new Date().toISOString(),
      };
      await writeRecovery(record);
      return { ok: true, createdAt: record.createdAt };
    },

    /** Disarm the door: forget the password and every ticket it minted. */
    async 'recovery-clear'() {
      await clearRecovery();
      return { ok: true };
    },

    /**
     * Mint a one-time pairing code.
     *
     * `days` is the lifetime the new device's credential should get: a positive
     * day count, or null for "never". Omitted means the default year, not "never".
     */
    async 'pair-code'(args, req) {
      const days = args?.days === null ? null : args?.days === undefined ? DEFAULT_DEVICE_DAYS : Number(args.days);
      if (days !== null && (!Number.isFinite(days) || days <= 0)) throw new Error('pair-code requires a positive day count or null');
      const pairCodePolicy = await readAccessPolicy();
      if (pairCodePolicy.deviceAccess === false) {
        throw refusal('remote-access/device-disabled', channelRefusal(pairCodePolicy).message);
      }
      spendPanelMint(req, 'pairing-code requests');
      return await mintPairCode(req, days);
    },

    /** Change one device token's expiry; null means it never expires. */
    /** Renew the platform cookie: hand back a fresh tokenized entry URL. */
    async 'renew-session'(args, req) {
      return renewSession(req);
    },
  };

  /**
   * Whether the browser that sent this request is on https.
   *
   * This decides the `Secure` attribute on the plugin's own cookies, and getting
   * it wrong in the *unsafe* direction drops them: a `Secure` cookie delivered
   * over http is discarded by the browser, while a cookie without `Secure` is
   * still accepted over https. So the answer is only "https" when there is
   * evidence, in this order:
   *
   *  1. the local proxy said so — cloudflared terminates TLS at the edge and
   *     forwards to the plain-http listener, and it is believed only when the TCP
   *     peer really is the loopback proxy, never for a header a stranger set;
   *  2. the listener itself is TLS;
   *  3. the request arrived on the advertised public authority, which is https by
   *     configuration (a tunnel host is https by construction).
   *
   * A LAN visit while a tunnel is also configured therefore gets a cookie without
   * `Secure` — accepted over that http origin — instead of a dropped one.
   *
   * Note for the docs: the plugin's own cookies (`mc-device`, `mc-unlock`) are
   * deliberately **not** authority-bound — they are the credentials that work
   * when the platform's authority-bound cookie has lapsed — while the platform's
   * `dsh-auth-*` is bound to the authority it was minted for.
   */
  function requestScheme(req) {
    if (isLoopbackSocket(req)) {
      const raw = req?.headers?.['x-forwarded-proto'];
      const forwarded = String(Array.isArray(raw) ? raw[0] : (raw ?? '')).split(',')[0].trim().toLowerCase();
      if (forwarded === 'https') return 'https';
      if (forwarded === 'http') return 'http';
    }
    if (String(listenerFacts().protocol ?? '').toLowerCase() === 'https') return 'https';
    const advertised = authorityFrom(configuredPublicUrl());
    const host = String(req?.headers?.host ?? '').trim().toLowerCase();
    if (advertised !== undefined && advertised.scheme === 'https' && host !== '' && host === String(advertised.base).toLowerCase()) {
      return 'https';
    }
    return 'http';
  }

  /**
   * The clean entry URL for this request: scheme and authority, and no secret.
   *
   * Everything the plugin hands back is built on this, never on the platform's
   * tokenized URL. `authority` stays a bare `host[:port]` for the callers that
   * probe the fence with it.
   */
  function entryUrl(req) {
    const resolved = linkBase(req);
    return {
      authority: resolved.base,
      scheme: resolved.scheme,
      url: `${resolved.scheme}://${resolved.base}/`,
      reachable: resolved.reachable,
    };
  }

  /**
   * Mint the platform's own browser cookie without ever showing its token.
   *
   * The platform exchanges a launch token for its cookie in `authorizeIndex`,
   * and the token it needs is the process-wide one — putting it in a redirect
   * Location or a JSON body hands out a reusable key to this Harness for the
   * life of the process, which no per-device revoke can ever withdraw. So the
   * exchange is run here, against a stand-in request and response, and only the
   * resulting cookie is passed on.
   *
   * The authority is the request's own `Host`, not the resolved link base: the
   * browser is talking to that authority right now, and the cookie it receives
   * has to match where it will re-request `/`.
   *
   * @returns the `set-cookie` values, or undefined when no exchange was possible.
   */
  function platformExchange(req) {
    const connection = getConnection();
    if (connection === undefined || typeof connection.authorizeIndex !== 'function') return undefined;
    const authority = String(req?.headers?.host ?? '').trim();
    if (authority === '') return undefined;
    const tokenizedUrl = attempt(() => connection.authenticatedUrl?.(`${requestScheme(req)}://${authority}/`));
    if (typeof tokenizedUrl !== 'string') return undefined;
    const launch = attempt(() => new URL(tokenizedUrl).searchParams.get(TOKEN_QUERY));
    if (typeof launch !== 'string' || launch === '') return undefined;

    const cookies = [];
    const standIn = {
      writeHead(_status, headers) {
        const value = headers?.['set-cookie'];
        if (typeof value === 'string') cookies.push(value);
        else if (Array.isArray(value)) cookies.push(...value);
        return standIn;
      },
      setHeader(name, value) {
        if (String(name).toLowerCase() !== 'set-cookie') return standIn;
        if (typeof value === 'string') cookies.push(value);
        else if (Array.isArray(value)) cookies.push(...value);
        return standIn;
      },
      end() {
        return standIn;
      },
    };
    const handled = attempt(() =>
      connection.authorizeIndex(
        { method: 'GET', url: `/?${TOKEN_QUERY}=${encodeURIComponent(launch)}`, headers: { host: authority } },
        standIn,
      ),
    );
    return handled === false && cookies.length > 0 ? cookies : undefined;
  }

  /**
   * Send this browser into the app with a session, and no token in the URL.
   *
   * The Location is a bare `/` on the authority the browser is already on; the
   * session arrives as a cookie from the server-side exchange. If the platform
   * cannot mint one there is nothing to send the browser *to* — a tokenless
   * redirect would loop — so this answers a plain 503 instead of leaking a URL
   * that works forever.
   */
  function reenter(res, req, cookies = []) {
    const platform = platformExchange(req);
    if (platform === undefined) {
      res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      res.end('dsh-remote-access: the platform did not hand out a session; open the URL printed by dsh web\n');
      return;
    }
    res.writeHead(303, {
      location: '/',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'set-cookie': [...platform, ...cookies],
    });
    res.end();
  }

  /**
   * Renew the session by telling the caller where the app is, and nothing else.
   *
   * The old answer was a tokenized URL, which is exactly the secret this plugin
   * must not hand out. The caller is already authenticated through the panel, so
   * the useful fact is the authority to visit; the device credential does the
   * rest when that browser comes back with a lapsed platform cookie.
   */
  function renewSession(req) {
    const entry = entryUrl(req);
    return { authority: entry.authority, url: entry.url, tokenized: false, reachable: entry.reachable };
  }

  // ── Recovery: a long-lived device token, and a fail-closed password door ───
  //
  // The platform's browser cookie is minted from a per-process launch token and
  // expires after `cookieMaxAgeDays`; a saved entry link dies with the process
  // that minted it. Both are fine at a desk and useless on a trip, so this layer
  // adds two ways back in that need no access to the computer:
  //
  //   1. A device token the plugin issues at pairing time: a year long, sliding
  //      on every use, revocable per device — which the platform itself cannot do.
  //   2. A password door verified by challenge-response, so the password never
  //      crosses the network (not even to the Cloudflare edge).
  //
  // Both are served from the root gate: an unauthenticated visit to the bare
  // hostname gets this page instead of the platform's plain-text 401.
  const RECOVERY_RECORD_KEY = 'dsh-remote-access/recovery';
  const TOKENS_RECORD_KEY = 'dsh-remote-access/device-tokens';
  const PAIR_RECORD_KEY = 'dsh-remote-access/pair-codes';

  // ── Credential-record key migration ───────────────────────────────────────
  //
  // This plugin stored its records under its previous name. Each one is copied
  // into the new scope on activation, and only while the new key holds nothing:
  // a second activation, or a machine that already wrote the new key, is a no-op
  // and never overwrites newer state. The old records are left in place on
  // purpose — they are the rollback path. Best effort throughout: a credential
  // store that is absent, locked or broken must not stop the plugin from
  // activating, and nothing here is user-visible.
  const LEGACY_RECORD_KEYS = [
    [DEVICE_RECORD_KEY, 'dsh-mobile-console/devices'],
    [RECOVERY_RECORD_KEY, 'dsh-mobile-console/recovery'],
    [TOKENS_RECORD_KEY, 'dsh-mobile-console/device-tokens'],
    [PAIR_RECORD_KEY, 'dsh-mobile-console/pair-codes'],
  ];

  /**
   * Copy each legacy record to its new key when the new key is absent.
   *
   * Deliberately never rejects: the activation-time call is fire-and-forget, and
   * the panel's first `state` call re-attempts it once the credentials service
   * is up. The in-flight promise is remembered so a second caller waits for the
   * first copy instead of racing it — which matters because the v2 device
   * migration below reads the record this one writes.
   */
  let legacyMigration = null;
  function migrateLegacyRecords() {
    if (legacyMigration !== null) return legacyMigration;
    const credentials = getCredentials();
    if (credentials === undefined) return Promise.resolve();
    if (typeof credentials.readRecord !== 'function' || typeof credentials.modifyRecord !== 'function') return Promise.resolve();
    legacyMigration = (async () => {
      try {
        for (const [next, legacy] of LEGACY_RECORD_KEYS) {
          await attemptAsync(async () => {
            if ((await credentials.readRecord(next)) !== undefined) return;
            const previous = await credentials.readRecord(legacy);
            // A legacy record is copied through the same guard as everything
            // else: it was written by an older revision, so it is exactly the
            // kind of payload that may hold a value this store cannot spell.
            if (previous === undefined || previous.kind !== 'grant') return;
            await modifyRecordGuarded(next, async () => previous.payload);
          });
        }
      } catch {
        // Best effort: a credential store that refuses must not fail activation.
      }
    })();
    return legacyMigration;
  }

  /** Whether this fiber already converted the legacy device tokens. */
  let devicesV2Migrated = null;

  /**
   * Copy the legacy device-token rows into the unified record, once.
   *
   * Copy-only: the v1 record is left exactly as it was, so a rollback to the
   * previous plugin version still finds its tokens. Idempotent: rows whose
   * fingerprint or id is already present are skipped, so this can run on every
   * activation without duplicating anything or overwriting a row the user has
   * since renamed, re-scoped or re-expired.
   */
  function migrateDeviceRecords() {
    if (devicesV2Migrated !== null) return devicesV2Migrated;
    const credentials = getCredentials();
    if (credentials === undefined) return Promise.resolve();
    if (typeof credentials.readRecord !== 'function' || typeof credentials.modifyRecord !== 'function') return Promise.resolve();
    devicesV2Migrated = (async () => {
      try {
        const record = await credentials.readRecord(DEVICES_V2_RECORD_KEY);
        const current = parseDeviceRows(record?.payload);
        const legacyRows = await readTokens();
        const { rows, added } = migrateLegacyDeviceRows(current, legacyRows);
        if (added === 0) return;
        await modifyRecordGuarded(DEVICES_V2_RECORD_KEY, async () => ({ version: 2, devices: rows }));
      } catch {
        // Best effort throughout: a store that refuses must not fail activation.
      }
    })();
    return devicesV2Migrated;
  }

  const TOKEN_QUERY = 'token';
  const CHALLENGE_TTL_MS = 2 * 60 * 1000;
  const MAX_TOKENS = 20;
  /** How many redeemed pairing codes stay queryable, and for how long. */
  const MAX_USED_PAIR_CODES = 20;
  const USED_PAIR_CODE_TTL_MS = 24 * 60 * 60 * 1000;
  const challenges = new Map();
  const recoverLimiter = createRateLimiter();
  /**
   * The same failures counted across every client, with a budget far above any
   * real mistyping.
   *
   * It is not the control — the per-client budget is — but a *small* global
   * budget is a lockout: five wrong passwords from anywhere and the owner's own
   * `/unlock/challenge` answers 429. Large enough to bound a distributed brute
   * force, small enough never to be the reason a real person cannot get in.
   */
  const recoverGlobalLimiter = createRateLimiter({ limit: 200 });
  /** The access-key door's budget: per client, and across every client. */
  const keyLimiter = createRateLimiter();
  const keyGlobalLimiter = createRateLimiter();
  /**
   * The public link-minting budget: five per client per quarter hour, and five
   * across every client.
   *
   * Strict on purpose — these doors are the ones a stranger can reach, so the
   * budget is what stops guessing. Nothing the panel does goes through it.
   */
  const linkLimiter = createRateLimiter();
  const linkGlobalLimiter = createRateLimiter();
  /**
   * The panel's minting budget: thirty per client per quarter hour.
   *
   * The fenced panel actions — minting a link for a device, a pairing code, an
   * access key — are performed by the person who already holds the session, and
   * the strict public budget made them fight their own tool: a handful of clicks
   * answered "retry in 796s". The public doors keep five; the panel gets a budget
   * sized for a person clicking around, still bounded so a runaway script cannot
   * mint without limit.
   */
  const panelLimiter = createRateLimiter({ limit: PANEL_LIMIT });
  /**
   * The panel's cross-client backstop: ten clients' worth of the panel budget.
   *
   * Deliberately far above what one person can spend, because a global budget
   * that a single panel user can exhaust is a lockout, not a limit.
   */
  const panelGlobalLimiter = createRateLimiter({ limit: PANEL_LIMIT * 10 });
  /**
   * The launch-token visit budget, per client.
   *
   * Only the *minting* is limited: a `?token=` visit that the platform accepts
   * used to add a device row, so a stranger could add fifty of them in a burst.
   * The exchange itself is never refused — the platform's own cookie is not a
   * resource this plugin hands out — but it buys no row once the budget is gone.
   */
  const entryLimiter = createRateLimiter();

  /** Read the password material; absent or malformed reads as absent. */
  async function readRecovery() {
    const credentials = getCredentials();
    if (credentials === undefined) return undefined;
    const record = await attempt(() => credentials.readRecord(RECOVERY_RECORD_KEY));
    const payload = record?.payload;
    if (payload === null || typeof payload !== 'object') return undefined;
    if (typeof payload.key !== 'string' || typeof payload.salt !== 'string' || typeof payload.secret !== 'string') return undefined;
    return {
      key: payload.key,
      salt: payload.salt,
      secret: payload.secret,
      iterations: Number.isSafeInteger(payload.iterations) ? payload.iterations : PBKDF2_ITERATIONS,
      createdAt: typeof payload.createdAt === 'string' ? payload.createdAt : undefined,
    };
  }

  /** Store password material: the derived key, its salt, and the ticket secret. */
  async function writeRecovery(record) {
    await modifyRecordGuarded(RECOVERY_RECORD_KEY, async () => ({ version: 1, ...record }));
    return record;
  }

  /** Forget the password and every ticket it minted. */
  async function clearRecovery() {
    const credentials = getCredentials();
    if (credentials === undefined) return;
    await attemptAsync(() => credentials.deleteRecord(RECOVERY_RECORD_KEY));
    challenges.clear();
    recoverLimiter.clear();
    recoverGlobalLimiter.clear();
  }

  /**
   * The legacy device-token rows (v1).
   *
   * Read-only on purpose: this record is the migration source, not a live
   * store. Nothing is ever written back to it, so a rollback to the previous
   * plugin version still finds its own rows untouched.
   */
  async function readTokens() {
    const credentials = getCredentials();
    if (credentials === undefined) return [];
    const record = await attempt(() => credentials.readRecord(TOKENS_RECORD_KEY));
    const payload = record?.payload;
    if (payload === null || typeof payload !== 'object' || !Array.isArray(payload.tokens)) return [];
    return payload.tokens.filter((row) => row !== null && typeof row === 'object' && typeof row.hash === 'string');
  }

  /**
   * Issue one durable device credential and record its row.
   *
   * The cookie value is returned and never stored; the row keeps only its
   * sha256 fingerprint. `days: null` is the explicit "never expires" choice —
   * and, as everywhere in this plugin, it is not renewed on use.
   * @returns `{ token, id, expiresAt }`: the cookie value to hand out, and the
   *   row's identity so a caller can report or reference what it just created.
   */
  async function issueDeviceToken(req, { days = DEFAULT_DEVICE_DAYS, source = 'device-code', temporary = false } = {}) {
    const token = newDeviceToken();
    const now = Date.now();
    const expiresAt = expiryFromDays(days);
    const id = newRecordId();
    const rows = await readDeviceRows();
    rows.unshift({
      id,
      name: deviceLabel(String(req?.headers?.['user-agent'] ?? '')),
      source,
      temporary,
      createdAt: new Date(now).toISOString(),
      lastUsedAt: new Date(now).toISOString(),
      lastUsedIp: clientAddress(req),
      // `null` means "never expires" — an explicit choice, not an accident.
      expiresAt,
      days: days === null ? null : Number(days),
      hash: hashDeviceToken(token),
    });
    await writeDeviceRows(rows);
    return { token, id, expiresAt };
  }

  /**
   * Whether this request carries a live device credential.
   *
   * A one-time link is refused here outright. Its row's fingerprint would match
   * if someone simply pasted the token into the `mc-device` cookie, and that
   * would hand out a working session for fifteen minutes *without* burning the
   * single use the link promises. A temp token is only ever redeemed through
   * {@link redeemTempToken}, which removes the row as it accepts it.
   *
   * A hit refreshes `lastUsedAt` and `lastUsedIp` at most once an hour. The
   * expiry is **not** extended: the lifetime is whatever was chosen when the
   * credential was issued (or set afterwards in the panel), so what the panel
   * shows is what is true.
   */
  async function deviceAuthorized(req) {
    const presented = cookieValue(req, DEVICE_COOKIE);
    if (presented === undefined || isTempToken(presented)) return false;
    const rows = await readDeviceRows();
    const index = rows.findIndex((row) => deviceTokenMatches(presented, row.hash));
    if (index < 0) return false;
    const row = rows[index];
    if (deviceStatus(row) === 'expired') {
      // Expired: the row stays so the panel can show it as expired, but it no
      // longer authorizes anything.
      return false;
    }
    const last = Date.parse(String(row.lastUsedAt ?? ''));
    if (!Number.isFinite(last) || Date.now() - last > 60 * 60 * 1000) {
      row.lastUsedAt = new Date().toISOString();
      row.lastUsedIp = clientAddress(req);
      await writeDeviceRows(rows);
    }
    return true;
  }

  /**
   * The URL inside a one-time link: this instance's own clean entry URL with
   * *our* single-use temp token as its only token.
   *
   * The platform's launch token never appears here — not in the link, not in
   * its QR. What the phone carries is a credential this plugin minted, can list,
   * and can revoke.
   */
  function tempEntry(req, token) {
    const entry = entryUrl(req);
    const url = `${entry.url}?${TOKEN_QUERY}=${encodeURIComponent(token)}`;
    return { authority: entry.authority, url, qr: qrFor(url), reachable: entry.reachable };
  }

  /**
   * Mint a one-time link and the row that makes it redeemable once.
   *
   * The row is what the panel lists while the link is outstanding, and it is
   * deleted — not merely marked used — the moment the link is opened, so a
   * captured link has nothing left to match.
   * @param name - an explicit label; when omitted, one is derived from the door.
   * @param parentId - the device this link belongs to, when it was minted for one.
   */
  async function mintTempLink(req, source, name, parentId) {
    const token = newTempToken();
    const now = Date.now();
    const label = deviceLabel(String(req?.headers?.['user-agent'] ?? ''));
    const row = {
      id: newRecordId(),
      name: absentText(name) ?? (source === 'access-key' ? `${label} · access key` : label),
      source,
      temporary: true,
      createdAt: new Date(now).toISOString(),
      lastUsedAt: null,
      expiresAt: tempTokenExpiry(now),
      days: null,
      hash: hashTempToken(token),
      ...(absentText(parentId) === undefined ? {} : { parentId: absentText(parentId) }),
    };
    const rows = await readDeviceRows();
    rows.unshift(row);
    await writeDeviceRows(rows);
    return { id: row.id, token, expiresAt: row.expiresAt, ...tempEntry(req, token) };
  }

  /**
   * Redeem a temp token: exactly once, and only while it is fresh.
   *
   * The row is removed before the expiry is even considered, so an expired link
   * is burned by the attempt too. A link minted *for a device* also has to have
   * that device still live: revoking a device has to take its outstanding links
   * with it, and a link that outlived its device would be a way back in for a
   * credential the panel says is gone.
   *
   * Returns the row on success.
   */
  async function redeemTempToken(value) {
    if (!isTempToken(value)) return undefined;
    const row = await takeDeviceRow((candidate) => tempTokenMatches(value, candidate.hash));
    if (row === undefined) return undefined;
    if (deviceStatus(row) === 'expired') return undefined;
    const parentId = absentText(row.parentId);
    if (parentId !== undefined) {
      const parent = (await readDeviceRows()).find((candidate) => candidate.id === parentId);
      if (parent === undefined || deviceStatus(parent) === 'expired') return undefined;
    }
    return row;
  }

  /** Invalidate a one-time link whose page closed itself. Best effort. */
  async function burnTempToken(value) {
    if (!isTempToken(value)) return false;
    const row = await attemptAsync(() => takeDeviceRow((candidate) => tempTokenMatches(value, candidate.hash)));
    return row !== undefined;
  }

  /**
   * Check a presented access key against the store.
   *
   * Every stored row is compared, in constant time, before any decision; the
   * loop deliberately does not stop early on a prefix match, and a malformed
   * presented value never reaches it at all.
   * @returns the matched row, or undefined.
   */
  async function verifyAccessKey(presented) {
    const normalized = normalizeAccessKey(presented);
    if (normalized === undefined) return undefined;
    const rows = await readKeyRows();
    const index = rows.findIndex((row) => accessKeyMatches(normalized, row.hash));
    if (index < 0) return undefined;
    const row = rows[index];
    if (deviceStatus(row) === 'expired') return undefined;
    row.lastUsedAt = new Date().toISOString();
    await writeKeyRows(rows);
    return row;
  }

  /** The pairing-code rows; absent or malformed reads as empty. */
  async function readPairCodes() {
    const credentials = getCredentials();
    if (credentials === undefined) return [];
    const record = await attempt(() => credentials.readRecord(PAIR_RECORD_KEY));
    const payload = record?.payload;
    if (payload === null || typeof payload !== 'object' || !Array.isArray(payload.codes)) return [];
    return payload.codes.filter((row) => row !== null && typeof row === 'object' && typeof row.hash === 'string');
  }

  /** A pairing-code row that has been redeemed. */
  function pairCodeUsed(row) {
    return typeof row?.usedAt === 'string' && row.usedAt !== '';
  }

  /**
   * Keep the record from growing without bound.
   *
   * Unused rows are all kept (they are the ones that still work, and there are at
   * most `MAX_TOKENS` of them); used rows are kept only while they are recent
   * enough to be worth showing, and only the most recent handful. The panel polls
   * a code's status to tell "used" from "expired", so a used row that has aged out
   * reads as unknown — which is honest.
   */
  function prunePairCodes(rows, now) {
    const unused = rows.filter((row) => !pairCodeUsed(row));
    const recentUsed = rows
      .filter(pairCodeUsed)
      .filter((row) => {
        const used = Date.parse(row.usedAt);
        return Number.isFinite(used) && now - used <= USED_PAIR_CODE_TTL_MS;
      })
      .sort((a, b) => Date.parse(b.usedAt) - Date.parse(a.usedAt))
      .slice(0, MAX_USED_PAIR_CODES);
    return [...unused.slice(0, MAX_TOKENS), ...recentUsed];
  }

  /**
   * Persist the pairing-code rows.
   *
   * Used rows are kept, not deleted: "already used" has to be distinguishable
   * from "expired" and from "never existed", and only a kept row can say which.
   */
  async function writePairCodes(codes) {
    const now = Date.now();
    const live = prunePairCodes(codes, now).filter(
      (row) => pairCodeUsed(row) || (typeof row.expiresAt === 'number' && row.expiresAt > now),
    );
    await modifyRecordGuarded(PAIR_RECORD_KEY, async () => ({ version: 1, codes: live }));
    return live;
  }

  /**
   * Mint a one-time pairing code.
   *
   * It exists so a device can be added while nobody is at the computer: the code
   * is short-lived, single-use, rate-limited on redemption, and can only be
   * created from an already authorized session. It carries the lifetime the new
   * device's token should get.
   *
   * The URL is built on the resolved link authority, never on the request's own
   * `Host`: a code generated in the desktop panel at `127.0.0.1:3080` has to
   * open on a phone, so it points at the tunnel or the LAN address instead.
   */
  async function mintPairCode(req, days) {
    const code = newPairCode();
    const hash = hashPairCode(code);
    const expiresAt = Date.now() + DEFAULT_PAIR_MINUTES * 60 * 1000;
    // The row gets an id the panel can poll: the code itself is only ever shown
    // once, and its fingerprint is not something to hand out.
    const id = newRecordId();
    const rows = await readPairCodes();
    rows.unshift({ id, hash, createdAt: new Date().toISOString(), expiresAt, days: days === null ? null : Number(days) });
    await writePairCodes(rows);
    const resolved = linkBase(req);
    const url = `${resolved.scheme}://${resolved.base}${CHANNEL}/unlock?code=${encodeURIComponent(code)}`;
    return {
      id,
      code,
      expiresAt,
      days: days === null ? null : Number(days),
      url,
      qr: qrFor(url),
      reachable: resolved.reachable,
    };
  }

  /**
   * Redeem a pairing code: single use, and only while it is fresh.
   *
   * The match-and-mark happens inside `modifyRecord`'s callback, against the
   * record's current value — the same compare-and-swap `takeDeviceRow` uses. A
   * read/splice/write cycle looks equivalent and is not: twelve concurrent
   * redemptions of one code all read the same rows, all find it, and all win.
   *
   * The row is **marked**, never removed, so the panel can still tell that this
   * code was used rather than expired — or never minted at all.
   *
   * @returns the token lifetime it carries, or undefined when it is not valid.
   */
  async function redeemPairCode(code) {
    const hash = hashPairCode(code);
    if (hash === undefined) return undefined;
    let taken;
    await modifyRecordGuarded(PAIR_RECORD_KEY, async (previous) => {
      const rows = Array.isArray(previous?.payload?.codes) ? previous.payload.codes : [];
      const index = rows.findIndex((row) => row !== null && typeof row === 'object' && fingerprintsMatch(hash, row.hash));
      // No match: leave the record untouched rather than handing the store back
      // a value it may already have refused to spell.
      if (index < 0) return undefined;
      const row = rows[index];
      // Already used, or past its life: refuse without touching the record, so
      // the status it reports stays the truth.
      if (pairCodeUsed(row)) return undefined;
      if (typeof row.expiresAt !== 'number' || row.expiresAt <= Date.now()) return undefined;
      taken = row;
      const now = Date.now();
      // Marked, never removed: "used" has to stay distinguishable from "expired".
      rows[index] = { ...row, usedAt: new Date(now).toISOString() };
      return { version: 1, codes: prunePairCodes(rows, now) };
    });
    if (taken === undefined) return undefined;
    return { days: taken.days === null ? null : Number(taken.days) };
  }

  /**
   * Whether this request carries a live unlock ticket.
   *
   * A ticket is only ever a *view* of one authorized-device row: it names that
   * row, and it stops working the moment the row is gone. That is what makes
   * "revoke" mean revoked — a ticket that only proved its own signature would
   * keep a deleted one-time link usable for the rest of its fifteen minutes,
   * including through the root gate's redirect. A ticket with no row (anything
   * minted before this rule) is refused rather than grandfathered in.
   */
  async function ticketAuthorized(req) {
    const recovery = await readRecovery();
    if (recovery === undefined) return false;
    const payload = verifyTicket(recovery.secret, cookieValue(req, UNLOCK_COOKIE));
    if (payload === undefined) return false;
    const rowId = typeof payload.row === 'string' ? payload.row : undefined;
    if (rowId === undefined) return false;
    const rows = await readDeviceRows();
    const row = rows.find((candidate) => candidate.id === rowId);
    return row !== undefined && deviceStatus(row) !== 'expired';
  }

  /** Read one cookie from the request. */
  function cookieValue(req, name) {
    const header = req?.headers?.cookie;
    if (typeof header !== 'string') return undefined;
    for (const part of header.split(';')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      if (part.slice(0, eq).trim() !== name) continue;
      const raw = part.slice(eq + 1).trim();
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    }
    return undefined;
  }

  /**
   * The client address a limit is counted against.
   *
   * `cf-connecting-ip` and `x-forwarded-for` are *claims*, and any caller can
   * make one — a fresh address per request turned a five-attempt budget into no
   * budget at all. They are believed only when the TCP peer is the loopback
   * proxy that cloudflared and the desktop panel actually are; anything else is
   * counted against the socket address it really came from.
   */
  function clientAddress(req) {
    if (isLoopbackSocket(req)) {
      const forwarded = req?.headers?.['cf-connecting-ip'] ?? req?.headers?.['x-forwarded-for'];
      const first = Array.isArray(forwarded) ? forwarded[0] : forwarded;
      if (typeof first === 'string' && first.trim() !== '') return first.split(',')[0].trim();
    }
    const socket = String(req?.socket?.remoteAddress ?? '');
    return socket === '' ? 'unknown' : socket;
  }

  /** Whole seconds until the stricter of two limiters lets this client try again. */
  function retrySeconds(perClient, global, address) {
    const wait = Math.max(perClient.retryAfterMs(address), global.retryAfterMs(GLOBAL_LIMIT_KEY));
    return Math.max(1, Math.ceil(wait / 1000));
  }

  /** The password door's wait, in seconds. */
  function throttleSeconds(address) {
    return retrySeconds(recoverLimiter, recoverGlobalLimiter, address);
  }

  /** The access-key door's wait, in seconds. */
  function keyThrottleSeconds(address) {
    return retrySeconds(keyLimiter, keyGlobalLimiter, address);
  }

  /** The link-minting wait, in seconds. */
  function linkThrottleSeconds(address) {
    return retrySeconds(linkLimiter, linkGlobalLimiter, address);
  }

  /** Whether the one-time log line about a refused platform-authenticated caller was written. */
  let notAuthorizedLogged = false;

  /** The panel's wait, in seconds. */
  function panelThrottleSeconds(address) {
    return retrySeconds(panelLimiter, panelGlobalLimiter, address);
  }

  /**
   * The two channels, read per request so a switch takes effect immediately.
   *
   * Absent, malformed or unreadable reads as **both on**: a policy record the
   * plugin cannot parse must never be the reason nobody can get in.
   */
  async function readAccessPolicy() {
    const credentials = getCredentials();
    if (credentials === undefined) return { ...DEFAULT_ACCESS_POLICY };
    const record = await attempt(() => credentials.readRecord(ACCESS_POLICY_RECORD_KEY));
    const payload = record?.payload;
    if (payload === null || typeof payload !== 'object') return { ...DEFAULT_ACCESS_POLICY };
    return {
      // Only an explicit `false` switches a channel off; anything else is on.
      temporaryAccess: payload.temporaryAccess !== false,
      deviceAccess: payload.deviceAccess !== false,
    };
  }

  /** Store the policy, through the same guard as every other record. */
  async function writeAccessPolicy(policy) {
    await modifyRecordGuarded(ACCESS_POLICY_RECORD_KEY, async () => ({
      version: 1,
      temporaryAccess: policy.temporaryAccess !== false,
      deviceAccess: policy.deviceAccess !== false,
    }));
    return { temporaryAccess: policy.temporaryAccess !== false, deviceAccess: policy.deviceAccess !== false };
  }

  /** The refusal for whichever channel is off, naming it and the way back. */
  function channelRefusal(policy) {
    if (policy.temporaryAccess === false) {
      return {
        code: 'remote-access/temporary-disabled',
        message: 'temporary links are switched off; turn the temporary-link channel back on in the panel to use or mint one',
      };
    }
    return {
      code: 'remote-access/device-disabled',
      message: 'authorized devices are switched off; turn the device channel back on in the panel to pair or use one',
    };
  }

  /**
   * Refuse a request whose channel is off, in the shape it asked for.
   *
   * A JSON client gets the structured refusal; a navigation gets the recovery
   * page with the reason in its subtitle, because a phone that scanned a code
   * has to be told something it can read.
   */
  async function answerChannelOff(req, res, url, policy) {
    const { code, message } = channelRefusal(policy);
    if (answerFormat(req, url, 'html') === 'json') {
      sendJson(res, 403, fail(code, message));
      return;
    }
    await serveRecoveryPage(req, res, false, message);
  }

  /**
   * Spend one panel mint, or refuse with the wait.
   *
   * The fenced panel actions share one budget, counted per client and per mint —
   * not per row, and not per failure. A successful mint clears nothing: the
   * budget bounds how much can be minted, so a person clicking through the panel
   * spends it exactly the way a script would, and the refusal carries
   * `details.retryAfter` so the panel can show a countdown instead of a sentence.
   *
   * @param what - the plural noun for the refusal message.
   */
  function spendPanelMint(req, what) {
    const address = clientAddress(req);
    if (panelLimiter.allowed(address) && panelGlobalLimiter.allowed(GLOBAL_LIMIT_KEY)) {
      panelLimiter.fail(address);
      panelGlobalLimiter.fail(GLOBAL_LIMIT_KEY);
      return;
    }
    const retryAfter = panelThrottleSeconds(address);
    throw refusal('remote-access/panel-throttled', `too many ${what} just now; retry in ${retryAfter}s`, { retryAfter });
  }

  /** Whether this request arrived on a loopback socket. */
  function isLoopbackSocket(req) {
    const address = String(req?.socket?.remoteAddress ?? '');
    return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
  }

  /**
   * Refuse a platform-authenticated caller that holds no live plugin credential.
   *
   * The platform's cookie is not this plugin's authorization: after a device row
   * is revoked the browser still holds a session, and forwarding it would keep a
   * revoked device inside the app. A navigation gets the recovery page, with the
   * reason in its subtitle, because a person is looking at it; a JSON client gets
   * the structured refusal. The first refusal is logged, once, so the migration
   * consequence is visible rather than silent.
   */
  async function refuseNotAuthorized(req, res, url, { json = false } = {}) {
    const message =
      'this browser is signed in to the platform but no longer authorized by the remote-access panel; pair again with a code or use the recovery password';
    if (!notAuthorizedLogged) {
      notAuthorizedLogged = true;
      attempt(() =>
        ctx.logger?.warn?.(
          `dsh-remote-access: refused a platform-authenticated public caller with no live plugin credential (${classifyRequestOrigin(req?.headers, req?.socket?.remoteAddress).via}); a device row may have been revoked`,
        ),
      );
    }
    // The panel API is JSON whatever the caller said it accepts; the root gate
    // gives a navigation the page, because a person is looking at it.
    if (json || answerFormat(req, url, 'html') === 'json') {
      sendJson(res, 403, fail('remote-access/not-authorized', message));
      return;
    }
    await serveRecoveryPage(req, res, req.method === 'HEAD', message);
  }

  /** One peer address as a bare literal, without the IPv4-mapped prefix. */
  function peerAddress(req, which) {
    return String(req?.socket?.[which] ?? '')
      .replace(/^::ffff:/, '')
      .trim();
  }

  /** Whether two authorities name the same host and port, ignoring default ports. */
  function sameAuthority(left, right) {
    const parse = (value) => {
      const text = String(value ?? '').trim();
      if (text === '') return undefined;
      const url = attempt(() => new URL(text.includes('://') ? text : `http://${text}`));
      if (url === undefined) return undefined;
      const host = url.hostname.replace(/^\[|\]$/g, '');
      const port = url.port !== '' ? url.port : url.protocol === 'https:' ? '443' : '80';
      return `${host}:${port}`;
    };
    const a = parse(left);
    const b = parse(right);
    return a !== undefined && a === b;
  }

  /** Whether this machine's own addresses include one text. */
  function isOwnAddress(address) {
    const value = String(address ?? '').replace(/^::ffff:/, '');
    if (value === '') return false;
    if (isLoopbackAuthority(value)) return true;
    return localAddresses().some((entry) => entry.address === value);
  }

  /**
   * Whether this request comes from the machine running the plugin.
   *
   * Three ways to be local, in order of directness:
   *
   *  - the loopback authority from a loopback socket — the desktop's own
   *    `127.0.0.1` visit, which is what the panel itself uses;
   *  - a self-dial to a *non-loopback* interface (`localAddress` and
   *    `remoteAddress` are the same LAN literal), which is how the desktop
   *    reaches a listener bound to a LAN address in LAN mode;
   *  - the listener's own bind authority with a peer that is one of this machine's
   *    own addresses, for the shapes where the source address differs.
   *
   * Two shapes are deliberately *not* local, because treating them as local would
   * hand the tunnel a free pass through this gate:
   *
   *  - a loopback self-dial to a public authority — that is exactly the shape of a
   *    tunnel client (cloudflared) or a local process forging a `Host`, and the
   *    desktop never needs it;
   *  - anything carrying a proxy's client header (`cf-connecting-ip`,
   *    `x-forwarded-for`, `x-real-ip`), which a direct browser self-dial never
   *    sends.
   *
   * A phone on the same LAN is local by none of these: its authority is not
   * loopback, its socket is not a self-dial, and its peer is its own address.
   */
  function isLocalCaller(req, authority) {
    if (isLoopbackAuthority(authority) && isLoopbackSocket(req)) return true;
    const headers = req?.headers ?? {};
    const proxied = [headers['cf-connecting-ip'], headers['x-forwarded-for'], headers['x-real-ip']].some(
      (value) => typeof value === 'string' && value.trim() !== '',
    );
    if (proxied) return false;
    const local = peerAddress(req, 'localAddress');
    const remote = peerAddress(req, 'remoteAddress');
    if (local !== '' && local === remote && !isLoopbackAuthority(local)) return true;
    const facts = attempt(() => listenerFacts()) ?? {};
    const bind = String(facts.host ?? '');
    if (bind !== '' && validBindAddress(bind) !== undefined) {
      const bound = `${bind}${facts.port === undefined ? '' : `:${facts.port}`}`;
      if (sameAuthority(authority, bound)) return isOwnAddress(remote);
    }
    return false;
  }

  /**
   * Which shape a client wants: the JSON API, the browser's redirect, or the page.
   *
   * The pairing flow must not depend on page JavaScript. A browser navigation
   * says `text/html` and gets a 303 straight into the app; the page's own fetch
   * says `application/json` and gets the JSON it renders; anything that says
   * neither (a script, an old client) gets `fallback`, which is the JSON for the
   * POST API and the redirect for a page navigation. `?format=json|html|page`
   * overrides everything, so both shapes stay reachable from a shell.
   *
   * @returns `'json' | 'html' | 'page'`.
   */
  function answerFormat(req, url, fallback) {
    const explicit = String(url?.searchParams?.get('format') ?? '').trim().toLowerCase();
    if (explicit === 'json' || explicit === 'html' || explicit === 'page') return explicit;
    const accept = String(req?.headers?.accept ?? '').toLowerCase();
    if (accept.includes('application/json')) return 'json';
    if (accept.includes('text/html') || accept.includes('application/xhtml+xml')) return 'html';
    return fallback;
  }

  /**
   * Whether this request is a link preview rather than a person.
   *
   * Prefetching clients must never redeem a one-time code: a chat client that
   * fetches the URL to draw a card would burn the code before anyone scanned it.
   * The header is a claim, but believing it costs nothing — a prefetch gets the
   * page instead of the redirect, and the page redeems nothing on its own.
   */
  function isPrefetch(req) {
    const value = ['purpose', 'x-purpose', 'x-moz', 'sec-purpose']
      .map((name) => String(req?.headers?.[name] ?? '').trim().toLowerCase())
      .join(' ');
    return value.includes('prefetch') || value.includes('preview');
  }

  /**
   * Answer a successful pairing with a redirect into the app.
   *
   * The cookies ride on the 303 itself, and the browser's next request to that
   * URL is answered by the root gate, which turns the device credential into a
   * platform session and sends it on to `/`. No script runs anywhere along that
   * path, which is the point: a QR code leads to an in-app browser with unknown
   * JavaScript, and "the page said it worked" is not the same as being inside.
   */
  function sendPairingRedirect(res, entry, cookie) {
    const headers = {
      location: entry.url,
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    };
    if (cookie !== undefined) headers['set-cookie'] = cookie;
    res.writeHead(303, headers);
    res.end();
  }

  /**
   * Whether this request carries a cross-site marker.
   *
   * The platform refuses cross-site callers on its own API; the public doors here
   * sit outside that check, so they apply it themselves. `sec-fetch-site` is the
   * browser's own statement — script cannot set it — and `Origin`, when present,
   * has to name the authority being called. A request with neither (curl, a
   * direct navigation, the desktop shell) is not cross-site, which is what keeps
   * the local workflow working.
   */
  function crossSiteRequest(req) {
    const site = String(req?.headers?.['sec-fetch-site'] ?? '').trim().toLowerCase();
    if (site === 'cross-site') return true;
    const raw = req?.headers?.origin;
    const origin = String(Array.isArray(raw) ? raw[0] : (raw ?? '')).trim();
    if (origin === '') return false;
    // `Origin: null` is a sandboxed frame or a `data:` URL: never our own page.
    if (origin.toLowerCase() === 'null') return true;
    const parsed = attempt(() => new URL(origin));
    if (parsed === undefined) return true;
    return parsed.host.toLowerCase() !== String(req?.headers?.host ?? '').trim().toLowerCase();
  }

  /** Whether a POST body is the JSON this API speaks. */
  function jsonRequest(req) {
    const mediaType = String(req?.headers?.['content-type'] ?? '').split(';', 1)[0].trim().toLowerCase();
    return mediaType === 'application/json';
  }

  /** One Set-Cookie value for this listener's protocol. */
  function cookieValueFor(req, name, value, maxAgeSeconds) {
    const parts = [
      `${name}=${encodeURIComponent(value)}`,
      `Max-Age=${maxAgeSeconds}`,
      `Expires=${new Date(Date.now() + maxAgeSeconds * 1000).toUTCString()}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
    ];
    if (requestScheme(req) === 'https') parts.push('Secure');
    return parts.join('; ');
  }

  /** Write an HTML response. */
  function sendHtml(res, status, html) {
    res.statusCode = status;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.setHeader('cache-control', 'no-store');
    res.setHeader('referrer-policy', 'no-referrer');
    res.end(html);
  }

  /**
   * Forward a request to the platform's own index.
   *
   * The dial address is the listener's *actual* bind, not loopback: in LAN mode
   * the process is bound to one concrete interface and nothing answers on
   * 127.0.0.1, so a hard-coded loopback upstream turned every page request into
   * `502 ... ECONNREFUSED` and left local-network mode with no UI at all.
   *
   * The caller's `Host` is preserved on purpose: the browser cookie is bound to
   * an authority and the platform's fence reads the same header, so rewriting it
   * would both fail authentication and look untrusted. Extra cookies are merged
   * into the upstream `set-cookie` list so a pairing can hand out the device
   * token in the same response.
   *
   * Three things keep this from becoming a stuck socket, which over a tunnel
   * surfaces as a Cloudflare 502/524 with nothing in the log:
   *
   *  1. a body-length header is never forwarded on a request whose body is not
   *     forwarded — a lying `Content-Length` used to leave both ends waiting for
   *     bytes that never came, and the client waited out Node's 300s default;
   *  2. the upstream gets a deadline of its own, after which it is destroyed and
   *     the client is told 504;
   *  3. if the client goes away first, the upstream is destroyed with it, so a
   *     stalled or vanished browser cannot pin a connection.
   */
  function forwardIndex(req, res, cookies = []) {
    const facts = listenerFacts();
    const target = localDialTarget(facts.host, facts.port);
    const method = String(req.method ?? 'GET').toUpperCase();
    // A GET/HEAD carries no body, and `req.pipe` would forward nothing — so the
    // length headers go too. Forwarding `content-length` while sending no body
    // is a promise the upstream then waits on.
    const carriesBody = method !== 'GET' && method !== 'HEAD';
    const headers = { ...req.headers };
    if (!carriesBody) {
      for (const name of ['content-length', 'content-type', 'transfer-encoding', 'expect']) delete headers[name];
    }
    let settled = false;
    const finish = () => {
      settled = true;
    };
    const upstream = httpRequest(
      {
        host: target.host,
        port: target.port,
        method,
        path: '/index.html',
        headers,
      },
      (answer) => {
        const answerHeaders = { ...answer.headers };
        if (cookies.length > 0) {
          const existing = answerHeaders['set-cookie'];
          answerHeaders['set-cookie'] = Array.isArray(existing) ? [...existing, ...cookies] : existing === undefined ? cookies : [existing, ...cookies];
        }
        res.writeHead(answer.statusCode ?? 502, answerHeaders);
        if (method === 'HEAD') {
          // A HEAD answer has no body to pipe; draining it and ending here is
          // what keeps the connection reusable instead of hanging on `end`.
          answer.resume();
          res.end();
          finish();
          return;
        }
        answer.pipe(res);
        answer.on('end', finish);
        answer.on('error', finish);
      },
    );
    // (2) A deadline, so a silent upstream cannot hold the client for five
    // minutes. 504 is the honest answer: the gateway waited and gave up.
    const timeoutMs = config.forwardTimeoutMs;
    const deadline = setTimeout(() => {
      if (settled) return;
      finish();
      attempt(() => upstream.destroy());
      if (!res.headersSent) {
        res.statusCode = 504;
        res.setHeader('content-type', 'text/plain; charset=utf-8');
        res.setHeader('cache-control', 'no-store');
        res.end('dsh-remote-access: the platform index did not answer in time\n');
      } else {
        attempt(() => res.end());
      }
    }, timeoutMs);
    if (typeof deadline.unref === 'function') deadline.unref();
    upstream.on('error', (error) => {
      clearTimeout(deadline);
      if (settled) return;
      finish();
      if (!res.headersSent) {
        res.statusCode = 502;
        res.setHeader('content-type', 'text/plain; charset=utf-8');
        res.end(`dsh-remote-access: index forward failed: ${error.message}`);
      } else {
        attempt(() => res.end());
      }
    });
    upstream.on('close', () => clearTimeout(deadline));
    // (3) The client is gone: drop the upstream rather than finish a response
    // nobody is reading.
    const abandon = () => {
      if (settled) return;
      finish();
      clearTimeout(deadline);
      attempt(() => upstream.destroy());
    };
    req.on('aborted', abandon);
    res.on('close', () => {
      if (!res.writableEnded) abandon();
    });
    if (carriesBody) req.pipe(upstream);
    else upstream.end();
  }

  /**
   * The recovery page.
   *
   * Fail-closed by construction: with no password stored, `configured` is false,
   * the page renders no form at all, and the challenge endpoint below refuses.
   * An unset password can therefore never mean "no password required".
   *
   * The page speaks the Web UI's own language rather than the browser's: the
   * locale is resolved from the live settings per request (see `requestLocale`),
   * so a phone that follows a recovery link from a Chinese desktop reads Chinese
   * even when its browser asks for English, and a language change takes effect on
   * the very next request.
   */
  async function serveRecoveryPage(req, res, headOnly = false, notice) {
    const recovery = await readRecovery();
    const devices = await readDeviceRows();
    const locale = requestLocale(ctx, req);
    const kind = recovery !== undefined ? 'configured' : devices.length > 0 ? 'missing-paired' : 'missing-unpaired';
    const strings = pageStrings(locale, kind);
    const html = unlockPageHtml({
      prefix: CHANNEL,
      configured: recovery !== undefined,
      lang: locale,
      ...strings,
      // A refusal the panel can undo is worth saying in the page's own subtitle:
      // the words come from the host, so no locale table has to grow a key for a
      // state the page does not otherwise have.
      ...(typeof notice === 'string' && notice !== '' ? { subtitle: notice } : {}),
    });
    sendHtml(res, 200, headOnly ? '' : html);
  }

  /**
   * Ask the platform to exchange whatever this request presents, and capture its
   * answer instead of writing it.
   *
   * The exchange lives in `connection.authorizeIndex`, and it only fires for a
   * request whose path is exactly `/` — the very path this plugin owns. So a
   * launch-token visit cannot be handed to the platform by proxying it to
   * `/index.html` (that path never mints a cookie, and proxying `/` would loop
   * straight back into this gate). The platform's own authorizer is therefore
   * called here, against a response stand-in.
   *
   * Nothing is written, and that is the whole point: the platform's verdict has
   * to be known *before* a response exists, so that a credential this plugin
   * mints can never ride along with a refusal. `accepted` is that verdict —
   * true only when the platform itself minted a session for this request.
   *
   * @returns `{ accepted, status, headers, body }`, or undefined when there was
   *   no authorizer to ask or it declined without answering.
   */
  function exchangeIndex(req) {
    const connection = getConnection();
    if (connection === undefined || typeof connection.authorizeIndex !== 'function') return undefined;
    const captured = { status: 200, headers: {}, chunks: [], answered: false };
    const proxy = {
      statusCode: 200,
      headersSent: false,
      setHeader(name, value) {
        captured.headers[String(name).toLowerCase()] = value;
        return proxy;
      },
      getHeader(name) {
        return captured.headers[String(name).toLowerCase()];
      },
      removeHeader(name) {
        delete captured.headers[String(name).toLowerCase()];
      },
      writeHead(status, headers) {
        captured.status = status;
        captured.headersSent = true;
        proxy.statusCode = status;
        if (headers !== null && typeof headers === 'object') {
          for (const [name, value] of Object.entries(headers)) captured.headers[String(name).toLowerCase()] = value;
        }
        return proxy;
      },
      write(chunk) {
        if (chunk !== undefined) captured.chunks.push(chunk);
        return true;
      },
      end(chunk) {
        if (chunk !== undefined) captured.chunks.push(chunk);
        captured.answered = true;
        return proxy;
      },
    };
    const handled = attempt(() => connection.authorizeIndex(req, proxy));
    if (handled !== false || !captured.answered) return undefined;
    const cookies = captured.headers['set-cookie'];
    const minted = Array.isArray(cookies) ? cookies.length > 0 : cookies !== undefined;
    return {
      // A redirect *with* a cookie is the platform handing out a session; its
      // 401 is a refusal, and a refusal is never a place to attach anything.
      accepted: captured.status >= 300 && captured.status < 400 && minted,
      status: captured.status,
      headers: captured.headers,
      body: captured.chunks.length === 0 ? undefined : Buffer.concat(captured.chunks.map((part) => (Buffer.isBuffer(part) ? part : Buffer.from(String(part))))),
    };
  }

  /**
   * Write a captured exchange answer, merging our cookies only into an accepted
   * one.
   *
   * This is the invariant, in one place: a response the platform refused leaves
   * with no credential of ours attached — not because a caller remembered to
   * check, but because there is no code path here that can do it.
   */
  function writeIndexAnswer(res, answer, cookies = []) {
    const headers = { ...answer.headers };
    if (answer.accepted && cookies.length > 0) {
      const existing = headers['set-cookie'];
      headers['set-cookie'] = existing === undefined ? cookies : Array.isArray(existing) ? [...existing, ...cookies] : [existing, ...cookies];
    }
    res.writeHead(answer.status, headers);
    res.end(answer.body);
  }

  /**
   * Let the platform exchange a launch token for its own cookie, keeping ours.
   *
   * @returns whether the platform wrote the response (it owns it when it did).
   */
  function authorizeIndexWithCookies(req, res, cookies = []) {
    const answer = exchangeIndex(req);
    if (answer === undefined) return false;
    writeIndexAnswer(res, answer, cookies);
    return true;
  }

  /**
   * One visit carrying a `token` parameter: a one-time link, or the platform's
   * own launch token.
   *
   * A one-time link is burned and the browser sent on with a fresh launch token.
   * A launch token buys the platform's cookie through its own authorizer, plus
   * our 30-day device credential — but only once the platform has *accepted*
   * that token. That order is not a detail: minting first and forwarding the
   * platform's 401 afterwards handed a valid device credential to any stranger
   * who asked for `?token=1`, and that credential was then worth a platform
   * cookie through the reentry path. An unproven token is not a key.
   *
   * @returns whether the response was written.
   */
  async function handleTokenVisit(req, res, presented, policy) {
    if (isTempToken(presented)) {
      // Burned whether or not it had already expired, so a captured link has
      // exactly one chance and no replay window.
      const redeemed = await redeemTempToken(presented);
      if (redeemed === undefined) return false;
      reenter(res, req);
      return true;
    }
    const answer = exchangeIndex(req);
    // Not the platform's launch token (or no authorizer to ask): fall through to
    // the ordinary gate, so `?token=1` behaves exactly like a bare `GET /`.
    if (answer === undefined || !answer.accepted) return false;
    let cookies = [];
    try {
      if (!(await deviceAuthorized(req))) {
        // An entry link *is* a temporary credential, so a switched-off temporary
        // channel means the visit still gets the platform's own session but no
        // credential of ours — nothing is minted, nothing is refused either, and
        // the desktop bootstrap keeps working.
        if (policy?.temporaryAccess === false) {
          writeIndexAnswer(res, answer);
          return true;
        }
        // Minting is the rate-limited part: this is the only row an
        // unauthenticated caller can cause, and it must not be a free resource.
        const address = clientAddress(req);
        if (!entryLimiter.allowed(address)) {
          writeIndexAnswer(res, answer);
          return true;
        }
        entryLimiter.fail(address);
        const issued = await issueDeviceToken(req, { days: ENTRY_LINK_DAYS, source: 'entry-link', temporary: true });
        cookies = [cookieValueFor(req, DEVICE_COOKIE, issued.token, ENTRY_LINK_DAYS * 24 * 60 * 60)];
      }
    } catch {
      cookies = [];
    }
    writeIndexAnswer(res, answer, cookies);
    return true;
  }

  /**
   * The root gate.
   *
   * Loopback, a launch token, a live device credential, a live (short) unlock
   * ticket, a one-time link and an authenticated caller all keep the platform's
   * own behaviour; only a genuinely unauthenticated remote visit gets the
   * recovery page.
   */
  async function handleRoot(req, res, url) {
    // The webserver calls an exact-route handler as `handler(req, res)`, so the
    // third argument is absent in practice and the request line is the only
    // source of the query string. An explicit URL is still honoured when one is
    // handed in, which keeps the handler drivable from a test.
    const requested = url instanceof URL ? url : attempt(() => new URL(String(req?.url ?? '/'), 'http://localhost'));
    if (requested === undefined) {
      res.statusCode = 400;
      res.end();
      return;
    }
    const host = String(req?.headers?.host ?? '');
    const connection = getConnection();
    if (connection === undefined || typeof connection.requestRejection !== 'function') {
      res.statusCode = 503;
      res.end();
      return;
    }
    const presented = requested.searchParams.has(TOKEN_QUERY) ? String(requested.searchParams.get(TOKEN_QUERY) ?? '') : undefined;
    // An absent or empty `token` is no token at all: `?token=` has to behave
    // exactly like a bare `GET /`. A non-empty one still has to prove itself to
    // the platform before it buys anything (see `handleTokenVisit`).
    const visit = presented === undefined || presented === '' ? undefined : presented;
    // The platform's own verdict is taken first, and a refused authority ends the
    // request right here — before the token visit, before our credentials, and
    // before any redirect. `reenter` builds its answer from this Host, so a
    // refused authority used to be told where the process launch token lives, and
    // a `?token=` visit from one used to be able to add a device row.
    const rejection = connection.requestRejection(req);
    if (rejection === 403) {
      res.statusCode = 403;
      res.end();
      return;
    }
    // The two channels, read now, so a switch in the panel takes effect on this
    // request. Nothing is deleted: a refused credential is simply not accepted.
    const policy = await readAccessPolicy();
    if (visit !== undefined && isTempToken(visit) && policy.temporaryAccess === false) {
      await answerChannelOff(req, res, requested, policy);
      return;
    }
    if (isLoopbackAuthority(host) && isLoopbackSocket(req)) {
      // A local browser arriving from the printed `?token=` URL needs the same
      // exchange a remote one does. The index proxy below requests
      // `/index.html`, and the platform only mints a cookie for a path of
      // exactly `/`, so proxying here would hand a fresh local browser a 401.
      if (visit !== undefined && (await handleTokenVisit(req, res, visit, policy))) return;
      forwardIndex(req, res);
      return;
    }
    if (visit !== undefined && (await handleTokenVisit(req, res, visit, policy))) return;
    // The platform's own verdict comes before our credentials. A caller the
    // platform already accepts — a live browser cookie, an API credential — is
    // simply served; only a caller it turns away gets sent through a device
    // credential. Checking ours first would bounce an already-authenticated
    // device through a fresh launch token on every visit, and, because that
    // token visit mints a new platform cookie and redirects back to `/`, it
    // would never stop.
    if (rejection === undefined) {
      // The platform accepts this caller, but the platform's cookie is not this
      // plugin's authorization. A local caller (the desktop) is served as always;
      // everyone else must still hold a live plugin credential, or a browser
      // whose device row was revoked would keep getting in on the platform's
      // say-so — which is exactly what a revoked device must stop doing.
      if (isLocalCaller(req, host)) {
        forwardIndex(req, res);
        return;
      }
      const hasDevice = await deviceAuthorized(req);
      const hasTicket = await ticketAuthorized(req);
      if (hasDevice && policy.deviceAccess === false) {
        await answerChannelOff(req, res, requested, policy);
        return;
      }
      if (hasTicket && policy.temporaryAccess === false) {
        await answerChannelOff(req, res, requested, policy);
        return;
      }
      if (!hasDevice && !hasTicket) {
        await refuseNotAuthorized(req, res, requested);
        return;
      }
      forwardIndex(req, res);
      return;
    }
    if (await deviceAuthorized(req)) {
      if (policy.deviceAccess === false) {
        await answerChannelOff(req, res, requested, policy);
        return;
      }
      reenter(res, req);
      return;
    }
    if (await ticketAuthorized(req)) {
      if (policy.temporaryAccess === false) {
        await answerChannelOff(req, res, requested, policy);
        return;
      }
      reenter(res, req);
      return;
    }
    if (rejection === 401) {
      // Silence by default: with no password armed, an unauthenticated stranger
      // gets exactly what the platform would have sent — its own 401 — instead
      // of a page that announces this plugin and its configuration state.
      const recovery = await readRecovery();
      if (recovery === undefined) {
        forwardIndex(req, res);
        return;
      }
      await serveRecoveryPage(req, res, req.method === 'HEAD');
      return;
    }
    res.statusCode = rejection;
    res.end();
  }

  /**
   * Redeem a pairing code and issue the device credential it buys.
   *
   * Both doors that can carry a code go through here — the page's own fetch and
   * a plain navigation — so a code is still single-use whichever shape asked for
   * it, and the rate limit counts the same budget for both.
   *
   * @returns `{ ok: true, entry, cookie, expiresAt, days }`, or
   *   `{ ok: false, throttled?, address }` when the code was not good.
   */
  async function issuePairedDevice(req, code) {
    const address = clientAddress(req);
    if (!recoverLimiter.allowed(address)) return { ok: false, throttled: true, address };
    const policy = await redeemPairCode(normalizePairCode(code));
    if (policy === undefined) {
      recoverLimiter.fail(address);
      return { ok: false, address };
    }
    recoverLimiter.reset(address);
    const issued = await issueDeviceToken(req, {
      days: policy.days === null ? null : policy.days,
      source: 'device-code',
      temporary: false,
    });
    const seconds = policy.days === null ? 10 * 365 * 24 * 60 * 60 : policy.days * 24 * 60 * 60;
    return {
      ok: true,
      entry: entryUrl(req),
      cookie: cookieValueFor(req, DEVICE_COOKIE, issued.token, seconds),
      expiresAt: issued.expiresAt,
      days: policy.days,
    };
  }

  /**
   * The recovery endpoints, behind the Host/Origin fence only.
   *
   * They must work precisely when the platform credential has lapsed, so they
   * deliberately skip the browser check. The password, the device credential and
   * a rate limit are the gate.
   *
   * The pairing-code door is the one exception to the fail-closed rule below:
   * a code can be minted from the panel whether or not a recovery password is
   * armed, so redeeming one must not depend on the password either. The code is
   * still single-use, short-lived and rate-limited; what the no-password rule
   * protects is the password door itself — the page, the challenge and the
   * proof check — not the credential a code carries.
   */
  async function handleRecoveryRoute(req, res, url) {
    const suffix = url.pathname.slice(`${CHANNEL}/unlock`.length).replace(/^\//, '');
    const host = String(req?.headers?.host ?? '');
    if (probeTrust(getConnection(), host) === 'refused') {
      res.statusCode = 403;
      res.end();
      return;
    }

    if (suffix === 'pair' && req.method === 'POST') {
      const pairPolicy = await readAccessPolicy();
      if (pairPolicy.deviceAccess === false) {
        await answerChannelOff(req, res, url, pairPolicy);
        return;
      }
      if (!jsonRequest(req)) {
        sendJson(res, 415, fail('remote-access/bad-request', 'this endpoint takes application/json'));
        return;
      }
      const format = answerFormat(req, url, 'json');
      const raw = await readBoundedBody(req);
      if (raw === null) {
        sendJson(res, 413, fail('remote-access/too-large', `request body exceeds ${MAX_BODY_BYTES} bytes`));
        return;
      }
      let payload = {};
      try {
        payload = raw.trim() === '' ? {} : JSON.parse(raw);
      } catch {
        payload = {};
      }
      const issued = await issuePairedDevice(req, payload?.code);
      if (issued.ok !== true) {
        if (issued.throttled === true) {
          sendJson(res, 429, fail('remote-access/recovery-throttled', `too many attempts; retry in ${throttleSeconds(issued.address)}s`));
          return;
        }
        // A browser that posted this way gets the page, whose own script reports
        // the refusal; a script gets the shape it has always had.
        if (format === 'html') {
          await serveRecoveryPage(req, res, false);
          return;
        }
        sendJson(res, 200, fail('remote-access/pair-denied', 'pairing code rejected or expired'));
        return;
      }
      if (format === 'html') {
        // The landing, done by the server: cookies on the redirect, no script.
        sendPairingRedirect(res, issued.entry, issued.cookie);
        return;
      }
      // The page's own path: it renders the link and the QR as a fallback, and
      // the plain anchor it shows is a real way in if its script never runs.
      res.setHeader('set-cookie', issued.cookie);
      sendJson(
        res,
        200,
        ok({
          url: issued.entry.url,
          qr: qrFor(issued.entry.url),
          expiresAt: issued.expiresAt,
          days: issued.days,
          reachable: issued.entry.reachable,
        }),
      );
      return;
    }

    // Fail closed and stay quiet: with no password armed this whole route behaves
    // as if it did not exist, so probing it reveals nothing. (A live device
    // credential never needs these endpoints — the root gate redirects it on.)
    // The pairing page is its own door. A QR code hands the phone
    // `/unlock?code=…`, and that page has to be served whether or not a
    // recovery password is armed — the code is the credential, it is single-use
    // and rate-limited, and the silence below protects the *password* door, not
    // this one. A bare page view still says nothing without a password.
    //
    // `entry` is exempt for the same reason: it answers only to an unlock ticket
    // or a device credential and checks both itself, so a paired phone with no
    // password armed can still ask for its entry link.
    const pairingPage =
      suffix === '' && (req.method === 'GET' || req.method === 'HEAD') && normalizePairCode(url.searchParams.get('code')) !== undefined;
    const selfAuthenticating = suffix === 'entry' && req.method === 'POST';
    if (!pairingPage && !selfAuthenticating && (await readRecovery()) === undefined) {
      res.statusCode = 404;
      res.end();
      return;
    }

    if (suffix === '' && (req.method === 'GET' || req.method === 'HEAD')) {
      const code = normalizePairCode(url.searchParams.get('code'));
      const format = answerFormat(req, url, 'html');
      // A plain navigation carrying a code is landed by the server: no page, no
      // script, no "it said it worked". A prefetch is never allowed to redeem —
      // a link preview must not burn a code nobody has scanned yet — and
      // `?format=page` asks for the page explicitly.
      if (code !== undefined && format !== 'page' && !isPrefetch(req)) {
        const pagePolicy = await readAccessPolicy();
        if (pagePolicy.deviceAccess === false) {
          await answerChannelOff(req, res, url, pagePolicy);
          return;
        }
        const issued = await issuePairedDevice(req, code);
        if (issued.ok === true) {
          if (format === 'json') {
            res.setHeader('set-cookie', issued.cookie);
            sendJson(
              res,
              200,
              ok({
                url: issued.entry.url,
                qr: qrFor(issued.entry.url),
                expiresAt: issued.expiresAt,
                days: issued.days,
                reachable: issued.entry.reachable,
              }),
            );
            return;
          }
          sendPairingRedirect(res, issued.entry, issued.cookie);
          return;
        }
        if (issued.throttled === true) {
          sendJson(res, 429, fail('remote-access/recovery-throttled', `too many attempts; retry in ${throttleSeconds(issued.address)}s`));
          return;
        }
        // A rejected code is a refusal, not a page. The shape the request asked
        // for decides, exactly as on the POST door — a client that said JSON must
        // not be handed the recovery page and left to guess.
        if (format === 'json') {
          sendJson(res, 200, fail('remote-access/pair-denied', 'pairing code rejected or expired'));
          return;
        }
        // The page reports the refusal itself, in words, when its script runs.
      }
      await serveRecoveryPage(req, res, req.method === 'HEAD');
      return;
    }

    if (suffix === 'challenge' && req.method === 'POST') {
      if (!jsonRequest(req)) {
        sendJson(res, 415, fail('remote-access/bad-request', 'this endpoint takes application/json'));
        return;
      }
      const recovery = await readRecovery();
      if (recovery === undefined) {
        // Fail closed: no password means no challenge, never a free pass.
        sendJson(res, 200, fail('remote-access/recovery-missing', 'no recovery password is set on this machine'));
        return;
      }
      const address = clientAddress(req);
      if (!recoverLimiter.allowed(address) || !recoverGlobalLimiter.allowed(GLOBAL_LIMIT_KEY)) {
        sendJson(res, 429, fail('remote-access/recovery-throttled', `too many attempts; retry in ${throttleSeconds(address)}s`));
        return;
      }
      const stamp = Date.now();
      for (const [nonce, issued] of challenges) {
        if (stamp - issued > CHALLENGE_TTL_MS) challenges.delete(nonce);
      }
      const nonce = newNonce();
      challenges.set(nonce, stamp);
      sendJson(res, 200, ok({ nonce, salt: recovery.salt, iterations: recovery.iterations }));
      return;
    }

    if (suffix === 'verify' && req.method === 'POST') {
      const verifyPolicy = await readAccessPolicy();
      if (verifyPolicy.temporaryAccess === false) {
        await answerChannelOff(req, res, url, verifyPolicy);
        return;
      }
      if (!jsonRequest(req)) {
        sendJson(res, 415, fail('remote-access/bad-request', 'this endpoint takes application/json'));
        return;
      }
      const address = clientAddress(req);
      if (!recoverLimiter.allowed(address) || !recoverGlobalLimiter.allowed(GLOBAL_LIMIT_KEY)) {
        sendJson(res, 429, fail('remote-access/recovery-throttled', `too many attempts; retry in ${throttleSeconds(address)}s`));
        return;
      }
      const raw = await readBoundedBody(req);
      if (raw === null) {
        sendJson(res, 413, fail('remote-access/too-large', `request body exceeds ${MAX_BODY_BYTES} bytes`));
        return;
      }
      let payload = {};
      try {
        payload = raw.trim() === '' ? {} : JSON.parse(raw);
      } catch {
        payload = {};
      }
      const nonce = typeof payload?.nonce === 'string' ? payload.nonce : '';
      const issued = challenges.get(nonce);
      challenges.delete(nonce);
      const recovery = await readRecovery();
      const fresh = issued !== undefined && Date.now() - issued <= CHALLENGE_TTL_MS;
      if (recovery === undefined || !fresh || !verifyProof(recovery.key, nonce, payload?.proof)) {
        recoverLimiter.fail(address);
        recoverGlobalLimiter.fail(GLOBAL_LIMIT_KEY);
        sendJson(res, 200, fail('remote-access/recovery-denied', 'password rejected'));
        return;
      }
      recoverLimiter.reset(address);
      recoverGlobalLimiter.reset(GLOBAL_LIMIT_KEY);
      // The password buys a one-time link now, not a long session: it is a temp
      // token in the URL, single use, dead after 15 minutes. The ticket is set
      // only so this page's own following /unlock/entry call still works, it
      // lives exactly as long as the link does, and it carries the row id — so
      // revoking that row in the panel kills the ticket too.
      const minted = await mintTempLink(req, 'password');
      const ticket = signTicket(recovery.secret, { v: 1, exp: minted.expiresAt, iat: Date.now(), row: minted.id });
      const seconds = Math.max(1, Math.floor((minted.expiresAt - Date.now()) / 1000));
      res.setHeader('set-cookie', cookieValueFor(req, UNLOCK_COOKIE, ticket, seconds));
      sendJson(res, 200, ok({ url: minted.url, qr: minted.qr, expiresAt: minted.expiresAt, reachable: minted.reachable }));
      return;
    }

    if (suffix === 'entry' && req.method === 'POST') {
      if (!jsonRequest(req)) {
        sendJson(res, 415, fail('remote-access/bad-request', 'this endpoint takes application/json'));
        return;
      }
      // Each way in belongs to its own channel: the ticket is the temporary
      // link's short-lived view, the device cookie is the durable credential.
      const entryPolicy = await readAccessPolicy();
      const allowed =
        (entryPolicy.temporaryAccess !== false && (await ticketAuthorized(req))) ||
        (entryPolicy.deviceAccess !== false && (await deviceAuthorized(req)));
      if (!allowed) {
        sendJson(res, 401, fail('remote-access/recovery-required', 'unlock first'));
        return;
      }
      // A clean URL and its matrix — no launch token. This answer is printed,
      // copied and screenshotted; it must not be a key to the process.
      const entry = entryUrl(req);
      sendJson(res, 200, ok({ authority: entry.authority, url: entry.url, qr: qrFor(entry.url), reachable: entry.reachable }));
      return;
    }

    sendJson(res, 404, fail('remote-access/bad-request', `unknown recovery endpoint ${JSON.stringify(suffix)}`));
  }

  /**
   * `POST /remote-access/token` — the access-key door.
   *
   * Behind the Host/Origin fence and nothing else: it exists precisely for the
   * browser that has no platform cookie left. The key is compared in constant
   * time, the failure budget is five attempts per quarter hour per client *and*
   * five across every client, and a success mints a one-time link rather than
   * any kind of session. With no key stored the endpoint answers 404, exactly as
   * the password door does when no password is armed: an unconfigured door is
   * indistinguishable from a missing one.
   */
  async function handleAccessKeyRoute(req, res) {
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.setHeader('allow', 'POST');
      res.end();
      return;
    }
    if (!jsonRequest(req)) {
      sendJson(res, 415, fail('remote-access/bad-request', 'this endpoint takes application/json'));
      return;
    }
    if (probeTrust(getConnection(), String(req?.headers?.host ?? '')) === 'refused') {
      res.statusCode = 403;
      res.end();
      return;
    }
    if ((await readKeyRows()).length === 0) {
      res.statusCode = 404;
      res.end();
      return;
    }
    const keyPolicy = await readAccessPolicy();
    if (keyPolicy.temporaryAccess === false) {
      sendJson(res, 403, fail('remote-access/temporary-disabled', channelRefusal(keyPolicy).message));
      return;
    }
    const address = clientAddress(req);
    if (!keyLimiter.allowed(address) || !keyGlobalLimiter.allowed(GLOBAL_LIMIT_KEY)) {
      sendJson(res, 429, fail('remote-access/key-throttled', `too many attempts; retry in ${keyThrottleSeconds(address)}s`));
      return;
    }
    const raw = await readBoundedBody(req);
    if (raw === null) {
      sendJson(res, 413, fail('remote-access/too-large', `request body exceeds ${MAX_BODY_BYTES} bytes`));
      return;
    }
    let payload = {};
    try {
      payload = raw.trim() === '' ? {} : JSON.parse(raw);
    } catch {
      payload = {};
    }
    const row = await verifyAccessKey(payload?.key);
    if (row === undefined) {
      keyLimiter.fail(address);
      keyGlobalLimiter.fail(GLOBAL_LIMIT_KEY);
      sendJson(res, 200, fail('remote-access/key-denied', 'access key rejected'));
      return;
    }
    keyLimiter.reset(address);
    keyGlobalLimiter.reset(GLOBAL_LIMIT_KEY);
    const minted = await mintTempLink(req, 'access-key');
    sendJson(res, 200, ok({ url: minted.url, qr: minted.qr, expiresAt: minted.expiresAt, reachable: minted.reachable }));
  }

  /**
   * `POST /remote-access/page-close` — invalidate a one-time link whose page
   * closed itself.
   *
   * A beacon: no authentication beyond the token being the capability, no
   * failure that matters, and never a throw. Calling it twice, calling it with
   * nothing, or calling it with a device cookie all answer the same `ok` with
   * `closed: false`.
   */
  async function handlePageCloseRoute(req, res) {
    let closed = false;
    try {
      if (req.method !== 'POST') {
        res.statusCode = 405;
        res.setHeader('allow', 'POST');
        res.end();
        return;
      }
      if (!jsonRequest(req)) {
        sendJson(res, 415, fail('remote-access/bad-request', 'this endpoint takes application/json'));
        return;
      }
      if (probeTrust(getConnection(), String(req?.headers?.host ?? '')) === 'refused') {
        res.statusCode = 403;
        res.end();
        return;
      }
      let payload = {};
      try {
        const raw = await readBoundedBody(req);
        payload = raw !== null && raw.trim() !== '' ? JSON.parse(raw) : {};
      } catch {
        payload = {};
      }
      const token = typeof payload?.token === 'string' ? payload.token : '';
      closed = token === '' ? false : await burnTempToken(token);
    } catch {
      closed = false;
    }
    try {
      sendJson(res, 200, ok({ closed }));
    } catch {
      // The socket is already gone; there is nothing left to answer.
    }
  }

  /**
   * The error code one failure answers with.
   *
   * A handler that knows why it refused can say so by setting `code` on the
   * error it throws (for example `remote-access/device-not-found`), and the
   * panel can then render something useful instead of a generic "internal".
   * Anything else — including a code that does not look like ours — stays the
   * generic one, so a thrown platform error cannot invent a code.
   */
  function failureCode(error) {
    const code = attempt(() => error?.code);
    return typeof code === 'string' && /^remote-access\/[a-z0-9-]+$/.test(code) ? code : 'remote-access/internal';
  }

  /** One refusal error carrying the code the panel should branch on. */
  function refusal(code, message, details) {
    const error = new Error(message);
    error.code = code;
    // Extra fields the panel can render (a countdown, for instance) travel in
    // the error payload rather than only inside its sentence.
    if (details !== undefined) error.details = details;
    return error;
  }

  /**
   * Answer one failure as JSON, and put it in the log.
   *
   * A handler that throws must not become the webserver's bare 400: the panel
   * needs the reason, and the log needs the stack, or the next bug is a blank
   * page nobody can explain. Every route below funnels its unexpected failures
   * through here, and the endpoint map keeps its own per-handler answer.
   */
  function reportFailure(res, error, where) {
    const message = error instanceof Error ? error.message : String(error);
    attempt(() => ctx.logger?.warn?.(error instanceof Error ? error : new Error(`dsh-remote-access: ${where}: ${message}`)));
    if (attempt(() => res.headersSent) === true) {
      attempt(() => res.end());
      return;
    }
    attempt(() => sendJson(res, 200, fail(failureCode(error), `${where}: ${message}`, error?.details ?? {})));
  }

  /** One JSON endpoint, or one of the self-authenticating routes. */
  async function handleChannelRoute(req, res) {
          // The platform's fence first: an untrusted or unauthenticated caller
          // never reaches a handler or a body read. Without the connection
          // service there is no fence, so this route fails closed.
          const connection = getConnection();
          if (connection === undefined || typeof connection.requestRejection !== 'function') {
            res.statusCode = 503;
            res.end();
            return;
          }
          // The recovery endpoints authenticate themselves: they must work
          // precisely when the platform credential has lapsed, so they pass the
          // Host/Origin fence but not the browser check. The access-key door and
          // the close beacon live on the same footing for the same reason.
          const requested = new URL(String(req.url), 'http://localhost');
          const isPublicDoor =
            requested.pathname === `${CHANNEL}/unlock` ||
            requested.pathname.startsWith(`${CHANNEL}/unlock/`) ||
            requested.pathname === `${CHANNEL}/token` ||
            requested.pathname === `${CHANNEL}/page-close`;
          // The public doors skip the browser check by design, so they carry the
          // fence's *cross-site* half themselves. Without this, a page on any
          // origin could POST a stolen pairing code, a guessed access key or a
          // link's own close beacon — the platform's CSRF defence covers `/api`,
          // and these doors are not on it.
          if (isPublicDoor && crossSiteRequest(req)) {
            res.statusCode = 403;
            res.end();
            return;
          }
          if (requested.pathname === `${CHANNEL}/unlock` || requested.pathname.startsWith(`${CHANNEL}/unlock/`)) {
            await handleRecoveryRoute(req, res, requested);
            return;
          }
          if (requested.pathname === `${CHANNEL}/token`) {
            await handleAccessKeyRoute(req, res);
            return;
          }
          if (requested.pathname === `${CHANNEL}/page-close`) {
            await handlePageCloseRoute(req, res);
            return;
          }
          const rejection = connection.requestRejection(req);
          if (rejection !== undefined) {
            res.statusCode = rejection;
            res.end();
            return;
          }
          // The same rule as the root gate, for the panel's own JSON API: a
          // public-authority caller the platform accepts still has to hold a live
          // plugin credential. The desktop is local, so nothing changes there.
          {
            const authority = String(req?.headers?.host ?? '');
            if (!isLocalCaller(req, authority)) {
              const panelPolicy = await readAccessPolicy();
              const hasDevice = await deviceAuthorized(req);
              const hasTicket = await ticketAuthorized(req);
              if (hasDevice && panelPolicy.deviceAccess === false) {
                sendJson(res, 403, fail('remote-access/device-disabled', channelRefusal(panelPolicy).message));
                return;
              }
              if (hasTicket && panelPolicy.temporaryAccess === false) {
                sendJson(res, 403, fail('remote-access/temporary-disabled', channelRefusal(panelPolicy).message));
                return;
              }
              if (!hasDevice && !hasTicket) {
                await refuseNotAuthorized(req, res, new URL(String(req.url ?? '/'), 'http://localhost'), { json: true });
                return;
              }
            }
          }
          if (req.method !== 'POST') {
            res.statusCode = 405;
            res.setHeader('allow', 'POST');
            res.end();
            return;
          }
          const mediaType = String(req.headers['content-type'] || '')
            .split(';', 1)[0]
            .trim()
            .toLowerCase();
          if (mediaType !== 'application/json') {
            sendJson(res, 415, fail('remote-access/bad-request', 'content type must be application/json'));
            return;
          }
          const pathname = new URL(String(req.url), 'http://localhost').pathname;
          const endpoint = pathname.slice(CHANNEL.length).replace(/^\//, '');
          if (!ENDPOINT_RE.test(endpoint)) {
            sendJson(res, 404, fail('remote-access/bad-request', 'malformed endpoint'));
            return;
          }
          const fn = Object.prototype.hasOwnProperty.call(handlers, endpoint) ? handlers[endpoint] : undefined;
          if (typeof fn !== 'function') {
            sendJson(res, 404, fail('remote-access/bad-request', `unknown endpoint ${JSON.stringify(endpoint)}`));
            return;
          }
          const raw = await readBoundedBody(req);
          if (raw === null) {
            sendJson(res, 413, fail('remote-access/too-large', `request body exceeds ${MAX_BODY_BYTES} bytes`));
            return;
          }
          let payload = {};
          if (raw.trim() !== '') {
            try {
              payload = JSON.parse(raw);
            } catch {
              sendJson(res, 400, fail('remote-access/bad-request', 'body is not valid JSON'));
              return;
            }
          }
          try {
            const args = payload !== null && typeof payload === 'object' ? payload : {};
            sendJson(res, 200, ok(await fn(args, req)));
          } catch (error) {
            reportFailure(res, error, endpoint);
          }
  }

  /** The route: one prefix handler for JSON endpoints, one exact asset route. */
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'prefix',
        path: CHANNEL,
        handler: async (req, res) => {
          try {
            await handleChannelRoute(req, res);
          } catch (error) {
            reportFailure(res, error, `${CHANNEL} route`);
          }
        },
      }),
    `dsh-remote-access: ${CHANNEL} route`,
  );

  /**
   * Claim the root path for the recovery gate.
   *
   * `/` is answered by the frontend fallback rather than by a named route, so an
   * exact route wins. If the composition refuses the claim, the plugin keeps
   * working through `/remote-access/unlock` — but the refusal is recorded and
   * reported in `state.capabilities`, because a silently missing root gate looks
   * exactly like "the panel loads but a link does nothing", which is not a thing
   * to debug twice.
   */
  let rootGate = { ok: false, error: 'not attempted' };
  ctx.effect(() => {
    try {
      const dispose = ctx.webServer.register({
        kind: 'exact',
        path: '/',
        handler: async (req, res) => {
          try {
            await handleRoot(req, res);
          } catch (error) {
            reportFailure(res, error, 'root gate');
          }
        },
      });
      rootGate = { ok: true };
      return dispose;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      rootGate = { ok: false, error: message };
      attempt(() => ctx.logger?.warn?.(new Error(`dsh-remote-access: the root gate could not claim "/" (${message}); links fall back to /remote-access/unlock`)));
      return () => {};
    }
  }, 'dsh-remote-access: root gate');

  // The heartbeat asset is public, like every other static asset the platform
  // serves: it carries no secret, and it must load on a page whose own index
  // request was already authenticated.
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'exact',
        path: HEARTBEAT_PATH,
        handler: (req, res) => {
          if (req.method !== 'GET' && req.method !== 'HEAD') {
            res.statusCode = 405;
            res.setHeader('allow', 'GET, HEAD');
            res.end();
            return;
          }
          const body = HEARTBEAT_SCRIPT;
          res.statusCode = 200;
          res.setHeader('content-type', 'text/javascript; charset=utf-8');
          res.setHeader('cache-control', 'no-store');
          res.end(req.method === 'HEAD' ? undefined : body);
        },
      }),
    `dsh-remote-access: ${HEARTBEAT_PATH} asset`,
  );

  // The setup guide ships as a runtime skill: installing the plugin installs the
  // guide, unloading the plugin removes it, and nothing is written into the
  // user's own skills directory.
  ctx.effect(() => {
    const skills = ctx.get('skills');
    if (skills === undefined || typeof skills.register !== 'function') return () => {};
    const off = skills.register(skillRegistration(name));
    return () => {
      if (typeof off === 'function') off();
    };
  }, 'dsh-remote-access: setup skill');

  // Every rendered index carries the heartbeat, so a phone that loads the UI
  // once shows up in the device view.
  ctx.effect(
    () =>
      ctx.webServer.tapIndex((html) => {
        if (typeof html !== 'string' || html.includes(HEARTBEAT_PATH)) return html;
        const tag = `<script defer src="${HEARTBEAT_PATH}"></script>`;
        return html.includes('</body>') ? html.replace('</body>', `${tag}</body>`) : html + tag;
      }),
    'dsh-remote-access: heartbeat injection',
  );

  // A child process must not outlive the plugin that started it.
  ctx.effect(() => () => {
    attempt(() => tunnel?.handle?.terminate?.());
    tunnel = null;
  }, 'dsh-remote-access: tunnel child');

  // Activation-time credential-record migration. Fire-and-forget on purpose: it
  // is best effort, and the panel's state call re-attempts it. The second copy
  // waits for the first, because it reads the record the first one writes.
  void migrateLegacyRecords().then(() => migrateDeviceRecords());
}

/** Inline heartbeat asset: one ping per page load, mobile user agents only. */
const HEARTBEAT_SCRIPT = `(function () {
  try {
    var KEY = 'dsh-remote-access-device';
    var ua = navigator.userAgent || '';
    if (!/Mobi|Android|iPhone|iPad|iPod/i.test(ua)) return;
    var id = '';
    try { id = localStorage.getItem(KEY) || ''; } catch (e) {}
    if (!id) {
      id = (self.crypto && self.crypto.randomUUID) ? self.crypto.randomUUID()
        : String(Date.now()) + '-' + Math.random().toString(16).slice(2);
      try { localStorage.setItem(KEY, id); } catch (e) {}
    }
    fetch('${CHANNEL}/heartbeat', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: id, ua: ua, path: location.pathname }),
      keepalive: true
    }).catch(function () {});
  } catch (e) {}
})();
`;

export {
  apply,
  inject,
  name,
  ROW_ID,
  CHANNEL,
  HEARTBEAT_PATH,
  DEVICE_RECORD_KEY,
  DEVICES_V2_RECORD_KEY,
  ACCESS_KEYS_RECORD_KEY,
  ENTRY_LINK_DAYS,
  PLATFORM_SESSION_KEY,
  reachabilityOf,
};