/**
 * dsh-mobile-console — host half.
 *
 * Route A: the phone uses the shipped Web UI over a Cloudflare named tunnel
 * (optionally behind Cloudflare Access). The platform already authenticates that
 * traffic — a per-process launch token exchanged for a signed, authority-bound
 * cookie, plus a Host/Origin fence — so this plugin never re-implements login.
 * What it adds is everything around that:
 *
 *  - `/mobile-console/state` and friends: the entry URLs (with the process's
 *    fresh launch token), a QR matrix for each, the trust verdict for the tunnel
 *    authority, the cloudflared child process, the devices that recently
 *    connected, and the platform cookie lifetime.
 *  - `/mobile-console/heartbeat`: the phone-side ping behind the injected
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
 * @module dsh-mobile-console
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
import { dirname } from 'node:path';
import { skillRegistration } from './skill.js';
import { randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import {
  PBKDF2_ITERATIONS,
  UNLOCK_COOKIE,
  DEVICE_COOKIE,
  DEFAULT_TICKET_DAYS,
  DEFAULT_DEVICE_DAYS,
  createRateLimiter,
  deriveKey,
  deviceTokenMatches,
  hashDeviceToken,
  newDeviceToken,
  newNonce,
  newSalt,
  qrSvg,
  signTicket,
  unlockPageHtml,
  verifyProof,
  verifyTicket,
} from './unlock.js';

/** Cordis plugin name reported to the loader. */
const name = 'mobile-console';

/**
 * `webServer` is a hard dependency: without a route there is nothing to serve.
 * `connection`, `credentials`, `configEditor`, `subprocess`, `webApp` and
 * `webStartup` are read through `ctx.get`, so this plugin still activates in a
 * composition that mounts only some of them.
 */
const inject = ['webServer'];

/** Absolute route prefix owned by this plugin; must match the client half. */
const CHANNEL = '/mobile-console';

/** Public static asset injected into the SPA index; holds no secret. */
const HEARTBEAT_PATH = '/mobile-console/heartbeat.js';

/** Credential record holding the device view, under this plugin's own scope. */
const DEVICE_RECORD_KEY = 'dsh-mobile-console/devices';

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
const DEFAULT_TUNNEL_NAME = 'dsh-mobile-console';

/** Panel requests are small JSON objects; anything larger is hostile. */
const MAX_BODY_BYTES = 64 * 1024;

/** Device rows kept in the view. */
const MAX_DEVICES = 50;

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

  // ── Device view ────────────────────────────────────────────────────────────

  /** Read the device rows; an absent or malformed record reads as empty. */
  async function readDevices() {
    const credentials = getCredentials();
    if (credentials === undefined) return [];
    const record = await attempt(() => credentials.readRecord(DEVICE_RECORD_KEY));
    const payload = record?.payload;
    if (payload === null || typeof payload !== 'object' || !Array.isArray(payload.devices)) return [];
    return payload.devices.filter((d) => d !== null && typeof d === 'object' && typeof d.id === 'string');
  }

  /** Persist the device rows under this plugin's own credential scope. */
  async function writeDevices(devices) {
    const credentials = getCredentials();
    if (credentials === undefined) throw new Error('the credentials service is unavailable in this composition');
    const kept = devices
      .slice()
      .sort((a, b) => Number(b.lastSeenAt ?? 0) - Number(a.lastSeenAt ?? 0))
      .slice(0, MAX_DEVICES);
    await credentials.modifyRecord(DEVICE_RECORD_KEY, async () => ({
      kind: 'grant',
      payload: { version: 1, devices: kept },
    }));
    return kept;
  }

  /** Drop rows that have not been seen inside the retention window. */
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
   * Write the tunnel authority into the shipped `connection` row's
   * `trustedHosts`, keeping whatever `--trusted-host` values the command line
   * supplied. That row's only config field is `trustedHosts`, so restating it
   * loses nothing.
   */
  async function writeTrustedHosts(authority) {
    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry('connection');
    if (entry === undefined) throw new Error('the profile has no "connection" row to write');
    const fromCli = attempt(() => ctx.get('webStartup')?.trustedHosts) ?? [];
    const merged = [...new Set([...(Array.isArray(fromCli) ? fromCli : []), authority].filter(Boolean))];
    await editor.edit(entry, (current) => ({ ...baseConfig('connection', current), trustedHosts: merged }));
    return { trustedHosts: merged, trust: probeTrust(getConnection(), authority) };
  }

  /**
   * Bind the listener to one concrete local interface. The shipped `webserver`
   * row carries host, port, tls and compression, so the write restates the
   * row's other values rather than dropping them.
   */
  async function writeLanHost(host) {
    const literal = validBindAddress(host);
    if (literal === undefined) {
      throw new Error('a bind address must be one concrete IPv4 or IPv6 literal; wildcards are refused by the platform');
    }
    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry('webserver');
    if (entry === undefined) throw new Error('the profile has no "webserver" row to write');
    await editor.edit(entry, (current) => ({ ...baseConfig('webserver', current), host: literal }));
    return { host: literal };
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
   * That is how `dsh-mobile-console/unlock-secret` once bricked a start, so the
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
    const entry = findEntry('mobile-console');
    if (entry === undefined) throw new Error('the profile has no "mobile-console" row to write');
    await editor.edit(entry, (current) => ({ ...baseConfig('mobile-console', current), ...patch }));
    return { ...patch };
  }

  // ── Endpoint map ───────────────────────────────────────────────────────────

  const handlers = {
    /** Everything the panel renders. */
    async state(args, req) {
      const facts = listenerFacts();
      const entries = buildEntries();
      const devices = prune(await readDevices());
      const cookieDays = cookieMaxAgeDays();
      const now = Date.now();
      const addresses = localAddresses();
      const here = classifyRequestOrigin(req?.headers, req?.socket?.remoteAddress);
      const recoveryRecord = await readRecovery();
      const tokenRows = await readTokens();
      return {
        config,
        /** The name this machine should use: dsh-mac, dsh-win, dsh-lin… */
        suggestedLabel: suggestedLabelFor(process.platform),
        platform: process.platform,
        /** The recovery door: whether a password is armed, and the device tokens. */
        recovery: {
          configured: recoveryRecord !== undefined,
          createdAt: recoveryRecord?.createdAt,
          ticketDays: DEFAULT_TICKET_DAYS,
          deviceDays: DEFAULT_DEVICE_DAYS,
          // The fingerprints stay on the host; the panel only needs the metadata.
          tokens: tokenRows.map(({ hash, ...rest }) => rest),
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
        devices: devices.map((d) => ({
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
        },
      };
    },

    /** Phone-side ping from the injected script; feeds the device view. */
    async heartbeat(args, req) {
      const id = text(args?.id);
      if (id === undefined) throw new Error('heartbeat requires a device id');
      const ua = text(args?.ua) ?? String(req?.headers?.['user-agent'] ?? '');
      const origin = classifyRequestOrigin(req?.headers, req?.socket?.remoteAddress);
      const devices = await readDevices();
      await writeDevices(prune(upsertDevice(devices, { id, ua, ip: origin.clientIp, via: origin.via })));
      return { recorded: true, via: origin.via };
    },

    /** Rename one device row (a label, never an authorization). */
    async 'device-rename'(args) {
      const id = text(args?.id);
      const next = text(args?.name);
      if (id === undefined || next === undefined) throw new Error('device-rename requires id and name');
      const devices = await readDevices();
      const index = devices.findIndex((d) => d.id === id);
      if (index < 0) throw new Error('no such device');
      devices[index] = { ...devices[index], name: next.slice(0, 60) };
      await writeDevices(devices);
      return { id, name: devices[index].name };
    },

    /** Forget one device row; this is not a security revocation. */
    async 'device-forget'(args) {
      const id = text(args?.id);
      if (id === undefined) throw new Error('device-forget requires id');
      const devices = await readDevices();
      await writeDevices(devices.filter((d) => d.id !== id));
      return { id, forgotten: true };
    },

    /** Clear the device view. */
    async 'devices-clear'() {
      await writeDevices([]);
      return { cleared: true };
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

    /** Whether the password door is armed, and which devices hold tokens. */
    async 'recovery-status'() {
      const recovery = await readRecovery();
      const tokens = await readTokens();
      return {
        configured: recovery !== undefined,
        createdAt: recovery?.createdAt,
        iterations: recovery?.iterations ?? PBKDF2_ITERATIONS,
        ticketDays: DEFAULT_TICKET_DAYS,
        deviceDays: DEFAULT_DEVICE_DAYS,
        tokens: tokens.map(({ hash, ...rest }) => rest),
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

    /** Revoke one device token by id. */
    async 'token-revoke'(args) {
      const id = absentText(args?.id);
      if (id === undefined) throw new Error('token-revoke requires an id');
      const rows = await readTokens();
      const kept = rows.filter((row) => row.id !== id);
      await writeTokens(kept);
      return { revoked: rows.length - kept.length };
    },

    /** Give one device token a name of your own. */
    async 'token-rename'(args) {
      const id = absentText(args?.id);
      const name = absentText(args?.name);
      if (id === undefined) throw new Error('token-rename requires an id');
      if (name === undefined) throw new Error('token-rename requires a name');
      const rows = await readTokens();
      const row = rows.find((candidate) => candidate.id === id);
      if (row === undefined) throw new Error(`no device token with id ${JSON.stringify(id)}`);
      row.name = name;
      await writeTokens(rows);
      return { id, name };
    },

    /** Revoke every device token. */
    async 'tokens-clear'() {
      const rows = await readTokens();
      await writeTokens([]);
      return { revoked: rows.length };
    },

    /** Renew the platform cookie: hand back a fresh tokenized entry URL. */
    async 'renew-session'(args, req) {
      return renewSession(req);
    },
  };

  /** The scheme the client actually used; the tunnel terminates TLS at the edge. */
  function requestScheme(req) {
    const proto = req?.headers?.['x-forwarded-proto'];
    const value = Array.isArray(proto) ? proto[0] : proto;
    return String(value ?? '').split(',')[0].trim().toLowerCase() === 'https' ? 'https' : 'http';
  }

  /** The freshest tokenized entry, preferring the configured tunnel hostname. */
  function freshEntry(req) {
    const scheme = requestScheme(req);
    const host = String(req?.headers?.host ?? '');
    const authority = config.tunnelHost ?? host;
    const url = tokenized(`${scheme}://${authority}/`);
    return { authority, url, qr: qrFor(url) };
  }

  /**
   * Renew the platform cookie by handing the caller a fresh tokenized URL.
   *
   * `authorizeIndex` mints a new cookie (with a full lifetime) only when the
   * request carries the launch token, so re-visiting that URL is what keeps a
   * phone paired without extending the configured lifetime.
   * @param req - the authenticated panel request.
   */
  function renewSession(req) {
    const entry = freshEntry(req);
    const clean = `${requestScheme(req)}://${entry.authority}/`;
    return { authority: entry.authority, url: entry.url, tokenized: entry.url !== clean };
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
  const RECOVERY_RECORD_KEY = 'dsh-mobile-console/recovery';
  const TOKENS_RECORD_KEY = 'dsh-mobile-console/device-tokens';
  const TOKEN_QUERY = 'token';
  const CHALLENGE_TTL_MS = 2 * 60 * 1000;
  const MAX_TOKENS = 20;
  const challenges = new Map();
  const recoverLimiter = createRateLimiter();

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
    const credentials = getCredentials();
    if (credentials === undefined) throw new Error('the credentials service is unavailable in this composition');
    await credentials.modifyRecord(RECOVERY_RECORD_KEY, async () => ({
      kind: 'grant',
      payload: { version: 1, ...record },
    }));
    return record;
  }

  /** Forget the password and every ticket it minted. */
  async function clearRecovery() {
    const credentials = getCredentials();
    if (credentials === undefined) return;
    await attemptAsync(() => credentials.deleteRecord(RECOVERY_RECORD_KEY));
    challenges.clear();
    recoverLimiter.clear();
  }

  /** The device-token rows; absent or malformed reads as empty. */
  async function readTokens() {
    const credentials = getCredentials();
    if (credentials === undefined) return [];
    const record = await attempt(() => credentials.readRecord(TOKENS_RECORD_KEY));
    const payload = record?.payload;
    if (payload === null || typeof payload !== 'object' || !Array.isArray(payload.tokens)) return [];
    return payload.tokens.filter((row) => row !== null && typeof row === 'object' && typeof row.hash === 'string');
  }

  /** Persist the device-token rows. */
  async function writeTokens(tokens) {
    const credentials = getCredentials();
    if (credentials === undefined) throw new Error('the credentials service is unavailable in this composition');
    await credentials.modifyRecord(TOKENS_RECORD_KEY, async () => ({
      kind: 'grant',
      payload: { version: 1, tokens },
    }));
    return tokens;
  }

  /** Issue a device token for this browser and return the cookie value. */
  async function issueDeviceToken(req) {
    const token = newDeviceToken();
    const hash = hashDeviceToken(token);
    const now = new Date().toISOString();
    const rows = await readTokens();
    rows.unshift({
      id: hash.slice(0, 16),
      hash,
      label: deviceLabel(String(req?.headers?.['user-agent'] ?? '')),
      createdAt: now,
      lastUsedAt: now,
      expiresAt: Date.now() + DEFAULT_DEVICE_DAYS * 24 * 60 * 60 * 1000,
    });
    await writeTokens(rows.slice(0, MAX_TOKENS));
    return token;
  }

  /**
   * Whether this request carries a live device token.
   *
   * A hit refreshes `lastUsedAt` at most once an hour, so the token slides
   * without writing the credential store on every request.
   */
  async function deviceAuthorized(req) {
    const presented = cookieValue(req, DEVICE_COOKIE);
    if (presented === undefined) return false;
    const rows = await readTokens();
    const index = rows.findIndex((row) => deviceTokenMatches(presented, row.hash));
    if (index < 0) return false;
    const row = rows[index];
    if (typeof row.expiresAt === 'number' && row.expiresAt <= Date.now()) {
      rows.splice(index, 1);
      await writeTokens(rows);
      return false;
    }
    const last = Date.parse(String(row.lastUsedAt ?? ''));
    if (!Number.isFinite(last) || Date.now() - last > 60 * 60 * 1000) {
      row.lastUsedAt = new Date().toISOString();
      await writeTokens(rows);
    }
    return true;
  }

  /** Whether this request carries a live unlock ticket. */
  async function ticketAuthorized(req) {
    const recovery = await readRecovery();
    if (recovery === undefined) return false;
    return verifyTicket(recovery.secret, cookieValue(req, UNLOCK_COOKIE)) !== undefined;
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

  /** The client address a limit is counted against, edge headers first. */
  function clientAddress(req) {
    const forwarded = req?.headers?.['cf-connecting-ip'] ?? req?.headers?.['x-forwarded-for'];
    const first = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    if (typeof first === 'string' && first.trim() !== '') return first.split(',')[0].trim();
    return String(req?.socket?.remoteAddress ?? 'unknown');
  }

  /** Whether this request arrived on a loopback socket. */
  function isLoopbackSocket(req) {
    const address = String(req?.socket?.remoteAddress ?? '');
    return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
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

  /** Send this browser into the app with a fresh launch token. */
  function reenter(res, req, cookies = []) {
    const entry = freshEntry(req);
    const headers = { location: entry.url, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' };
    if (cookies.length > 0) headers['set-cookie'] = cookies;
    res.writeHead(303, headers);
    res.end();
  }

  /**
   * Forward a request to the platform's own index.
   *
   * The caller's `Host` is preserved on purpose: the browser cookie is bound to
   * an authority and the platform's fence reads the same header, so rewriting it
   * would both fail authentication and look untrusted. Extra cookies are merged
   * into the upstream `set-cookie` list so a pairing can hand out the device
   * token in the same response.
   */
  function forwardIndex(req, res, cookies = []) {
    const facts = listenerFacts();
    const port = Number.isFinite(facts.port) ? facts.port : 3080;
    const upstream = httpRequest(
      {
        host: '127.0.0.1',
        port,
        method: req.method ?? 'GET',
        path: '/index.html',
        headers: { ...req.headers },
      },
      (answer) => {
        const headers = { ...answer.headers };
        if (cookies.length > 0) {
          const existing = headers['set-cookie'];
          headers['set-cookie'] = Array.isArray(existing) ? [...existing, ...cookies] : existing === undefined ? cookies : [existing, ...cookies];
        }
        res.writeHead(answer.statusCode ?? 502, headers);
        if (req.method === 'HEAD') {
          answer.resume();
          res.end();
          return;
        }
        answer.pipe(res);
      },
    );
    upstream.on('error', (error) => {
      if (!res.headersSent) {
        res.statusCode = 502;
        res.setHeader('content-type', 'text/plain; charset=utf-8');
        res.end(`dsh-mobile-console: index forward failed: ${error.message}`);
      } else {
        res.end();
      }
    });
    req.pipe(upstream);
  }

  /**
   * The recovery page.
   *
   * Fail-closed by construction: with no password stored, `configured` is false,
   * the page renders no form at all, and the challenge endpoint below refuses.
   * An unset password can therefore never mean "no password required".
   */
  async function serveRecoveryPage(req, res, headOnly = false) {
    const recovery = await readRecovery();
    const tokens = await readTokens();
    const html = unlockPageHtml({
      prefix: CHANNEL,
      configured: recovery !== undefined,
      title: 'dsh · 手机访问恢复',
      subtitle:
        recovery === undefined
          ? '这台机器没有设置恢复密码。'
          : '输入恢复密码取回入口链接。密码不会离开这台手机：本页用 PBKDF2 派生密钥，再用 HMAC 应答一次性挑战。',
      passwordLabel: '恢复密码',
      buttonLabel: '取回入口链接',
      wrongLabel: '密码不正确。',
      missingLabel:
        tokens.length > 0
          ? '这台机器没有设置恢复密码。如果你曾在某台设备上配对过，用那台设备打开即可自动恢复；否则请在电脑上打开「设置 → 手机访问 → 高级」设置密码。'
          : '这台机器没有设置恢复密码。请在电脑上打开「设置 → 手机访问 → 高级」设置密码，或扫码重新配对。',
      successLabel: '已解锁。用手机扫描下面的二维码，或打开这个链接完成配对：',
      openLabel: '打开',
    });
    sendHtml(res, 200, headOnly ? '' : html);
  }

  /**
   * The root gate.
   *
   * Loopback, a launch token, a live device token, a live unlock ticket and an
   * authenticated caller all keep the platform's own behaviour; only a genuinely
   * unauthenticated remote visit gets the recovery page.
   */
  async function handleRoot(req, res, url) {
    const host = String(req?.headers?.host ?? '');
    const connection = getConnection();
    if (connection === undefined || typeof connection.requestRejection !== 'function') {
      res.statusCode = 503;
      res.end();
      return;
    }
    if (isLoopbackAuthority(host) && isLoopbackSocket(req)) {
      forwardIndex(req, res);
      return;
    }
    if (url.searchParams.has(TOKEN_QUERY)) {
      // This is the pairing visit: hand the browser a long-lived device token in
      // the same response that mints the platform cookie.
      let cookies = [];
      try {
        const token = await issueDeviceToken(req);
        cookies = [cookieValueFor(req, DEVICE_COOKIE, token, DEFAULT_DEVICE_DAYS * 24 * 60 * 60)];
      } catch {
        cookies = [];
      }
      forwardIndex(req, res, cookies);
      return;
    }
    if (await deviceAuthorized(req)) {
      reenter(res, req);
      return;
    }
    if (await ticketAuthorized(req)) {
      reenter(res, req);
      return;
    }
    const rejection = connection.requestRejection(req);
    if (rejection === undefined) {
      forwardIndex(req, res);
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
   * The recovery endpoints, behind the Host/Origin fence only.
   *
   * They must work precisely when the platform credential has lapsed, so they
   * deliberately skip the browser check. The password, the device token and a
   * rate limit are the gate.
   */
  async function handleRecoveryRoute(req, res, url) {
    const suffix = url.pathname.slice(`${CHANNEL}/unlock`.length).replace(/^\//, '');
    const host = String(req?.headers?.host ?? '');
    if (probeTrust(getConnection(), host) === 'refused') {
      res.statusCode = 403;
      res.end();
      return;
    }

    // Fail closed and stay quiet: with no password armed this whole route behaves
    // as if it did not exist, so probing it reveals nothing. (A live device token
    // never needs these endpoints — the root gate redirects it directly.)
    if ((await readRecovery()) === undefined) {
      res.statusCode = 404;
      res.end();
      return;
    }

    if (suffix === '' && (req.method === 'GET' || req.method === 'HEAD')) {
      await serveRecoveryPage(req, res, req.method === 'HEAD');
      return;
    }

    if (suffix === 'challenge' && req.method === 'POST') {
      const recovery = await readRecovery();
      if (recovery === undefined) {
        // Fail closed: no password means no challenge, never a free pass.
        sendJson(res, 200, fail('mobile-console/recovery-missing', 'no recovery password is set on this machine'));
        return;
      }
      const address = clientAddress(req);
      if (!recoverLimiter.allowed(address)) {
        sendJson(res, 429, fail('mobile-console/recovery-throttled', `too many attempts; retry in ${Math.ceil(recoverLimiter.retryAfterMs(address) / 1000)}s`));
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
      const address = clientAddress(req);
      if (!recoverLimiter.allowed(address)) {
        sendJson(res, 429, fail('mobile-console/recovery-throttled', `too many attempts; retry in ${Math.ceil(recoverLimiter.retryAfterMs(address) / 1000)}s`));
        return;
      }
      const raw = await readBoundedBody(req);
      if (raw === null) {
        sendJson(res, 413, fail('mobile-console/too-large', `request body exceeds ${MAX_BODY_BYTES} bytes`));
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
        sendJson(res, 200, fail('mobile-console/recovery-denied', 'password rejected'));
        return;
      }
      recoverLimiter.reset(address);
      const expiresAt = Date.now() + DEFAULT_TICKET_DAYS * 24 * 60 * 60 * 1000;
      const ticket = signTicket(recovery.secret, { v: 1, exp: expiresAt, iat: Date.now() });
      res.setHeader('set-cookie', cookieValueFor(req, UNLOCK_COOKIE, ticket, DEFAULT_TICKET_DAYS * 24 * 60 * 60));
      sendJson(res, 200, ok({ expiresAt }));
      return;
    }

    if (suffix === 'entry' && req.method === 'POST') {
      const allowed = (await ticketAuthorized(req)) || (await deviceAuthorized(req));
      if (!allowed) {
        sendJson(res, 401, fail('mobile-console/recovery-required', 'unlock first'));
        return;
      }
      const entry = freshEntry(req);
      sendJson(res, 200, ok({ authority: entry.authority, url: entry.url, qr: qrSvg(entry.qr, { label: 'dsh mobile entry' }) }));
      return;
    }

    sendJson(res, 404, fail('mobile-console/bad-request', `unknown recovery endpoint ${JSON.stringify(suffix)}`));
  }

  /** The route: one prefix handler for JSON endpoints, one exact asset route. */
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'prefix',
        path: CHANNEL,
        handler: async (req, res) => {
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
          // Host/Origin fence but not the browser check.
          const requested = new URL(String(req.url), 'http://localhost');
          if (requested.pathname === `${CHANNEL}/unlock` || requested.pathname.startsWith(`${CHANNEL}/unlock/`)) {
            await handleRecoveryRoute(req, res, requested);
            return;
          }
          const rejection = connection.requestRejection(req);
          if (rejection !== undefined) {
            res.statusCode = rejection;
            res.end();
            return;
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
            sendJson(res, 415, fail('mobile-console/bad-request', 'content type must be application/json'));
            return;
          }
          const pathname = new URL(String(req.url), 'http://localhost').pathname;
          const endpoint = pathname.slice(CHANNEL.length).replace(/^\//, '');
          if (!ENDPOINT_RE.test(endpoint)) {
            sendJson(res, 404, fail('mobile-console/bad-request', 'malformed endpoint'));
            return;
          }
          const fn = Object.prototype.hasOwnProperty.call(handlers, endpoint) ? handlers[endpoint] : undefined;
          if (typeof fn !== 'function') {
            sendJson(res, 404, fail('mobile-console/bad-request', `unknown endpoint ${JSON.stringify(endpoint)}`));
            return;
          }
          const raw = await readBoundedBody(req);
          if (raw === null) {
            sendJson(res, 413, fail('mobile-console/too-large', `request body exceeds ${MAX_BODY_BYTES} bytes`));
            return;
          }
          let payload = {};
          if (raw.trim() !== '') {
            try {
              payload = JSON.parse(raw);
            } catch {
              sendJson(res, 400, fail('mobile-console/bad-request', 'body is not valid JSON'));
              return;
            }
          }
          try {
            const args = payload !== null && typeof payload === 'object' ? payload : {};
            sendJson(res, 200, ok(await fn(args, req)));
          } catch (error) {
            sendJson(res, 200, fail('mobile-console/internal', error instanceof Error ? error.message : String(error)));
          }
        },
      }),
    `dsh-mobile-console: ${CHANNEL} route`,
  );

  /**
   * Claim the root path for the recovery gate.
   *
   * `/` is answered by the frontend fallback rather than by a named route, so an
   * exact route wins. If a future composition claims `/` first, registration
   * throws and the plugin keeps working through `/mobile-console/unlock`.
   */
  ctx.effect(() => {
    try {
      return ctx.webServer.register({ kind: 'exact', path: '/', handler: handleRoot });
    } catch {
      return () => {};
    }
  }, 'dsh-mobile-console: root gate');

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
    `dsh-mobile-console: ${HEARTBEAT_PATH} asset`,
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
  }, 'dsh-mobile-console: setup skill');

  // Every rendered index carries the heartbeat, so a phone that loads the UI
  // once shows up in the device view.
  ctx.effect(
    () =>
      ctx.webServer.tapIndex((html) => {
        if (typeof html !== 'string' || html.includes(HEARTBEAT_PATH)) return html;
        const tag = `<script defer src="${HEARTBEAT_PATH}"></script>`;
        return html.includes('</body>') ? html.replace('</body>', `${tag}</body>`) : html + tag;
      }),
    'dsh-mobile-console: heartbeat injection',
  );

  // A child process must not outlive the plugin that started it.
  ctx.effect(() => () => {
    attempt(() => tunnel?.handle?.terminate?.());
    tunnel = null;
  }, 'dsh-mobile-console: tunnel child');
}

/** Inline heartbeat asset: one ping per page load, mobile user agents only. */
const HEARTBEAT_SCRIPT = `(function () {
  try {
    var KEY = 'dsh-mobile-console-device';
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

export { apply, inject, name, CHANNEL, HEARTBEAT_PATH, DEVICE_RECORD_KEY, PLATFORM_SESSION_KEY };
