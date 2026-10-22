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

/** Whether an authority (host[:port]) names this machine's loopback. */
export function isLoopbackAuthority(authority) {
  const host = String(authority).replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || /^127\./.test(host);
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
 * Insert or refresh one device row, newest first, capped at {@link MAX_DEVICES}.
 * @param devices - existing rows.
 * @param input - `{ id, ua, ip, now }`.
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

  /** Describe the managed child for the panel. */
  function tunnelStatus() {
    const output = tunnelOutput();
    return {
      configured: config.cloudflared !== undefined,
      command: config.cloudflared ? [config.cloudflared.command, ...config.cloudflared.args].join(' ') : undefined,
      running: tunnel !== null && tunnel.exited !== true,
      startedAt: tunnel?.startedAt,
      exit: tunnel?.exit,
      url: output.url,
      lines: output.lines.slice(-20),
      lossy: output.lossy,
      available: getSubprocess() !== undefined,
    };
  }

  /** Start the configured cloudflared command as a managed child. */
  async function tunnelStart() {
    if (tunnel !== null && tunnel.exited !== true) return { started: false, reason: 'already-running' };
    if (config.cloudflared === undefined) {
      throw new Error('no cloudflared command is configured for this plugin row');
    }
    const subprocess = getSubprocess();
    if (subprocess === undefined) throw new Error('the subprocess service is unavailable in this composition');
    const resolved = await subprocess.resolveExecutable(config.cloudflared.command);
    const handle = subprocess.spawn({
      argv: [resolved, ...config.cloudflared.args],
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
    return { started: true, resolved };
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
    await editor.edit(entry, (current) => ({ ...current, trustedHosts: merged }));
    return { trustedHosts: merged, trust: probeTrust(getConnection(), authority) };
  }

  /**
   * Bind the listener to one concrete local interface. The shipped `webserver`
   * row carries host, port, tls and compression, so the write restates the live
   * values rather than dropping them.
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
    await editor.edit(entry, (current) => ({ ...current, host: literal }));
    return { host: literal };
  }

  /** Advertise the tunnel root as the application URL. */
  async function writePublicUrl(url) {
    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry('web-runtime');
    if (entry === undefined) throw new Error('the profile has no "web-runtime" row to write');
    await editor.edit(entry, (current) => ({ ...current, publicUrl: String(url) }));
    return { publicUrl: String(url) };
  }

  /** Rewrite this plugin's own row config (its fields are all ours). */
  async function writeOwnConfig(patch) {
    const editor = getConfigEditor();
    if (editor === undefined) throw new Error('the configEditor service is unavailable in this composition');
    const entry = findEntry('mobile-console');
    if (entry === undefined) throw new Error('the profile has no "mobile-console" row to write');
    await editor.edit(entry, (current) => ({ ...current, ...patch }));
    return { ...patch };
  }

  // ── Endpoint map ───────────────────────────────────────────────────────────

  const handlers = {
    /** Everything the panel renders. */
    async state() {
      const facts = listenerFacts();
      const entries = buildEntries();
      const devices = prune(await readDevices());
      const cookieDays = cookieMaxAgeDays();
      const now = Date.now();
      return {
        config,
        listener: facts,
        entries,
        localAddresses: localAddresses(),
        tunnel: tunnelStatus(),
        devices: devices.map((d) => ({
          ...d,
          name: d.name ?? deviceLabel(d.ua),
          daysLeft: cookieDays - Math.floor((now - Number(d.firstSeenAt ?? now)) / (24 * 60 * 60 * 1000)),
        })),
        platform: {
          cookieMaxAgeDays: cookieDays,
          sessionRecordPresent: (await attemptAsync(() => getCredentials()?.readRecord(PLATFORM_SESSION_KEY))) !== undefined,
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
      const forwarded = String(req?.headers?.['x-forwarded-for'] ?? '').split(',')[0].trim();
      const ip = forwarded !== '' ? forwarded : (req?.socket?.remoteAddress ?? undefined);
      const devices = await readDevices();
      await writeDevices(prune(upsertDevice(devices, { id, ua, ip })));
      return { recorded: true };
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

    /** Rewrite this plugin's own row config. */
    async 'set-plugin-config'(args) {
      const patch = {};
      if (typeof args?.narrowEnhance === 'boolean') patch.narrowEnhance = args.narrowEnhance;
      if (text(args?.tunnelHost) !== undefined) patch.tunnelHost = text(args.tunnelHost);
      if (text(args?.publicUrl) !== undefined) patch.publicUrl = text(args.publicUrl);
      if (text(args?.lanHost) !== undefined) patch.lanHost = text(args.lanHost);
      if (Object.keys(patch).length === 0) throw new Error('set-plugin-config requires at least one field');
      const written = await writeOwnConfig(patch);
      Object.assign(config, normalizeConfig({ ...config, ...patch }));
      return written;
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
  };

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
