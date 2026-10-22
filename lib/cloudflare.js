/**
 * dsh-mobile-console — Cloudflare API client.
 *
 * Why the API and not `cloudflared tunnel login`: the interactive login writes
 * a `cert.pem` and needs a browser. With an API token this plugin can create a
 * remotely-managed tunnel, point its ingress at the local listener, publish the
 * DNS record and (optionally) create the Access application — so the only manual
 * steps left are the ones no API can do: delegating the domain's nameservers and
 * enabling a login method.
 *
 * The plugin has no dependencies, so this is plain `fetch` against the documented
 * v4 API. Every function takes the token explicitly; the caller owns where it is
 * stored (the Harness credential store).
 *
 * @module dsh-mobile-console/cloudflare
 */

/** Cloudflare API root. */
export const API_BASE = 'https://api.cloudflare.com/client/v4';

/** One month, the longest Access session the dashboard offers. */
export const ACCESS_SESSION = '720h';

/** The permissions an API token needs for the full automatic setup. */
export const REQUIRED_TOKEN_SCOPES = [
  'Zone → Zone → Read (the zone list)',
  'Zone → DNS → Edit (the tunnel hostname record)',
  'Account → Cloudflare Tunnel → Edit (create the tunnel and read its token)',
  'Account → Access: Apps and Policies → Edit (only for the optional Access step)',
];

/** First Cloudflare error message in a payload, or a generic fallback. */
export function firstError(payload, fallback = 'Cloudflare refused the request') {
  const errors = payload?.errors;
  if (Array.isArray(errors) && errors.length > 0) {
    const first = errors[0];
    const code = first?.code === undefined ? '' : `${first.code} `;
    if (typeof first?.message === 'string' && first.message !== '') return `${code}${first.message}`;
  }
  return fallback;
}

/** Whether a string looks like a hostname the tunnel can serve. */
export function validHostname(value) {
  const host = String(value ?? '').trim().toLowerCase();
  if (host === '' || host.length > 253) return undefined;
  if (host.includes('/') || host.includes(' ') || host.includes(':')) return undefined;
  const labels = host.split('.');
  if (labels.length < 2) return undefined;
  for (const label of labels) {
    if (label === '' || label.length > 63) return undefined;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) return undefined;
  }
  return host;
}

/** The apex a hostname belongs to, assuming the registrable form is the last two labels. */
export function apexOf(hostname) {
  const host = validHostname(hostname);
  if (host === undefined) return undefined;
  const labels = host.split('.');
  return labels.length <= 2 ? host : labels.slice(-2).join('.');
}

/**
 * The `name` field a DNS record needs: relative to the zone, with `@` for the
 * apex. The Cloudflare API accepts a full name too, but the relative form is
 * what the dashboard shows and what survives a zone rename.
 */
export function dnsRecordName(hostname, zoneName) {
  const host = validHostname(hostname);
  const zone = validHostname(zoneName);
  if (host === undefined || zone === undefined) return undefined;
  if (host === zone) return '@';
  if (!host.endsWith(`.${zone}`)) return undefined;
  return host.slice(0, -(zone.length + 1));
}

/** The tunnel ingress list that publishes one hostname over the local service. */
export function ingressConfig(hostname, service) {
  const host = validHostname(hostname);
  if (host === undefined) throw new Error('a tunnel ingress needs a valid hostname');
  return [
    { hostname: host, service: String(service), originRequest: { noTLSVerify: false } },
    { service: 'http_status:404' },
  ];
}

/** The body that creates a self-hosted Access application with one email policy. */
export function accessAppBody({ hostname, email, name }) {
  const host = validHostname(hostname);
  if (host === undefined) throw new Error('an Access application needs a valid hostname');
  const address = String(email ?? '').trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address)) throw new Error('an Access policy needs an email address');
  return {
    name: name ?? `dsh-mobile-console (${host})`,
    domain: host,
    type: 'self_hosted',
    session_duration: ACCESS_SESSION,
    app_launcher_visible: false,
    auto_redirect_to_identity: false,
    policies: [
      {
        name: 'owner email',
        decision: 'allow',
        include: [{ email: { email: address } }],
      },
    ],
  };
}

/**
 * Create a Cloudflare API client.
 * @param options - `fetchImpl` (defaults to global fetch) and `apiBase`, both
 *   injectable so the tests can drive every branch without a network.
 */
export function createCloudflareClient(options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const apiBase = options.apiBase ?? API_BASE;

  /** One API call; returns `{ ok, result, error, status }`. */
  async function call(token, path, init = {}) {
    if (typeof fetchImpl !== 'function') return { ok: false, error: 'no fetch implementation is available' };
    let response;
    try {
      response = await fetchImpl(`${apiBase}${path}`, {
        ...init,
        headers: {
          authorization: `Bearer ${String(token ?? '')}`,
          'content-type': 'application/json',
          ...(init.headers ?? {}),
        },
      });
    } catch (error) {
      return { ok: false, error: `network failure: ${error instanceof Error ? error.message : String(error)}` };
    }
    let payload;
    const text = await response.text().catch(() => '');
    try {
      payload = text === '' ? {} : JSON.parse(text);
    } catch {
      return { ok: false, status: response.status, error: `HTTP ${response.status} with a non-JSON body` };
    }
    if (payload?.success !== true) {
      return { ok: false, status: response.status, error: firstError(payload, `HTTP ${response.status}`), errors: payload?.errors };
    }
    return { ok: true, status: response.status, result: payload.result };
  }

  return {
    /** Confirm the token is live, and report its status. */
    async verifyToken(token) {
      const response = await call(token, '/user/tokens/verify');
      if (!response.ok) return response;
      return { ok: true, status: response.result?.status, result: response.result };
    },

    /** Find the active zone for one hostname's apex. */
    async findZone(token, hostname) {
      const apex = apexOf(hostname);
      if (apex === undefined) return { ok: false, error: 'a valid hostname is required to find its zone' };
      const response = await call(token, `/zones?name=${encodeURIComponent(apex)}&status=active&per_page=5`);
      if (!response.ok) return response;
      const zone = Array.isArray(response.result) ? response.result[0] : undefined;
      if (zone === undefined) {
        return {
          ok: false,
          error: `no active Cloudflare zone for ${apex} — add the domain to Cloudflare and point its nameservers there first`,
        };
      }
      return { ok: true, result: { id: zone.id, name: zone.name, accountId: zone.account?.id, accountName: zone.account?.name } };
    },

    /** Tunnels of that name in the account, deleted ones excluded. */
    async findTunnel(token, accountId, name) {
      const response = await call(
        token,
        `/accounts/${accountId}/cfd_tunnel?name=${encodeURIComponent(name)}&is_deleted=false&per_page=20`,
      );
      if (!response.ok) return response;
      const list = Array.isArray(response.result) ? response.result : [];
      return { ok: true, result: list[0] };
    },

    /** Create a remotely-managed tunnel, so its ingress lives in the API. */
    async createTunnel(token, accountId, name) {
      const response = await call(token, `/accounts/${accountId}/cfd_tunnel`, {
        method: 'POST',
        body: JSON.stringify({ name, config_src: 'cloudflare' }),
      });
      if (!response.ok) return response;
      return { ok: true, result: { id: response.result?.id, name: response.result?.name } };
    },

    /** The connector token `cloudflared tunnel run --token` consumes. */
    async tunnelToken(token, accountId, tunnelId) {
      const response = await call(token, `/accounts/${accountId}/cfd_tunnel/${tunnelId}/token`);
      if (!response.ok) return response;
      return { ok: true, result: typeof response.result === 'string' ? response.result : undefined };
    },

    /** Publish one hostname through the tunnel to a local service. */
    async setIngress(token, accountId, tunnelId, hostname, service) {
      const config = { ingress: ingressConfig(hostname, service) };
      const response = await call(token, `/accounts/${accountId}/cfd_tunnel/${tunnelId}/configurations`, {
        method: 'PUT',
        body: JSON.stringify({ config }),
      });
      if (!response.ok) return response;
      return { ok: true, result: config };
    },

    /** Create (or update) the proxied CNAME that points the hostname at the tunnel. */
    async upsertDnsRecord(token, zoneId, zoneName, hostname, tunnelId) {
      const name = dnsRecordName(hostname, zoneName);
      if (name === undefined) return { ok: false, error: `${hostname} is not inside the zone ${zoneName}` };
      const body = {
        type: 'CNAME',
        name,
        content: `${tunnelId}.cfargotunnel.com`,
        proxied: true,
        ttl: 1,
        comment: 'dsh-mobile-console',
      };
      const existing = await call(token, `/zones/${zoneId}/dns_records?type=CNAME&name=${encodeURIComponent(hostname)}`);
      if (!existing.ok) return existing;
      const record = Array.isArray(existing.result) ? existing.result[0] : undefined;
      if (record === undefined) {
        const created = await call(token, `/zones/${zoneId}/dns_records`, { method: 'POST', body: JSON.stringify(body) });
        if (!created.ok) return created;
        return { ok: true, result: { id: created.result?.id, created: true } };
      }
      const updated = await call(token, `/zones/${zoneId}/dns_records/${record.id}`, { method: 'PUT', body: JSON.stringify(body) });
      if (!updated.ok) return updated;
      return { ok: true, result: { id: record.id, created: false } };
    },

    /** Delete the hostname's record, for teardown. */
    async deleteDnsRecord(token, zoneId, hostname) {
      const existing = await call(token, `/zones/${zoneId}/dns_records?name=${encodeURIComponent(hostname)}`);
      if (!existing.ok) return existing;
      const records = Array.isArray(existing.result) ? existing.result : [];
      const mine = records.filter((record) => record.comment === 'dsh-mobile-console' || String(record.content ?? '').endsWith('.cfargotunnel.com'));
      for (const record of mine) {
        const deleted = await call(token, `/zones/${zoneId}/dns_records/${record.id}`, { method: 'DELETE' });
        if (!deleted.ok) return deleted;
      }
      return { ok: true, result: { removed: mine.length } };
    },

    /** Remove a tunnel created by this plugin. */
    async deleteTunnel(token, accountId, tunnelId) {
      const response = await call(token, `/accounts/${accountId}/cfd_tunnel/${tunnelId}`, { method: 'DELETE' });
      if (!response.ok) return response;
      return { ok: true };
    },

    /** Login methods configured for the Zero Trust organization. */
    async listIdentityProviders(token, accountId) {
      const response = await call(token, `/accounts/${accountId}/access/identity_providers`);
      if (!response.ok) return response;
      const list = Array.isArray(response.result) ? response.result : [];
      return { ok: true, result: list.map((idp) => ({ id: idp.id, name: idp.name, type: idp.type })) };
    },

    /** Access applications already covering one hostname. */
    async findAccessApp(token, accountId, hostname) {
      const response = await call(token, `/accounts/${accountId}/access/apps?per_page=50`);
      if (!response.ok) return response;
      const list = Array.isArray(response.result) ? response.result : [];
      return { ok: true, result: list.find((app) => app.domain === hostname) };
    },

    /** Create the self-hosted Access application with one email policy. */
    async createAccessApp(token, accountId, body) {
      const response = await call(token, `/accounts/${accountId}/access/apps`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      if (!response.ok) return response;
      return { ok: true, result: { id: response.result?.id, domain: response.result?.domain } };
    },
  };
}
