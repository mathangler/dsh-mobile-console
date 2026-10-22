/**
 * dsh-remote-access — `cloudflared` command-line helpers.
 *
 * The interactive path (`cloudflared tunnel login`) writes `cert.pem`, then
 * `tunnel create` / `tunnel route dns` / a local `config.yml` publish the
 * hostname. These are the pure parts: parsing the CLI's output, rendering the
 * config file, and the per-platform install hints. Spawning lives in index.js.
 *
 * @module dsh-remote-access/cloudflared
 */
import { homedir } from 'node:os';
import { join } from 'node:path';

/** The directory cloudflared keeps its certificate and tunnel credentials in. */
export function cloudflaredDir(env = process.env) {
  const home = env.USERPROFILE ?? env.HOME ?? homedir();
  return join(home, '.cloudflared');
}

/** The certificate `cloudflared tunnel login` writes. */
export function certPemPath(env = process.env) {
  return join(cloudflaredDir(env), 'cert.pem');
}

/** The local config file this plugin writes for a certificate-based tunnel. */
export function tunnelConfigPath(env = process.env) {
  return join(cloudflaredDir(env), 'dsh-remote-access.yml');
}

/** Credentials file cloudflared writes for one tunnel. */
export function credentialsPath(tunnelId, env = process.env) {
  return join(cloudflaredDir(env), `${tunnelId}.json`);
}

/**
 * The authorization URL `cloudflared tunnel login` prints for the user to open.
 * The CLI writes it to stderr; the callback carries the zone selection.
 * @returns the URL, or `undefined` while the CLI has not printed it yet.
 */
export function parseLoginUrl(output) {
  const match = String(output ?? '').match(/https:\/\/dash\.cloudflare\.com\/argotunnel\?[^\s"'<>]+/);
  if (match === null) return undefined;
  // The CLI prints the URL inside a sentence, so trailing punctuation is not
  // part of it.
  return match[0].replace(/[.,;:)\]]+$/, '');
}

/**
 * The tunnel UUID in `cloudflared tunnel create` output, or in the "already
 * exists" message the CLI prints when the name is taken.
 */
export function parseTunnelId(output) {
  const text = String(output ?? '');
  const uuid = text.match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i);
  return uuid === null ? undefined : uuid[0].toLowerCase();
}

/** Whether a `cloudflared tunnel list --output json` payload names the tunnel. */
export function findTunnelInList(json, name) {
  let parsed;
  try {
    parsed = typeof json === 'string' ? JSON.parse(json) : json;
  } catch {
    return undefined;
  }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.tunnels) ? parsed.tunnels : [];
  const hit = list.find((tunnel) => tunnel?.name === name && tunnel?.deleted_at == null);
  return hit === undefined ? undefined : { id: hit.id, name: hit.name };
}

/**
 * Render the `config.yml` a certificate-based tunnel needs: which tunnel, which
 * credentials file, and the ingress that publishes one hostname to the local
 * listener.
 * @returns YAML text.
 */
export function renderTunnelConfig({ tunnelId, hostname, service, env = process.env }) {
  const id = String(tunnelId ?? '').trim();
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error('renderTunnelConfig needs a tunnel UUID');
  const host = String(hostname ?? '').trim();
  if (host === '') throw new Error('renderTunnelConfig needs a hostname');
  const target = String(service ?? '').trim();
  if (target === '') throw new Error('renderTunnelConfig needs a local service URL');
  const credentials = credentialsPath(id, env).replace(/\\/g, '/');
  return [
    `# Written by dsh-remote-access. Edit the plugin row config, not this file.`,
    `tunnel: ${id}`,
    `credentials-file: ${credentials}`,
    `ingress:`,
    `  - hostname: ${host}`,
    `    service: ${target}`,
    `  - service: http_status:404`,
    ``,
  ].join('\n');
}

/** The command that starts a certificate-based tunnel with the written config. */
export function tunnelRunArgs({ configPath, tunnelName }) {
  return ['tunnel', '--no-autoupdate', '--config', String(configPath), 'run', String(tunnelName)];
}

/** The command that starts a token-based tunnel. */
export function tunnelTokenArgs(token) {
  return ['tunnel', '--no-autoupdate', 'run', '--token', String(token)];
}

/**
 * How to install cloudflared on this platform, and the page that always works.
 * @returns `{ platform, command, note }`.
 */
export function installHint(platform = process.platform) {
  if (platform === 'win32') {
    return {
      platform: 'windows',
      command: 'winget install --id Cloudflare.cloudflared',
      note: 'or download cloudflared-windows-amd64.exe from the releases page and put it on PATH',
    };
  }
  if (platform === 'darwin') {
    return {
      platform: 'macos',
      command: 'brew install cloudflared',
      note: 'or download the darwin package from the releases page',
    };
  }
  return {
    platform: 'linux',
    command: 'sudo apt install cloudflared   # or the .deb/.rpm from the releases page',
    note: 'any recent cloudflared works; the plugin only needs `tunnel login`, `create`, `route dns` and `run`',
  };
}

/** The release page, for the install hint in the panel. */
export const CLOUDFLARED_RELEASES = 'https://github.com/cloudflare/cloudflared/releases/latest';

/**
 * One line summarizing the environment the panel shows at the top of the
 * Cloudflare card.
 * @returns `{ ready, missing }` where `missing` lists what still blocks setup.
 */
export function environmentSummary({ cloudflaredFound, certPresent, apiTokenStored, hostname }) {
  const missing = [];
  if (!cloudflaredFound) missing.push('cloudflared');
  if (!certPresent && !apiTokenStored) missing.push('authentication');
  if (typeof hostname !== 'string' || hostname.trim() === '') missing.push('hostname');
  return { ready: missing.length === 0, missing };
}
