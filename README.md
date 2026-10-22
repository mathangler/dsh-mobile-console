# dsh-mobile-console

Mobile access for [DeepSeek Harness](https://www.npmjs.com/package/@deepseek-ai/dsh): reach the Harness Web UI from a phone, and manage that access from one settings page.

English | [中文](README.zh.md)

## What it does

The Harness already ships everything a phone needs: a browser UI, a per-process launch token exchanged for a signed cookie, a Host/Origin trust fence, and a listener that can bind one concrete interface address. What it does not ship is the part around it — knowing *which* URL to open, whether the tunnel authority is trusted, whether `cloudflared` is running, which devices have connected, and how to revoke them.

This plugin is that part, and nothing more:

| Panel section | What it gives you |
|---|---|
| **Entry links** | The tunnel and LAN entry URLs, each carrying the process's fresh launch token, with a QR code to scan and a copy button |
| **Trust verdict** | Whether the platform's `/api` fence accepts the tunnel authority, and one button that writes it into the shipped `connection` row |
| **Local network entry** | The machine's non-loopback addresses, and one button that binds the listener to one of them |
| **cloudflared child process** | Detect the binary, start/stop a named tunnel as a managed child, and show its recent output |
| **Devices** | A read-only view of the phones that recently loaded the UI (name, client, first/last seen, address) |
| **Pairing lifetime** | The platform's real `cookieMaxAgeDays`, and one button that revokes every paired browser session |
| **Phone layout** | A switch for the narrow-viewport tweaks (touch-sized controls, 16px inputs, safe-area padding) |

## What it deliberately does not do

**It does not build a second mobile UI.** The phone uses the shipped Web UI. The layout already collapses its sidebar to a 56px rail below 1024px (`dsh-client-ui-layout`, `SIDEBAR_AUTO_COLLAPSE`), so a phone gets a usable single-column conversation with every feature the desktop has — sessions, workspaces, approvals, settings, files.

That choice has two costs, and both are worth stating plainly:

- **The phone holds owner-level access.** It is the same UI, so it can do everything the desktop can, including changing permission presets and installing plugins. The boundary is the tunnel identity (Cloudflare Access) plus the platform cookie, not a reduced feature set.
- **There is no per-device revocation inside the Harness.** The platform keeps no per-device state for browser cookies, and a plugin cannot add a middleware to the shipped `/api` route (the route table matches exact-then-longest-prefix and rejects a duplicate registration). Revocation therefore happens at the tunnel identity (revoke the user's Cloudflare Access session) or all at once, with the panel's *Revoke every paired browser session* button.

The device list is a **view, not an authority**: the injected heartbeat records which phone loaded the page, and that row cannot revoke anything.

## Install

```sh
dsh plugin --profile web add /absolute/path/to/dsh-mobile-console
```

Or install the workspace directory through the plugin manager (`install_bundle`). Then open **Settings → Mobile Access**.

## Configure

Everything lives in the plugin row's `config`, and the panel writes it into your own profile patch layer for you (so it survives upgrades):

```yaml
- insert:
    - id: mobile-console
      name: dsh-mobile-console
      config:
        tunnelHost: dsh.example.com
        publicUrl: https://dsh.example.com
        lanHost: 10.0.161.47
        cloudflared:
          command: cloudflared
          args: ['tunnel', 'run', 'dsh-mobile']
        narrowEnhance: true
        deviceRetentionDays: 180
```

| Field | Meaning |
|---|---|
| `tunnelHost` | The authority the tunnel serves. The entry link and its QR appear only once this is set. |
| `publicUrl` | Optional advertised root URL (what the Harness prints and puts in `DSH_WEB_URL`). |
| `lanHost` | Optional concrete local interface literal for a LAN entry. Wildcards are refused by the platform itself. |
| `cloudflared` | Optional command to manage as a child process. Omit it to run your tunnel yourself. |
| `narrowEnhance` | Apply the phone layout tweaks below 1024px (default `true`). |
| `deviceRetentionDays` | Drop device rows unseen for this long (default 180). |

### Cloudflare walkthrough

1. **Domain.** A domain registered anywhere works, as long as its DNS is served by Cloudflare: add the domain as a zone in the Cloudflare dashboard and change its nameservers at your registrar to the two Cloudflare assigns. Cloudflare does not sell or give away domains — it hosts DNS for the one you own.
2. **Tunnel.** `cloudflared tunnel login`, `cloudflared tunnel create dsh-mobile`, then route your hostname to it (`cloudflared tunnel route dns dsh-mobile dsh.example.com`). Put `tunnel: run dsh-mobile` under `config.cloudflared.args` to let the panel manage the process.
3. **Trust the authority.** Open the panel, and press *Add this authority to trustedHosts*. Without it the UI loads but every `/api` call answers 403: the platform's fence only accepts loopback, the listener's own bind address, or a declared authority.
4. **Optional — Cloudflare Access.** In Zero Trust, create a self-hosted Access application for `dsh.example.com` with a One-time PIN policy for your own email address, and set the session duration (the default is 24 hours; up to one month is allowed). Access then authenticates the device at the edge, and revoking its session there is your per-identity revocation.

### Local network entry

The shipped listener binds one concrete address. To use the LAN entry, bind the machine's own address — `dsh web --host 10.0.161.47`, or the panel's *Bind the listener to this address* button, which writes the live `webserver` row values into your patch. Loopback keeps working either way, so the desktop is unaffected.

## Security model

- **The platform authenticates, not this plugin.** Every panel request calls `ctx.connection.requestRejection(req)` first — the shipped Host/Origin fence plus the login-token/cookie check — and returns its status before reading a byte of the body. This is the same convention the shipped open-in-app plugin follows; nothing here is hand-rolled.
- **The launch token is per process.** `dsh web` prints a tokenized URL at startup, and this plugin builds the same URL through `ctx.connection.authenticatedUrl()`. Re-opening a fresh entry link re-pairs a phone, which is also how a phone renews an expired cookie.
- **The cookie is authority-bound.** A phone paired through the tunnel and the same phone paired over the LAN hold different cookies; changing the tunnel hostname invalidates the old one.
- **Revocation is all-or-nothing inside the Harness.** *Revoke every paired browser session* deletes the `client-connection/browser-session` credential record. The running process still holds the signing secret in memory, so the effect lands at the next start — the panel says exactly that. For per-identity revocation, revoke the Cloudflare Access session.
- **The heartbeat asset is public.** `/mobile-console/heartbeat.js` is served like any other static asset: it carries no secret, and it only pings when the page itself was already authenticated. The heartbeat endpoint behind it is fenced.
- **Config writes are explicit.** Every write goes through `ctx.configEditor`, which persists into your own profile patch layer and reconciles through the normal Loader path. Writes that would freeze inherited values (the `webserver` row's `host`) restate the live values, and the panel labels them as needing a restart.

## Tests

```sh
npm run check
```

- `test/qr.test.mjs` — the hand-written QR encoder. Its golden matrices were produced by the reference `qrcode` npm package (byte mode, pinned masks) and match this encoder for **every error-correction level, versions 1–10 and all eight masks** (152 matrices). The suite also checks the function patterns, the always-dark module, the remainder bits, and the Reed–Solomon root property.
- `test/trusted-hosts.test.mjs` — config normalization, bind-address admission (wildcards refused), the trust probe's 403/401/throw cases, device labelling, and the device view's upsert/prune/cap rules.
- `test/client-load.test.mjs` — runs `lib/client.js` in a minimal module-loader and React stub, then asserts the module id, the inject list, the one `settings.section` registration, the two stylesheets, and the locale dictionaries.

The plugin has **no runtime dependencies**: no `@deepseek-ai/*` imports, no zod, no bundler. The QR encoder exists precisely because the Harness installation contains no QR library, and a pairing URL that carries a launch token must never be handed to an online QR service.

## Limitations

- The narrow-viewport tweaks are CSS-only and are applied at page load, so a desktop window resized down to phone width after loading keeps the desktop sizing until reload.
- The device list only knows about phones that loaded the UI while the plugin was installed and the heartbeat could reach the host.
- The cloudflared child process is managed only while this Harness process runs; a tunnel started outside the panel is reported as unconfigured rather than adopted.
- Approval cards and the rest of the UI are the shipped ones — this plugin adds no phone-specific interaction.

## License

MIT.
