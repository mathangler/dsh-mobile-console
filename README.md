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
| **Cloudflare setup** | An environment checklist (binary, certificate, stored tokens, hostname), a guided browser login that shows the authorization URL, a one-click API-token setup, optional Access creation, and teardown |
| **Setup skill** | Installing the plugin installs `dsh-mobile-access`, so a new conversation can walk the whole configuration |
| **Session renewal** | Every app load re-mints the phone's cookie with a full lifetime, plus a manual *Renew this device now* button |
| **Advertised URL** | One button that makes the platform advertise the tunnel hostname, and one that puts it back to `127.0.0.1` |
| **Devices** | A read-only view of the phones that recently loaded the UI (name, client, first/last seen, address) |
| **Pairing lifetime** | The platform's real `cookieMaxAgeDays`, and one button that revokes every paired browser session |
| **Phone layout** | A switch for the narrow-viewport tweaks (touch-sized controls, 16px inputs, safe-area padding) |

## What it deliberately does not do

**It does not build a second mobile UI.** The phone uses the shipped Web UI. The layout already collapses its sidebar to a 56px rail below 1024px (`dsh-client-ui-layout`, `SIDEBAR_AUTO_COLLAPSE`), so a phone gets a usable single-column conversation with every feature the desktop has — sessions, workspaces, approvals, settings, files.

That choice has two costs, and both are worth stating plainly:

- **The phone holds owner-level access.** It is the same UI, so it can do everything the desktop can, including changing permission presets and installing plugins. The boundary is the tunnel identity (Cloudflare Access) plus the platform cookie, not a reduced feature set.
- **There is no per-device revocation inside the Harness.** The platform keeps no per-device state for browser cookies, and a plugin cannot add a middleware to the shipped `/api` route (the route table matches exact-then-longest-prefix and rejects a duplicate registration). Revocation therefore happens at the tunnel identity (revoke the user's Cloudflare Access session) or all at once, with the panel's *Revoke every paired browser session* button.

The device list is a **view, not an authority**: the injected heartbeat records which phone loaded the page, and that row cannot revoke anything.

## Requirements

- A DeepSeek Harness install with a `web` profile. This is a **profile bundle**: it adds one host row and one settings section, nothing else.
- `cloudflared` — only for remote access. The panel detects it, shows the install command for your platform, and the guided login or an API token does the rest. Loopback-only use needs nothing.
- A domain whose DNS Cloudflare serves — only for remote access. No public server, no open inbound port.
- Node 20+ and no runtime dependencies (the plugin uses `node:crypto` and the platform's own services).

## Install

```sh
# from GitHub (pnpm resolves the default branch)
dsh plugin --profile web add github:mathangler/dsh-mobile-console

# or from a checkout on disk — the form used while developing this plugin
dsh plugin --profile web add /absolute/path/to/dsh-mobile-console
```

`dsh plugin` forwards its arguments to `pnpm` inside the profile directory, and every dependency that declares `dsh.bundle` is appended to `dsh.profile.bundles`. If your network blocks git over HTTPS, use the checkout form.

Then:

1. **Restart the Harness.** The host half — routes, the managed tunnel child, the setup skill — is loaded at startup.
2. Open **Settings → Mobile Access**. That section is the whole interface.

Installing also installs the setup skill, so a new conversation can walk the whole configuration for you: ask it to *configure phone access*.

## Update

```sh
dsh plugin --profile web add github:mathangler/dsh-mobile-console   # re-resolve the branch
dsh plugin --profile web update dsh-mobile-console                  # or update the dependency
```

Then restart the Harness. Everything the panel wrote survives an update, because it lives in **your** profile patch layer rather than in the package: the hostname, the tunnel name, the `trustedHosts` entry, the advertised URL and the cloudflared settings. The device list and the Cloudflare credentials live in the Harness credential store and survive as well.

## Uninstall

```sh
dsh plugin --profile web remove dsh-mobile-console
```

Then restart the Harness. The package, its row and its settings section are gone, and the tunnel it was running dies with it — the child process belongs to the plugin's fiber.

Deliberately left behind, because they are yours:

| What | Where | How to clean it |
|---|---|---|
| Row config the panel wrote (hostname, tunnel name, advertised URL) | your profile's `cordis.patch.yml`, the `id: mobile-console` entry | delete that entry |
| The trust entry | same file, `id: connection` → `trustedHosts` | drop the hostname from the list |
| The Cloudflare tunnel, its DNS record and the stored connector token | Cloudflare, plus the Harness credential store | press **Teardown** in the panel's Advanced card *before* removing the plugin |
| The written tunnel config | `~/.cloudflared/dsh-mobile-console.yml` | delete the file |
| A stored Cloudflare API token | the Harness credential store (`CLOUDFLARE_API_TOKEN`) | panel → **Forget the stored API token** |

## Usage

The panel is a control surface, not a wizard. Five things, in the order you need them:

1. **Fill in two fields** (in the Advanced card): the **hostname** the phone will open, for example `<label>.example.com`, and this machine's **tunnel name**, `<label>`. The panel suggests `<label>` from the machine's own platform — `dsh-mac` on macOS, `dsh-win` on Windows, `dsh-lin` on Linux — because each machine gets its own hostname and tunnel name.
2. **Create the tunnel**, either way:
   - **Check the environment → Start the browser login → Create the tunnel and configure**, or
   - paste a Cloudflare API token → **Set up automatically**.
   Both create the tunnel, publish the DNS record, write `~/.cloudflared/dsh-mobile-console.yml` and put the hostname into the platform's trust fence. Start the browser login **from the panel**: a login process started in a terminal is short-lived, gets killed before it can write `cert.pem`, and the authorization then looks like it did nothing.
3. **Press Start** on the cloudflared card. The tunnel runs as a child of the Harness: it starts when you start it, and it stops with the plugin or a restart.
4. **Scan the entry QR code with the phone.** That single visit exchanges the process launch token for a signed cookie. The first arrival from a QR code or another app needs one refresh — the platform's cookie is `SameSite=Strict`, so it is not sent on the redirect that follows a cross-site navigation. Pasting the link into the address bar works first time.
5. **Optionally create the Access application** (same card) so Cloudflare asks for an e-mail one-time PIN before any traffic reaches this machine.

Day to day the phone stays paired by itself: every app load asks the host for a fresh tokenized URL, which re-mints the cookie with a full lifetime. Open the app at least once a month and it never lapses; **Renew this device now** does the same on demand. Revocation is all-at-once — **Revoke every paired browser session** (needs a restart, because the running process holds the old signing secret) — or per identity in Cloudflare Access. The device list is a **view**, not an authorization list.

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

### Automatic setup from the panel

The *Cloudflare setup* card does the tunnel work for you. It first **checks the environment** — whether `cloudflared` is installed (and its version), whether `cert.pem` exists, whether an API token or connector token is stored, whether a hostname is configured — and then offers whichever path fits:

- **No cloudflared?** The card shows the install command for your platform (`winget install --id Cloudflare.cloudflared`, `brew install cloudflared`, or the release page) and a *Check the environment* button to re-test after installing.
- **Browser authorization.** *Start the browser login* runs `cloudflared tunnel login`, captures the `dash.cloudflare.com/argotunnel` URL it prints and shows it in the panel (the tab cloudflared opens works too), polls until `cert.pem` appears, then *Create the tunnel and configure* runs `tunnel create`, `tunnel route dns`, writes `~/.cloudflared/dsh-mobile-console.yml`, and adds the hostname to the platform trust fence.
- **API token.** Paste a token with the permissions the card lists, press *Save and verify*, then *Set up automatically*: the plugin creates or reuses a remotely-managed tunnel, points its ingress at the local listener, publishes the proxied CNAME, stores the connector token, and trusts the hostname. No browser, no `cert.pem`.
- **Access (optional).** Give an email and press *Create the Access application* for a self-hosted application with a one-time-PIN policy and a one-month session. The card also reports whether the Zero Trust organization has any login method at all.
- **Teardown.** One button deletes the DNS record and tunnel this plugin created and forgets the stored connector token.

Secrets live in the Harness credential store (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_TUNNEL_TOKEN`), never in configuration and never in a response. Every other value is written into your own profile patch layer.

The one step no API can do is the nameserver change at your registrar — including for a domain registered at Tencent Cloud/DNSPod: add the domain in Cloudflare, then replace DNSPod's nameservers with the two Cloudflare assigns. Records still living at DNSPod stop answering, so import anything else you need (mail, other sites) into Cloudflare first; Cloudflare offers an import during onboarding. Wait for the zone to show **Active** (minutes to 24 hours) before the automatic setup can find it.

### The setup skill

Installing the plugin also installs a **runtime skill** named `dsh-mobile-access` (registered through `ctx.skills.register`, so disabling the plugin removes it and nothing is written into your own skills directory). Ask for it in a new conversation — "配置手机访问" or "set up phone access" — and the model walks the whole path: the one manual step (nameserver delegation at the registrar), the environment check, the tunnel, the trust entry, the optional Access application, and the first phone pairing. Its body covers Windows, macOS and Linux separately (install commands, `%USERPROFILE%\.cloudflared` versus `~/.cloudflared`, `$env:DSH_HOME` versus `$DSH_HOME`, and the service story for each), and it ends with a troubleshooting table for the failures people actually hit: a 403 from the trust fence, `no active Cloudflare zone`, a stale plugin generation, and the 100 MB upload ceiling.

The panel itself no longer carries the tutorial: it shows state and performs actions, the skill explains them.

### Does a Harness restart require re-pairing the phone?

No. The launch token is per process, but it is only needed for the *initial* exchange: the cookie it mints is signed with a secret persisted in `$DSH_HOME/.credentials.yaml`, so a paired phone keeps working across restarts for `cookieMaxAgeDays` (default 30 days). Re-pairing is needed only when the cookie lifetime runs out, when you press *Revoke every paired browser session*, when the credentials file is deleted, when the hostname changes (cookies are bound to an authority), or when the Cloudflare Access session expires — and that last one asks for an email one-time PIN rather than a new pairing.

### Cloudflare walkthrough

1. **Domain.** A domain registered anywhere works, as long as its DNS is served by Cloudflare: add the domain as a zone in the Cloudflare dashboard and change its nameservers at your registrar to the two Cloudflare assigns. Cloudflare does not sell or give away domains — it hosts DNS for the one you own.
2. **Tunnel.** `cloudflared tunnel login`, `cloudflared tunnel create dsh-mobile`, then route your hostname to it (`cloudflared tunnel route dns dsh-mobile dsh.example.com`). Put `tunnel: run dsh-mobile` under `config.cloudflared.args` to let the panel manage the process.
3. **Trust the authority.** Open the panel, and press *Add this authority to trustedHosts*. Without it the UI loads but every `/api` call answers 403: the platform's fence only accepts loopback, the listener's own bind address, or a declared authority.
4. **Optional — Cloudflare Access.** In Zero Trust, create a self-hosted Access application for `dsh.example.com` with a One-time PIN policy for your own email address, and set the session duration (the default is 24 hours; up to one month is allowed). Access then authenticates the device at the edge, and revoking its session there is your per-identity revocation.

### Do I need a public server?

No. `cloudflared` dials **out** from this machine to Cloudflare's edge, and Cloudflare routes your hostname back down that connection. There is no inbound port, no public IP, and no VPS. What the tunnel does need is a hostname whose DNS Cloudflare serves — so a domain is the one thing you must have. Cloudflare does not give domains away; a cheap registration is enough, and a free third-party domain works only if its operator lets you delegate the nameservers to Cloudflare.

With no domain at all, two options remain:

- **Quick tunnel.** `cloudflared tunnel --url http://127.0.0.1:3080` prints a random `*.trycloudflare.com` URL with no account and no domain. The platform's fence refuses an authority nobody declared, so press *Trust this temporary domain* in the panel: the plugin writes that hostname into `trustedHosts` through the Config Editor, which reconciles the row in place. The hostname changes on every start, so the phone pairs again each time — fine for a test, tedious for daily use.
- **Tailscale.** A tailnet gives the machine a stable `machine.tailnet-name.ts.net` hostname with a real certificate and no domain purchase. Declare that hostname once and it keeps working; the phone needs the Tailscale app.

### Which access paths can coexist

The platform binds **one** concrete address and refuses wildcards, so of these three paths you can have any two — and the recommended pair is loopback plus tunnel:

| Configuration | Desktop on `127.0.0.1` | Phone over the internet | Phone on the same Wi-Fi |
|---|---|---|---|
| `host: 127.0.0.1`, tunnel dialling `127.0.0.1` | yes | yes (through Cloudflare) | only through the tunnel |
| `host: 10.0.161.47`, tunnel dialling `10.0.161.47` | **no** | yes | yes, direct |

The first row is what the panel's *Restore the loopback bind* button returns you to, and it is the only configuration where the desktop keeps the default address. The second row is worth it only when LAN-direct speed matters more than loopback: a listener bound to one literal does not answer on `127.0.0.1`.

### Why there is no automatic "am I at home?" switch

Three constraints make an honest one impossible:

1. **One listener, one address.** Nothing listens on loopback *and* a LAN literal at once, and a plugin cannot add a second listener for the shipped `/api` route (the route table rejects a duplicate prefix).
2. **DNS has already answered.** When the phone opens `https://win.example.com`, that name resolves to Cloudflare's edge, so the request has already crossed the internet. A server-side redirect could only make *later* requests direct, and it lands on a second authority (`http://10.0.161.47:3080`) — a second cookie and a second pairing.
3. **A public switch would leak access.** A plugin route that hands a phone a tokenized LAN URL hands that token to anyone who can reach the route. Gating it needs a pairing code, a second authentication path this plugin deliberately does not have.

What the panel does instead is report the truth: *How this panel is being reached right now* for the browser in front of you, a **Reached via** column per device (`tunnel` / `local network` / `this machine`), and a `same network` badge when a phone's address shares a /24 with one of this machine's addresses.

### Local network entry, and what it costs

The shipped listener binds exactly one concrete address and the platform refuses wildcards, so **binding a local address replaces the loopback listener**: after a restart `http://127.0.0.1:3080` stops answering and the desktop must use that address too. Measured, not assumed — a listener bound to `10.0.161.47` refuses `127.0.0.1`.

A tunnel does not need a LAN bind at all, because `cloudflared` runs on this same machine and dials `127.0.0.1`. Keeping the default loopback is therefore how you get local *and* remote access at once. Bind a local address only if you also want a phone on the same Wi-Fi to reach the Harness directly; the panel has a *Restore the loopback bind* button for when you change your mind.

### Two machines (for example a Windows desktop and a Mac)

Give each machine its **own hostname** and its **own tunnel**:

| Machine | Tunnel | DNS route | Access application | `tunnelHost` |
|---|---|---|---|---|
| Windows | `dsh-win` | `win.example.com` | `win.example.com` (or one wildcard `*.example.com`) | `win.example.com` |
| Mac | `dsh-mac` | `mac.example.com` | `mac.example.com` | `mac.example.com` |

Each machine runs its own Harness and its own `cloudflared`, so each panel writes only its own authority into its own `trustedHosts`. Do not point both hostnames at one tunnel: a Harness is stateful, so a request that lands on the wrong machine shows the wrong sessions. Cookies are bound to an authority, so each machine pairs separately — which is what you want, since the two Harnesses hold different sessions.

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
