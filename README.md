# dsh-remote-access

Remote access for [DeepSeek Harness](https://www.npmjs.com/package/@deepseek-ai/dsh): reach the Harness Web UI from a phone or another device, and manage every door into it from one settings page.

English | [中文](README.zh.md)

## What it does

The Harness already ships the hard half: a browser UI, a per-process launch token exchanged for a signed cookie, a Host/Origin trust fence, and a listener that can bind one concrete interface address. What it does not ship is the part around it — the switch between "only this computer and its Wi-Fi" and "the internet", the credentials other devices use, which of them are still alive, and how to take one back.

This plugin is that part:

| Panel section | What it gives you |
|---|---|
| **Access mode** | A two-button switch, **Local network** / **Public**, auto-detected from the current bind. The switch only **previews** a mode; **Enable this mode** applies it (immediately — reopen the panel at the new address; a restart is still recommended). Only the previewed mode's settings render. |
| **Entry link** | The tokenized URL the device opens, with its QR code behind a **Show QR** toggle. Under **Local network** it is labelled *Temporary: it dies with this process*; the platform's launch token is per process either way. |
| **One-time pairing code** | Eight characters, ten minutes, single use, with a QR code that carries the code in a URL — for a device that cannot reach this screen's QR code. |
| **Authorized devices** | The authority list: every credential this machine handed out (source, temporary/long-lived, created, last used + client IP, explicit expiry, status), each revocable, renamable and re-datable on its own — plus **Get link**, which mints a fresh 15-minute single-use link for a live device. |
| **Cloudflare tunnel** | A prominent **Start tunnel** button, the child process's state and recent output, and the hostname the tunnel serves. |
| **Edge authentication** | Whether a Cloudflare Access application fronts the hostname — a status line that turns warning-coloured when it is off. |
| **Advanced** | The Cloudflare setup (environment check, guided browser login, API token, teardown), the access keys, the recovery password, and the phone-layout tweak. |
| **Setup skill** | Installing the plugin installs `dsh-remote-access`, so a new conversation can walk the whole configuration. |

Four kinds of credential can get a device in, and all four become rows in the same **Authorized devices** list: the **entry link**, a **one-time pairing code**, an **access key**, and the optional **password**. Their exact parameters are in [The four credential sources](#the-four-credential-sources).

## What it deliberately does not do

**It does not build a second mobile UI.** The phone uses the shipped Web UI. The layout already collapses its sidebar below 1024px, so a phone gets a usable single-column conversation with every feature the desktop has. That choice has two costs, and both are worth stating plainly:

- **The device holds owner-level access.** It is the same UI, so it can do everything the desktop can. The boundary is the platform cookie plus the tunnel identity, not a reduced feature set.
- **The platform cookie cannot be revoked per device.** The platform keeps no per-device state for browser cookies, and a plugin cannot insert middleware into the shipped `/api` route. Revoking the cookie happens all at once. Per-device revocation exists only for the credentials this plugin issues.

It also deliberately does the following, or refuses to:

- **It cannot mint platform tokens.** The launch token belongs to the running process. A "temporary token" here is a plugin credential that is exchanged for a platform entry link; it is not a platform token.
- **It never slides a lifetime.** No hidden renewal extends anything: what the panel shows is what expires.
- **It does not enforce Cloudflare Access.** Access is optional, and when it is on it sits in front of everything on that hostname — including the pairing-code and password pages.
- **It does not switch automatically between LAN and tunnel.** One listener binds one address, and DNS has already answered by the time a request arrives; the panel reports the path actually taken instead.
- **It does not read `DSH_*` from a `.env` file.** Those variables must be exported in the launcher environment; any `DSH_*` in a `.env` makes startup throw.

## Requirements

- A DeepSeek Harness install with a `web` profile. This is a **profile bundle**: it adds one host row (`id: remote-access-panel`) and one settings section, nothing else.
- `cloudflared` — only for public access. The panel detects it, shows the install command for your platform, and either the guided login or an API token does the rest. Local-network-only use needs nothing.
- A domain whose DNS Cloudflare serves — only for public access. No public server, no open inbound port.
- Node 20+ and no runtime dependencies (the plugin uses `node:crypto` and the platform's own services).

## Install

```sh
  # from GitHub (pnpm resolves the default branch)
dsh plugin --profile web add github:mathangler/dsh-remote-access

  # or from a checkout on disk — the form used while developing this plugin
dsh plugin --profile web add /absolute/path/to/dsh-remote-access
```

`dsh plugin` forwards its arguments to `pnpm` inside the profile directory, and every dependency that declares `dsh.bundle` is appended to `dsh.profile.bundles`. If your network blocks git over HTTPS, use the checkout form.

Then:

1. **Restart the Harness.** The host half — routes, the managed tunnel child, the setup skill — is loaded at startup.
2. Open **Settings → Remote Access**. That section is the whole interface.

Installing also installs the setup skill, so a new conversation can walk the whole configuration for you: ask it to *set up remote access*.

## Update

```sh
dsh plugin --profile web add github:mathangler/dsh-remote-access   # re-resolve the branch
dsh plugin --profile web update dsh-remote-access                  # or update the dependency
```

Then restart the Harness. Everything the panel wrote survives an update, because it lives in **your** profile patch layer rather than in the package: the hostname, the tunnel name, the LAN bind, the advertised URL, the `trustedHosts` entry and the cloudflared settings. The credential records and the Cloudflare secrets live in the Harness credential store and survive as well.

## Uninstall

```sh
dsh plugin --profile web remove dsh-remote-access
```

Then restart the Harness. The package, its row and its settings section are gone, and the tunnel it was running dies with it — the child process belongs to the plugin's fiber.

Deliberately left behind, because they are yours:

| What | Where | How to clean it |
|---|---|---|
| The credential records (`devices`, `devices-v2`, `access-keys`, `recovery`, `device-tokens`, `pair-codes`, all under the `dsh-remote-access/` scope) | the Harness credential store | revoke and delete the rows in the panel, and remove the recovery password, *before* removing the plugin |
| Row config the panel wrote (hostname, tunnel name, LAN bind, advertised URL) | your profile's `cordis.patch.yml`, the `id: remote-access-panel` entry | delete that entry |
| The trust entry | same file, `id: connection` → `trustedHosts` | drop the hostname from the list |
| `~/.cloudflared/*` — the tunnel config, the connector credentials file and `cert.pem` | your home directory (`%USERPROFILE%\.cloudflared` on Windows) | delete the files |
| The DNS record, the tunnel and any Access application this plugin created | Cloudflare | press the teardown button in **Advanced → Cloudflare setup** *before* removing the plugin, or delete them in the dashboard |
| The stored Cloudflare API token and connector token (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_TUNNEL_TOKEN`) | the Harness credential store | panel → **Forget the stored API token**; teardown removes the connector token |

## Usage

### Choose a mode

The panel starts on the mode the current bind implies: **Local network** when the listener is bound to one of this machine's own non-loopback addresses, **Public** when it is on `127.0.0.1`. The two-button switch at the top is a **preview**: it only chooses which configuration is displayed, and nothing is written until you press **Enable this mode** (the panel shows *Currently enabled* when the previewed mode is already the live one). Enabling **takes effect immediately** — the listener rebinds, so this page may go blank or stop responding and you should reopen the panel at the new address; a dsh restart is still recommended. After enabling Local network, the desktop must use the new address too, because a listener bound to one literal stops answering on `127.0.0.1`.

### LAN steps

1. Choose **Local network** and pick an address from the list — the switch only previews; nothing is written yet.
2. Press **Enable this mode**. It applies immediately: the listener rebinds to that address, and this page may go blank or stop responding, so reopen the panel at the new address (`http://<address>:3080`). A dsh restart is still recommended.
3. Open the entry link, or press **Show QR** and scan it with the device. It is labelled **Temporary: it dies with this process**.
4. Nothing else is needed: there is **no device management in this mode**, because the platform's launch token dies with the process and this plugin keeps no long-lived record for it.
5. To go back, press **Restore the loopback bind (127.0.0.1)** — the page may go blank again, so reopen the panel at `http://127.0.0.1:3080`.

### Public steps

1. Choose **Public** and press **Enable this mode** — the listener returns to `127.0.0.1`, and if this page goes blank, reopen the panel there.
2. Under **Advanced → Cloudflare setup**, fill in the hostname the device will open (for example `dsh-win.example.com`) and this machine's tunnel name (`dsh-win`), then create the tunnel either way:
   - **Check the environment → Start the browser login → Create the tunnel and configure**, or
   - paste a Cloudflare API token → **Set up automatically**.
   Both publish the DNS record, write `~/.cloudflared/dsh-remote-access.yml` and put the hostname into the platform's trust fence. Start the browser login **from the panel**: a login process started in a terminal is short-lived, gets killed before it can write `cert.pem`, and the authorization then looks like it did nothing.
3. Press the prominent **Start tunnel** button on the Cloudflare tunnel card. The tunnel runs as a child of the Harness and stops with the plugin or a restart.
4. Pair a device: press **Show QR** on the entry link and scan it, or generate a pairing code (next section).
5. Optionally create the Access application so Cloudflare asks for an e-mail one-time PIN before any traffic reaches this machine.

The entry link's first visit exchanges the process launch token for the platform cookie. Its QR code is collapsed behind **Show QR**. From a QR code or another app that first landing usually needs one refresh — the platform cookie is `SameSite=Strict`, so it is not sent on the redirect that follows a cross-site navigation. Pasting the link into the address bar works first time.

If the panel marks a generated link **loopback-only** — *this link only works on this machine* — the link cannot leave this computer: configure a domain under **Advanced → Cloudflare setup** (public mode), or switch to local network mode.

### Add a device by code or QR

In the **Public** mode, the panel's pairing card generates a **one-time pairing code**: eight characters from an alphabet without `0`, `O`, `1`, `I` or `L`. It is valid for **ten minutes**, works **once**, is rate-limited, and can only be generated **from an authorized session**. The panel shows the code and a QR code; the QR encodes a URL carrying the code, so the new device can scan it or type it by hand.

Before generating, choose the **lifetime** the new device's record gets: *never expires*, 30 days, 90 days, 1 year, or a custom date (the host default for an unspecified lifetime is one year). The record then appears in **Authorized devices** with that expiry.

### Use an access key

Under **Advanced → Access keys**, press **Create access key** and give it a name. The key looks like `dra_…`, is shown **exactly once**, and is stored on this machine only as its sha256 fingerprint — copy it now, or reset it later to get a new one. Present it at `POST /remote-access/token` and the answer is a **15-minute, single-use** entry link: it forwards that browser into the app once and is burned on use, whether or not it had already expired.

Keys can be revoked one by one, which kills the key immediately, or reset, which invalidates the old secret and shows a new one once.

### Recover with the password

Under **Advanced → Recovery access**, set a password of at least 12 characters. Verification is challenge-response: the host sends a single-use nonce and a salt, the browser derives a key with PBKDF2-SHA256 (600,000 iterations) and answers with an HMAC over the nonce. **The password never crosses the network.** On success the host hands back a one-time link valid for **at most 15 minutes**; a page-close beacon invalidates it early on a best-effort basis.

With no password stored, the recovery page renders **nothing at all** and the public surface stays silent: an unauthenticated visit to the hostname gets the platform's own 401, and `/remote-access/unlock` returns 404.

The recovery order, in the order to try it:

1. **The device record** — a device that paired once carries a plugin credential, and a lapsed platform cookie is renewed automatically when it returns. To hand a live device a fresh link by hand, press **Get link** on its row in **Authorized devices**: it mints a new 15-minute single-use link, with its own **Show QR** toggle.
2. **An access key** — exchange it at `POST /remote-access/token` for a fresh single-use link.
3. **The password** — visit `https://<hostname>/remote-access/unlock` and answer the challenge.
4. **Reach the computer** — with none of the three, re-pairing needs the machine itself.

## Configure

Everything lives in the plugin row's `config`, and the panel writes it into your own profile patch layer for you (so it survives upgrades):

```yaml
- insert:
    - id: remote-access-panel
      name: dsh-remote-access
      config:
        tunnelHost: dsh-win.example.com
        publicUrl: https://dsh-win.example.com
        lanHost: 10.0.161.47
        tunnelName: dsh-win
        accessEmail: you@example.com
        cloudflared:
          command: cloudflared
          args: ['tunnel', 'run', 'dsh-win']
        narrowEnhance: true
        deviceRetentionDays: 180
```

| Field | Meaning |
|---|---|
| `tunnelHost` | The authority the tunnel serves. The public entry link and its QR appear only once this is set. |
| `publicUrl` | Optional advertised root URL (what the Harness prints and puts in `DSH_WEB_URL`). |
| `lanHost` | Optional concrete local interface literal for a LAN entry. Wildcards are refused by the platform itself. |
| `tunnelName` | The tunnel the automatic setup creates or reuses (default `dsh-remote-access`; use one name per machine). |
| `accessEmail` | The email the optional Cloudflare Access policy allows. |
| `cloudflared` | Optional command to manage as a child process. Omit it to run your tunnel yourself. |
| `narrowEnhance` | Apply the phone layout tweaks below 1024px (default `true`). |
| `deviceRetentionDays` | Drop activity rows unseen for this long (default 180). |

Secrets never live here: the Cloudflare API token, the connector token, the access keys and the recovery password live in the Harness credential store, under `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_TUNNEL_TOKEN` and the plugin's own `dsh-remote-access/*` records.

The row id is `remote-access-panel`, **not** `remote-access`: the shipped `dsh-base` bundle already owns `remote-access` for a platform plugin, and the Loader dedupes rows by id without a diagnostic — reusing that id would silently drop the shipped row and break the UI's RPC.

### The setup skill

Installing the plugin also installs a **runtime skill** named `dsh-remote-access` (registered through `ctx.skills.register`, so disabling the plugin removes it and nothing is written into your own skills directory). Ask for it in a new conversation — "配置远程访问" or "set up remote access" — and the model walks the fixed pipeline: it always asks you for the domain, hostname, mode and setup path instead of assuming them, and it never invents a hostname or runs `cloudflared tunnel login` on your behalf.

Its body covers Windows, macOS and Linux separately (install commands, `%USERPROFILE%\.cloudflared` versus `~/.cloudflared`, `$env:DSH_HOME` versus `$DSH_HOME`), the four credential sources with their real parameters, the recovery order, and a troubleshooting table for the failures people actually hit: the trust fence's 403, `no active Cloudflare zone`, a stale plugin generation, an expired one-time link, and the 100 MB upload ceiling.

The panel itself carries no tutorial: it shows state and performs actions, the skill explains them.

## Security model

### The four credential sources

| Source | What it is | Lifetime | Revocation |
|---|---|---|---|
| **Entry link** | The platform's per-process launch token, exchanged once for the platform cookie. The first pairing also writes a device record. | The link dies with the process; the record lasts **30 days**, matching the platform cookie. | The record is revoked per device. The platform cookie itself can only be revoked **all at once**. |
| **One-time pairing code** | Eight characters from an alphabet without `0`/`O`/`1`/`I`/`L`, generatable only from an authorized session, rate-limited. The QR encodes a URL carrying the code. | **10 minutes, single use.** It carries the lifetime the new device's record gets: never / 30 / 90 / 365 days / a custom date. | Consumed on use; the record it wrote stays revocable. |
| **Access key** | A named key `dra_…`, shown once, stored only as a sha256 fingerprint; exchanged at `POST /remote-access/token`. | The key is a stored credential; the link it mints is **15 minutes and single use**. | Revoke or reset each key individually. |
| **Password** (optional, fail-closed) | Challenge-response: PBKDF2-SHA256, 600,000 iterations, plus an HMAC over a single-use nonce, so the password never crosses the network. | A one-time link valid for **at most 15 minutes**; a page-close beacon invalidates it early, best effort. | Remove the password (which also revokes outstanding tickets). |

### Honest limits

- **Per-device revocation covers plugin-issued credentials.** The platform's browser cookie cannot be revoked per device — only wholesale with **Revoke every paired browser session**, which deletes the platform's session record and takes effect at the next restart.
- **The plugin cannot mint platform tokens.** A temp token is a plugin credential that is exchanged for a platform entry link; the platform still issues the cookie.
- **Nothing slides.** No hidden renewal extends any credential: what the panel shows is what expires. Using a device credential only refreshes its "last used" stamp and client IP.
- **No password means no recovery surface.** With no password stored, the recovery page renders nothing and the public surface stays silent: an unauthenticated visit to the hostname receives the platform's own 401, and `/remote-access/unlock` answers 404.
- **Cloudflare Access is optional and not enforced by the plugin.** The panel only reports whether an Access application fronts the hostname. When it is on, it sits in front of everything on that hostname, including the pairing-code and password pages.
- **The platform's fence authenticates every panel call.** Each panel request calls `ctx.connection.requestRejection(req)` first and returns its verdict before reading a byte of the body; the pairing-code, access-key and password doors authenticate their own callers, because they must work precisely when the platform credential has lapsed.
- **`DSH_*` variables belong to the launcher environment.** Export them where you start dsh; any `DSH_*` entry in a `.env` file makes startup throw.
- **The tunnel is public.** Whoever learns the hostname reaches this Harness, so the credentials above are what stands between them and the UI.

## Tests

```sh
npm run check
```

- `test/qr.test.mjs` — the hand-written QR encoder. Its golden matrices were produced by the reference `qrcode` npm package and match this encoder for every error-correction level, versions 1–10 and all eight masks.
- `test/trusted-hosts.test.mjs` — config normalization, bind-address admission (wildcards refused), the trust probe's 403/401/throw cases, and the device view's upsert/prune/cap rules.
- `test/unlock.test.mjs` — the password door: PBKDF2 derivation, HMAC proofs, single-use nonces, ticket signing and the rate limiter.
- `test/accesskey.test.mjs` — access keys and one-time links: minting, sha256 fingerprints, constant-time comparison, single use and expiry.
- `test/cloudflare.test.mjs` — the Cloudflare API calls, the guided login's state machine, and teardown.
- `test/cloudflared.test.mjs` — the child-process wrapper: start, stop, output capture and exit reporting.
- `test/client-load.test.mjs` — runs `lib/client.js` in a minimal module-loader and React stub, then asserts the module id, the inject list, the single `settings.section` registration, the stylesheets and the locale dictionaries.

The plugin has **no runtime dependencies**: no `@deepseek-ai/*` imports, no zod, no bundler. The QR encoder exists precisely because the Harness installation contains no QR library, and a pairing URL that carries a credential must never be handed to an online QR service.

## Limitations

- **One listener, one address.** Loopback, a LAN literal and the tunnel cannot all be live at once: binding a local address replaces the loopback listener, so `http://127.0.0.1:3080` stops answering and the desktop must use the new address too.
- **LAN mode has no device management.** A platform launch token dies with the process, so that mode shows only the entry link, its QR code and the way back to loopback.
- **The cloudflared child process is managed only while this Harness process runs.** A tunnel started outside the panel is reported as unconfigured rather than adopted.
- **The activity list only knows what the heartbeat saw.** It records devices that loaded the UI while the plugin was installed and the heartbeat could reach the host; it is a sighting log, not an authorization.
- **A quick tunnel changes hostname on every start**, so it must be trusted again and the device pairs again each time.
- **The narrow-viewport tweaks are CSS-only** and applied at page load, so a desktop window resized down to phone width keeps the desktop sizing until reload.
- **Approval cards and the rest of the UI are the shipped ones** — this plugin adds no phone-specific interaction.

## License

MIT.
