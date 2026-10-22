/**
 * dsh-mobile-console — browser half.
 *
 * Two jobs:
 *
 *  1. The "Mobile Access" settings section: entry URLs with QR codes, the trust
 *     verdict for the tunnel authority and a button that writes it into the
 *     shipped `connection` row, the cloudflared child process, the read-only
 *     device view, and one button that revokes every paired browser session.
 *  2. The narrow-viewport enhancement, applied only on a phone-sized viewport
 *     and only while the plugin config allows it. It is CSS-only on purpose:
 *     the shipped layout already collapses its sidebar below 1024px, so nothing
 *     here drives layout state and nothing breaks if a class name changes.
 *
 * The panel talks to the host half over `${CHANNEL}/<endpoint>`, same-origin, so
 * the browser attaches the platform's login cookie automatically.
 */
window.__ModuleLoader__.load({
  id: 'dsh-mobile-console',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    /** Route prefix owned by the host half; must match lib/index.js. */
    const CHANNEL = '/mobile-console';
    /** Locale namespace for every string this panel shows. */
    const NS = 'mobile-console';

    const EN = {
      title: 'Mobile Access',
      intro:
        'Open the shipped Web UI from a phone. The platform authenticates it with a per-process launch token and a signed cookie; this panel shows the entry links, checks whether the platform trust fence accepts the tunnel authority, and can write it for you.',
      entries: 'Entry links',
      noEntries:
        'No entry yet. Set a tunnel authority below (or bind the listener to a local interface) and the link appears here.',
      tunnelEntry: 'Cloudflare tunnel',
      lanEntry: 'Local network',
      openOnPhone: 'Open on the phone',
      copyLink: 'Copy link',
      copied: 'Copied',
      trustTrusted: 'trust fence: accepted',
      trustRefused: 'trust fence: refused — /api calls will fail with 403',
      trustUnknown: 'trust fence: unknown (connection service unavailable)',
      trustFix: 'Add this authority to trustedHosts',
      trustFixed: 'Written. The Loader reconciles the row in place.',
      domainTitle: 'The hostname phones will open',
      domainHint:
        'Exactly one hostname, no scheme, no path — for example dsh-win.example.com. This is the name your tunnel serves and the name that must be accepted by the platform trust fence; saving it writes this plugin row\u2019s config into your own profile patch layer, so it survives upgrades.',
      domainPlaceholder: 'dsh-win.example.com',
      publicUrlLabel: 'Advertised root URL (optional)',
      publicUrlPlaceholder: 'https://dsh-win.example.com',
      tunnelNamePlaceholder: 'dsh-win',
      tunnelNameHint:
        'The tunnel this machine creates or reuses. One name per machine, and the usual pattern is to reuse it as the leftmost label of the hostname: tunnel dsh-win with dsh-win.example.com, tunnel dsh-mac with dsh-mac.example.com.',
      advancedTitle: 'Advanced: Cloudflare setup, local network, layout',
      save: 'Save',
      quickTrust: 'Trust this temporary domain',
      quickTrustHint:
        'A quick tunnel gets a new random hostname on every start, so this must be repeated each time — and each new hostname pairs the phone again. A named tunnel with your own domain avoids that.',
      restoreLoopback: 'Restore the loopback bind (127.0.0.1)',
      lanWarning:
        'Binding a local address replaces the loopback listener: after a restart, 127.0.0.1 stops answering and the desktop must use {host} too. A tunnel needs no LAN bind — cloudflared dials 127.0.0.1 from this same machine, so keeping the default loopback gives you local and remote access at once.',
      lanTitle: 'Local network entry',
      lanBound: 'The listener is bound to {host}, so a phone on the same network can use it.',
      lanNotBound:
        'The listener is bound to {host}, so another device cannot reach it directly. That is the right default when you use a tunnel; bind a local address only if you also want phone access over the same Wi-Fi.',
      lanAddresses: 'Addresses on this machine',
      lanWrite: 'Bind the listener to this address',
      lanWritten: 'Written. A restart is required for a new bind address.',
      publicUrlWrite: 'Advertise this root URL',
      publicUrlClear: 'Back to 127.0.0.1',
      publicUrlCleared: 'Removed. The advertised URL is the listener origin again.',
      publicUrlWarning:
        'This writes the platform\u2019s advertised base URL, so the desktop app and the printed URL start using it too. Leave it unset if you want the desktop on 127.0.0.1 and only the phone on this hostname.',
      publicUrlWritten: 'Written. A restart is required for a new advertised URL.',
      tunnelTitle: 'cloudflared child process',
      tunnelUnconfigured:
        'No cloudflared command is configured for this plugin row. Add one under config.cloudflared, for example { command: "cloudflared", args: ["tunnel", "run", "dsh-mobile"] }.',
      tunnelUnavailable: 'The subprocess service is unavailable in this composition.',
      tunnelRunning: 'running (pid {pid})',
      tunnelStopped: 'stopped',
      tunnelExited: 'exited: {exit}',
      tunnelStart: 'Start',
      tunnelStop: 'Stop',
      tunnelOutput: 'Recent output',
      cfTitle: 'Cloudflare setup',
      cfIntro:
        'Two ways to publish this Harness: the browser authorization that cloudflared itself uses, or an API token that lets the plugin do everything without a browser. Both end with a hostname served through a tunnel.',
      cfCheck: 'Check the environment',
      cfChecking: 'Checking…',
      cfCloudflared: 'cloudflared',
      cfFound: 'found ({version})',
      cfFoundNoVersion: 'found',
      cfNotFound: 'not found',
      cfInstallWith: 'Install it with:',
      cfReleases: 'or download it from the releases page',
      cfCert: 'browser authorization (cert.pem)',
      cfCertPresent: 'present',
      cfCertAbsent: 'absent',
      cfApiToken: 'API token',
      cfStored: 'stored',
      cfNotStored: 'not stored',
      cfConnectorToken: 'connector token',
      cfHostname: 'hostname',
      cfHostnameMissing: 'not set yet',
      cfConfigFile: 'tunnel config file',
      cfService: 'local service',
      cfReady: 'Everything needed is in place.',
      cfMissing: 'Still missing: {list}',
      cfLoginStart: 'Start the browser login',
      cfLoginCancel: 'Cancel the login',
      cfLoginOpen: 'Open this URL and pick the zone for {hostname}:',
      cfLoginWaiting: 'Waiting for authorization… (the browser tab cloudflared opened works too)',
      cfLoginDone: 'Authorized: cert.pem is present.',
      cfLoginFailed: 'The login process exited without writing a certificate.',
      cfConfigure: 'Create the tunnel and configure',
      cfTokenLabel: 'API token (the alternative to the browser login)',
      cfTokenHint:
        'Create a token in the Cloudflare dashboard under My Profile → API Tokens → Create Token → Custom token, with these permissions:',
      cfTokenSave: 'Save and verify the token',
      cfAutoSetup: 'Set up automatically',
      cfAutoHint:
        'Creates or reuses a remotely-managed tunnel, points its ingress at the local listener, publishes a proxied CNAME, stores the connector token, and adds the hostname to the platform trust fence. It never touches your nameservers — that stays a registrar action.',
      cfAccessEmail: 'Email allowed by the Access policy',
      cfAccessCreate: 'Create the Access application',
      cfAccessHint:
        'Optional, but recommended on a public hostname: one self-hosted Access application with a one-time-PIN policy for your own email and a one-month session.',
      cfTeardown: 'Remove what this plugin created in Cloudflare',
      cfTeardownConfirm: 'Delete the DNS record and the tunnel this plugin created, and forget the stored connector token?',
      cfSteps: 'Steps',
      cfNeedHostname: 'Save a hostname first (the tunnel domain field above).',
      cfForgetToken: 'Forget the stored API token',
      cfForgetTokenDone: 'The stored API token was removed.',
      cfSavedToken: 'Token verified and stored.',
      renewNow: 'Renew this device now',
      devicesTitle: 'Devices that recently connected',
      devicesNote:
        'This list is a view, not an authority: the platform keeps no per-device state for browser cookies, so a row here cannot be revoked individually. Revoking happens at the tunnel identity (Cloudflare Access) or with the button below.',
      devicesEmpty: 'No phone has loaded the UI yet.',
      deviceName: 'Name',
      devicePlatform: 'Client',
      deviceFirst: 'First seen',
      deviceLast: 'Last seen',
      deviceIp: 'Address',
      deviceVia: 'Reached via',
      viaTunnel: 'tunnel',
      viaLan: 'local network',
      viaLocal: 'this machine',
      viaDirect: 'direct',
      viaUnknown: 'unknown',
      onLanBadge: 'same network',
      lanHintForDevice:
        'A phone shown as “same network” is on your LAN right now, so the LAN entry would skip Cloudflare for it.',
      noAutoSwitch:
        'There is no automatic LAN switch, and this is why: one listener binds exactly one address, and by the time a request arrives the phone’s DNS has already answered with the tunnel, so a tunnelled request cannot become a direct one. The panel reports the path that was actually taken instead.',
      reachTitle: 'How this panel is being reached right now',
      reachLocal: 'directly on this machine (loopback)',
      reachLan: 'over the local network, from {ip}',
      reachTunnel: 'through the tunnel, from {ip}',
      reachDirect: 'directly, from {ip}',
      reachUnknown: 'from an address the host could not classify',
      reachTrusted: 'The fence accepts {host}.',
      reachUntrusted: 'The fence refuses {host} — /api calls would answer 403.',
      deviceRename: 'Rename',
      deviceSave: 'Save',
      deviceForget: 'Remove row',
      devicesClear: 'Clear the list',
      platformTitle: 'Pairing lifetime',
      platformCookie: 'Browser cookie lifetime: {days} days (connection row, cookieMaxAgeDays).',
      platformExpiry:
        'A paired phone stops working once its cookie expires or the signing secret changes. Re-opening a fresh entry link pairs it again.',
      platformRecord: 'The platform browser-session record is {state}.',
      platformRecordPresent: 'present',
      platformRecordAbsent: 'absent',
      revoke: 'Revoke every paired browser session',
      revokeConfirm:
        'Delete the platform browser-session record? Every paired browser — phone and desktop — loses access, and the Harness must be restarted for it to take effect.',
      revoked: 'Record deleted. Restart the Harness: the running process still holds the old signing secret.',
      revokeNothing: 'There was no browser-session record to delete.',
      settingsTitle: 'Phone layout',
      narrowEnhance: 'Apply the phone layout tweaks on a narrow viewport',
      narrowEnhanceHint:
        'Touch-sized controls, 16px inputs (stops iOS from zooming on focus) and safe-area padding. The shipped layout already collapses its sidebar below 1024px, so this only adjusts sizing.',
      saved: 'Saved',
      loading: 'Loading…',
      failed: 'Failed: {message}',
      refresh: 'Refresh',
      configTitle: 'Plugin row config',
      configHint: 'Written into your own profile patch layer, so it survives upgrades.',
    };

    const ZH = {
      title: '手机访问',
      intro:
        '用手机打开现有的 Web UI。平台用「每次启动的令牌 → 签名 Cookie」完成认证；本面板负责显示入口链接、检查平台信任栅栏是否接受隧道域名，并可以替你写入。',
      entries: '入口链接',
      noEntries: '还没有入口。在下面填入隧道域名（或把监听绑定到本机局域网地址），链接就会出现在这里。',
      tunnelEntry: 'Cloudflare 隧道',
      lanEntry: '局域网',
      openOnPhone: '在手机上打开',
      copyLink: '复制链接',
      copied: '已复制',
      trustTrusted: '信任栅栏：已接受',
      trustRefused: '信任栅栏：被拒绝 —— /api 调用会 403',
      trustUnknown: '信任栅栏：未知（connection 服务不可用）',
      trustFix: '把这个域名加入 trustedHosts',
      trustFixed: '已写入，Loader 会就地重建该行。',
      domainTitle: '手机要打开的域名',
      domainHint:
        '只填一个主机名，不要带 http:// 和路径——例如 dsh-win.example.com。它就是隧道对外服务的域名，也必须是平台信任栅栏接受的那个名字；保存后写入本插件行配置，落在你自己的 profile patch 层，升级不会丢。',
      domainPlaceholder: 'dsh-win.example.com',
      publicUrlLabel: '对外公开根地址（可选）',
      publicUrlPlaceholder: 'https://dsh-win.example.com',
      tunnelNamePlaceholder: 'dsh-win',
      tunnelNameHint:
        '本机创建或复用的隧道名。一台机器一个名字，惯用做法是把它当作域名最左边那一段：隧道 dsh-win 配 dsh-win.example.com，隧道 dsh-mac 配 dsh-mac.example.com。',
      advancedTitle: '高级：Cloudflare 配置 / 局域网 / 布局',
      save: '保存',
      quickTrust: '信任这个临时域名',
      quickTrustHint:
        '快速隧道每次启动都会换一个随机域名，所以每次都要重新信任一次——而且换域名等于手机要重新配对。用自己的域名建命名隧道就没有这个问题。',
      restoreLoopback: '恢复回环绑定（127.0.0.1）',
      lanWarning:
        '绑定局域网地址会顶掉回环监听：重启后 127.0.0.1 不再响应，桌面端也必须改用 {host}。用隧道时根本不需要绑定局域网地址——cloudflared 就在这台机器上、直接连 127.0.0.1，所以保持默认回环就能同时拿到本地与远程访问。',
      lanTitle: '局域网入口',
      lanBound: '监听已绑定到 {host}，同一网络下的手机可以直接使用。',
      lanNotBound:
        '监听当前绑定在 {host}，其它设备无法直连。用隧道时这正是正确的默认值；只有你也想在同一 Wi-Fi 下用手机直连时，才需要绑定局域网地址。',
      lanAddresses: '本机地址',
      lanWrite: '把监听绑定到这个地址',
      lanWritten: '已写入。新的绑定地址需要重启才生效。',
      publicUrlWrite: '把这个根地址设为公开地址',
      publicUrlClear: '改回 127.0.0.1',
      publicUrlCleared: '已移除。对外广播的地址恢复为监听地址本身。',
      publicUrlWarning:
        '它写的是平台的「对外广播基址」，所以桌面端与启动时打印的地址也会跟着用它。想让桌面留在 127.0.0.1、只有手机用这个域名，就**不要**设它。',
      publicUrlWritten: '已写入。新的公开地址需要重启才生效。',
      tunnelTitle: 'cloudflared 子进程',
      tunnelUnconfigured:
        '本插件行还没有配置 cloudflared 命令。请在 config.cloudflared 下添加，例如 { command: "cloudflared", args: ["tunnel", "run", "dsh-mobile"] }。',
      tunnelUnavailable: '当前组合没有 subprocess 服务。',
      tunnelRunning: '运行中（pid {pid}）',
      tunnelStopped: '未运行',
      tunnelExited: '已退出：{exit}',
      tunnelStart: '启动',
      tunnelStop: '停止',
      tunnelOutput: '最近输出',
      cfTitle: 'Cloudflare 配置',
      cfIntro:
        '两种把 Harness 发布出去的方式：用 cloudflared 自己的浏览器授权，或用 API Token 让插件全程无需浏览器完成。两者最终都是"一个域名经隧道指向本机"。',
      cfCheck: '检测环境',
      cfChecking: '检测中…',
      cfCloudflared: 'cloudflared',
      cfFound: '已找到（{version}）',
      cfFoundNoVersion: '已找到',
      cfNotFound: '未找到',
      cfInstallWith: '安装命令：',
      cfReleases: '或从 releases 页面下载',
      cfCert: '浏览器授权（cert.pem）',
      cfCertPresent: '已存在',
      cfCertAbsent: '不存在',
      cfApiToken: 'API Token',
      cfStored: '已保存',
      cfNotStored: '未保存',
      cfConnectorToken: '连接器令牌',
      cfHostname: '域名',
      cfHostnameMissing: '还没设置',
      cfConfigFile: '隧道配置文件',
      cfService: '本地服务',
      cfReady: '所需条件都已就绪。',
      cfMissing: '还缺：{list}',
      cfLoginStart: '开始浏览器登录',
      cfLoginCancel: '取消登录',
      cfLoginOpen: '打开这个网址，并选择 {hostname} 所属的 zone：',
      cfLoginWaiting: '等待授权中……（cloudflared 自动打开的那个浏览器标签也可以）',
      cfLoginDone: '已授权：cert.pem 已生成。',
      cfLoginFailed: '登录进程退出但没有生成证书。',
      cfConfigure: '创建隧道并完成配置',
      cfTokenLabel: 'API Token（浏览器登录的替代方案）',
      cfTokenHint: '在 Cloudflare 控制台 My Profile → API Tokens → Create Token → Custom token 创建，权限如下：',
      cfTokenSave: '保存并验证 Token',
      cfAutoSetup: '一键自动配置',
      cfAutoHint:
        '创建或复用一条远端托管的隧道、把 ingress 指向本机监听、发布一条代理 CNAME、保存连接器令牌，并把域名加入平台信任栅栏。它不会碰你的 NS——那是注册商侧的动作。',
      cfAccessEmail: 'Access 策略允许的邮箱',
      cfAccessCreate: '创建 Access 应用',
      cfAccessHint: '可选，但公网域名上强烈建议：一个自托管 Access 应用 + 只允许你自己邮箱的 One-time PIN 策略 + 1 个月会话。',
      cfTeardown: '清理本插件在 Cloudflare 创建的东西',
      cfTeardownConfirm: '删除本插件创建的 DNS 记录与隧道，并清除已保存的连接器令牌？',
      cfSteps: '步骤',
      cfNeedHostname: '请先保存域名（上面那个隧道域名输入框）。',
      cfForgetToken: '清除已保存的 API Token',
      cfForgetTokenDone: '已清除保存的 API Token。',
      cfSavedToken: 'Token 已验证并保存。',
      renewNow: '立即为本设备续期',
      devicesTitle: '最近连接过的设备',
      devicesNote:
        '这个列表只是「看得见」，不是授权依据：平台不保存浏览器 Cookie 的设备维度状态，所以这里无法逐台撤销。撤销只有两条路——隧道身份侧（Cloudflare Access）或下面的全部撤销。',
      devicesEmpty: '还没有手机加载过界面。',
      deviceName: '名称',
      devicePlatform: '客户端',
      deviceFirst: '首次',
      deviceLast: '最后',
      deviceIp: '地址',
      deviceVia: '接入方式',
      viaTunnel: '隧道',
      viaLan: '局域网',
      viaLocal: '本机',
      viaDirect: '直连',
      viaUnknown: '未知',
      onLanBadge: '同网段',
      lanHintForDevice: '标为「同网段」的手机此刻就在你的局域网内，用局域网入口可以绕过 Cloudflare。',
      noAutoSwitch:
        '不做自动切换，原因是硬约束：一个监听只能绑定一个地址，而且请求到达时手机的 DNS 早已解析到隧道，所以"已经走隧道的请求"无法再变成直连。面板改为如实显示实际走了哪条路。',
      reachTitle: '本面板当前的访问方式',
      reachLocal: '本机直连（回环）',
      reachLan: '经局域网，来自 {ip}',
      reachTunnel: '经隧道，来自 {ip}',
      reachDirect: '直连，来自 {ip}',
      reachUnknown: '来自一个无法分类的地址',
      reachTrusted: '栅栏已接受 {host}。',
      reachUntrusted: '栅栏拒绝 {host} —— /api 调用会返回 403。',
      deviceRename: '改名',
      deviceSave: '保存',
      deviceForget: '移除记录',
      devicesClear: '清空列表',
      platformTitle: '配对有效期',
      platformCookie: '浏览器 Cookie 有效期：{days} 天（connection 行的 cookieMaxAgeDays）。',
      platformExpiry: '已配对的手机会在 Cookie 过期或签名密钥变化后失效；重新打开一次新的入口链接即可重新配对。',
      platformRecord: '平台浏览器会话记录：{state}。',
      platformRecordPresent: '存在',
      platformRecordAbsent: '不存在',
      revoke: '撤销全部已配对浏览器会话',
      revokeConfirm:
        '删除平台的浏览器会话记录？所有已配对的浏览器（手机与桌面）都会失去访问权，且必须重启 Harness 才生效。',
      revoked: '记录已删除。请重启 Harness：当前进程仍持有旧的签名密钥。',
      revokeNothing: '没有可删除的浏览器会话记录。',
      settingsTitle: '手机端布局',
      narrowEnhance: '窄屏时应用手机端布局微调',
      narrowEnhanceHint:
        '触控尺寸的控件、16px 输入框（避免 iOS 聚焦时自动缩放）与安全区留白。现有布局在 1024px 以下已自动收起侧栏，所以这里只调整尺寸。',
      saved: '已保存',
      loading: '加载中…',
      failed: '失败：{message}',
      refresh: '刷新',
      configTitle: '插件行配置',
      configHint: '写入你自己的 profile patch 层，升级不会丢。',
    };

    /** Panel styles; only theme tokens, so light/dark follows the host. */
    /**
     * Panel styles.
     *
     * Every colour, border and surface comes from the shipped theme tokens
     * (`--dsw-alias-*`), so the panel follows the app's light/dark setting and
     * third-party themes instead of carrying its own palette. Rhythm follows the
     * settings page: 14px section titles, 13px body, 12px secondary, 8px radii,
     * quiet bordered controls rather than filled ones.
     */
    const PANEL_CSS = `
.mc-root { display: flex; flex-direction: column; gap: 16px; }
.mc-h2 { font-size: 14px; line-height: 22px; font-weight: 600; color: var(--dsw-alias-label-primary); margin: 0; }
.mc-title { font-size: 14px; line-height: 22px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.mc-p { font-size: 13px; line-height: 20px; color: var(--dsw-alias-label-secondary); margin: 0; }
.mc-muted { color: var(--dsw-alias-label-secondary); font-size: 12px; line-height: 18px; margin: 0; }
.mc-err { color: var(--dsw-alias-state-error-primary); font-size: 12px; }
.mc-ok { color: var(--dsw-alias-state-success-primary); font-size: 12px; }

.mc-card { border: 1px solid var(--dsw-alias-border-l1); border-radius: 8px; padding: 12px 14px; display: flex; flex-direction: column; gap: 10px; background: var(--dsw-alias-bg-layer-1); }
.mc-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

.mc-btn { font: inherit; font-size: 12px; line-height: 18px; padding: 5px 10px; border-radius: 8px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); cursor: pointer; transition: background-color var(--ds-transition-duration-slow, .15s) var(--ds-ease-in-out, ease), border-color var(--ds-transition-duration-slow, .15s) var(--ds-ease-in-out, ease); }
.mc-btn:hover:not([disabled]) { border-color: var(--dsw-alias-brand-primary); color: var(--dsw-alias-brand-primary); }
.mc-btn:focus-visible, .mc-input:focus-visible, .mc-device-name:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 1px; }
.mc-btn[disabled] { opacity: .5; cursor: default; }
.mc-btn-danger { border-color: var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary); }
.mc-btn-danger:hover:not([disabled]) { border-color: var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary); }

.mc-input { font: inherit; font-size: 12px; line-height: 18px; padding: 5px 8px; border-radius: 8px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); }
.mc-input::placeholder { color: var(--dsw-alias-label-secondary); }
.mc-label { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--dsw-alias-label-primary); }

.mc-badge { font-size: 11px; line-height: 16px; padding: 1px 6px; border-radius: 999px; border: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); white-space: nowrap; }
.mc-badge-ok { color: var(--dsw-alias-state-success-primary); border-color: var(--dsw-alias-state-success-primary); }
.mc-badge-bad { color: var(--dsw-alias-state-error-primary); border-color: var(--dsw-alias-state-error-primary); }

.mc-code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 18px; overflow-wrap: anywhere; color: var(--dsw-alias-label-primary); background: var(--dsw-alias-bg-layer-2); border-radius: 8px; padding: 6px 8px; }
.mc-pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; line-height: 16px; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 140px; overflow: auto; color: var(--dsw-alias-label-secondary); background: var(--dsw-alias-bg-layer-2); border-radius: 8px; padding: 6px 8px; margin: 0; }
.mc-qr { background: #fff; padding: 6px; border-radius: 8px; width: 168px; height: 168px; }

.mc-table { width: 100%; border-collapse: collapse; font-size: 12px; color: var(--dsw-alias-label-secondary); }
.mc-table th { text-align: left; font-weight: 500; padding: 4px 6px; border-bottom: 1px solid var(--dsw-alias-border-l1); }
.mc-table td { padding: 4px 6px; border-bottom: 1px solid var(--dsw-alias-border-l1); color: var(--dsw-alias-label-primary); overflow-wrap: anywhere; }

.mc-devices { display: flex; flex-direction: column; gap: 8px; }
.mc-device { display: flex; flex-direction: column; gap: 6px; padding: 10px; border: 1px solid var(--dsw-alias-border-l1); border-radius: 8px; background: var(--dsw-alias-bg-layer-2); }
.mc-device-main { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.mc-device-name { flex: 1 1 160px; min-width: 0; }
.mc-device-meta { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); overflow-wrap: anywhere; }

details.mc-card > summary.mc-title { cursor: pointer; list-style-position: inside; }
details.mc-card > summary.mc-title:hover { color: var(--dsw-alias-brand-primary); }
details.mc-card[open] > summary.mc-title { margin-bottom: 2px; }

.mc-title-row { display: flex; align-items: center; gap: 6px; }
.mc-hint { display: inline-flex; align-items: center; justify-content: center; flex: none; width: 16px; height: 16px; border-radius: 999px; border: 1px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); font-size: 11px; line-height: 1; cursor: help; user-select: none; }
.mc-hint:hover, .mc-hint:focus-visible { color: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); outline: none; }
`;

    /** Phone-only sizing tweaks; conservative on purpose. */
    const NARROW_CSS = `
@media (max-width: 1023px) {
  button, [role="button"] { min-height: 40px; }
  input, textarea, select { font-size: 16px; }
  html { -webkit-text-size-adjust: 100%; }
}
@supports (padding: env(safe-area-inset-left)) {
  @media (max-width: 1023px) {
    body { padding-left: env(safe-area-inset-left); padding-right: env(safe-area-inset-right); padding-bottom: env(safe-area-inset-bottom); }
  }
}
`;

    /** One call into the host route; folds transport and envelope faults together. */
    function hostCall(method, args) {
      let pending;
      try {
        pending = fetch(`${CHANNEL}/${method}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(args ?? {}),
        });
      } catch (error) {
        return Promise.resolve({ ok: false, error: String(error?.message ?? error) });
      }
      return Promise.resolve(pending).then(
        (res) =>
          res.json().then(
            (env) => {
              if (env && env.ok) return env.value;
              const message = env?.error ? env.error.message || env.error.code || 'host call failed' : `HTTP ${res.status}`;
              return { ok: false, error: String(message) };
            },
            () => ({ ok: false, error: `HTTP ${res.status} with a non-JSON body` }),
          ),
        (error) => ({ ok: false, error: String(error?.message ?? error) }),
      );
    }

    /**
     * Renew this browser's platform cookie.
     *
     * `authorizeIndex` mints the cookie exactly once — on a request carrying the
     * process launch token — and never re-mints it on an ordinary request. So
     * "keep me paired without extending the lifetime" means: ask the host for a
     * fresh tokenized URL and visit it, which mints a new cookie with a full
     * lifetime again.
     * @returns `{ ok, detail }` for the caller to show.
     */
    async function renewPlatformSession() {
      const answer = await hostCall('renew-session', {});
      if (answer === null || typeof answer !== 'object' || answer.ok !== true || typeof answer.url !== 'string') {
        return { ok: false, detail: String(answer?.error ?? answer?.message ?? 'the host declined to mint a fresh entry URL') };
      }
      try {
        await fetch(answer.url, { credentials: 'same-origin', cache: 'no-store', redirect: 'follow' });
      } catch (error) {
        return { ok: false, detail: String(error?.message ?? error) };
      }
      return { ok: true, detail: `${answer.authority} · ${new Date().toLocaleString()}` };
    }

    /** Render a QR matrix as one SVG path. */
    function QrCode({ qr }) {
      if (qr === undefined || qr === null || typeof qr.bits !== 'string') return null;
      const size = qr.size;
      const scale = 4;
      let path = '';
      for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
          if (qr.bits[y * size + x] === '1') path += `M${x * scale} ${y * scale}h${scale}v${scale}h-${scale}z`;
        }
      }
      return h(
        'svg',
        {
          className: 'mc-qr',
          viewBox: `0 0 ${size * scale} ${size * scale}`,
          role: 'img',
          'aria-label': 'QR code',
          shapeRendering: 'crispEdges',
        },
        h('rect', { width: size * scale, height: size * scale, fill: '#fff' }),
        h('path', { d: path, fill: '#000' }),
      );
    }

    /**
     * A circled question mark whose explanation lives in the native tooltip.
     *
     * The panel used to spell every rationale out in the page, which buried the
     * lines that actually matter ("what is configured", "what to press").
     * Explanations now live here: hover, focus or long-press reveals them, and
     * assistive tech reads the same text from `aria-label`.
     * @param props - `text` is the explanation; `label` optionally prefixes it.
     */
    function Hint({ text, label }) {
      if (typeof text !== 'string' || text === '') return null;
      return h(
        'span',
        {
          className: 'mc-hint',
          title: label === undefined ? text : `${label}: ${text}`,
          tabIndex: 0,
          role: 'note',
          'aria-label': text,
        },
        '?',
      );
    }

    /**
     * The first sentence of an explanation.
     *
     * Long strings keep their full text in a Hint tooltip; the page shows only
     * the first sentence, so nothing has to be written twice and a translation
     * cannot drift out of sync with its own summary.
     * @param text - the full explanation.
     */
    function firstSentence(text) {
      const value = String(text ?? '').trim();
      const cut = value.split(/(?<=[。．.！!？?；;])\s*/)[0];
      return cut === '' ? value : cut;
    }

    /** One entry link with its trust verdict, QR code and actions. */
    function EntryCard({ entry, translate, onTrust, onPublicUrl, onClearPublicUrl, advertised, busy }) {
      const [copied, setCopied] = React.useState(false);
      const trustClass = entry.trust === 'trusted' ? 'mc-badge mc-badge-ok' : entry.trust === 'refused' ? 'mc-badge mc-badge-bad' : 'mc-badge';
      const trustText =
        entry.trust === 'trusted' ? translate('trustTrusted') : entry.trust === 'refused' ? translate('trustRefused') : translate('trustUnknown');
      const copy = () => {
        const clipboard = navigator.clipboard;
        if (clipboard === undefined) return;
        Promise.resolve(clipboard.writeText(entry.url)).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          },
          () => {},
        );
      };
      return h(
        'div',
        { className: 'mc-card' },
        h(
          'div',
          { className: 'mc-row' },
          h('span', { className: 'mc-title' }, entry.label),
          h('span', { className: trustClass }, trustText),
        ),
        h('div', { className: 'mc-code' }, entry.url),
        h(
          'div',
          { className: 'mc-row' },
          h('button', { className: 'mc-btn', onClick: copy }, copied ? translate('copied') : translate('copyLink')),
          h('a', { className: 'mc-btn', href: entry.url, target: '_blank', rel: 'noreferrer' }, translate('openOnPhone')),
          entry.trust === 'refused'
            ? h(
                'button',
                { className: 'mc-btn', disabled: busy, onClick: () => onTrust(entry.authority) },
                translate('trustFix'),
              )
            : null,
          entry.kind === 'tunnel'
            ? h(
                'button',
                { className: 'mc-btn', disabled: busy, onClick: () => onPublicUrl(entry.base) },
                translate('publicUrlWrite'),
              )
            : null,
          entry.kind === 'tunnel' && typeof advertised === 'string' && advertised !== '' && advertised !== entry.base
            ? h(
                'button',
                { className: 'mc-btn', disabled: busy, onClick: () => onClearPublicUrl() },
                translate('publicUrlClear'),
              )
            : null,
        ),
        entry.kind === 'tunnel' ? h('p', { className: 'mc-muted mc-title-row' }, firstSentence(translate('publicUrlWarning')), h(Hint, { text: translate('publicUrlWarning') })) : null,
        h(QrCode, { qr: entry.qr }),
      );
    }

    /** Mutable view of the active translator; the panel re-renders on locale change. */
    const localeListeners = new Set();
    let activeTranslate = (key) => key;

    /** The whole settings section. */
    function Panel() {
      const [state, setState] = React.useState(null);
      const [error, setError] = React.useState('');
      const [notice, setNotice] = React.useState('');
      const [busy, setBusy] = React.useState(false);
      const [renaming, setRenaming] = React.useState({});
      const [, bumpLocale] = React.useState(0);
      // `null` means "untouched": the input shows the configured value until
      // the user types, and returns to it after a successful save.
      const [domainDraft, setDomainDraft] = React.useState(null);
      const [tunnelNameDraft, setTunnelNameDraft] = React.useState(null);
      const [env, setEnv] = React.useState(null);

      /** Refresh the Cloudflare environment checklist (it spawns `--version`). */
      const refreshEnv = React.useCallback(() => {
        hostCall('cf-env', {}).then((value) => setEnv(value !== null && typeof value === 'object' && value.ok === false ? null : value));
      }, []);

      const load = React.useCallback(() => {
        hostCall('state', {}).then((value) => {
          if (value && value.ok === false) setError(value.error);
          else {
            setError('');
            setState(value);
          }
        });
      }, []);

      React.useEffect(() => {
        load();
        const timer = setInterval(load, 10000);
        return () => clearInterval(timer);
      }, [load]);

      React.useEffect(() => {
        // Re-render on locale change so labels follow the active language.
        const listener = () => bumpLocale((n) => n + 1);
        localeListeners.add(listener);
        return () => localeListeners.delete(listener);
      }, []);

      const t = (key, vars) => {
        let text = activeTranslate(key);
        for (const [name, value] of Object.entries(vars ?? {})) text = text.replace(`{${name}}`, String(value));
        return text;
      };

      const act = (method, args, done) => {
        setBusy(true);
        setNotice('');
        hostCall(method, args).then((value) => {
          setBusy(false);
          if (value && value.ok === false) setError(value.error);
          else {
            setError('');
            setNotice(typeof done === 'function' ? done(value) : '');
            load();
          }
        });
      };

      if (state === null) {
        return h('div', { className: 'mc-root' }, h('p', { className: 'mc-p' }, error !== '' ? t('failed', { message: error }) : t('loading')));
      }

      const entries = Array.isArray(state.entries) ? state.entries : [];
      const devices = Array.isArray(state.devices) ? state.devices : [];
      const lanEntry = entries.find((entry) => entry.kind === 'lan');
      const listener = state.listener ?? {};
      const tunnel = state.tunnel ?? {};
      const capabilities = state.capabilities ?? {};
      const platform = state.platform ?? {};

      return h(
        'div',
        { className: 'mc-root' },
        h('h2', { className: 'mc-h2' }, t('title')),
        h('p', { className: 'mc-p mc-title-row' }, firstSentence(t('intro')), h(Hint, { text: t('intro') })),
        error !== '' ? h('p', { className: 'mc-err' }, t('failed', { message: error })) : null,
        notice !== '' ? h('p', { className: 'mc-ok' }, notice) : null,

        h(
          'div',
          { className: 'mc-card' },
          h('span', { className: 'mc-title' }, t('reachTitle')),
          h('p', { className: 'mc-p' }, reachText(t, state.request)),
          state.request?.host
            ? h(
                'p',
                { className: state.request.trusted === false ? 'mc-err' : 'mc-muted' },
                state.request.trusted === false
                  ? t('reachUntrusted', { host: state.request.host })
                  : t('reachTrusted', { host: state.request.host }),
              )
            : null,
        ),

        h('h3', { className: 'mc-h2' }, t('entries')),
        entries.length === 0 ? h('p', { className: 'mc-p' }, t('noEntries')) : null,
        ...entries.map((entry) =>
          h(EntryCard, {
            key: entry.id,
            entry,
            translate: t,
            busy,
            onTrust: (authority) => act('trust-authority', { authority }, () => t('trustFixed')),
            onPublicUrl: (url) => act('set-public-url', { url }, () => t('publicUrlWritten')),
            onClearPublicUrl: () => act('clear-public-url', {}, () => t('publicUrlCleared')),
            advertised: state.listener?.advertised,
          }),
        ),

        h(
          'div',
          { className: 'mc-card' },
          h('span', { className: 'mc-title' }, t('domainTitle')),
          h('p', { className: 'mc-p mc-title-row' }, firstSentence(t('domainHint')), h(Hint, { text: t('domainHint') })),
          h(
            'div',
            { className: 'mc-row' },
            h('input', {
              className: 'mc-input',
              style: { minWidth: '260px' },
              placeholder: t('domainPlaceholder'),
              value: domainDraft ?? state.config?.tunnelHost ?? '',
              onChange: (event) => setDomainDraft(event.target.value),
            }),
            h(
              'button',
              {
                className: 'mc-btn',
                disabled: busy || capabilities.configEditor !== true || (domainDraft ?? state.config?.tunnelHost ?? '').trim() === '',
                onClick: () =>
                  act('set-plugin-config', { tunnelHost: String(domainDraft).trim() }, () => {
                    setDomainDraft(null);
                    return t('saved');
                  }),
              },
              t('save'),
            ),
          ),
          // The advertised root URL is written by the entry card's own button
          // (`set-public-url`), which is the only thing that actually reaches the
          // platform's `web-runtime` row. A second input here wrote the plugin's
          // own unused field and only looked like it did something.
          h('p', { className: 'mc-muted' }, t('publicUrlLabel')),
          h(
            'div',
            { className: 'mc-row' },
            h('input', {
              className: 'mc-input',
              style: { minWidth: '260px' },
              placeholder: t('tunnelNamePlaceholder'),
              value: tunnelNameDraft ?? state.config?.tunnelName ?? '',
              onChange: (event) => setTunnelNameDraft(event.target.value),
            }),
            h(
              'button',
              {
                className: 'mc-btn',
                disabled: busy || capabilities.configEditor !== true || (tunnelNameDraft ?? state.config?.tunnelName ?? '').trim() === '',
                onClick: () =>
                  act('set-plugin-config', { tunnelName: String(tunnelNameDraft).trim() }, () => {
                    setTunnelNameDraft(null);
                    return t('saved');
                  }),
              },
              t('save'),
            ),
          ),
          h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('tunnelNameHint')), h(Hint, { text: t('tunnelNameHint') })),
        ),

        h(
          'div',
          { className: 'mc-card' },
          h('span', { className: 'mc-title' }, t('lanTitle')),
          h(
            'p',
            { className: 'mc-p' },
            lanEntry ? t('lanBound', { host: listener.host ?? '?' }) : t('lanNotBound', { host: listener.host ?? '?' }),
          ),
          h('p', { className: 'mc-muted' }, t('lanWarning', { host: lanEntry?.authority ?? listener.host ?? '?' })),
          h(
            'div',
            { className: 'mc-row' },
            ...(Array.isArray(state.localAddresses) ? state.localAddresses : []).map((address) =>
              h(
                'button',
                {
                  key: address.address,
                  className: 'mc-btn',
                  disabled: busy || capabilities.configEditor !== true,
                  onClick: () => act('set-lan-host', { host: address.address }, () => t('lanWritten')),
                },
                `${address.address} (${address.interface})`,
              ),
            ),
            typeof listener.host === 'string' && listener.host !== '' && listener.host !== '127.0.0.1'
              ? h(
                  'button',
                  {
                    className: 'mc-btn',
                    disabled: busy || capabilities.configEditor !== true,
                    onClick: () => act('set-lan-host', { host: '127.0.0.1' }, () => t('lanWritten')),
                  },
                  t('restoreLoopback'),
                )
              : null,
          ),
          capabilities.configEditor !== true ? h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('configHint')), h(Hint, { text: t('configHint') })) : null,
        ),

        h(
          'div',
          { className: 'mc-card' },
          h('span', { className: 'mc-title' }, t('tunnelTitle')),
          h(
            'p',
            { className: 'mc-p' },
            tunnel.configured !== true
              ? t('tunnelUnconfigured')
              : tunnel.available !== true
                ? t('tunnelUnavailable')
                : `${tunnel.command} — ${
                    tunnel.running === true
                      ? t('tunnelRunning', { pid: tunnel.pid ?? '?' })
                      : tunnel.exit !== undefined && tunnel.exit !== null
                        ? t('tunnelExited', { exit: JSON.stringify(tunnel.exit) })
                        : t('tunnelStopped')
                  }`,
          ),
          tunnel.url ? h('div', { className: 'mc-code' }, tunnel.url) : null,
          h(
            'div',
            { className: 'mc-row' },
            h(
              'button',
              { className: 'mc-btn', disabled: busy || tunnel.configured !== true || tunnel.running === true, onClick: () => act('tunnel-start', {}) },
              t('tunnelStart'),
            ),
            h(
              'button',
              { className: 'mc-btn', disabled: busy || tunnel.running !== true, onClick: () => act('tunnel-stop', {}) },
              t('tunnelStop'),
            ),
          ),
          tunnel.url
            ? h(
                'div',
                { className: 'mc-row' },
                h(
                  'button',
                  {
                    className: 'mc-btn',
                    disabled: busy,
                    onClick: () => act('trust-authority', { authority: authorityOf(tunnel.url) }, () => t('trustFixed')),
                  },
                  t('quickTrust'),
                ),
              )
            : null,
          tunnel.url ? h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('quickTrustHint')), h(Hint, { text: t('quickTrustHint') })) : null,
          Array.isArray(tunnel.lines) && tunnel.lines.length > 0
            ? h('div', null, h('p', { className: 'mc-muted' }, t('tunnelOutput')), h('pre', { className: 'mc-pre' }, tunnel.lines.join('\n')))
            : null,
        ),

        h(
          'details',
          { className: 'mc-card' },
          h('summary', { className: 'mc-title' }, t('advancedTitle')),
          h(CfCard, { env, translate: t, busy, act, onRefresh: refreshEnv }),
        ),

        h(
          'div',
          { className: 'mc-card' },
          h('span', { className: 'mc-title' }, t('devicesTitle')),
          h('p', { className: 'mc-p mc-title-row' }, firstSentence(t('devicesNote')), h(Hint, { text: t('devicesNote') }), h(Hint, { text: t('noAutoSwitch') })),
          devices.length === 0
            ? h('p', { className: 'mc-muted' }, t('devicesEmpty'))
            : h(
                'div',
                { className: 'mc-devices' },
                ...devices.map((device) =>
                  h(
                    'div',
                    { className: 'mc-device', key: device.id },
                    h(
                      'div',
                      { className: 'mc-device-main' },
                      h('input', {
                        className: 'mc-input mc-device-name',
                        'aria-label': t('deviceName'),
                        placeholder: deviceLabelOf(device.ua),
                        value: renaming[device.id] ?? device.name ?? '',
                        onChange: (event) => setRenaming({ ...renaming, [device.id]: event.target.value }),
                      }),
                      h(
                        'span',
                        { className: device.lastVia === 'tunnel' ? 'mc-badge' : 'mc-badge mc-badge-ok' },
                        viaLabel(t, device.lastVia),
                      ),
                      device.onLan === true ? h('span', { className: 'mc-badge' }, t('onLanBadge')) : null,
                      h(
                        'button',
                        {
                          className: 'mc-btn',
                          disabled: busy,
                          onClick: () => act('device-rename', { id: device.id, name: renaming[device.id] ?? device.name }, () => t('saved')),
                        },
                        t('deviceSave'),
                      ),
                      h('button', { className: 'mc-btn', disabled: busy, onClick: () => act('device-forget', { id: device.id }) }, t('deviceForget')),
                    ),
                    // One muted line carries what the table spread over five
                    // columns, so nothing has to fight for width in a narrow
                    // settings column.
                    h(
                      'p',
                      { className: 'mc-device-meta' },
                      `${t('deviceLast')} ${formatTime(device.lastSeenAt)} · ${t('deviceFirst')} ${formatTime(device.firstSeenAt)} · ${t('deviceIp')} ${device.lastIp ?? '—'} · ${deviceLabelOf(device.ua)}`,
                    ),
                  ),
                ),
              ),
          devices.some((d) => d.onLan === true) ? h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('lanHintForDevice')), h(Hint, { text: t('lanHintForDevice') })) : null,
          devices.length > 0
            ? h('div', { className: 'mc-row' }, h('button', { className: 'mc-btn', disabled: busy, onClick: () => act('devices-clear', {}) }, t('devicesClear')))
            : null,
        ),

        h(
          'div',
          { className: 'mc-card' },
          h('span', { className: 'mc-title' }, t('platformTitle')),
          h('p', { className: 'mc-p' }, t('platformCookie', { days: platform.cookieMaxAgeDays ?? 30 })),
          h('p', { className: 'mc-p' }, t('platformExpiry')),
          h('p', { className: 'mc-muted' }, t('platformRecord', { state: platform.sessionRecordPresent ? t('platformRecordPresent') : t('platformRecordAbsent') })),
          h(
            'div',
            { className: 'mc-row' },
            h(
              'button',
              {
                className: 'mc-btn mc-btn-danger',
                disabled: busy || platform.sessionRecordPresent !== true,
                onClick: () => {
                  if (!window.confirm(t('revokeConfirm'))) return;
                  act('revoke-platform-sessions', {}, (value) => (value?.deleted ? t('revoked') : t('revokeNothing')));
                },
              },
              t('revoke'),
            ),
          ),
        ),

        h(
          'div',
          { className: 'mc-card' },
          h('span', { className: 'mc-title' }, t('settingsTitle')),
          h(
            'label',
            { className: 'mc-label' },
            h('input', {
              type: 'checkbox',
              checked: state.config?.narrowEnhance !== false,
              disabled: busy || capabilities.configEditor !== true,
              onChange: (event) => act('set-plugin-config', { narrowEnhance: event.target.checked }, () => t('saved')),
            }),
            t('narrowEnhance'),
          ),
          h('p', { className: 'mc-muted' }, t('narrowEnhanceHint')),
          h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('configHint')), h(Hint, { text: t('configHint') })),
        ),

        h('div', { className: 'mc-row' }, h('button', { className: 'mc-btn', onClick: load }, t('refresh'))),
      );
    }

    /** Host[:port] of a URL, for the quick-tunnel trust button. */
    function authorityOf(url) {
      try {
        return new URL(String(url)).host;
      } catch {
        return String(url).replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      }
    }

    /** Human label for one request origin, as recorded on a device row. */
    function viaLabel(t, via) {
      if (via === 'tunnel') return t('viaTunnel');
      if (via === 'lan') return t('viaLan');
      if (via === 'local') return t('viaLocal');
      if (via === 'direct') return t('viaDirect');
      return t('viaUnknown');
    }

    /** One sentence describing how the current panel request arrived. */
    function reachText(t, request) {
      const via = request?.via;
      const ip = request?.clientIp;
      if (via === 'local') return t('reachLocal');
      if (via === 'lan') return t('reachLan', { ip: ip ?? '?' });
      if (via === 'tunnel') return t('reachTunnel', { ip: ip ?? '?' });
      if (via === 'direct') return t('reachDirect', { ip: ip ?? '?' });
      return t('reachUnknown');
    }

    /** The Cloudflare card: environment checklist, guided login, token setup. */
    function CfCard({ env, translate: t, busy, act, onRefresh }) {
      const [token, setToken] = React.useState('');
      const [email, setEmail] = React.useState('');
      const [steps, setSteps] = React.useState(null);
      const [login, setLogin] = React.useState(null);
      React.useEffect(() => {
        onRefresh();
      }, []);

      // While a login is pending, poll its status so the URL and the certificate
      // appear without the user pressing anything.
      React.useEffect(() => {
        if (login?.running !== true) return undefined;
        const timer = setInterval(() => {
          hostCall('cf-login-status', {}).then((value) => {
            if (value && value.ok !== false) setLogin(value);
          });
        }, 3000);
        return () => clearInterval(timer);
      }, [login?.running]);

      const runSteps = (method, args) => {
        setSteps(null);
        return act(method, args, (value) => {
          if (value && Array.isArray(value.steps)) setSteps(value.steps);
          return '';
        });
      };

      if (env === null || env === undefined) {
        return h('div', { className: 'mc-card' }, h('span', { className: 'mc-title' }, t('cfTitle')), h('p', { className: 'mc-p' }, t('cfChecking')));
      }

      const info = env.cloudflared ?? {};
      const cert = env.cert ?? {};
      const summary = env.summary ?? { ready: false, missing: [] };
      const current = login ?? env.login ?? {};
      const hostname = env.hostname;

      const checklist = [
        [t('cfCloudflared'), info.found === true ? (info.version ? t('cfFound', { version: info.version }) : t('cfFoundNoVersion')) : t('cfNotFound')],
        [t('cfCert'), cert.present === true ? t('cfCertPresent') : t('cfCertAbsent')],
        [t('cfApiToken'), env.apiTokenStored === true ? t('cfStored') : t('cfNotStored')],
        [t('cfConnectorToken'), env.connectorTokenStored === true ? t('cfStored') : t('cfNotStored')],
        [t('cfHostname'), hostname ?? t('cfHostnameMissing')],
        [t('cfConfigFile'), env.configFile?.present === true ? env.configFile.path : t('cfCertAbsent')],
        [t('cfService'), env.service ?? '—'],
      ];

      return h(
        'div',
        { className: 'mc-card' },
        h('span', { className: 'mc-title' }, t('cfTitle')),
          h('p', { className: 'mc-p mc-title-row' }, firstSentence(t('cfIntro')), h(Hint, { text: t('cfIntro') })),

        h(
          'table',
          { className: 'mc-table' },
          h(
            'tbody',
            null,
            ...checklist.map(([label, value]) => h('tr', { key: label }, h('td', null, label), h('td', null, value))),
          ),
        ),
        h('p', { className: summary.ready === true ? 'mc-ok' : 'mc-muted' }, summary.ready === true ? t('cfReady') : t('cfMissing', { list: (summary.missing ?? []).join(', ') })),
        info.found !== true
          ? h(
              'div',
              null,
              h('p', { className: 'mc-muted' }, t('cfInstallWith')),
              h('div', { className: 'mc-code' }, env.install?.command ?? ''),
              h(
                'p',
                { className: 'mc-muted' },
                `${env.install?.note ?? ''} — `,
                h('a', { href: env.releases, target: '_blank', rel: 'noreferrer' }, t('cfReleases')),
              ),
            )
          : null,

        h(
          'div',
          { className: 'mc-row' },
          h('button', { className: 'mc-btn', disabled: busy, onClick: onRefresh }, t('cfCheck')),
          h(
            'button',
            {
              className: 'mc-btn',
              disabled: busy || info.found !== true || hostname === undefined || hostname === null,
              onClick: () => {
                setSteps(null);
                act('cf-login-start', {}, () => '').then(() => hostCall('cf-login-status', {}).then((value) => setLogin(value && value.ok !== false ? value : null)));
              },
            },
            t('cfLoginStart'),
          ),
          current.running === true ? h('button', { className: 'mc-btn', disabled: busy, onClick: () => act('cf-login-cancel', {}, () => '').then(() => setLogin(null)) }, t('cfLoginCancel')) : null,
          h(
            'button',
            { className: 'mc-btn', disabled: busy || cert.present !== true || hostname === undefined || hostname === null, onClick: () => runSteps('cf-login-configure', { hostname }) },
            t('cfConfigure'),
          ),
        ),
        current.url
          ? h(
              'div',
              null,
              h('p', { className: 'mc-p' }, t('cfLoginOpen', { hostname: hostname ?? '?' })),
              h('div', { className: 'mc-code' }, current.url),
              h('p', { className: 'mc-muted' }, t('cfLoginWaiting')),
            )
          : null,
        current.certPresent === true || cert.present === true ? h('p', { className: 'mc-ok' }, t('cfLoginDone')) : null,
        current.running === false && current.exit !== undefined && current.certPresent !== true && cert.present !== true
          ? h('p', { className: 'mc-err' }, t('cfLoginFailed'))
          : null,

        h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('cfTokenHint')), h(Hint, { text: t('cfTokenHint') })),
        h(
          'ul',
          { className: 'mc-muted' },
          ...(Array.isArray(env.scopes) ? env.scopes : []).map((scope) => h('li', { key: scope }, scope)),
        ),
        h(
          'div',
          { className: 'mc-row' },
          h('input', {
            className: 'mc-input',
            style: { minWidth: '240px' },
            type: 'password',
            placeholder: t('cfTokenLabel'),
            value: token,
            onChange: (event) => setToken(event.target.value),
          }),
          h(
            'button',
            { className: 'mc-btn', disabled: busy || token.trim() === '', onClick: () => act('cf-set-token', { token: token.trim(), hostname }, () => { setToken(''); return t('cfSavedToken'); }).then(onRefresh) },
            t('cfTokenSave'),
          ),
          h(
            'button',
            { className: 'mc-btn', disabled: busy || hostname === undefined || hostname === null, onClick: () => runSteps('cf-connect', { hostname }).then(onRefresh) },
            t('cfAutoSetup'),
          ),
          env.apiTokenStored === true
            ? h('button', { className: 'mc-btn', disabled: busy, onClick: () => act('cf-forget-token', {}, () => t('cfForgetTokenDone')).then(onRefresh) }, t('cfForgetToken'))
            : null,
        ),
        h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('cfAutoHint')), h(Hint, { text: t('cfAutoHint') })),

        h(
          'div',
          { className: 'mc-row' },
          h('input', {
            className: 'mc-input',
            style: { minWidth: '240px' },
            placeholder: t('cfAccessEmail'),
            value: email,
            onChange: (event) => setEmail(event.target.value),
          }),
          h(
            'button',
            { className: 'mc-btn', disabled: busy || email.trim() === '' || hostname === undefined || hostname === null, onClick: () => runSteps('cf-access', { hostname, email: email.trim() }) },
            t('cfAccessCreate'),
          ),
        ),
        h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('cfAccessHint')), h(Hint, { text: t('cfAccessHint') })),

        h(
          'div',
          { className: 'mc-row' },
          h(
            'button',
            {
              className: 'mc-btn mc-btn-danger',
              disabled: busy,
              onClick: () => {
                if (!window.confirm(t('cfTeardownConfirm'))) return;
                runSteps('cf-teardown', {}).then(onRefresh);
              },
            },
            t('cfTeardown'),
          ),
        ),

        h(
          'div',
          { className: 'mc-row' },
          h(
            'button',
            {
              className: 'mc-btn',
              disabled: busy,
              onClick: () =>
                renewPlatformSession().then((result) => setSteps([{ step: 'renew', ok: result.ok === true, detail: result.detail }])),
            },
            t('renewNow'),
          ),
        ),

        Array.isArray(steps)
          ? h(
              'div',
              null,
              h('p', { className: 'mc-muted' }, t('cfSteps')),
              h(
                'ul',
                { className: 'mc-muted' },
                ...steps.map((step, index) =>
                  h('li', { key: `${step.step}-${index}`, className: step.ok ? 'mc-ok' : 'mc-err' }, `${step.ok ? '✓' : '✗'} ${step.step}: ${step.detail}`),
                ),
              ),
            )
          : null,
      );
    }

    /** Local device label, mirroring the host half's mapping. */
    function deviceLabelOf(userAgent) {
      const s = String(userAgent ?? '');
      if (/iPhone/.test(s)) return 'iPhone';
      if (/iPad/.test(s)) return 'iPad';
      if (/Android/.test(s)) return 'Android';
      if (/Macintosh|Mac OS X/.test(s)) return 'Mac';
      if (/Windows/.test(s)) return 'Windows';
      if (/Linux/.test(s)) return 'Linux';
      return 'Unknown';
    }

    /** Short local timestamp for the device table. */
    function formatTime(value) {
      const at = Number(value);
      if (!Number.isFinite(at) || at <= 0) return '—';
      const d = new Date(at);
      const pad = (n) => String(n).padStart(2, '0');
      return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        const locale = ctx.locale;
        const pickDict = (id) => (/^zh/i.test(String(id ?? '')) ? ZH : EN);
        const activeId = () => {
          try {
            return String(locale.getSnapshot()?.active ?? '');
          } catch {
            return '';
          }
        };
        let bound = null;
        try {
          let ids = [];
          try {
            const snapshot = locale.getSnapshot();
            ids = Array.isArray(snapshot?.locales) ? snapshot.locales.map((d) => String(d.id)) : [];
          } catch {
            /* fall back to the known pair */
          }
          if (ids.length === 0) ids = ['en', 'zh'];
          for (const id of ids) {
            const off = locale.register(NS, id, pickDict(id));
            if (typeof off === 'function') ctx.effect(() => off);
          }
          bound = typeof locale.bind === 'function' ? locale.bind(NS) : null;
        } catch {
          bound = null;
        }
        const translate = (key) => {
          if (bound !== null) {
            try {
              const value = bound(key);
              if (typeof value === 'string' && value !== key && value.length > 0) return value;
            } catch {
              /* fall through to the literal dictionary */
            }
          }
          return pickDict(activeId())[key] ?? EN[key] ?? key;
        };
        activeTranslate = translate;

        ctx.effect(() => {
          let off;
          try {
            off = locale.subscribe(() => {
              for (const listener of localeListeners) {
                try {
                  listener();
                } catch {
                  /* a broken subscriber must not break the locale service */
                }
              }
            });
          } catch {
            off = undefined;
          }
          return () => {
            if (typeof off === 'function') off();
          };
        }, 'dsh-mobile-console: locale subscription');

        ctx.effect(() => {
          const style = document.createElement('style');
          style.setAttribute('data-plugin', 'dsh-mobile-console');
          style.textContent = PANEL_CSS;
          document.head.append(style);
          return () => style.remove();
        }, 'dsh-mobile-console: panel styles');

        // Keep this device paired without changing the configured cookie
        // lifetime: `authorizeIndex` only mints a cookie on a request that
        // carries the launch token, so visit one now — and twice a day while
        // the page lives. Nothing here may break a page load, and `unref` keeps
        // a Node-side import (the tests) from waiting on the interval.
        try {
          const renew = () => {
            renewPlatformSession().catch(() => {});
          };
          const first = setTimeout(renew, 5000);
          const repeat = setInterval(renew, 12 * 60 * 60 * 1000);
          if (typeof first?.unref === 'function') first.unref();
          if (typeof repeat?.unref === 'function') repeat.unref();
        } catch {
          /* a client without timers still gets the panel */
        }

        ctx.slots.inject('settings.section', () =>
          ctx.slots.register(
            { name: 'settings.section', id: 'mobile-console', order: 30, label: () => activeTranslate('title') },
            Panel,
          ),
        );

        // Phone layout tweaks: the stylesheet is injected synchronously (so it is
        // fiber-owned) and its `media` attribute is the switch — enabled by
        // default, disabled when the plugin row config says so. A failed state
        // call leaves the default in place.
        ctx.effect(() => {
          const style = document.createElement('style');
          style.setAttribute('data-plugin', 'dsh-mobile-console-narrow');
          style.textContent = NARROW_CSS;
          style.media = 'all';
          document.head.append(style);
          hostCall('state', {}).then((value) => {
            if (value !== null && typeof value === 'object' && value.ok !== false && value.config?.narrowEnhance === false) {
              style.media = 'not all';
            }
          });
          return () => style.remove();
        }, 'dsh-mobile-console: narrow viewport tweaks');
      },
    };
  },
});
