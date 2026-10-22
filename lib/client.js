/**
 * dsh-remote-access — browser half.
 *
 * One settings section, built around a two-way mode switch:
 *
 *  1. `局域网` (LAN): the listener binds one of this machine's own
 *     addresses, so a phone on the same Wi-Fi opens it directly. The panel shows
 *     the address picker, the resulting entry link with its QR, and the button
 *     that puts the bind back on 127.0.0.1. No device management here.
 *  2. `公网` (public): the listener stays on 127.0.0.1 and cloudflared publishes
 *     it. The panel shows a Start/Stop pair, the entry link with its QR, a
 *     one-time pairing code with a live countdown, the authorized-device list
 *     (rename / re-date / revoke / delete), and the edge-authentication status.
 *
 * Under `高级` live the Cloudflare setup, the tunnel hostname, the access keys
 * this plugin mints and verifies itself, the recovery password, and the one
 * button that revokes every paired browser session — which is the platform's
 * only, all-or-nothing revocation.
 *
 * The narrow-viewport enhancement is CSS-only on purpose: the shipped layout
 * already collapses its sidebar below 1024px, so nothing here drives layout
 * state and nothing breaks if a class name changes.
 *
 * The panel talks to the host half over `${CHANNEL}/<endpoint>`, same-origin, so
 * the browser attaches the platform's login cookie automatically.
 */
window.__ModuleLoader__.load({
  id: 'dsh-remote-access',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    /** Route prefix owned by the host half; must match lib/index.js. */
    const CHANNEL = '/remote-access';
    /** Locale namespace for every string this panel shows. */
    const NS = 'remote-access';

    const EN = {
      title: 'Remote Access',
      intro:
        'Open the shipped Web UI from a phone. This panel shows the entry links, checks the platform trust fence, and manages the credentials other devices use.',
      noEntries:
        'No entry yet. Set a tunnel authority below (or bind the listener to a local interface) and the link appears here.',
      tunnelEntry: 'Cloudflare tunnel',
      lanEntry: 'Local network',
      copyLink: 'Copy link',
      copied: 'Copied',
      trustTrusted: 'trust fence: accepted',
      trustRefused: 'trust fence: refused — /api calls will fail with 403',
      trustUnknown: 'trust fence: unknown (connection service unavailable)',
      trustFix: 'Add this authority to trustedHosts',
      trustFixed: 'Written. The Loader reconciles the row in place.',
      domainTitle: 'The hostname phones will open',
      domainHint:
        'Exactly one hostname, no scheme, no path — for example {label}.example.com. It must be the name the platform trust fence accepts; saving writes this plugin row\u2019s config into your own profile patch layer.',
      domainPlaceholder: '{label}.example.com',
      tunnelNamePlaceholder: '{label}',
      tunnelNameHint:
        'The tunnel this machine creates or reuses; the usual pattern is {label} with {label}.example.com. The suggestion follows this machine\u2019s platform, so a Mac is not told to use the Windows name.',
      advancedTitle: 'Advanced',
      advancedDesc: 'Hostname, tunnel, Cloudflare, Cloudflare Access, access keys, recovery password, layout',
      save: 'Save',
      quickTrust: 'Trust this temporary domain',
      quickTrustHint:
        'A quick tunnel gets a new random hostname on every start, so you must trust it again each time — and pair the phone again. A named tunnel with your own domain avoids that.',
      restoreLoopback: 'Restore the loopback bind (127.0.0.1)',
      lanWarning:
        'Binding a local address replaces the loopback listener: after a restart, 127.0.0.1 stops answering and the desktop must use {host} too.',
      lanTitle: 'Local network entry',
      lanBound: 'The listener is bound to {host}, so a phone on the same network can use it.',
      lanNotBound:
        'The listener is bound to {host}, so another device cannot reach it directly. That is the right default when you use a tunnel; bind a local address only if you also want phone access over the same Wi-Fi.',
      lanAddresses: 'Addresses on this machine',
      tunnelTitle: 'cloudflared child process',
      tunnelUnconfigured:
        'No cloudflared command is configured for this plugin row. Add one under config.cloudflared, for example { command: "cloudflared", args: ["tunnel", "run", "dsh-win"] }.',
      tunnelUnavailable: 'The subprocess service is unavailable in this composition.',
      tunnelRunning: 'running (pid {pid})',
      tunnelStopped: 'stopped',
      tunnelExited: 'exited: {exit}',
      tunnelStart: 'Start tunnel',
      tunnelStop: 'Stop',
      tunnelOutput: 'Recent output',
      cfTitle: 'Cloudflare setup',
      cfIntro:
        'Two ways to publish this Harness: the browser authorization that cloudflared itself uses, or an API token that lets the plugin do everything without a browser.',
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
        'Creates or reuses a remotely-managed tunnel, points its ingress at the local listener, publishes a proxied CNAME, stores the connector token, and adds the hostname to the platform trust fence.',
      cfAccessEmail: 'Email allowed by the Access policy',
      cfAccessCreate: 'Create the Access application',
      cfAccessHint: 'Optional, but recommended on a public hostname: one self-hosted Access application with a one-time-PIN policy for your own email.',
      cfTeardown: 'Remove what this plugin created in Cloudflare',
      cfTeardownConfirm: 'Delete the DNS record and the tunnel this plugin created, and forget the stored connector token?',
      cfSteps: 'Steps',
      cfForgetToken: 'Forget the stored API token',
      cfForgetTokenDone: 'The stored API token was removed.',
      cfSavedToken: 'Token verified and stored.',
      renewNow: 'Renew this device now',
      recoveryTitle: 'Recovery access',
      recoveryHint:
        'Two ways back in when this phone\u2019s cookie has lapsed and you cannot reach the computer. An authorized device is issued at pairing time, is issued with an explicit lifetime (a year by default, or never), and each one can be revoked here — the per-device revocation the platform itself cannot do. The password is the fallback: verified by challenge-response, so it never crosses the network, and it is fail-closed — with no password stored the recovery page offers nothing at all.',
      recoveryArmed: 'Recovery password set ({date}).',
      recoveryUnarmed: 'No recovery password. The recovery page will not accept anything until you set one.',
      recoveryPassword: 'Recovery password (12 characters or more)',
      recoverySet: 'Set password',
      recoveryReplace: 'Replace password',
      recoverySaved: 'Password set. Every earlier unlock ticket was revoked.',
      recoveryClear: 'Remove password',
      recoveryClearConfirm: 'Remove the recovery password and revoke every unlock ticket?',
      recoveryCleared: 'Password removed.',
      recoveryTokensNote:
        'Setting a password revokes earlier unlock tickets only — it never touches an authorized device. Rename, change the expiry or revoke one in the Authorized devices list.',
      pairTitle: 'Add a device with a pairing code',
      pairHint:
        'Generate a code, then type or scan it on the new device. It works once, for ten minutes, and carries the lifetime the new authorized device should get.',
      pairNever: 'never expires',
      pairYear: '1 year',
      pairDays: ' days',
      pairGenerate: 'Generate pairing code',
      pairCreated: 'Code created. It works once, for ten minutes.',
      tokenNever: 'never expires',
      tokenExpired: 'expired',
      tokenValidUntil: 'valid until',
      tokenExpirySave: 'Save lifetime',
      tokenExpirySaved: 'Lifetime updated.',
      recoveryRevoke: 'Revoke',
      recoveryTokenRevoked: 'Authorized device revoked. That device will have to pair again.',
      recoveryIssued: 'Issued',
      recoveryUsed: 'Last used',
      deviceName: 'Name',
      deviceSave: 'Save',
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
      configHint: 'Written into your own profile patch layer, so it survives upgrades.',
      modeTitle: 'Access mode',
      modeLan: 'Local network',
      modePublic: 'Public',
      modeEnable: 'Enable this mode',
      modeEnabled: 'Currently enabled',
      modeHint:
        'Local network binds the listener to one of this machine\u2019s own addresses, so a phone on the same Wi-Fi opens it directly. Public keeps the listener on 127.0.0.1 and publishes it through the Cloudflare tunnel. Switching above only previews a mode — nothing is written until you enable it.',
      modeSwitchConfirm:
        'This takes effect immediately: this page may go blank or stop responding, so reopen the panel at the new address — a dsh restart is still recommended. Switch now?',
      modeSwitchNotice: 'Applied immediately — if this page stops responding, reopen the panel at the new address; a dsh restart is recommended.',
      restartPending:
        'The configured mode is {mode}, while this machine would pick {auto}: if you just switched, restart dsh for it to take effect.',
      tempEntry: 'Temporary: it dies with this process. After a restart, open a fresh entry link to pair this device again.',
      qrShow: 'Show QR',
      qrHide: 'Hide QR',
      deviceLinkGet: 'Get link',
      deviceLinkHide: 'Hide link',
      deviceLinkExpires: 'Single use, expires {time}',
      linkLoopbackOnly:
        'This link only works on this machine — configure a domain in Advanced (public mode) or switch to local network mode.',
      lanNoAddresses: 'No local network address was found on this machine.',
      lanNoEntry: 'No tokenized local-network link yet. Pick an address, then restart dsh, and the link appears here.',
      lifetimeCustom: 'Custom date',
      pairLifetime: 'Lifetime',
      countdownLeft: '{time} left',
      authorizedDevices: 'Authorized devices',
      authorizedDevicesNote:
        'This table is the authority: every row is a credential this machine handed out, and every row can be renamed, re-dated or revoked on its own.',
      deviceListEmpty: 'No authorized device yet. Add one with a pairing code, an access key or the entry link.',
      sourceEntry: 'Entry link',
      sourcePassword: 'Password',
      sourceKey: 'Access key',
      sourcePair: 'Pairing code',
      sourceUnknown: 'Unknown',
      temporaryBadge: 'Temporary',
      statusValid: 'Valid',
      deviceDelete: 'Delete',
      deviceDeleted: 'Row deleted.',
      deviceDeleteConfirm: 'Delete this expired row?',
      deviceRevokeConfirm: 'Revoke this device? It loses access at once and has to be paired again.',
      edgeAuthTitle: 'Cloudflare Access (the edge layer in front of this hostname)',
      edgeAuthOn: 'Cloudflare Access is enabled',
      edgeAuthOff: 'Cloudflare Access is not enabled',
      edgeAuthChipOn: 'Cloudflare Access: enabled',
      edgeAuthChipOff: 'Cloudflare Access: not enabled',
      edgeAuthEmail: 'Policy email: {email}',
      edgeAuthGo: 'Set up Access',
      edgeAuthHint:
        'The tunnel itself is public: whoever learns the hostname reaches this Harness. A Cloudflare Access application in front of it asks for a one-time PIN before the platform ever sees the request.',
      tunnelStartHint:
        'Starting runs cloudflared on this machine and points the entry link at the tunnel hostname.',
      keysTitle: 'Access keys',
      keysHint:
        'An access key is a credential this plugin mints and verifies itself: it is shown once, it can be revoked one by one, and resetting it kills the old secret immediately. Use one on a device that cannot scan the entry QR code.',
      keyName: 'Name',
      keyNamePlaceholder: 'for example: my phone',
      keyCreate: 'Create access key',
      keyCreated: 'Access key created.',
      keyOnceWarning:
        'This key is shown only once. Copy it now — it cannot be shown again, because only its fingerprint is stored. Resetting it is the way to get a new one.',
      copy: 'Copy',
      keyReset: 'Reset',
      keyResetConfirm: 'Reset this access key? The old key stops working immediately.',
      keyResetDone: 'Reset. The new key is shown only once.',
      keyRevokeConfirm: 'Revoke this access key? Devices using it lose access at once.',
      keyRevoked: 'Access key revoked.',
      keysEmpty: 'No access key yet.',
      accessLimit:
        'Credentials this plugin issues (authorized devices, access keys) can be revoked one by one. The platform\u2019s own cookie has no per-device revocation: it can only be revoked wholesale, with Revoke every paired browser session.',
      customDateRequired: 'Pick a date in the future.',
    };

    const ZH = {
      title: '远程访问',
      intro:
        '用手机打开现有的 Web UI。本面板负责显示入口链接、检查平台信任栅栏，并管理别的设备用什么凭据进来。',
      noEntries: '还没有入口。在下面填入隧道域名（或把监听绑定到本机局域网地址），链接就会出现在这里。',
      tunnelEntry: 'Cloudflare 隧道',
      lanEntry: '局域网',
      copyLink: '复制链接',
      copied: '已复制',
      trustTrusted: '信任栅栏：已接受',
      trustRefused: '信任栅栏：被拒绝 —— /api 调用会 403',
      trustUnknown: '信任栅栏：未知（connection 服务不可用）',
      trustFix: '把这个域名加入 trustedHosts',
      trustFixed: '已写入，Loader 会就地重建该行。',
      domainTitle: '手机要打开的域名',
      domainHint:
        '只填一个主机名，不要带 http:// 和路径——例如 {label}.example.com。它必须是平台信任栅栏接受的那个名字；保存后写入本插件行配置，落在你自己的 profile patch 层。',
      domainPlaceholder: '{label}.example.com',
      tunnelNamePlaceholder: '{label}',
      tunnelNameHint:
        '本机创建或复用的隧道名；惯用做法是 {label} 配 {label}.example.com。推荐值跟随本机系统，所以 Mac 上不会让你用 Windows 的名字。',
      advancedTitle: '高级',
      advancedDesc: '域名、隧道、Cloudflare、Cloudflare Access、访问密钥、恢复密码、布局',
      save: '保存',
      quickTrust: '信任这个临时域名',
      quickTrustHint:
        '快速隧道每次启动都会换一个随机域名，所以每次都要重新信任、手机也要重新配对。用自己的域名建命名隧道就没有这个问题。',
      restoreLoopback: '恢复回环绑定（127.0.0.1）',
      lanWarning:
        '绑定局域网地址会顶掉回环监听：重启后 127.0.0.1 不再响应，桌面端也必须改用 {host}。',
      lanTitle: '局域网入口',
      lanBound: '监听已绑定到 {host}，同一网络下的手机可以直接使用。',
      lanNotBound:
        '监听当前绑定在 {host}，其它设备无法直连。用隧道时这正是正确的默认值；只有你也想在同一 Wi-Fi 下用手机直连时，才需要绑定局域网地址。',
      lanAddresses: '本机地址',
      tunnelTitle: 'cloudflared 子进程',
      tunnelUnconfigured:
        '本插件行还没有配置 cloudflared 命令。请在 config.cloudflared 下添加，例如 { command: "cloudflared", args: ["tunnel", "run", "dsh-win"] }。',
      tunnelUnavailable: '当前组合没有 subprocess 服务。',
      tunnelRunning: '运行中（pid {pid}）',
      tunnelStopped: '未运行',
      tunnelExited: '已退出：{exit}',
      tunnelStart: '启动隧道',
      tunnelStop: '停止',
      tunnelOutput: '最近输出',
      cfTitle: 'Cloudflare 配置',
      cfIntro:
        '两种把 Harness 发布出去的方式：用 cloudflared 自己的浏览器授权，或用 API Token 让插件全程无需浏览器完成。',
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
        '创建或复用一条远端托管的隧道、把 ingress 指向本机监听、发布一条代理 CNAME、保存连接器令牌，并把域名加入平台信任栅栏。',
      cfAccessEmail: 'Access 策略允许的邮箱',
      cfAccessCreate: '创建 Access 应用',
      cfAccessHint: '可选，但公网域名上建议：一个自托管 Access 应用 + 只允许你自己邮箱的 One-time PIN 策略。',
      cfTeardown: '清理本插件在 Cloudflare 创建的东西',
      cfTeardownConfirm: '删除本插件创建的 DNS 记录与隧道，并清除已保存的连接器令牌？',
      cfSteps: '步骤',
      cfForgetToken: '清除已保存的 API Token',
      cfForgetTokenDone: '已清除保存的 API Token。',
      cfSavedToken: 'Token 已验证并保存。',
      renewNow: '立即为本设备续期',
      recoveryTitle: '恢复访问',
      recoveryHint:
        '当这台手机的 Cookie 失效、又碰不到电脑时，有两条回来的路。**授权设备**在配对时自动签发，**有效期是明确设定的**（默认一年，事后可改为永久或别的期限），可以在这里逐台改名、改有效期或撤销——这正是平台自己做不到的按设备管理。**密码**是兜底：用挑战-应答校验，密码不过网；而且是 fail-closed——没有设置密码时，恢复页什么都不提供。',
      recoveryArmed: '已设置恢复密码（{date}）。',
      recoveryUnarmed: '未设置恢复密码。在设置之前，恢复页不会接受任何东西。',
      recoveryPassword: '恢复密码（至少 12 个字符）',
      recoverySet: '设置密码',
      recoveryReplace: '更换密码',
      recoverySaved: '密码已设置。此前签发的解锁票据都已撤销。',
      recoveryClear: '移除密码',
      recoveryClearConfirm: '移除恢复密码并撤销全部解锁票据？',
      recoveryCleared: '密码已移除。',
      recoveryTokensNote:
        '设置密码只会作废此前的解锁票据，不会动任何授权设备。逐台改名、改有效期或撤销请在「已授权设备」列表里操作。',
      pairTitle: '用配对码添加设备',
      pairHint:
        '先生成一个码，再到新设备上输入或扫码。**10 分钟内有效、只能用一次**；码里携带新授权设备的有效期。',
      pairNever: '永不过期',
      pairYear: '1 年',
      pairDays: ' 天',
      pairGenerate: '生成配对码',
      pairCreated: '配对码已生成：10 分钟内有效，且只能使用一次。',
      tokenNever: '永不过期',
      tokenExpired: '已过期',
      tokenValidUntil: '有效至',
      tokenExpirySave: '保存有效期',
      tokenExpirySaved: '有效期已更新。',
      recoveryRevoke: '撤销',
      recoveryTokenRevoked: '授权设备已撤销。那台设备需要重新配对。',
      recoveryIssued: '签发于',
      recoveryUsed: '最近使用',
      deviceName: '名称',
      deviceSave: '保存',
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
      configHint: '写入你自己的 profile patch 层，升级不会丢。',
      modeTitle: '访问模式',
      modeLan: '局域网',
      modePublic: '公网',
      modeEnable: '启用此模式',
      modeEnabled: '当前已启用',
      modeHint:
        '局域网把监听绑到本机的一个地址，同一 Wi-Fi 下的手机可直接打开；公网让监听留在 127.0.0.1，通过 Cloudflare 隧道发布。上面的切换只是预览，点「启用此模式」才会写入配置。',
      modeSwitchConfirm: '切换会立即生效：本页可能变空白或停止响应，在新地址重新打开面板即可——仍建议重启 dsh。现在切换？',
      modeSwitchNotice: '已立即生效——如果本页停止响应，请在新地址重新打开面板；建议重启 dsh。',
      restartPending: '配置的模式是 {mode}，而这台机器会自动选择 {auto}：如果刚刚切换过，需要重启 dsh 才生效。',
      tempEntry: '临时：随进程失效。重启后需要重新打开一条新的入口链接来配对。',
      qrShow: '显示二维码',
      qrHide: '隐藏二维码',
      deviceLinkGet: '获取链接',
      deviceLinkHide: '收起链接',
      deviceLinkExpires: '只能用一次，到期时间 {time}',
      linkLoopbackOnly: '此链接只在本机有效——请在高级里配置域名（公网模式），或切换到局域网模式。',
      lanNoAddresses: '没有找到本机的局域网地址。',
      lanNoEntry: '还没有带令牌的局域网链接。先选一个地址并重启 dsh，链接就会出现在这里。',
      lifetimeCustom: '自定义日期',
      pairLifetime: '有效期',
      countdownLeft: '剩余 {time}',
      authorizedDevices: '已授权设备',
      authorizedDevicesNote:
        '这张表才是授权依据：每一行都是本机签发出去的凭据，可以单独改名、改有效期或撤销。',
      deviceListEmpty: '还没有已授权的设备。用配对码、访问密钥或入口链接添加一台。',
      sourceEntry: '入口链接',
      sourcePassword: '密码',
      sourceKey: '访问密钥',
      sourcePair: '设备验证码',
      sourceUnknown: '未知',
      temporaryBadge: '临时',
      statusValid: '有效',
      deviceDelete: '删除',
      deviceDeleted: '记录已删除。',
      deviceDeleteConfirm: '删除这条已过期的记录？',
      deviceRevokeConfirm: '撤销这台设备？它会立刻失去访问，需要重新配对。',
      edgeAuthTitle: 'Cloudflare Access（主机名前的边缘认证层）',
      edgeAuthOn: 'Cloudflare Access 已启用',
      edgeAuthOff: 'Cloudflare Access 未启用',
      edgeAuthChipOn: 'Cloudflare Access：已启用',
      edgeAuthChipOff: 'Cloudflare Access：未启用',
      edgeAuthEmail: '策略邮箱：{email}',
      edgeAuthGo: '配置 Access',
      edgeAuthHint:
        '隧道本身是公网可达的：知道域名的人都能连上这台 Harness。在它前面加一个 Cloudflare Access 应用，会在平台收到请求之前先要求一次性验证码。',
      tunnelStartHint:
        '启动会在本机拉起 cloudflared，并把入口链接指向隧道域名。',
      keysTitle: '访问密钥',
      keysHint:
        '访问密钥由插件自己签发、自己校验：只显示一次，可以逐条撤销；重置会立刻作废旧密钥。给无法扫入口二维码的设备使用。',
      keyName: '名称',
      keyNamePlaceholder: '例如：我的手机',
      keyCreate: '创建访问密钥',
      keyCreated: '访问密钥已创建。',
      keyOnceWarning: '这把密钥只显示这一次，请现在复制保存：之后无法再看，本机只保存它的指纹；需要新的就重置。',
      copy: '复制',
      keyReset: '重置',
      keyResetConfirm: '重置这把访问密钥？旧密钥会立刻失效。',
      keyResetDone: '已重置。新密钥只显示这一次。',
      keyRevokeConfirm: '撤销这把访问密钥？正在使用它的设备会立刻失去访问。',
      keyRevoked: '访问密钥已撤销。',
      keysEmpty: '还没有访问密钥。',
      accessLimit:
        '插件签发的凭据（授权设备、访问密钥）可以单独撤销。平台自己的 Cookie 没有按设备撤销：只能整体撤销（撤销全部已配对浏览器会话）。',
      customDateRequired: '请选择一个将来的日期。',
    };

    /** Panel styles; only theme tokens, so light/dark follows the host. */
    /**
     * Panel styles.
     *
     * Every colour, border and surface comes from the shipped theme tokens
     * (`--dsw-alias-*`), so the panel follows the app's light/dark setting and
     * third-party themes instead of carrying its own palette. Rhythm follows the
     * settings page: 14px section titles, 13px body, 12px secondary, 8px radii,
     * quiet bordered controls rather than filled ones — except the one filled
     * primary button the tunnel's Start deliberately is.
     */
    const PANEL_CSS = `
.mc-root { display: flex; flex-direction: column; gap: 10px; }
.mc-h2 { font-size: 14px; line-height: 22px; font-weight: 600; color: var(--dsw-alias-label-primary); margin: 0; }
.mc-title { font-size: 14px; line-height: 22px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.mc-p { font-size: 13px; line-height: 20px; color: var(--dsw-alias-label-secondary); margin: 0; }
.mc-muted { color: var(--dsw-alias-label-secondary); font-size: 12px; line-height: 18px; margin: 0; }
.mc-err { color: var(--dsw-alias-state-error-primary); font-size: 12px; }
.mc-ok { color: var(--dsw-alias-state-success-primary); font-size: 12px; }
.mc-warn { color: var(--dsw-alias-state-warn-primary); font-size: 12px; }
.mc-dim { opacity: .5; }

/* First-party settings card: 20px radius, .5px stroke, no shadow. */
.mc-card { display: flex; flex-direction: column; gap: 10px; padding: 12px 16px; border: .5px solid var(--dsw-alias-settings-card-stroke); border-radius: var(--dsw-radius-xl); background: var(--dsw-alias-settings-card-fill); box-shadow: none; }
/* The Advanced disclosure needs its own stack: a <details> drops its content
   into an anonymous box, so the cards would otherwise share one flex item and
   their borders would touch. */
.mc-advanced-body { display: flex; flex-direction: column; gap: 10px; }
.mc-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.mc-inline { display: inline-flex; align-items: center; gap: 6px; flex-wrap: wrap; }

/* Normal button: 36px tall, 14px text, md radius; only the primary is filled. */
.mc-btn { display: inline-flex; align-items: center; justify-content: center; font: inherit; font-size: 14px; line-height: 22px; height: 36px; padding: 0 14px; border-radius: var(--dsw-radius-md); border: .5px solid var(--dsw-alias-border-l3); background: none; color: var(--dsw-alias-label-primary); cursor: pointer; transition: background-color var(--ds-transition-duration-slow, .15s) var(--ds-ease-in-out, ease), border-color var(--ds-transition-duration-slow, .15s) var(--ds-ease-in-out, ease); }
.mc-btn:hover:not([disabled]) { background: var(--dsw-alias-interactive-bg-hover); }
.mc-btn:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 1px; }
.mc-btn[disabled] { opacity: .5; cursor: default; }
.mc-btn-danger { border: .5px solid var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary); }
.mc-btn-danger:hover:not([disabled]) { background: var(--dsw-alias-interactive-bg-hover); }
.mc-btn-on { border-color: var(--dsw-alias-brand-primary); color: var(--dsw-alias-brand-primary); }
/* In-row actions — rename, save, revoke, get link, delete, reset — are small. */
.mc-device .mc-btn, .mc-btn-sm { height: 28px; padding: 0 10px; border-radius: var(--dsw-radius-sm); font-size: 12px; line-height: 18px; }

/* The paired actions: one filled primary (the brand token) and one outlined
   error button, stacked one per row at equal width, so Start and Stop read as
   one pair with a clear primary. */
.mc-btn-primary { background: var(--dsw-alias-button-primary-fill); color: var(--dsw-alias-label-primary-foreground); border: none; }
.mc-btn-primary:hover:not([disabled]) { background: var(--dsw-alias-button-primary-hover); color: var(--dsw-alias-label-primary-foreground); }
.mc-action-stack { display: flex; flex-direction: column; gap: 8px; align-items: flex-start; }
/* the action buttons keep their intrinsic width: no stretching anywhere */
.mc-btn-slot { align-self: flex-start; min-width: 150px; }
/* The "nothing to do" state of an action control: same box, muted colour. */
.mc-btn-muted { color: var(--dsw-alias-label-secondary); }

/* Segmented mode switch: two buttons sharing one border. */
.mc-seg { display: inline-flex; align-items: stretch; border: .5px solid var(--dsw-alias-border-l2); border-radius: var(--dsw-radius-md); overflow: hidden; }
.mc-seg-btn { font: inherit; font-size: 12px; line-height: 18px; padding: 6px 14px; border: 0; background: none; color: var(--dsw-alias-label-secondary); cursor: pointer; white-space: nowrap; }
.mc-seg-btn + .mc-seg-btn { border-left: .5px solid var(--dsw-alias-border-l2); }
.mc-seg-btn:hover:not([disabled]) { color: var(--dsw-alias-brand-primary); }
.mc-seg-btn[disabled] { opacity: .5; cursor: default; }
.mc-seg-on { background: var(--dsw-alias-bg-layer-3); color: var(--dsw-alias-brand-primary); font-weight: 600; }
.mc-seg-btn:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: -2px; }

.mc-input { font: inherit; font-size: 13px; height: 34px; padding: 0 12px; border: .5px solid var(--dsw-alias-border-l4); border-radius: var(--dsw-radius-md); background: var(--dsw-alias-bg-layer-3); color: var(--dsw-alias-label-primary); }
.mc-input:focus-visible { outline: none; border-color: var(--dsw-alias-state-business-primary); }
.mc-input::placeholder { color: var(--dsw-alias-label-secondary); }
.mc-label { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--dsw-alias-label-primary); }

.mc-badge { font-size: 11px; line-height: 16px; padding: 1px 6px; border-radius: 999px; border: .5px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); white-space: nowrap; }
.mc-badge-ok { color: var(--dsw-alias-state-success-primary); border-color: var(--dsw-alias-state-success-primary); }
.mc-badge-bad { color: var(--dsw-alias-state-error-primary); border-color: var(--dsw-alias-state-error-primary); }

.mc-code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 18px; overflow-wrap: anywhere; color: var(--dsw-alias-label-primary); background: var(--dsw-alias-bg-layer-3); border-radius: var(--dsw-radius-md); padding: 6px 8px; }
.mc-code-lg { font-size: 20px; line-height: 30px; font-weight: 600; letter-spacing: .12em; text-align: center; }
.mc-key { flex: 1 1 200px; min-width: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.mc-pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; line-height: 16px; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 140px; overflow: auto; color: var(--dsw-alias-label-secondary); background: var(--dsw-alias-bg-layer-3); border-radius: var(--dsw-radius-md); padding: 6px 8px; margin: 0; }
/* The QR keeps its black-on-white contrast: the one place no theme token fits. */
.mc-qr { background: #fff; padding: 6px; border-radius: var(--dsw-radius-md); width: 168px; height: 168px; }
.mc-countdown { font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); font-variant-numeric: tabular-nums; white-space: nowrap; }

.mc-table { width: 100%; border-collapse: collapse; font-size: 12px; color: var(--dsw-alias-label-secondary); }
.mc-table th { text-align: left; font-weight: 500; padding: 4px 6px; border-bottom: .5px solid var(--dsw-alias-border-l2); }
.mc-table td { padding: 4px 6px; border-bottom: .5px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-primary); overflow-wrap: anywhere; }

/* Rows inside a card are divider rows, not nested boxes: a .5px rule and
   compact padding, so a list reads as part of its card. */
.mc-devices { display: flex; flex-direction: column; }
.mc-device { display: flex; flex-direction: column; gap: 6px; padding: 12px 0; border-bottom: .5px solid var(--dsw-alias-border-l2); }
.mc-device:last-child { border-bottom: none; }
.mc-device-main { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.mc-device-name { flex: 1 1 160px; min-width: 0; }
.mc-device-meta { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); overflow-wrap: anywhere; }

details.mc-card > summary.mc-title { cursor: pointer; list-style-position: inside; }
details.mc-card > summary.mc-title:hover { color: var(--dsw-alias-brand-primary); }
details.mc-card[open] > summary.mc-title { margin-bottom: 2px; }
/* The secondary line under a summary: wraps freely, never truncated. */
.mc-summary-desc { display: block; margin-top: 4px; font-size: 12px; line-height: 18px; font-weight: 400; color: var(--dsw-alias-label-tertiary); white-space: normal; overflow: visible; text-overflow: clip; }

.mc-title-row { display: flex; align-items: center; gap: 6px; }
.mc-hint-wrap { position: relative; display: inline-flex; flex: none; }
.mc-hint { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; padding: 0; border-radius: var(--dsw-radius-sm); border: .5px solid var(--dsw-alias-border-l3); background: none; color: var(--dsw-alias-label-tertiary); font: inherit; font-size: 12px; line-height: 1; cursor: pointer; }
.mc-hint:hover, .mc-hint[aria-expanded="true"] { color: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); }
.mc-hint:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 1px; }
.mc-hint-pop { position: fixed; z-index: 30; width: max-content; max-width: min(340px, calc(100vw - 16px)); padding: 8px 10px; border-radius: var(--dsw-radius-md); border: .5px solid var(--dsw-alias-border-l3); background: var(--dsw-alias-bg-overlay); color: var(--dsw-alias-label-primary); font-size: 12px; line-height: 18px; white-space: pre-line; box-shadow: var(--dsw-elevation-panel); }
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
     * The message out of a failure, whichever envelope it arrived in.
     *
     * The route wraps an endpoint's own `{ ok: false, error }` in its success
     * envelope, so a failed endpoint call is a *value* here rather than a
     * rejection, and `error` may be a string or the route's `{ code, message }`.
     */
    function errorText(value, fallback) {
      const error = value?.error;
      if (typeof error === 'string' && error !== '') return error;
      if (error !== null && typeof error === 'object') return String(error.message ?? error.code ?? fallback);
      return fallback;
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

    /** Milliseconds from a stamp that may be an absolute number or an ISO string. */
    function toMillis(value) {
      if (typeof value === 'number' && Number.isFinite(value)) return value > 0 ? value : undefined;
      if (typeof value === 'string' && value !== '') {
        const parsed = Date.parse(value);
        return Number.isFinite(parsed) ? parsed : undefined;
      }
      return undefined;
    }

    /** Short local timestamp, or an em dash when there is nothing to show. */
    function formatTime(value) {
      const at = toMillis(value);
      if (at === undefined) return '—';
      const d = new Date(at);
      const pad = (n) => String(n).padStart(2, '0');
      return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
    }

    /** mm:ss left until one instant; never negative. */
    function formatCountdown(untilMs, nowMs) {
      const left = Math.max(0, Math.floor((untilMs - nowMs) / 1000));
      const pad = (n) => String(n).padStart(2, '0');
      return `${pad(Math.floor(left / 60))}:${pad(left % 60)}`;
    }

    /** Host[:port] of a URL, for the quick-tunnel trust button. */
    function authorityOf(url) {
      try {
        return new URL(String(url)).host;
      } catch {
        return String(url).replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      }
    }

    /** Whether one bind host means "this machine only". */
    function isLoopbackHost(value) {
      const host = String(value ?? '').toLowerCase();
      return host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
    }

    /** The lifetime choices, shared by the pairing code, the device rows and the keys. */
    const LIFETIME_CHOICES = ['never', '30', '90', '365', 'custom'];

    /** One `<option>` list for every lifetime selector. */
    function lifetimeOptions(t) {
      return LIFETIME_CHOICES.map((value) =>
        h(
          'option',
          { key: value, value },
          value === 'never'
            ? t('pairNever')
            : value === '365'
              ? t('pairYear')
              : value === 'custom'
                ? t('lifetimeCustom')
                : `${value}${t('pairDays')}`,
        ),
      );
    }

    /** The selector value that matches one stored day count. */
    function lifetimeChoiceOf(days) {
      if (days === null || days === undefined) return 'never';
      const value = String(days);
      return LIFETIME_CHOICES.includes(value) ? value : 'custom';
    }

    /**
     * One selector choice as the host wants it.
     *
     * A custom date is turned into an exact instant (`until`) *and* the whole
     * days that are left, because the pairing code and the key endpoints only
     * carry a day count while `device-expiry` accepts the instant as well.
     * @returns `{ days, until? }`, or `undefined` when a custom date is missing.
     */
    function lifetimeValue(choice, date) {
      if (choice === 'never') return { days: null };
      if (choice === 'custom') {
        const at = toMillis(`${date}T23:59:59`);
        if (at === undefined || at <= Date.now()) return undefined;
        return { days: Math.max(1, Math.ceil((at - Date.now()) / 86400000)), until: new Date(at).toISOString() };
      }
      const days = Number(choice);
      return Number.isFinite(days) && days > 0 ? { days } : undefined;
    }

    /** A lifetime selector: four presets, plus an explicit date when asked for. */
    function LifetimeSelect({ translate: t, value, onChange, date, onDate, disabled }) {
      return h(
        'span',
        { className: 'mc-inline' },
        h(
          'select',
          { className: 'mc-input', value, disabled: disabled === true, onChange: (event) => onChange(event.target.value) },
          ...lifetimeOptions(t),
        ),
        value === 'custom'
          ? h('input', {
              className: 'mc-input',
              type: 'date',
              value: date,
              disabled: disabled === true,
              'aria-label': t('lifetimeCustom'),
              onChange: (event) => onDate(event.target.value),
            })
          : null,
      );
    }

    /** A copy button bound to one string, with a short “copied” flash. */
    function CopyButton({ translate: t, value, idleKey, className }) {
      const [copied, setCopied] = React.useState(false);
      return h(
        'button',
        {
          type: 'button',
          className: className ?? 'mc-btn',
          disabled: typeof value !== 'string' || value === '',
          onClick: () => {
            const clipboard = typeof navigator === 'undefined' ? undefined : navigator.clipboard;
            if (clipboard === undefined) return;
            Promise.resolve(clipboard.writeText(value)).then(
              () => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              },
              () => {},
            );
          },
        },
        copied ? t('copied') : t(idleKey ?? 'copy'),
      );
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
     * A circled question mark that opens its explanation on click.
     *
     * A native `title` tooltip appeared too slowly, could not be dismissed, and
     * on touch needed a long press. This opens on click, closes on a click
     * anywhere else or on Escape, and keeps the text in `aria-label` for
     * assistive technology.
     *
     * The popover is `position: fixed` and placed from `getBoundingClientRect()`
     * so no ancestor's `overflow: hidden` can clip it. It lines its left edge up
     * with the trigger and flips to the trigger's right edge when that would
     * overflow the viewport; it sits below the trigger, or above when there is
     * no room below; and it always keeps an 8px viewport margin. While it is
     * open it is repositioned on resize and on scroll (capture phase, so a
     * scrolling ancestor counts).
     * @param props - `text` is the explanation; `label` optionally prefixes it.
     */
    function Hint({ text, label }) {
      const [open, setOpen] = React.useState(false);
      const [pos, setPos] = React.useState(null);
      const wrapRef = React.useRef(null);
      const popRef = React.useRef(null);

      /** Measure the trigger and the popover, then pin the popover in the viewport. */
      const place = React.useCallback(() => {
        const wrap = wrapRef.current;
        const pop = popRef.current;
        if (wrap === null || pop === null) return;
        if (typeof wrap.getBoundingClientRect !== 'function' || typeof pop.getBoundingClientRect !== 'function') return;
        const trigger = wrap.getBoundingClientRect();
        const box = pop.getBoundingClientRect();
        const width = box.width > 0 ? box.width : pop.offsetWidth;
        const height = box.height > 0 ? box.height : pop.offsetHeight;
        const viewportWidth = window.innerWidth || document.documentElement?.clientWidth || 0;
        const viewportHeight = window.innerHeight || document.documentElement?.clientHeight || 0;
        if (viewportWidth <= 0 || viewportHeight <= 0) return;
        const margin = 8;
        const gap = 6;
        let left = trigger.left;
        if (left + width > viewportWidth - margin) left = trigger.right - width;
        left = Math.max(margin, Math.min(left, Math.max(margin, viewportWidth - margin - width)));
        let top = trigger.bottom + gap;
        if (top + height > viewportHeight - margin && trigger.top - gap - height >= margin) top = trigger.top - gap - height;
        top = Math.max(margin, Math.min(top, Math.max(margin, viewportHeight - margin - height)));
        setPos({ left, top });
      }, []);

      React.useEffect(() => {
        if (!open) {
          setPos(null);
          return undefined;
        }
        place();
        const onMove = () => place();
        window.addEventListener('resize', onMove);
        window.addEventListener('scroll', onMove, true);
        return () => {
          window.removeEventListener('resize', onMove);
          window.removeEventListener('scroll', onMove, true);
        };
      }, [open, place]);

      React.useEffect(() => {
        if (!open) return undefined;
        const close = (event) => {
          // A click on the button itself is handled by the button, not here.
          if (typeof event?.target?.closest === 'function' && event.target.closest('.mc-hint-wrap') !== null) return;
          setOpen(false);
        };
        const onKey = (event) => {
          if (event.key === 'Escape') setOpen(false);
        };
        document.addEventListener('pointerdown', close);
        document.addEventListener('keydown', onKey);
        return () => {
          document.removeEventListener('pointerdown', close);
          document.removeEventListener('keydown', onKey);
        };
      }, [open]);

      if (typeof text !== 'string' || text === '') return null;
      const full = label === undefined ? text : `${label}: ${text}`;
      return h(
        'span',
        { className: 'mc-hint-wrap', ref: wrapRef },
        h(
          'button',
          {
            type: 'button',
            className: 'mc-hint',
            'aria-label': full,
            'aria-expanded': open,
            onClick: (event) => {
              event.stopPropagation();
              setOpen((value) => !value);
            },
          },
          '?',
        ),
        open
          ? h(
              'span',
              {
                className: 'mc-hint-pop',
                role: 'note',
                ref: popRef,
                style: pos === null ? undefined : { left: `${pos.left}px`, top: `${pos.top}px` },
              },
              full,
            )
          : null,
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

    /** The translated label of one access source. */
    function sourceLabel(t, source) {
      const value = String(source ?? '');
      if (value === 'entry-link' || value === 'entry' || value === 'link') return t('sourceEntry');
      if (value === 'password' || value === 'recovery') return t('sourcePassword');
      if (value === 'access-key' || value === 'key') return t('sourceKey');
      if (value === 'pair-code' || value === 'pair' || value === 'code') return t('sourcePair');
      return value === '' ? t('sourceUnknown') : value;
    }

    /** The translated label of one derived device status. */
    function statusLabel(t, status) {
      if (status === 'expired') return t('tokenExpired');
      if (status === 'never') return t('tokenNever');
      return t('statusValid');
    }

    /** The badge class for one derived device status. */
    function statusClass(status) {
      if (status === 'expired') return 'mc-badge mc-badge-bad';
      if (status === 'valid') return 'mc-badge mc-badge-ok';
      return 'mc-badge';
    }

    /** The translated name of one mode. */
    function modeLabel(t, mode) {
      return mode === 'lan' ? t('modeLan') : t('modePublic');
    }

    /**
     * One entry link: its trust verdict, a copy button, and a QR the user
     * expands. Expanding the QR is also the refresh — it re-fetches the entry
     * URL — so a stale link is fixed by the same click.
     *
     * `entry.trust` is absent for a link the panel assembled itself (from
     * `mode-status` or a renewed session), and then no verdict is claimed.
     */
    function EntryCard({ entry, translate, onTrust, busy, onRefresh, linksReachable }) {
      const [showQr, setShowQr] = React.useState(false);
      const hasUrl = typeof entry.url === 'string' && entry.url !== '';
      const hasQr = entry.qr !== undefined && entry.qr !== null;
      const trustClass = entry.trust === 'trusted' ? 'mc-badge mc-badge-ok' : entry.trust === 'refused' ? 'mc-badge mc-badge-bad' : 'mc-badge';
      const trustText =
        entry.trust === 'trusted' ? translate('trustTrusted') : entry.trust === 'refused' ? translate('trustRefused') : translate('trustUnknown');
      return h(
        'div',
        { className: 'mc-card' },
        h(
          'div',
          { className: 'mc-row' },
          h('span', { className: 'mc-title' }, entry.label),
          typeof entry.trust === 'string' ? h('span', { className: trustClass }, trustText) : null,
        ),
        hasUrl ? h('div', { className: 'mc-code' }, entry.url) : h('p', { className: 'mc-muted' }, translate('noEntries')),
        h('p', { className: 'mc-muted mc-title-row' }, firstSentence(translate('tempEntry')), h(Hint, { text: translate('tempEntry') })),
        h(
          'div',
          { className: 'mc-row' },
          h(CopyButton, { translate, value: entry.url, idleKey: 'copyLink' }),
          entry.trust === 'refused'
            ? h('button', { className: 'mc-btn', disabled: busy, onClick: () => onTrust(entry.authority) }, translate('trustFix'))
            : null,
        ),
        hasQr
          ? h(
              'div',
              { className: 'mc-row' },
              h(
                'button',
                {
                  type: 'button',
                  className: 'mc-btn',
                  disabled: busy,
                  onClick: () => {
                    if (showQr) {
                      setShowQr(false);
                      return;
                    }
                    setShowQr(true);
                    if (typeof onRefresh === 'function') onRefresh();
                  },
                },
                showQr ? translate('qrHide') : translate('qrShow'),
              ),
            )
          : null,
        showQr && hasQr ? h(QrCode, { qr: entry.qr }) : null,
        linksReachable === 'loopback-only' ? h('p', { className: 'mc-warn' }, translate('linkLoopbackOnly')) : null,
      );
    }

    /** The cloudflared child: the matched Start/Stop pair, the edge-auth chip, trust and the output. */
    function TunnelCard({ translate: t, busy, act, tunnel, tunnelRunning, edgeEnabled }) {
      const configured = tunnel?.configured === true;
      const available = tunnel?.available !== false;
      const running = tunnelRunning === true || tunnel?.running === true;
      const state =
        configured !== true
          ? t('tunnelUnconfigured')
          : available !== true
            ? t('tunnelUnavailable')
            : `${tunnel.command ?? 'cloudflared'} — ${
                running
                  ? t('tunnelRunning', { pid: tunnel.pid ?? '?' })
                  : tunnel.exit !== undefined && tunnel.exit !== null
                    ? t('tunnelExited', { exit: JSON.stringify(tunnel.exit) })
                    : t('tunnelStopped')
              }`;
      return h(
        'div',
        { className: 'mc-card' },
        h(
          'div',
          { className: 'mc-title-row' },
          h('span', { className: 'mc-title' }, t('tunnelTitle')),
          h('span', { className: edgeEnabled === true ? 'mc-ok' : 'mc-warn' }, edgeEnabled === true ? t('edgeAuthChipOn') : t('edgeAuthChipOff')),
        ),
        h('p', { className: 'mc-p' }, state),
        h(
          'div',
          { className: 'mc-action-stack' },
          h(
            'button',
            {
              className: 'mc-btn mc-btn-primary',
              disabled: busy || configured !== true || available !== true || running,
              onClick: () => act('tunnel-start', {}),
            },
            t('tunnelStart'),
          ),
          h('button', { className: 'mc-btn mc-btn-danger', disabled: busy || running !== true, onClick: () => act('tunnel-stop', {}) }, t('tunnelStop')),
        ),
        h('p', { className: 'mc-muted' }, t('tunnelStartHint')),
        tunnel?.url ? h('div', { className: 'mc-code' }, tunnel.url) : null,
        tunnel?.url
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
        tunnel?.url ? h('p', { className: 'mc-muted' }, t('quickTrustHint')) : null,
        Array.isArray(tunnel?.lines) && tunnel.lines.length > 0
          ? h('div', null, h('p', { className: 'mc-muted' }, t('tunnelOutput')), h('pre', { className: 'mc-pre' }, tunnel.lines.join('\n')))
          : null,
      );
    }

    /**
     * The one-time pairing code: a lifetime, a Generate button, and the code
     * itself with its QR and a live mm:ss countdown that greys out when it ends.
     */
    function PairCodeCard({ translate: t, busy, act, now }) {
      const [choice, setChoice] = React.useState('365');
      const [date, setDate] = React.useState('');
      const [pair, setPair] = React.useState(null);
      const value = lifetimeValue(choice, date);
      const expiresAt = pair === null ? undefined : toMillis(pair.expiresAt);
      const expired = expiresAt !== undefined && expiresAt <= now;
      const code = pair !== null && typeof pair.code === 'string' ? pair.code : undefined;
      return h(
        'div',
        { className: 'mc-card' },
        h('span', { className: 'mc-title' }, t('pairTitle')),
        h('p', { className: 'mc-p' }, t('pairHint')),
        h(
          'div',
          { className: 'mc-row' },
          h('span', { className: 'mc-muted' }, t('pairLifetime')),
          h(LifetimeSelect, { translate: t, value: choice, onChange: setChoice, date, onDate: setDate, disabled: busy }),
          h(
            'button',
            {
              className: 'mc-btn',
              disabled: busy || value === undefined,
              onClick: () =>
                act('pair-code', { days: value.days }, (answer) => {
                  setPair(answer !== null && typeof answer === 'object' && typeof answer.code === 'string' ? answer : null);
                  return t('pairCreated');
                }),
            },
            t('pairGenerate'),
          ),
        ),
        choice === 'custom' && value === undefined ? h('p', { className: 'mc-muted' }, t('customDateRequired')) : null,
        pair === null
          ? null
          : h(
              'div',
              { className: expired ? 'mc-device mc-dim' : 'mc-device' },
              code === undefined ? null : h('div', { className: 'mc-code mc-code-lg' }, code),
              h(
                'div',
                { className: 'mc-row' },
                h(
                  'span',
                  { className: 'mc-countdown' },
                  expired ? t('tokenExpired') : t('countdownLeft', { time: formatCountdown(expiresAt ?? now, now) }),
                ),
                h(CopyButton, { translate: t, value: code }),
              ),
              h(QrCode, { qr: pair.qr }),
              typeof pair.url === 'string' && pair.url !== '' ? h('p', { className: 'mc-device-meta' }, pair.url) : null,
            ),
      );
    }

    /**
     * One authorized device: an editable name, its origin and status badges, the
     * stamps that matter, a lifetime editor, and revoke (or, once expired, delete).
     */
    function DeviceRow({ translate: t, device, busy, act, onChanged, now }) {
      const [name, setName] = React.useState(device.name ?? '');
      const [choice, setChoice] = React.useState(lifetimeChoiceOf(device.days));
      const [date, setDate] = React.useState('');
      const [link, setLink] = React.useState(null);
      const [showQr, setShowQr] = React.useState(false);
      const value = lifetimeValue(choice, date);
      const expiresAt = toMillis(device.expiresAt);
      const status =
        typeof device.status === 'string' ? device.status : expiresAt === undefined ? 'never' : expiresAt > now ? 'valid' : 'expired';
      const expired = status === 'expired';
      const lastUsedIp = typeof device.lastUsedIp === 'string' && device.lastUsedIp !== '' ? ` · ${device.lastUsedIp}` : '';
      return h(
        'div',
        { className: expired ? 'mc-device mc-dim' : 'mc-device' },
        h(
          'div',
          { className: 'mc-device-main' },
          h('input', {
            className: 'mc-input mc-device-name',
            'aria-label': t('deviceName'),
            placeholder: device.id,
            value: name,
            onChange: (event) => setName(event.target.value),
          }),
          h(
            'button',
            {
              className: 'mc-btn',
              disabled: busy || name.trim() === '',
              onClick: () => act('device-rename', { id: device.id, name: name.trim() }, () => t('saved')).then(onChanged),
            },
            t('deviceSave'),
          ),
          h('span', { className: 'mc-badge' }, sourceLabel(t, device.source)),
          device.temporary === true ? h('span', { className: 'mc-badge' }, t('temporaryBadge')) : null,
          h('span', { className: statusClass(status) }, statusLabel(t, status)),
          expired
            ? null
            : h(
                'button',
                {
                  className: 'mc-btn',
                  disabled: busy,
                  onClick: () => {
                    if (link !== null) {
                      setLink(null);
                      setShowQr(false);
                      return;
                    }
                    act('device-link', { id: device.id }, (answer) => {
                      if (answer !== null && typeof answer === 'object' && typeof answer.url === 'string') {
                        setLink(answer);
                        setShowQr(false);
                      }
                      return '';
                    });
                  },
                },
                link === null ? t('deviceLinkGet') : t('deviceLinkHide'),
              ),
          h(
            'button',
            {
              className: 'mc-btn mc-btn-danger',
              disabled: busy,
              onClick: () => {
                if (!window.confirm(t('deviceRevokeConfirm'))) return;
                act('device-revoke', { id: device.id }, () => t('recoveryTokenRevoked')).then(onChanged);
              },
            },
            t('recoveryRevoke'),
          ),
          expired
            ? h(
                'button',
                {
                  className: 'mc-btn mc-btn-danger',
                  disabled: busy,
                  onClick: () => {
                    if (!window.confirm(t('deviceDeleteConfirm'))) return;
                    act('device-delete', { id: device.id }, () => t('deviceDeleted')).then(onChanged);
                  },
                },
                t('deviceDelete'),
              )
            : null,
        ),
        h(
          'p',
          { className: 'mc-device-meta' },
          `${t('recoveryIssued')} ${formatTime(device.createdAt)} · ${
            expiresAt === undefined ? t('tokenNever') : `${t('tokenValidUntil')} ${formatTime(expiresAt)}`
          } · ${t('recoveryUsed')} ${formatTime(device.lastUsedAt)}${lastUsedIp}`,
        ),
        link === null
          ? null
          : h(
              'div',
              { className: 'mc-device' },
              h(
                'div',
                { className: 'mc-row' },
                h('input', {
                  className: 'mc-input mc-key',
                  readOnly: true,
                  value: link.url,
                  'aria-label': t('deviceLinkGet'),
                  onFocus: (event) => {
                    if (typeof event?.target?.select === 'function') event.target.select();
                  },
                }),
                h(CopyButton, { translate: t, value: link.url, idleKey: 'copyLink' }),
                h('button', { type: 'button', className: 'mc-btn', onClick: () => setShowQr((value) => !value) }, showQr ? t('qrHide') : t('qrShow')),
              ),
              showQr && link.qr !== undefined && link.qr !== null ? h(QrCode, { qr: link.qr }) : null,
              h('p', { className: 'mc-device-meta' }, t('deviceLinkExpires', { time: formatTime(link.expiresAt) })),
            ),
        h(
          'div',
          { className: 'mc-row' },
          h('span', { className: 'mc-muted' }, t('pairLifetime')),
          h(LifetimeSelect, { translate: t, value: choice, onChange: setChoice, date, onDate: setDate, disabled: busy }),
          h(
            'button',
            {
              className: 'mc-btn',
              disabled: busy || value === undefined,
              onClick: () =>
                act(
                  'device-expiry',
                  { id: device.id, days: value.days, ...(value.until === undefined ? {} : { until: value.until }) },
                  () => t('tokenExpirySaved'),
                ).then(onChanged),
            },
            t('tokenExpirySave'),
          ),
        ),
        choice === 'custom' && value === undefined ? h('p', { className: 'mc-muted' }, t('customDateRequired')) : null,
      );
    }

    /** The authorized-device list, shared by the public panel and the recovery card. */
    function DeviceList({ translate: t, devices, busy, act, onChanged, now }) {
      if (devices.length === 0) return h('p', { className: 'mc-muted' }, t('deviceListEmpty'));
      return h(
        'div',
        { className: 'mc-devices' },
        ...devices.map((device) => h(DeviceRow, { key: device.id, translate: t, device, busy, act, onChanged, now })),
      );
    }

    /**
     * A secret that exists exactly once.
     *
     * The host stores a fingerprint, never the key, so this field is the only
     * place the plaintext will ever be: read-only, selectable, and copyable.
     */
    function KeyOnce({ translate: t, label, value }) {
      return h(
        'div',
        { className: 'mc-device' },
        typeof label === 'string' && label !== '' ? h('p', { className: 'mc-title' }, label) : null,
        h(
          'div',
          { className: 'mc-row' },
          h('input', {
            className: 'mc-input mc-key',
            readOnly: true,
            value,
            'aria-label': t('keyOnceWarning'),
            onFocus: (event) => {
              if (typeof event?.target?.select === 'function') event.target.select();
            },
          }),
          h(CopyButton, { translate: t, value }),
        ),
        h('p', { className: 'mc-warn' }, t('keyOnceWarning')),
      );
    }

    /** The access keys: create one, then reset or revoke each row. */
    function AccessKeyCard({ translate: t, busy, act, keys, onChanged, now }) {
      const [name, setName] = React.useState('');
      const [choice, setChoice] = React.useState('365');
      const [date, setDate] = React.useState('');
      const [created, setCreated] = React.useState(null);
      const [reset, setReset] = React.useState(null);
      const value = lifetimeValue(choice, date);
      return h(
        'div',
        { className: 'mc-card' },
        h('span', { className: 'mc-title' }, t('keysTitle')),
        h('p', { className: 'mc-p mc-title-row' }, firstSentence(t('keysHint')), h(Hint, { text: t('keysHint') })),
        h(
          'div',
          { className: 'mc-row' },
          h('input', {
            className: 'mc-input',
            style: { minWidth: '180px' },
            placeholder: t('keyNamePlaceholder'),
            'aria-label': t('keyName'),
            value: name,
            onChange: (event) => setName(event.target.value),
          }),
          h(LifetimeSelect, { translate: t, value: choice, onChange: setChoice, date, onDate: setDate, disabled: busy }),
          h(
            'button',
            {
              className: 'mc-btn',
              disabled: busy || value === undefined,
              onClick: () =>
                act('key-create', { name: name.trim() === '' ? undefined : name.trim(), days: value.days }, (answer) => {
                  if (answer !== null && typeof answer === 'object' && typeof answer.key === 'string') {
                    setCreated({ label: answer.name ?? name, value: answer.key });
                  }
                  setName('');
                  return t('keyCreated');
                }),
            },
            t('keyCreate'),
          ),
        ),
        choice === 'custom' && value === undefined ? h('p', { className: 'mc-muted' }, t('customDateRequired')) : null,
        created === null ? null : h(KeyOnce, { translate: t, label: created.label, value: created.value }),
        keys.length === 0
          ? h('p', { className: 'mc-muted' }, t('keysEmpty'))
          : h(
              'div',
              { className: 'mc-devices' },
              ...keys.map((key) => {
                const expiresAt = toMillis(key.expiresAt);
                const status =
                  typeof key.status === 'string' ? key.status : expiresAt === undefined ? 'never' : expiresAt > now ? 'valid' : 'expired';
                return h(
                  'div',
                  { className: 'mc-device', key: key.id },
                  h(
                    'div',
                    { className: 'mc-device-main' },
                    h('span', { className: 'mc-title' }, key.name ?? key.id),
                    h('span', { className: statusClass(status) }, statusLabel(t, status)),
                    h(
                      'button',
                      {
                        className: 'mc-btn',
                        disabled: busy,
                        onClick: () => {
                          if (!window.confirm(t('keyResetConfirm'))) return;
                          act('key-reset', { id: key.id }, (answer) => {
                            if (answer !== null && typeof answer === 'object' && typeof answer.key === 'string') {
                              setReset({ id: key.id, label: key.name, value: answer.key });
                            }
                            return t('keyResetDone');
                          }).then(onChanged);
                        },
                      },
                      t('keyReset'),
                    ),
                    h(
                      'button',
                      {
                        className: 'mc-btn mc-btn-danger',
                        disabled: busy,
                        onClick: () => {
                          if (!window.confirm(t('keyRevokeConfirm'))) return;
                          act('key-revoke', { id: key.id }, () => t('keyRevoked')).then(onChanged);
                        },
                      },
                      t('recoveryRevoke'),
                    ),
                  ),
                  h(
                    'p',
                    { className: 'mc-device-meta' },
                    `${t('recoveryIssued')} ${formatTime(key.createdAt)} · ${
                      expiresAt === undefined ? t('tokenNever') : `${t('tokenValidUntil')} ${formatTime(expiresAt)}`
                    } · ${t('recoveryUsed')} ${formatTime(key.lastUsedAt)}`,
                  ),
                  reset !== null && reset.id === key.id ? h(KeyOnce, { translate: t, label: reset.label, value: reset.value }) : null,
                );
              }),
            ),
      );
    }

    /**
     * The recovery card: the password status, the set/replace/remove controls,
     * and one honest line about what a password change does — nothing else.
     *
     * The authorized-device list lives exactly once, in the public panel above,
     * so there are no per-device buttons here either.
     */
    function RecoveryCard({ translate: t, busy, act, recovery, onChanged }) {
      const [password, setPassword] = React.useState('');
      const armed = recovery?.configured === true;
      return h(
        'div',
        { className: 'mc-card' },
        h('div', { className: 'mc-title-row' }, h('span', { className: 'mc-title' }, t('recoveryTitle')), h(Hint, { text: t('recoveryHint') })),
        h('p', { className: armed ? 'mc-ok' : 'mc-muted' }, armed ? t('recoveryArmed', { date: formatTime(recovery?.createdAt) }) : t('recoveryUnarmed')),
        h(
          'div',
          { className: 'mc-row' },
          h('input', {
            className: 'mc-input',
            style: { minWidth: '220px' },
            type: 'password',
            autoComplete: 'new-password',
            placeholder: t('recoveryPassword'),
            value: password,
            onChange: (event) => setPassword(event.target.value),
          }),
          h(
            'button',
            {
              className: 'mc-btn',
              disabled: busy || password.length < 12,
              onClick: () =>
                act('recovery-set', { password }, () => {
                  setPassword('');
                  return t('recoverySaved');
                }).then(onChanged),
            },
            armed ? t('recoveryReplace') : t('recoverySet'),
          ),
          armed
            ? h(
                'button',
                {
                  className: 'mc-btn mc-btn-danger',
                  disabled: busy,
                  onClick: () => {
                    if (!window.confirm(t('recoveryClearConfirm'))) return;
                    act('recovery-clear', {}, () => t('recoveryCleared')).then(onChanged);
                  },
                },
                t('recoveryClear'),
              )
            : null,
        ),
        h('p', { className: 'mc-muted' }, t('recoveryTokensNote')),
      );
    }

    /**
     * The edge-authentication block, in Advanced next to the Cloudflare card it
     * configures. The public main area only carries the one-line status chip
     * that TunnelCard renders.
     */
    function EdgeAuthCard({ translate: t, enabled, email, onConfigure }) {
      return h(
        'div',
        { className: 'mc-card' },
        h('span', { className: 'mc-title' }, t('edgeAuthTitle')),
        h('p', { className: enabled === true ? 'mc-ok' : 'mc-warn' }, enabled === true ? t('edgeAuthOn') : t('edgeAuthOff')),
        typeof email === 'string' && email !== '' ? h('p', { className: 'mc-muted' }, t('edgeAuthEmail', { email })) : null,
        h('p', { className: 'mc-muted' }, t('edgeAuthHint')),
        h('div', { className: 'mc-row' }, h('button', { className: 'mc-btn', onClick: onConfigure }, t('edgeAuthGo'))),
      );
    }

    /** Mutable view of the active translator; the panel re-renders on locale change. */
    const localeListeners = new Set();
    let activeTranslate = (key) => key;

    /** The whole settings section. */
    function Panel() {
      const [state, setState] = React.useState(null);
      const [modeStatus, setModeStatus] = React.useState(null);
      const [deviceRows, setDeviceRows] = React.useState(null);
      const [keyRows, setKeyRows] = React.useState(null);
      const [recovery, setRecovery] = React.useState(null);
      const [fresh, setFresh] = React.useState(null);
      const [env, setEnv] = React.useState(null);
      const [error, setError] = React.useState('');
      const [notice, setNotice] = React.useState('');
      const [busy, setBusy] = React.useState(false);
      const [accessCreated, setAccessCreated] = React.useState(false);
      const [now, setNow] = React.useState(() => Date.now());
      // `null` means "untouched": the input shows the configured value until
      // the user types, and returns to it after a successful save.
      const [domainDraft, setDomainDraft] = React.useState(null);
      const [tunnelNameDraft, setTunnelNameDraft] = React.useState(null);
      // The segmented control is a *preview*: it only picks which mode's config
      // is shown. `null` means "follow the mode the host is actually running".
      const [displayMode, setDisplayMode] = React.useState(null);
      const [lanHostDraft, setLanHostDraft] = React.useState(null);
      const [, bumpLocale] = React.useState(0);

      /** Refresh the Cloudflare environment checklist (it spawns `--version`). */
      const refreshEnv = React.useCallback(() => {
        hostCall('cf-env', {}).then((value) => setEnv(value !== null && typeof value === 'object' && value.ok !== false ? value : null));
      }, []);

      const load = React.useCallback(() => {
        // `state` is the broad view; if the endpoint is unavailable the panel
        // still renders from `mode-status`, `device-list` and `key-list`.
        hostCall('state', {}).then((value) => setState(value !== null && typeof value === 'object' && value.ok !== false ? value : {}));
        hostCall('mode-status', {}).then((value) => {
          if (value !== null && typeof value === 'object' && value.ok === false) setError(errorText(value, 'mode-status failed'));
          else if (value !== null && typeof value === 'object') {
            setError('');
            setModeStatus(value);
          }
        });
        hostCall('device-list', {}).then((value) => {
          if (value !== null && typeof value === 'object' && Array.isArray(value.devices)) setDeviceRows(value.devices);
        });
        hostCall('key-list', {}).then((value) => {
          if (value !== null && typeof value === 'object' && Array.isArray(value.keys)) setKeyRows(value.keys);
        });
        hostCall('recovery-status', {}).then((value) => {
          if (value !== null && typeof value === 'object' && value.ok !== false) setRecovery(value);
        });
        hostCall('renew-session', {}).then((value) => {
          if (value !== null && typeof value === 'object' && typeof value.url === 'string') setFresh(value);
        });
      }, []);

      React.useEffect(() => {
        load();
        const timer = setInterval(load, 10000);
        return () => clearInterval(timer);
      }, [load]);

      React.useEffect(() => {
        // The pairing countdown, and the "is it still valid" greying of the
        // device and key rows, all read from one shared second.
        const timer = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(timer);
      }, []);

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
        return hostCall(method, args).then((value) => {
          setBusy(false);
          if (value !== null && typeof value === 'object' && value.ok === false) {
            setError(errorText(value, 'the host declined the request'));
          } else {
            setError('');
            setNotice(typeof done === 'function' ? done(value) : '');
            load();
          }
          return value;
        });
      };

      if (state === null && modeStatus === null) {
        return h('div', { className: 'mc-root' }, h('p', { className: 'mc-p' }, error !== '' ? t('failed', { message: error }) : t('loading')));
      }

      const status = modeStatus ?? state?.mode ?? {};
      const mode = status.mode === 'lan' ? 'lan' : 'public';
      const entries = Array.isArray(state?.entries) ? state.entries : [];
      const devices = deviceRows ?? (Array.isArray(state?.devices) ? state.devices : []);
      const keys = keyRows ?? (Array.isArray(state?.keys) ? state.keys : []);
      const recoveryStatus = recovery ?? state?.recovery ?? null;
      const tunnel = state?.tunnel ?? {};
      const capabilities = state?.capabilities ?? {};
      const platform = state?.platform ?? {};
      /** `loopback-only` means the minted link cannot leave this machine. */
      const linksReachable = typeof status.linksReachable === 'string' ? status.linksReachable : state?.linksReachable;
      const tunnelHost = typeof state?.config?.tunnelHost === 'string' && state.config.tunnelHost !== '' ? state.config.tunnelHost : undefined;
      const freshAuthority = typeof fresh?.authority === 'string' && fresh.authority !== '' ? fresh.authority : undefined;
      const mismatch = typeof status.auto === 'string' && typeof status.mode === 'string' && status.auto !== status.mode;

      // What the panel is *showing*; `status.mode` is what the host runs.
      const shown = displayMode ?? mode;
      const activeHost = typeof status.host === 'string' && status.host !== '' ? status.host : undefined;
      // Only a LAN bind seeds the address picker: in public mode the host is
      // 127.0.0.1, which is not a LAN address to hand back to `set-mode`.
      const lanHost = lanHostDraft ?? (mode === 'lan' ? activeHost : undefined);
      const modePending = shown !== mode || (shown === 'lan' && lanHostDraft !== null && lanHostDraft !== activeHost);

      /**
       * Apply the previewed mode — the only place the mode is written.
       *
       * The segmented control and the LAN address picker are local view state,
       * so browsing between the two modes never touches the config.
       */
      const enableMode = () => {
        if (!modePending) return;
        if (!window.confirm(t('modeSwitchConfirm'))) return;
        // A LAN bind needs one concrete address; with none chosen here the host
        // picks this machine's first usable one itself.
        if (shown === 'lan' && lanHost !== undefined) act('set-mode', { mode: 'lan', host: lanHost }, () => t('modeSwitchNotice'));
        else act('set-mode', { mode: shown }, () => t('modeSwitchNotice'));
      };

      /** Preview one LAN address; `启用此模式` is what binds it. */
      const pickLan = (host) => {
        setLanHostDraft(host);
        setDisplayMode('lan');
      };

      /**
       * Fetch a fresh tokenized entry link without pairing this browser again.
       *
       * Expanding the entry QR is what calls this, and it stays silent on
       * purpose: the QR and the URL field updating in place is the feedback, and
       * a notice line at the top of the panel would jump the whole layout on a
       * click that happens further down.
       */
      const refreshLink = () => {
        hostCall('renew-session', {}).then((value) => {
          if (value !== null && typeof value === 'object' && typeof value.url === 'string') {
            setFresh(value);
          } else {
            setError(errorText(value, 'the host declined to mint a fresh entry URL'));
          }
        });
      };

      /**
       * Open the advanced disclosure and bring the Cloudflare card into view.
       *
       * The disclosure is left uncontrolled — the per-second countdown tick
       * re-renders this panel, and a React-controlled `open` attribute would
       * fight the browser's own toggle — so it is opened through the DOM, one
       * tick later, once the element exists.
       */
      const jumpToCf = () => {
        setTimeout(() => {
          try {
            if (typeof document?.getElementById !== 'function') return;
            const details = document.getElementById('dsh-remote-access-advanced');
            if (details !== null && details !== undefined) details.open = true;
            const card = document.getElementById('dsh-remote-access-cf');
            if (card !== null && card !== undefined && typeof card.scrollIntoView === 'function') card.scrollIntoView({ block: 'start' });
          } catch {
            /* a client without the DOM still gets the panel */
          }
        }, 0);
      };

      const access = env?.access;
      const accessEnabled =
        access?.enabled === true || access?.configured === true || Array.isArray(access?.apps) || accessCreated === true;
      const accessEmail =
        typeof access?.email === 'string' && access.email !== ''
          ? access.email
          : typeof state?.cloudflare?.accessEmail === 'string'
            ? state.cloudflare.accessEmail
            : undefined;

      const modeChildren = [
        h(
          'div',
          { className: 'mc-card', key: 'mode' },
          h('span', { className: 'mc-title' }, t('modeTitle')),
          h(
            'div',
            { className: 'mc-row' },
            h(
              'div',
              { className: 'mc-seg', role: 'group', 'aria-label': t('modeTitle') },
              h(
                'button',
                {
                  type: 'button',
                  className: shown === 'lan' ? 'mc-seg-btn mc-seg-on' : 'mc-seg-btn',
                  'aria-pressed': shown === 'lan',
                  disabled: busy,
                  onClick: () => setDisplayMode('lan'),
                },
                t('modeLan'),
              ),
              h(
                'button',
                {
                  type: 'button',
                  className: shown === 'public' ? 'mc-seg-btn mc-seg-on' : 'mc-seg-btn',
                  'aria-pressed': shown === 'public',
                  disabled: busy,
                  onClick: () => setDisplayMode('public'),
                },
                t('modePublic'),
              ),
            ),
          ),
          h('p', { className: 'mc-muted' }, t('modeHint')),
          // One button-shaped slot, two states: actionable when the previewed
          // mode differs from the live one, otherwise the same box muted and
          // disabled, so the card never reflows when the preview changes.
          h(
            'button',
            {
              className: modePending ? 'mc-btn mc-btn-primary mc-btn-slot' : 'mc-btn mc-btn-muted mc-btn-slot',
              disabled: busy || !modePending,
              onClick: enableMode,
            },
            modePending ? t('modeEnable') : t('modeEnabled'),
          ),
          mismatch ? h('p', { className: 'mc-warn' }, t('restartPending', { mode: modeLabel(t, mode), auto: modeLabel(t, status.auto) })) : null,
        ),
      ];

      const lanEntry = entries.find((entry) => entry.kind === 'lan');
      const lanAuthority = typeof status.lanHost === 'string' && status.lanHost !== '' ? status.lanHost : undefined;
      const lanFresh = freshAuthority !== undefined && lanAuthority !== undefined && freshAuthority === lanAuthority;
      const lanCardAuthority = lanEntry?.authority ?? lanAuthority;
      const lanChildren = [
        h(
          'div',
          { className: 'mc-card', key: 'lan' },
          h('span', { className: 'mc-title' }, t('lanTitle')),
          h(
            'p',
            { className: 'mc-p' },
            status.host === undefined || status.host === null || isLoopbackHost(status.host)
              ? t('lanNotBound', { host: typeof status.host === 'string' ? status.host : '127.0.0.1' })
              : t('lanBound', { host: status.host }),
          ),
          h('p', { className: 'mc-muted' }, t('lanWarning', { host: lanCardAuthority ?? '?' })),
          h('p', { className: 'mc-muted' }, t('lanAddresses')),
          h(
            'div',
            { className: 'mc-row' },
            ...(Array.isArray(status.addresses) ? status.addresses : []).map((entry) =>
              h(
                'button',
                {
                  key: entry.address,
                  className: lanHost === entry.address ? 'mc-btn mc-btn-on' : 'mc-btn',
                  disabled: busy,
                  onClick: () => pickLan(entry.address),
                },
                entry.label === undefined || entry.label === entry.address ? String(entry.address) : `${entry.address} (${entry.label})`,
              ),
            ),
            (Array.isArray(status.addresses) ? status.addresses : []).length === 0
              ? h('span', { className: 'mc-muted', key: 'none' }, t('lanNoAddresses'))
              : null,
          ),
          h(
            'div',
            { className: 'mc-row' },
            h(
              'button',
              {
                className: 'mc-btn',
                disabled: busy,
                onClick: () => {
                  if (!window.confirm(t('modeSwitchConfirm'))) return;
                  act('restore-loopback', {}, () => t('modeSwitchNotice'));
                },
              },
              t('restoreLoopback'),
            ),
          ),
        ),
        h(EntryCard, {
          key: 'lan-entry',
          entry: {
            id: 'lan',
            kind: 'lan',
            label: t('lanEntry'),
            authority: lanCardAuthority,
            base: lanCardAuthority === undefined ? undefined : `http://${lanCardAuthority}/`,
            url: lanEntry?.url ?? (lanFresh ? fresh?.url : lanAuthority === undefined ? undefined : `http://${lanAuthority}/`),
            qr: lanEntry?.qr ?? (lanFresh ? fresh?.qr : undefined),
            trust: lanEntry?.trust,
          },
          translate: t,
          busy,
          linksReachable,
          onRefresh: refreshLink,
        }),
        lanEntry === undefined ? h('p', { key: 'lan-note', className: 'mc-muted' }, t('lanNoEntry')) : null,
      ];

      const tunnelEntry = entries.find((entry) => entry.kind === 'tunnel');
      const publicUrl = typeof status.publicUrl === 'string' && status.publicUrl !== '' ? status.publicUrl : undefined;
      const publicFresh = freshAuthority !== undefined && tunnelHost !== undefined && freshAuthority === tunnelHost;
      const publicAuthority = tunnelEntry?.authority ?? (publicUrl === undefined ? (publicFresh ? freshAuthority : undefined) : authorityOf(publicUrl));
      const publicChildren = [
        h(TunnelCard, { key: 'tunnel', translate: t, busy, act, tunnel, tunnelRunning: status.tunnelRunning === true, edgeEnabled: accessEnabled }),
        h(EntryCard, {
          key: 'entry',
          entry: {
            id: 'tunnel',
            kind: 'tunnel',
            label: t('tunnelEntry'),
            authority: publicAuthority,
            base: publicAuthority === undefined ? undefined : `https://${publicAuthority}/`,
            url: tunnelEntry?.url ?? publicUrl ?? (publicFresh ? fresh?.url : undefined),
            qr: tunnelEntry?.qr ?? (publicFresh ? fresh?.qr : undefined),
            trust: tunnelEntry?.trust,
          },
          translate: t,
          busy,
          linksReachable,
          onRefresh: refreshLink,
          onTrust: (authority) => act('trust-authority', { authority }, () => t('trustFixed')),
        }),
        h(PairCodeCard, { key: 'pair', translate: t, busy, act, now }),
        h(
          'div',
          { className: 'mc-card', key: 'devices' },
          h('span', { className: 'mc-title' }, t('authorizedDevices')),
          h('p', { className: 'mc-p' }, t('authorizedDevicesNote')),
          h(DeviceList, { translate: t, devices, busy, act, onChanged: load, now }),
        ),
      ];

      return h(
        'div',
        { className: 'mc-root' },
        h('h2', { className: 'mc-h2' }, t('title')),
        h('p', { className: 'mc-p' }, t('intro')),
        error !== '' ? h('p', { className: 'mc-err' }, t('failed', { message: error })) : null,
        notice !== '' ? h('p', { className: 'mc-ok' }, notice) : null,

        ...modeChildren,
        ...(shown === 'lan' ? lanChildren : publicChildren),

        h(
          'details',
          { className: 'mc-card', id: 'dsh-remote-access-advanced' },
          h(
            'summary',
            { className: 'mc-title' },
            t('advancedTitle'),
            h('span', { className: 'mc-summary-desc' }, t('advancedDesc')),
          ),
          h(
            'div',
            { className: 'mc-advanced-body' },

            h(
              'div',
              { className: 'mc-card' },
              h('span', { className: 'mc-title' }, t('domainTitle')),
              h('p', { className: 'mc-p' }, t('domainHint', { label: state?.suggestedLabel ?? 'dsh' })),
              h(
                'div',
                { className: 'mc-row' },
                h('input', {
                  className: 'mc-input',
                  style: { minWidth: '260px' },
                  placeholder: t('domainPlaceholder', { label: state?.suggestedLabel ?? 'dsh' }),
                  value: domainDraft ?? state?.config?.tunnelHost ?? '',
                  onChange: (event) => setDomainDraft(event.target.value),
                }),
                h(
                  'button',
                  {
                    className: 'mc-btn',
                    disabled: busy || capabilities.configEditor !== true || (domainDraft ?? state?.config?.tunnelHost ?? '').trim() === '',
                    onClick: () =>
                      act('set-plugin-config', { tunnelHost: String(domainDraft).trim() }, () => {
                        setDomainDraft(null);
                        return t('saved');
                      }),
                  },
                  t('save'),
                ),
              ),
              h(
                'div',
                { className: 'mc-row' },
                h('input', {
                  className: 'mc-input',
                  style: { minWidth: '260px' },
                  placeholder: t('tunnelNamePlaceholder', { label: state?.suggestedLabel ?? 'dsh' }),
                  value: tunnelNameDraft ?? state?.config?.tunnelName ?? '',
                  onChange: (event) => setTunnelNameDraft(event.target.value),
                }),
                h(
                  'button',
                  {
                    className: 'mc-btn',
                    disabled: busy || capabilities.configEditor !== true || (tunnelNameDraft ?? state?.config?.tunnelName ?? '').trim() === '',
                    onClick: () =>
                      act('set-plugin-config', { tunnelName: String(tunnelNameDraft).trim() }, () => {
                        setTunnelNameDraft(null);
                        return t('saved');
                      }),
                  },
                  t('save'),
                ),
              ),
              h('p', { className: 'mc-muted' }, t('tunnelNameHint', { label: state?.suggestedLabel ?? 'dsh' })),
              capabilities.configEditor !== true
                ? h('p', { className: 'mc-muted' }, t('configHint'))
                : null,
            ),

            h(CfCard, {
              env,
              translate: t,
              busy,
              act,
              onRefresh: refreshEnv,
              onAccessCreated: () => setAccessCreated(true),
            }),

            // Edge authentication is the layer in front of the *published*
            // hostname, so it only renders for the ACTIVE public mode: browsing
            // to the LAN preview must not hide a control the user may be about to
            // enable, and LAN mode (no tunnel) must not carry the block at all.
            mode === 'public' ? h(EdgeAuthCard, { key: 'edge', translate: t, enabled: accessEnabled, email: accessEmail, onConfigure: jumpToCf }) : null,

            h(AccessKeyCard, { translate: t, busy, act, keys, onChanged: load, now }),

            h(RecoveryCard, { translate: t, busy, act, recovery: recoveryStatus, onChanged: load }),

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
              h('p', { className: 'mc-muted mc-title-row' }, firstSentence(t('accessLimit')), h(Hint, { text: t('accessLimit') })),
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
                  checked: state?.config?.narrowEnhance !== false,
                  disabled: busy || capabilities.configEditor !== true,
                  onChange: (event) => act('set-plugin-config', { narrowEnhance: event.target.checked }, () => t('saved')),
                }),
                t('narrowEnhance'),
              ),
              h('p', { className: 'mc-muted' }, t('narrowEnhanceHint')),
              h('p', { className: 'mc-muted' }, t('configHint')),
            ),
          ),
        ),

        h('div', { className: 'mc-row' }, h('button', { className: 'mc-btn', onClick: load }, t('refresh'))),
      );
    }

    /** The Cloudflare card: environment checklist, guided login, token setup. */
    function CfCard({ env, translate: t, busy, act, onRefresh, onAccessCreated }) {
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
        return h('div', { className: 'mc-card', id: 'dsh-remote-access-cf' }, h('span', { className: 'mc-title' }, t('cfTitle')), h('p', { className: 'mc-p' }, t('cfChecking')));
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
        { className: 'mc-card', id: 'dsh-remote-access-cf' },
        h('span', { className: 'mc-title' }, t('cfTitle')),
        h('p', { className: 'mc-p' }, t('cfIntro')),

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

        h('p', { className: 'mc-muted' }, t('cfTokenHint')),
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
        h('p', { className: 'mc-muted' }, t('cfAutoHint')),

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
            {
              className: 'mc-btn',
              disabled: busy || email.trim() === '' || hostname === undefined || hostname === null,
              onClick: () =>
                runSteps('cf-access', { hostname, email: email.trim() }).then((value) => {
                  if (value !== null && typeof value === 'object' && value.ok !== false && typeof onAccessCreated === 'function') onAccessCreated(value);
                }),
            },
            t('cfAccessCreate'),
          ),
        ),
        h('p', { className: 'mc-muted' }, t('cfAccessHint')),

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
        }, 'dsh-remote-access: locale subscription');

        ctx.effect(() => {
          const style = document.createElement('style');
          style.setAttribute('data-plugin', 'dsh-remote-access');
          style.textContent = PANEL_CSS;
          document.head.append(style);
          return () => style.remove();
        }, 'dsh-remote-access: panel styles');

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
            { name: 'settings.section', id: 'remote-access', order: 30, label: () => activeTranslate('title') },
            Panel,
          ),
        );

        // Phone layout tweaks: the stylesheet is injected synchronously (so it is
        // fiber-owned) and its `media` attribute is the switch — enabled by
        // default, disabled when the plugin row config says so. A failed state
        // call leaves the default in place.
        ctx.effect(() => {
          const style = document.createElement('style');
          style.setAttribute('data-plugin', 'dsh-remote-access-narrow');
          style.textContent = NARROW_CSS;
          style.media = 'all';
          document.head.append(style);
          hostCall('state', {}).then((value) => {
            if (value !== null && typeof value === 'object' && value.ok !== false && value.config?.narrowEnhance === false) {
              style.media = 'not all';
            }
          });
          return () => style.remove();
        }, 'dsh-remote-access: narrow viewport tweaks');
      },
    };
  },
});
