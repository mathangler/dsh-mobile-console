/**
 * dsh-mobile-console — the setup skill that ships with the plugin.
 *
 * The plugin registers this as a runtime skill at activation, so installing the
 * plugin installs the guide and disabling the plugin removes it. Nothing is
 * written into the user's own skills directory.
 *
 * The body is a FIXED pipeline, not advice: numbered phases, an explicit entry
 * condition per phase, one idempotent check before each action, a fixed report
 * format, and a fixed answer table for what the user reports back. Two runs on
 * the same machine must produce the same sequence and the same wording, and a
 * re-run must skip whatever is already done instead of redoing it.
 *
 * @module dsh-mobile-console/skill
 */

/** Skill name; the user invokes it by this name. */
export const SKILL_NAME = 'dsh-mobile-access';

/** One-line catalog description. */
export const SKILL_DESCRIPTION =
  '按固定流程配置 dsh 手机访问（Cloudflare 隧道 + 平台认证），Windows / macOS / Linux 通用 / Run the fixed pipeline that publishes this Harness to a phone through a Cloudflare tunnel.';

/** When the model should reach for it. */
export const SKILL_WHEN_TO_USE =
  '用户想用手机访问这台 dsh、要配置或排查 Cloudflare 隧道、要拿入口二维码，或问到 dsh-mobile-console 插件设置时。';

/** The full skill body. */
export const SKILL_CONTENT = `# 手机访问配置（dsh-mobile-console）— 固定流程

这是一条**固定流水线**。严格按 Phase 0 → 6 顺序执行。

## 执行契约（不可协商）

1. **固定顺序**：不跳步、不重排、不合并、不自行发明步骤。需要替代方案时，只能用本文件写明的 Phase 1b / 3A / 3B。
2. **幂等**：每个 Phase 开头先做它自己的检查。已满足 → 只输出一行「Phase N — 已完成，跳过」然后进入下一个 Phase；**不要重做、不要重复询问、不要重新创建已有资源**。
3. **固定汇报**：每个 Phase 用同一格式输出两行——\`Phase N — <结论>\` 与 \`  证据: <命令或面板字段>\`。全文结尾用固定的「配置完成」模板。
4. **需要用户动手时**，给**编号、可照做**的指令，并明确「完成后回复：<一句话>」。用户回复后按末尾的**应答表**处理，不要即兴发挥。
5. **密钥纪律**：API Token 只粘贴到面板（进入平台凭据库）。**不要打印、不要写入文件、不要出现在聊天里**。
6. **DNS 纪律**：只允许新增/修改本插件需要的那条主机名记录。**不要删除、不要改动用户已有的其它记录**。
7. 面板路径统一是 **设置 → 手机访问**（Settings → Mobile Access）。

## Phase 0 — 状态检测（永远第一步，永不跳过）

依次取这五项，缺工具就用面板替代：

| 检查 | Windows | macOS / Linux |
|---|---|---|
| cloudflared 是否可用 | \`cloudflared --version\` | \`cloudflared --version\` |
| 隧道是否已配置 | 面板「检测环境」→ 连接器令牌/配置文件；或列 \`%USERPROFILE%\\.cloudflared\\\` | 同左，目录 \`~/.cloudflared/\` |
| 域名 NS 指向 | \`Resolve-DnsName <域名> -Type NS\`（**不要**加 \`-Server\`） | \`dig +short NS <域名>\`（**不要**加 \`@8.8.8.8\`） |
| 隧道是否在跑 | 面板 cloudflared 卡片状态 | 同左 |
| 平台环境变量 | \`$env:DSH_HOME\` | \`echo $DSH_HOME\` |

固定输出：

\`\`\`
Phase 0 — 环境
  dsh: 127.0.0.1:3080 运行中
  cloudflared: <版本 | 未安装>
  隧道: <未创建 | 名称/ID，运行中/已停止>
  域名 NS: <仍在原注册商 | 已指向 Cloudflare | 未检测>
  下一步: Phase <N>
\`\`\`

判定：cloudflared 缺失 → Phase 2；NS 未指向 Cloudflare → Phase 1；隧道未创建 → Phase 3；隧道未运行 → Phase 4；手机未配对 → Phase 5；否则 Phase 6。
（Phase 2 与 Phase 1 互不依赖，但**顺序固定**：先域名后安装。）

## Phase 0b — 收集输入（**必须询问用户，禁止自行假设**）

进入 Phase 1/3 之前，必须问清这三项，并把答案原样用于后续所有命令、面板字段与 DNS 记录。**任何一项都不要替用户挑一个默认值或「建议一个」**：

1. **用哪个域名（zone）？** 例如 \`example.com\`——用户可能持有多个域名，必须问。
2. **这台机器对外用哪个主机名？** 惯用写法是 \`<隧道名>.<域名>\`（例如隧道 \`dsh-win\` → \`dsh-win.example.com\`；Mac 则 \`dsh-mac.example.com\`）。**先问用户要哪个主机名**，再由它推导隧道名＝主机名最左边那一段。**绝不要自己发明主机名**：写错域名会导致手机打不开并需要重配。
3. **配置方式选 A 还是 B？** A＝建 API Token（全自动），B＝浏览器授权。

固定问法（一次问完，不要挤牙膏）：

> 开始前需要你确认三件事：
> 1）用哪个域名？（例如 \`example.com\`）
> 2）这台机器对外用哪个主机名？（惯用 \`<隧道名>.<域名>\`，例如 \`dsh-win.example.com\`）
> 3）配置方式选 A（建 API Token，全自动）还是 B（浏览器授权）？

得到答复后，先输出这一行固定记录，再继续：

\`\`\`
输入: 域名=<域名>  主机名=<主机名>  隧道名=<主机名最左段>  路径=<A|B>
\`\`\`

**每台机器都要重新问一遍**：同一套域名下，各机器的主机名与隧道名必须不同（\`dsh-win\` / \`dsh-mac\` / \`dsh-linux\`）；换机器执行本 skill 时**不要沿用上一台的主机名**，也不要指望沿用上一台的 \`~/.cloudflared\` 证书——证书属于本机，每台机器各自授权或各自用 Token。

## Phase 1 — 域名交给 Cloudflare（唯一必须人工的步骤）

进入条件：NS 未指向 Cloudflare。已满足 → 「Phase 1 — 已完成，跳过」→ Phase 2。

给用户这条固定指令：

1. 打开 https://dash.cloudflare.com → **Add a site** → 输入 \`<域名>\` → 选 **Free** → Continue。
2. 记下页面给出的两个 NS（形如 \`xxx.ns.cloudflare.com\`）。
3. 到注册商处把 NS 改成这两个：
   - **腾讯云 / DNSPod**：控制台 → 域名与网站 → 我的域名 → \`<域名>\` → **修改 DNS 服务器** → 选「自定义」→ 填两个 NS → 提交
   - **阿里云**：域名 → 域名列表 → \`<域名>\` → **DNS 修改** → 自定义 DNS
   - **Namecheap**：Domain List → Manage → Nameservers → Custom DNS
   - **GoDaddy**：My Products → DNS → Nameservers → Change → I'll use my own
4. 完成后回复：**「NS 已改」**。

然后告知：生效通常 5 分钟 ~ 24 小时，期间 Cloudflare 控制台该域名显示 Pending。

**固定验证循环（最多重复 3 轮，措辞不变）**：
- 运行上表的 NS 查询命令；期望结果里出现 \`ns.cloudflare.com\`；或 Cloudflare 控制台显示 **Active**。
- **若查询超时或失败**（企业网络/防火墙常拦直连 8.8.8.8 与 DoH）：改用系统解析器 \`Resolve-DnsName <域名> -Type NS\`（Windows）/ \`dig +short NS <域名>\`（macOS/Linux），或直接以 Cloudflare 控制台的 zone 状态为准。**这只是换查询手段，不改变本 Phase 的任何步骤。**
- 用户回「还没生效」→ 让用户等 30 分钟后再跑同一条命令。**重复同一指令，不换方案、不加步骤。**
- 连续 3 轮仍未生效 → 输出「Phase 1 — 阻塞：NS 未生效」并停止，等用户主动继续（不要自行改 DNS、不要跳到 Phase 3）。

**Phase 1b（唯一允许的替代路径）**：用户明确表示域名不在手上或无法改 NS 时使用，并**停止 Phase 1**：
- Tailscale（免费、免域名）：安装 Tailscale → \`tailscale up\` → \`tailscale serve --bg 3080\` → 得到 \`<机器>.<tailnet>.ts.net\` 作为域名，随后从 Phase 3B 起继续（把该域名填进面板）。
- 快速隧道（临时，每次启动换域名）：面板 cloudflared 卡片填入 \`--url http://127.0.0.1:3080\` 的等价配置，启动后用「信任这个临时域名」。

## Phase 2 — 安装 cloudflared

进入条件：\`cloudflared --version\` 失败。已满足 → 「Phase 2 — 已完成，跳过」→ Phase 3。

**只给对应平台的那一条**：

| 平台 | 命令 | 装完必须做的 |
|---|---|---|
| Windows | \`winget install --id Cloudflare.cloudflared\` | **新开一个终端**（PATH 刷新） |
| macOS | \`brew install cloudflared\` | 无 |
| Linux (Debian/Ubuntu) | \`sudo apt install cloudflared\` | 无 |
| Linux (Fedora/RHEL) | \`sudo dnf install cloudflared\` | 无 |
| Linux (其它) | 从 releases 页面取二进制放到 \`/usr/local/bin\` 并 \`chmod +x\` | 无 |

常驻方式（仅在用户问「怎么让它一直跑」时回答，不要主动改）：面板的「启动」随 dsh 进程存活；要独立常驻，Windows 用任务计划程序或 \`nssm\`，macOS 用 \`launchd\`/\`brew services\`，Linux 用 \`systemd\`。

验证：\`cloudflared --version\` 打印版本号。回复：**「装好了」**。

## Phase 3 — 建立隧道（二选一，默认 A）

进入条件：面板显示隧道未配置（\`%USERPROFILE%\\.cloudflared\\dsh-mobile-console.yml\` 或 \`~/.cloudflared/dsh-mobile-console.yml\` 不存在）。已满足 → 「Phase 3 — 已完成，跳过」→ Phase 4。

在面板 **手机要打开的域名** 填入 Phase 0b 收集到的**主机名**（例如 \`dsh-win.example.com\`）并保存；**隧道名** 填该主机名最左边那一段（例如 \`dsh-win\`）。**注意：域名与隧道名这两个输入框、以及下面用到的所有 Cloudflare 按钮，都在「设置 → 手机访问 → 高级：Cloudflare 配置」折叠区里**（默认收起，先展开）。

**路径 A（默认，无需浏览器）**：
1. 面板 → Cloudflare 配置 → 粘贴 API Token。
   用户没有 Token 时给这条固定指引：Cloudflare → My Profile → **API Tokens** → Create Token → **Custom token**，权限四项：
   \`Zone → Zone → Read\`、\`Zone → DNS → Edit\`、\`Account → Cloudflare Tunnel → Edit\`、\`Account → Access: Apps and Policies → Edit\`（第四项仅在要自动建 Access 时需要）→ Continue → Create Token。
2. 点 **保存并验证 Token**。
3. 点 **一键自动配置**（创建/复用远端托管隧道 → ingress 指向 \`http://127.0.0.1:3080\` → 发布代理 CNAME → 保存连接器令牌 → 写入 trustedHosts）。
4. 期望：步骤列表全 ✓，最后一行含 \`trustedHosts now accepts <域名>\`。

**路径 B（浏览器授权，仅在用户拒绝建 Token 或路径 A 失败时使用）**：
1. 点 **开始浏览器登录**。
2. 复制面板显示的 \`https://dash.cloudflare.com/argotunnel?...\` 链接，在浏览器打开并选中该域名所属 zone 授权（cloudflared 也会自动打开浏览器；**无图形界面的 Linux** 就把链接复制到别的设备完成）。
3. 回面板点 **创建隧道并完成配置**。

验证（两条路径一致）：面板「检测环境」显示 cloudflared 已找到、域名已填、连接器令牌已保存。

## Phase 4 — 启动隧道

进入条件：隧道未运行。已满足 → 「Phase 4 — 已完成，跳过」→ Phase 5。

固定动作：面板 → cloudflared 卡片 → **启动**。验证：状态显示运行中。
若提示「没有可启动的隧道」→ **回 Phase 3**（不换方案）。

## Phase 5 — 手机首次配对

进入条件：面板设备表为空。已满足 → 「Phase 5 — 已完成，跳过」→ Phase 6。

固定动作：让用户用手机**扫面板上入口链接的二维码**（或直接打开该链接，链接必须带 \`?token=\`）。这一步把本次进程的启动令牌换成签名 Cookie。
验证：面板设备表出现一行，且 **接入方式 = 隧道**。

## Phase 6 — 可选加固（建议做，用户可跳过）

固定动作：面板 → 填自己的邮箱 → **创建 Access 应用**（自托管应用 + One-time PIN + 1 个月会话）。
用户跳过时，只说明一句风险：知道域名的人都能到达登录页（仍需 token/Cookie 才能进入），不追加其它步骤。

## 会话续期（固定说辞）

- **正常情况**：手机每次打开应用，面板都会访问一个带启动令牌的新地址，平台据此**重新签发一个满 30 天的 Cookie**。只要**每 30 天内至少打开一次**应用，手机就永远不会掉线，也不需要重新扫码——**不要**为此去改 \`cookieMaxAgeDays\`。
- **前提**：续期需要「仍然有效的 Cookie」才能发起。下列情况自动续期帮不上：超过 30 天没打开、按过「撤销全部已配对浏览器会话」、清了浏览器数据、换了手机或浏览器、域名变了（Cookie 绑定 authority）。
- **唯一的补救路径**：在能碰到这台电脑时重启 dsh，然后在面板「入口链接」里重新扫码。
- **因此**：预计超过 30 天不打开应用时，出门前先在手机上打开一次（把 Cookie 续满），或确认自己能远程碰到这台电脑。**不要**建议延长 Cookie 有效期，也不要建议任何额外的口令入口。

## 固定结尾模板## 固定结尾模板

\`\`\`
配置完成
  入口: https://<域名>/        （二维码在面板「手机访问」）
  隧道: <隧道名> 运行中
  认证: 平台 Cookie 30 天 + Access（已启用 / 未启用）
  手机: 已配对 <N> 台（<客户端>）
  维护: Cookie 到期前重开一次入口链接即可续期；撤销用面板「撤销全部已配对浏览器会话」（需重启 dsh）
\`\`\`

## 用户反馈应答表（照表回答，不要即兴发挥）

| 用户说 | 你做什么 |
|---|---|
| NS 已改 | 跑 Phase 1 的 NS 查询确认；未生效则让用户等 30 分钟再跑同一条命令（最多 3 轮） |
| 找不到改 NS 的地方 | 给出 Phase 1 里该注册商的具体菜单路径 |
| 域名不在我手上 / 无法改 NS | 走 Phase 1b（Tailscale 或快速隧道），并停止 Phase 1 |
| cloudflared 装好了 | \`cloudflared --version\` 验证 → Phase 3 |
| 不想建 API Token | 走 Phase 3 路径 B |
| 面板报 \`no active Cloudflare zone\` | 回 Phase 1（NS 未生效），不要重试自动配置 |
| 面板报「未知端点 cf-env」 | 让用户**重启 dsh**，然后从 Phase 0 重跑 |
| 界面能开但 \`/api\` 403 | Phase 3 的信任写入没完成：点面板「把这个域名加入 trustedHosts」 |
| 手机打开空白 / 401 | 用的不是带 \`?token=\` 的入口链接：重新扫面板二维码（同一指令） |
| 隧道启动后手机仍打不开 | 确认 Phase 4 状态为运行中；再确认手机用的是隧道入口而非局域网入口 |
| 上传大文件失败 | 说明 Cloudflare 免费版单次请求上限 **100 MB**（平台自身是 300 MiB），不是故障 |
| 想让隧道开机自启 | 给出该平台的常驻方式（Phase 2 表） |
| 想撤销某台手机 | 平台**不支持按设备撤销**：用 Cloudflare 控制台按身份 Revoke sessions，或面板「撤销全部已配对浏览器会话」（删记录后**需重启 dsh** 才生效） |
| dsh 重启了，手机要重新配对吗 | 不需要：启动令牌只用于首次换 Cookie，Cookie 密钥持久化在 \`$DSH_HOME/.credentials.yaml\`（Windows \`%DSH_HOME%\\.credentials.yaml\`），默认 30 天有效；而且每次打开应用都会自动续期 |
| 手机提示 401 / 打不开，人又不在电脑边 | 明确告知：只能在能碰到这台电脑时重启 dsh 并重新扫码；不要发明别的入口 |
| 用户问要不要延长 Cookie 有效期 | 不要。改为说明自动续期机制（每次打开应用重签 30 天），并提醒每月至少打开一次 |

## 两条硬约束（不要尝试绕过）

- 一个监听只能绑定一个地址，且平台拒绝通配地址——「回环 + 局域网直连 + 隧道」最多同时拿两条；推荐「回环 + 隧道」。不要为了手机去绑定局域网地址：那会顶掉回环监听（实测绑到局域网 IP 后 \`127.0.0.1\` 直接拒绝连接），面板有「恢复回环绑定（127.0.0.1）」。
- 没有自动「是否在同一局域网」切换：手机 DNS 已把域名解析到 Cloudflare，已走隧道的请求无法变直连；服务端重定向只会落到第二个 authority（要重新配对），公开的切换入口等于把启动令牌交给任何能访问它的人。
`;

/**
 * The registration payload for `ctx.skills.register`.
 *
 * Model-invocable and user-invocable: the model reaches for it when the user
 * asks about phone access, and the user can run it by name.
 * @param provider - the plugin's own name, used as the provider id.
 */
export function skillRegistration(provider) {
  return {
    name: SKILL_NAME,
    description: SKILL_DESCRIPTION,
    whenToUse: SKILL_WHEN_TO_USE,
    content: SKILL_CONTENT,
    source: 'runtime',
    provider,
    resourceBase: {
      kind: 'opaque',
      description:
        'the dsh-mobile-console panel at Settings → Mobile Access, plus ~/.cloudflared (Windows: %USERPROFILE%\\.cloudflared) and the platform credential store',
    },
    invocation: { modelInvocable: true, userInvocable: true },
  };
}
