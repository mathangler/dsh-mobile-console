/**
 * dsh-remote-access — the setup skill that ships with the plugin.
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
 * It documents the current shape of the plugin: one top-level mode switch
 * (local network versus public), four credential sources (entry link, one-time
 * pairing code, access key, password), the authorized-device list that revokes
 * them one by one, the Cloudflare tunnel with optional Access, and the honest
 * limits of each.
 *
 * @module dsh-remote-access/skill
 */

/** Skill name; the user invokes it by this name. */
export const SKILL_NAME = 'dsh-remote-access';

/** One-line catalog description. */
export const SKILL_DESCRIPTION =
  '按固定流程配置 dsh 远程访问（局域网/公网模式切换 + Cloudflare 隧道 + 入口链接/一次性配对码/访问密钥/密码四种凭据），Windows / macOS / Linux 通用 / Run the fixed pipeline that publishes this Harness to a remote device through a Cloudflare tunnel.';

/** When the model should reach for it. */
export const SKILL_WHEN_TO_USE =
  '用户想用手机或其它远程设备访问这台 dsh、要配置或排查 Cloudflare 隧道、要切换局域网/公网模式、要拿入口链接或一次性配对码、要发访问密钥或设置恢复密码，或问到 dsh-remote-access 插件设置时。';

/** The full skill body. */
export const SKILL_CONTENT = `# 远程访问配置（dsh-remote-access）— 固定流程

这是一条**固定流水线**。严格按 Phase 0 → 7 顺序执行。

## 执行契约（不可协商）

1. **固定顺序**：不跳步、不重排、不合并、不自行发明步骤。需要替代方案时，只能用本文件写明的 Phase 1b、Phase 3 路径 A / 路径 B。
2. **幂等**：每个 Phase 开头先做它自己的检查。已满足 → 只输出一行「Phase N — 已完成，跳过」然后进入下一个 Phase；**不要重做、不要重复询问、不要重新创建已有资源**。
3. **固定汇报**：每个 Phase 用同一格式输出两行——\`Phase N — <结论>\` 与 \`  证据: <命令或面板字段>\`。全文结尾用固定的「配置完成」模板。
4. **需要用户动手时**，给**编号、可照做**的指令，并明确「完成后回复：<一句话>」。用户回复后按末尾的**应答表**处理，不要即兴发挥。
5. **密钥纪律**：API Token、访问密钥、恢复密码只粘贴或生成在面板里（进入平台凭据库）。**不要打印、不要写入文件、不要出现在聊天里**；访问密钥只在创建那一次显示。
6. **DNS 纪律**：只允许新增/修改本插件需要的那条主机名记录。**不要删除、不要改动用户已有的其它记录**。
7. 面板路径统一是 **设置 → 远程访问**（Settings → Remote Access）；需要 Cloudflare、访问密钥、恢复密码这些控件时，先说「**高级 → Cloudflare 配置 / 访问密钥 / 恢复访问**」这个折叠区（默认收起，要先展开）。
8. **行 id 是 \`remote-access-panel\`，不是 \`remote-access\`**：平台自带的 \`remote-access\` 行属于 shipped 插件，Loader 按 id 去重且**不报错**——占用它会静默顶掉那一行、让界面上的 RPC 失效。写 profile patch、核对配置、回答「配置写在哪」时都用 \`remote-access-panel\`。

## Phase 0 — 状态检测（永远第一步，永不跳过）

依次取这七项，缺工具就用面板替代：

| 检查 | 怎么取 | 期望 |
|---|---|---|
| 当前模式 | 面板「访问模式」段：**局域网** 或 **公网**（开关只是预览，「启用此模式」才真正应用） | 与用户要用的模式一致 |
| 监听地址 | 面板状态里的 host | 一个具体字面量（\`127.0.0.1\` ＝ 公网模式），**不是**通配地址 |
| cloudflared 是否可用 | \`cloudflared --version\` | 打印版本号 |
| 隧道是否已配置 | 面板「检测环境」→ 连接器令牌/配置文件；或列 \`%USERPROFILE%\\.cloudflared\\\` | 连接器令牌已保存 |
| 域名 NS 指向 | \`Resolve-DnsName <域名> -Type NS\`（**不要**加 \`-Server\`） | 结果含 \`ns.cloudflare.com\`，或控制台 Active |
| 隧道是否在跑 | 面板 Cloudflare 隧道卡片状态 | 运行中（pid） |
| 平台环境变量 | \`$env:DSH_HOME\` | 非空；\`DSH_*\` 必须在启动器环境里 export |

macOS / Linux 的替代命令：NS 用 \`dig +short NS <域名>\`（**不要**加 \`@8.8.8.8\`），环境变量用 \`echo $DSH_HOME\`，目录是 \`~/.cloudflared/\`。

固定输出：

\`\`\`
Phase 0 — 环境
  模式: <局域网 | 公网>（本机自动判定：<...>，可覆盖）
  监听: <host:port>
  cloudflared: <版本 | 未安装>
  隧道: <未创建 | 名称/ID，运行中/已停止>
  域名 NS: <仍在原注册商 | 已指向 Cloudflare | 未检测>
  下一步: Phase <N>
\`\`\`

判定：cloudflared 缺失 → Phase 2；NS 未指向 Cloudflare（且用户要公网）→ Phase 1；隧道未创建 → Phase 3；隧道未运行 → Phase 4；**授权设备**列表为空 → Phase 5；否则 Phase 6，最后 Phase 7。
（Phase 2 与 Phase 1 互不依赖，但**顺序固定**：先域名后安装。用户只要局域网时，Phase 1 ~ 4 全部跳过，直接 Phase 5。）

## Phase 0b — 收集输入（**必须询问用户，禁止自行假设**）

进入 Phase 1/3 之前，必须问清这四项，并把答案原样用于后续所有命令、面板字段与 DNS 记录。**任何一项都不要替用户挑一个默认值或「建议一个」**：

1. **用哪个域名（zone）？** 例如 \`example.com\`——用户可能持有多个域名，必须问。（只走局域网时不需要域名，跳过本项。）
2. **这台机器对外用哪个主机名？** 惯用写法是 \`<隧道名>.<域名>\`，而**隧道名由本机系统决定**：macOS → \`dsh-mac\`、Windows → \`dsh-win\`、Linux → \`dsh-lin\`（面板里的占位符与示例也跟随本机系统）。**先问用户要哪个主机名**，再由它推导隧道名＝主机名最左边那一段。**绝不要自己发明主机名**：写错域名会导致设备打不开并需要重配。
3. **走局域网还是公网？** 局域网＝把监听绑到本机一个非回环地址，同一 Wi-Fi 的设备直接打开（不需要域名、不需要隧道）；公网＝监听留在 \`127.0.0.1\`，用 Cloudflare 隧道发布（需要域名）。面板按当前绑定自动判定，用户可以覆盖。
4. **配置方式选 A 还是 B？** A＝建 API Token（全自动），B＝浏览器授权。

固定问法（一次问完，不要挤牙膏）：

> 开始前需要你确认几件事：
> 1）用哪个域名？（例如 \`example.com\`；只走局域网可以说不填）
> 2）这台机器对外用哪个主机名？（惯用 \`<隧道名>.<域名>\`，例如 \`dsh-win.example.com\`）
> 3）走局域网，还是公网？
> 4）公网配置方式选 A（建 API Token，全自动）还是 B（浏览器授权）？

得到答复后，先输出这一行固定记录，再继续：

\`\`\`
输入: 域名=<域名>  主机名=<主机名>  隧道名=<主机名最左段>  模式=<局域网|公网>  路径=<A|B>
\`\`\`

**每台机器都要重新问一遍**：同一套域名下，各机器的主机名与隧道名必须不同（\`dsh-win\` / \`dsh-mac\` / \`dsh-lin\`）；换机器执行本 skill 时**不要沿用上一台的主机名**，也不要指望沿用上一台的 \`~/.cloudflared\` 证书——证书属于本机，每台机器各自授权或各自用 Token。

模式开关只是**预览**：点「局域网」或「公网」只决定面板显示哪一套配置，在你点 **启用此模式** 之前什么都不会写入（已应用时面板显示「当前已启用」）。点下 **启用此模式** 后**立即生效**：监听会重新绑定，面板页面可能变空白或失联，到新地址重新打开面板即可，**重启 dsh 仍然建议做**；之后桌面端也要改用新地址。这句话必须原样转达。

## Phase 1 — 域名交给 Cloudflare（唯一必须人工的步骤）

进入条件：NS 未指向 Cloudflare 且用户要公网。已满足 → 「Phase 1 — 已完成，跳过」→ Phase 2。

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
- 快速隧道（临时，每次启动换域名）：面板「高级 → Cloudflare 配置」里填入 \`--url http://127.0.0.1:3080\` 的等价配置，启动后用「信任这个临时域名」。

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

常驻方式（仅在用户问「怎么让它一直跑」时回答，不要主动改）：面板的「启动隧道」随 dsh 进程存活；要独立常驻，Windows 用任务计划程序或 \`nssm\`，macOS 用 \`launchd\`/\`brew services\`，Linux 用 \`systemd\`。

验证：\`cloudflared --version\` 打印版本号。回复：**「装好了」**。

## Phase 3 — 建立隧道（二选一，默认 A）

进入条件：面板显示隧道未配置（\`%USERPROFILE%\\.cloudflared\\dsh-remote-access.yml\` 或 \`~/.cloudflared/dsh-remote-access.yml\` 不存在）。已满足 → 「Phase 3 — 已完成，跳过」→ Phase 4。

在面板 **设置 → 远程访问 → 高级 → Cloudflare 配置** 里，**手机要打开的域名** 填 Phase 0b 收集到的**主机名**（例如 \`dsh-win.example.com\`）并保存；**隧道名** 填该主机名最左边那一段（例如 \`dsh-win\`）。

**路径 A（默认，无需浏览器）**：
1. 面板 → Cloudflare 配置 → 粘贴 API Token。
   用户没有 Token 时给这条固定指引：Cloudflare → My Profile → **API Tokens** → Create Token → **Custom token**，权限四项：
   \`Zone → Zone → Read\`、\`Zone → DNS → Edit\`、\`Account → Cloudflare Tunnel → Edit\`、\`Account → Access: Apps and Policies → Edit\`（第四项仅在要自动建 Access 时需要）→ Continue → Create Token。
2. 点 **保存并验证 Token**。
3. 点 **一键自动配置**（创建/复用远端托管隧道 → ingress 指向 \`http://127.0.0.1:3080\` → 发布代理 CNAME → 保存连接器令牌 → 写入 trustedHosts）。
4. 期望：步骤列表全 ✓，最后一行含 \`trustedHosts now accepts <域名>\`。

**路径 B（浏览器授权，仅在用户拒绝建 Token 或路径 A 失败时使用）**：

> **绝对不要自己运行 \`cloudflared tunnel login\`。** 你在工具里起的进程会随工具调用结束而被终止：用户即使完成了授权，也不会写出 \`cert.pem\`，现象就是"你给的授权链接没用，必须去面板里再授权一次"。这个子进程必须由 dsh 进程托管——**让用户点面板的「开始浏览器登录」**，你只负责把面板显示的授权链接转述给他，等他授权完成后点「创建隧道并完成配置」。

1. 让用户点 **开始浏览器登录**（不要代跑）。
2. 把面板显示的 \`https://dash.cloudflare.com/argotunnel?...\` 链接转述给用户，在浏览器打开并选中该域名所属 zone 授权（cloudflared 也会自动打开浏览器；**无图形界面的 Linux** 就把链接复制到别的设备完成）。
3. 等用户回来后点 **创建隧道并完成配置**。

验证（两条路径一致）：面板「检测环境」显示 cloudflared 已找到、域名已填、连接器令牌已保存。

## Phase 4 — 启动隧道

进入条件：隧道未运行。已满足 → 「Phase 4 — 已完成，跳过」→ Phase 5。

固定动作：面板 → Cloudflare 隧道卡片 → 点 **启动隧道** 那颗主按钮（卡片里唯一一颗填充色大按钮）。验证：状态显示运行中（pid）。
要停就点同一张卡片的 **停止**。
若提示「没有可启动的隧道」→ **回 Phase 3**（不换方案）。

## Phase 5 — 添加第一台设备

进入条件：**授权设备**列表为空（LAN 模式没有设备管理，见 Phase 6）。已满足 → 「Phase 5 — 已完成，跳过」→ Phase 6。

两条固定路径，任选一条，不要发明第三条：

1. **入口链接**（默认）：二维码默认收起，让用户先点 **显示二维码**（Show QR）再扫，或直接打开该链接（链接必须带 \`?token=\`）。链接旁的标记是 **临时：随进程失效**——这条链接只用于首次配对；\`?token=\` 是 harness 自己打印的那枚每次进程令牌，**插件从不发放启动令牌**，而且**只有平台接受了出示的令牌，插件才会给这台设备签一条记录**（**30 天**，与平台 Cookie 同寿命；入口链接的记录放在只有 3 个位置的小桶里，匿名访问洪水挤不掉真正授权过的设备）。若面板对这条链接显示 **loopback-only** 警示（「此链接只在本机有效」），说明它出不了这台机器：要么在「高级 → Cloudflare 配置」里配好域名（公网模式），要么切到局域网模式。从二维码或别的 App 点开时，第一次落地通常要刷新一次（平台的会话 Cookie 是 \`SameSite=Strict\`）。
2. **一次性配对码**：面板「用配对码添加设备」卡片 → 先选**有效期**（永不过期 / 30 天 / 90 天 / 1 年 / 自定义日期；不指定时主机默认 1 年）→ 点 **生成配对码**。让新设备**扫这个码的二维码**或**手输这 8 位字符**：字母表不含 \`0 O 1 I L\`。码 **10 分钟内有效、只能用一次**、有速率限制，且**只能从已授权会话生成**；二维码里编码的就是带上该码的网址。

验证：面板 **授权设备** 列表出现一行，**来源** = 入口链接 或 设备验证码，临时/长期标记与所选有效期一致。

## Phase 6 — 授权设备（看得见，且能逐条撤销）

进入条件：Phase 5 已完成。这里固定要交代这四件事，一句不要多：

- **授权设备**列表是**授权依据**（不同于只读的活动记录）。每一行都是本机签发出去的凭据，字段是：名称、来源、临时/长期、创建时间、最近使用 + 客户端 IP、明确的到期时间、状态（有效 / 已过期 / 永不过期）。
- **四种来源**（面板「来源」列）：**入口链接**、**设备验证码**、**访问密钥**、**密码**。
- 每行都可以**改名、改有效期、逐条撤销**；撤销立即生效，那台设备必须重新配对。每台**有效**设备还有一颗 **获取链接**（Get link）：它现场签发一条**新的 15 分钟、一次性**链接（同样可以点 **显示二维码** 展开二维码），手机浏览器留不住长期 Cookie 时就用它重新进来。
- **撤销的确切边界（实测）**：撤销一台设备，杀掉的是**本插件签发的凭据**——那台设备的设备凭据、它还没用的一次性链接（以及由它派生、随它一起撤销的链接行），以及短命的解锁票据；它**不会**结束浏览器已经持有的会话。平台自己的 Cookie（\`dsh-auth-*\`）插件撤不掉：按设备不行，**撤销全部已配对浏览器会话** 不行，**重启 dsh** 也不行（签名密钥持久化在主目录），它只在 30 天到期时结束。这条边界照实说，不要美化。

**LAN 模式例外**：局域网模式下**没有设备管理**——平台的启动令牌随进程失效，插件不会为它留长期记录；那里只有入口链接与二维码，以及 **恢复回环绑定（127.0.0.1）** 那颗退回按钮。

## Phase 7 — 可选加固（建议做，用户可跳过）

固定动作，三项各自独立：

1. **边缘认证**：面板 **边缘认证** 状态行会显示 Cloudflare Access 是否启用（未启用时是警示色）。要加就在「高级 → Cloudflare 配置」里填自己的邮箱 → **创建 Access 应用**（自托管应用 + One-time PIN + 1 个月会话）。Access 是**可选、且不强制**的，但它排在该域名上的一切之前——**包括配对码页面与密码页面**。
2. **访问密钥**（「高级 → 访问密钥」）：给扫不了二维码、也不方便输配对码的设备。点 **创建访问密钥** 并命名，密钥形如 \`dra_…\`，**只显示一次**，本机只保存它的 sha256 指纹；可重置、可逐条撤销。设备拿它在 \`POST /remote-access/token\` 换一条 **15 分钟、一次性**的入口链接。
3. **恢复密码**（「高级 → 恢复访问」）：设一个至少 12 字符的密码。校验走挑战-应答（PBKDF2-SHA256 600k + 对解码后的挑战 nonce 做 HMAC），**密码不过网**；成功后给一条**最多 15 分钟的一次性链接**；页面关闭时会尽力提前作废它，但要知道代价——把标签页切到后台也算"关闭"，链接可能被提前烧掉，**真正的控制是那 15 分钟到期**。

用户跳过时，只说明一句风险：知道域名的人都能到达登录页（仍需凭据才能进入），而且没有恢复密码时，换设备或清了浏览器数据就只能回到电脑前处理。

## 会话、有效期与恢复顺序（固定说辞）

- **入口链接是 harness 自己的引导链接**：\`?token=\` 是 harness 自己打印的每次进程令牌，插件只是显示同一个网址。**插件从不发放启动令牌**——它生成的每次跳转都是裸 \`/\`，会话靠服务端交换后的 Cookie 到达，插件自己签发的一次性链接里从不包含启动令牌。这条链接只用于**首次配对**，重启 dsh 后要重新取；只有平台接受了出示的令牌，插件才会给设备签记录，而且入口链接的记录单独放在只有 3 个位置的小桶里，匿名访问洪水挤不掉真正授权过的设备。
- **记录不滑动**：面板显示什么就什么时候到期——插件**不做**任何隐藏续期，也不延长任何凭据；凭据被使用时只刷新「最近使用 + 客户端 IP」。
- **恢复顺序（严格按此顺序，不要发明别的）**：
  1. **设备记录**：只要这台设备当初配对过，它的浏览器里就有一枚设备凭据。平台 Cookie 失效时访问域名会**自动带着它跳回应用**，用户什么都不用做——"配对过一次"本身就有冗余。要手动重来，就在 **授权设备** 里对那一行点 **获取链接**，拿一条新的 15 分钟一次性链接。
  2. **访问密钥**：设备上界面打不开时，用访问密钥换一条 15 分钟的一次性链接（\`POST /remote-access/token\`）。
  3. **恢复密码**：未认证访问域名会自动显示恢复页；也可以直接打开 \`https://<主机名>/remote-access/unlock\` → 输入密码 → 取回带新令牌的一次性链接。
  4. 三者都不可用：只能在能碰到电脑时重启 dsh 并重新配对。
- **fail-closed 且保持沉默**：**没有设置密码时，恢复页什么都不渲染**——未认证访问域名只会看到平台原本那句 401，\`/remote-access/unlock\` 直接返回 404（不暴露插件与配置状态）。
- **撤销的边界（实测）**：逐条撤销只杀**本插件签发的凭据**（设备凭据、它未用的一次性链接与派生链接行、解锁票据），**不结束浏览器已经持有的会话**。平台自己的 Cookie（\`dsh-auth-*\`）插件撤不掉：按设备撤销、**撤销全部已配对浏览器会话**、**重启 dsh** 都不行（签名密钥持久化在主目录），它只在 30 天到期时结束。不要说成"重启就掉线"。
- **对外的门（实测）**：\`/remote-access/unlock\`、\`/unlock/*\`、\`/remote-access/token\`、\`/remote-access/page-close\` 都要求 \`content-type: application/json\`，并拒绝跨站请求（外部 \`Origin\` 或 \`Sec-Fetch-Site: cross-site\`）。限流按客户端：每 15 分钟 5 次，键取 socket 地址，除非对端是回环代理（cloudflared 与桌面壳就是）；全局预算是兜底，不是一刀切封禁。配对码的兑换是 compare-and-swap，并发兑换只有一个赢家。Cloudflare Access 可选、不强制，但开启后它排在整个域名之前，**包括配对码页面与密码页面**。

## 固定结尾模板

\`\`\`
配置完成
  模式: <局域网 | 公网>
  入口: <https://<主机名>/ | http://<局域网地址>:3080/>   （二维码在面板「远程访问」）
  隧道: <隧道名 运行中 | 未使用>
  认证: 平台 Cookie 30 天 + 四种凭据（入口链接 30 天记录 / 配对码 10 分钟一次性 / 访问密钥 / 恢复密码 <已设置|未设置>）
  边缘认证: <已启用 | 未启用>
  设备: 授权 <N> 条（入口链接 <a> · 配对码 <b> · 访问密钥 <c> · 密码 <d>）
  维护: 撤销在「授权设备」，只杀插件签发的凭据；平台 Cookie（dsh-auth-*）不可撤，重启也不行，只在 30 天到期时结束；恢复顺序 设备记录 → 访问密钥 → 密码 → 回到电脑前
\`\`\`

## 用户反馈应答表（照表回答，不要即兴发挥）

| 用户说 | 你做什么 |
|---|---|
| NS 已改 | 跑 Phase 1 的 NS 查询确认；未生效则让用户等 30 分钟再跑同一条命令（最多 3 轮） |
| 找不到改 NS 的地方 | 给出 Phase 1 里该注册商的具体菜单路径 |
| 域名不在我手上 / 无法改 NS | 走 Phase 1b（Tailscale 或快速隧道），并停止 Phase 1 |
| cloudflared 装好了 | \`cloudflared --version\` 验证 → Phase 3 |
| 不想建 API Token | 走 Phase 3 路径 B |
| 只想同一 Wi-Fi 下直连 | 选「局域网」→ 选一个本机地址 → 点 **启用此模式**（立即生效，页面可能变空白，到新地址重新打开面板；重启 dsh 仍建议做）→ 桌面端也要改用该地址；改主意就点「恢复回环绑定（127.0.0.1）」 |
| 切了模式还是打不开 / 还是旧地址 | 开关只是预览：必须点 **启用此模式** 才会应用。应用**立即生效**，页面可能变空白或失联——到新地址重新打开面板；重启 dsh 仍然建议做（面板会提示 restartPending） |
| 面板提示链接只在本机有效（loopback-only） | 说明这条链接出不了这台机器：要么在「高级 → Cloudflare 配置」里配好域名（公网模式），要么切到局域网模式 |
| 面板报 \`no active Cloudflare zone\` | 回 Phase 1（NS 未生效），不要重试自动配置 |
| 面板报「未知端点 cf-env」 | 让用户**重启 dsh**，然后从 Phase 0 重跑 |
| 界面能开但 \`/api\` 403 | Phase 3 的信任写入没完成：点面板「把这个域名加入 trustedHosts」 |
| 手机打开空白 / 401 | 用的不是带 \`?token=\` 的入口链接，或这条链接已随进程失效：回面板重新取一条（同一指令） |
| 手机第一次打开显示「未认证」，刷新一次才正常 | **预期行为，不是故障**：平台的会话 Cookie 是 \`SameSite=Strict\`，从二维码或别的 App 点开属于跨站导航，刚签发的 Cookie 不会随同一次跳转带上；手动刷新（或在地址栏粘贴链接）即正常。开了 Cloudflare Access 之后，经 Access 跳转的第一次落地同样可能需要刷新一次 |
| 隧道启动后手机仍打不开 | 确认 Phase 4 状态为运行中；再确认设备用的是隧道入口而非局域网入口 |
| 上传大文件失败 | 说明 Cloudflare 免费版单次请求上限 **100 MB**（平台自身是 300 MiB），不是故障 |
| 想让隧道开机自启 | 给出该平台的常驻方式（Phase 2 表） |
| 想撤销某台手机 | 在 **授权设备** 里逐条撤销：杀掉的是插件签发的凭据（设备凭据、它未用的一次性链接与派生链接行、解锁票据），**不会**结束那个浏览器已经持有的会话 |
| 撤销了 / 重启了，手机怎么还进得来 | **预期行为**：平台 Cookie（\`dsh-auth-*\`）由 harness 签名、绑定 authority，签名密钥持久化在主目录——按设备撤销、**撤销全部已配对浏览器会话**、重启都不会让它失效，它只在 30 天到期时结束。要立刻挡住某台设备，只能用 Cloudflare Access 按身份撤销 |
| 设备扫不了二维码 / 输不了链接 | 走 Phase 5 路径 2：面板「生成配对码」（8 位、10 分钟、只能用一次），或「高级 → 访问密钥」（\`dra_…\`，15 分钟一次性链接），或在 **授权设备** 里对那一行点 **获取链接** |
| 配对码输了没反应 | 码已过期（10 分钟）或已经用过：回面板重新生成一个 |
| 密码忘了 / 恢复页空白 | 恢复页在没设密码时**故意什么都不渲染**（\`/remote-access/unlock\` 返回 404）。只能在能碰到电脑时重启 dsh 并重新配对或重设密码 |
| dsh 重启了，手机会掉线吗 | 不会：**重启不结束已配对的会话**——平台 Cookie（\`dsh-auth-*\`）的签名密钥持久化在 \`$DSH_HOME/.credentials.yaml\`（Windows \`%DSH_HOME%\\.credentials.yaml\`），默认 30 天，只在到期时结束；但入口链接本身随进程失效，要新链接就重新取一条 |
| 手机提示 401 / 打不开，人又不在电脑边 | 按恢复顺序答：设备记录 → 访问密钥 → 密码；三者都没有就只能回到电脑前 |
| 用户问要不要延长 Cookie 有效期 | 不要。说明：记录不滑动，面板显示什么就什么时候到期，插件不做隐藏续期 |
| 用户说「你给的授权链接没用」/「授权后还是要再登录一次」 | 你违规自己跑了 \`cloudflared tunnel login\`，那个进程已被工具结束掉，所以 \`cert.pem\` 从未写出。让用户改点面板的「开始浏览器登录」（由 dsh 托管该子进程），然后重走 Phase 3 路径 B |
| 启动时报 \`DSH_*\` 相关错误 | \`DSH_*\` 必须在**启动器环境**里 export；**不要**写进 \`.env\`——任何 \`DSH_*\` 出现在 \`.env\` 里都会让启动直接抛错 |

## 两条硬约束（不要尝试绕过）

- 一个监听只能绑定一个地址，且平台拒绝通配地址——「回环 + 局域网直连 + 隧道」最多同时拿两条；公网模式的推荐形态就是「回环 + 隧道」。不要为了手机去绑定局域网地址：那会顶掉回环监听（实测绑到局域网 IP 后 \`127.0.0.1\` 直接拒绝连接），面板有「恢复回环绑定（127.0.0.1）」。
- 没有自动「是否在同一局域网」切换：手机 DNS 已把域名解析到 Cloudflare，已走隧道的请求无法变直连；服务端重定向只会落到第二个 authority（要重新配对），公开的切换入口等于把启动令牌交给任何能访问它的人。面板改为如实显示实际走了哪条路。
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
        'the dsh-remote-access panel at Settings → Remote Access, plus ~/.cloudflared (Windows: %USERPROFILE%\\.cloudflared) and the platform credential store',
    },
    invocation: { modelInvocable: true, userInvocable: true },
  };
}
