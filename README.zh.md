# dsh-mobile-console

给 [DeepSeek Harness](https://www.npmjs.com/package/@deepseek-ai/dsh) 加上手机访问：用手机打开 Harness 的 Web UI，并在一页设置里管理这套访问。

[English](README.md) | 中文

## 它做什么

Harness 本身已经具备手机所需的一切：浏览器界面、每次启动生成的一次性令牌（换取签名 Cookie）、Host/Origin 信任栅栏，以及"只绑定一个具体网卡地址"的监听能力。它缺的是外面那一圈——该打开哪个网址、隧道域名是否已被信任栅栏接受、`cloudflared` 是否在跑、有哪些设备连过、以及怎么撤销。

本插件就是这一圈，仅此而已：

| 面板区块 | 提供什么 |
|---|---|
| **入口链接** | 隧道与局域网两个入口网址（各自带本次进程的新鲜令牌），附二维码与复制按钮 |
| **信任判定** | 平台 `/api` 栅栏是否接受该隧道域名；一个按钮把它写进平台的 `connection` 行 |
| **局域网入口** | 本机所有非回环地址；一个按钮把监听绑定到其中之一 |
| **cloudflared 子进程** | 检测可执行文件、以受管子进程方式启停命名隧道、显示最近输出 |
| **设备** | 只读列表：最近加载过界面的手机（名称、客户端、首次/最后在线、地址） |
| **配对有效期** | 平台真实的 `cookieMaxAgeDays`，以及"撤销全部已配对浏览器会话"按钮 |
| **手机端布局** | 窄屏微调开关（触控尺寸控件、16px 输入框、安全区留白） |

## 它刻意不做什么

**它不另做一套手机界面。** 手机用的就是现有 Web UI：布局在 1024px 以下会自动把侧栏收成 56px 轨道（`dsh-client-ui-layout` 的 `SIDEBAR_AUTO_COLLAPSE`），因此手机拿到的是可用的单列对话界面，且具备桌面的全部功能——会话、工作区、审批、设置、文件。

这个选择有两个代价，必须说清楚：

- **手机上拿到的是 owner 全权。** 因为就是同一个界面，它能做桌面能做的一切，包括修改权限预设、安装插件。边界来自隧道身份（Cloudflare Access）与平台 Cookie，而不是被削减的功能集。
- **Harness 内部没有"按设备撤销"。** 平台不为浏览器 Cookie 保存设备维度状态，插件也无法给平台的 `/api` 路由加中间件（路由表按"精确 → 最长前缀"匹配，重复注册会抛错）。所以撤销只有两条路：隧道身份侧（撤销该用户的 Cloudflare Access 会话），或用面板上的"撤销全部已配对浏览器会话"一次性清空。

设备列表是**看得见、不是授权依据**：注入的心跳脚本只记录哪台手机加载过页面，那一行无法撤销任何东西。

## 安装

```sh
dsh plugin --profile web add /absolute/path/to/dsh-mobile-console
```

或通过插件管理器安装该工作区目录（`install_bundle`）。然后打开 **设置 → 手机访问**。

## 配置

全部配置都在插件行的 `config` 里，面板会替你写入你自己的 profile patch 层（因此升级不会丢）：

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

| 字段 | 含义 |
|---|---|
| `tunnelHost` | 隧道服务的域名（authority）。只有设置后，入口链接与二维码才会出现。 |
| `publicUrl` | 可选的对外公开根地址（Harness 打印的 URL 与 `DSH_WEB_URL`）。 |
| `lanHost` | 可选的局域网具体地址字面量。通配地址由平台本身拒绝。 |
| `cloudflared` | 可选：作为子进程管理的命令。不填就由你自己跑隧道。 |
| `narrowEnhance` | 是否在 1024px 以下应用手机端布局微调（默认 `true`）。 |
| `deviceRetentionDays` | 超过该天数未再出现的设备记录会被清理（默认 180）。 |

### 面板内的自动配置

*Cloudflare 配置* 卡片会替你把隧道这部分做完。它先**检测环境**——cloudflared 是否安装（及版本）、`cert.pem` 是否存在、是否已保存 API Token 或连接器令牌、是否已配置域名——然后给出适合当前状态的路径：

- **没有 cloudflared？** 卡片显示对应平台的安装命令（`winget install --id Cloudflare.cloudflared`、`brew install cloudflared`，或 releases 页面），装完点"检测环境"重新检测。
- **浏览器授权。** 点"开始浏览器登录"会运行 `cloudflared tunnel login`，把它打印的 `dash.cloudflare.com/argotunnel` 网址抓到面板里显示（cloudflared 自动打开的那个标签同样可用），轮询直到 `cert.pem` 出现；再点"创建隧道并完成配置"，它会执行 `tunnel create`、`tunnel route dns`，写出 `~/.cloudflared/dsh-mobile-console.yml`，并把域名加入平台信任栅栏。
- **API Token。** 粘贴一个具备卡片所列权限的 Token，点"保存并验证"，再点"一键自动配置"：插件创建或复用一条远端托管隧道、把 ingress 指向本机监听、发布代理 CNAME、保存连接器令牌、信任该域名。不需要浏览器，也不需要 `cert.pem`。
- **Access（可选）。** 填一个邮箱，点"创建 Access 应用"，得到一个自托管应用 + 只允许该邮箱的 One-time PIN 策略 + 1 个月会话。卡片同时会报告该 Zero Trust 组织是否配置了任何登录方式。
- **清理。** 一个按钮删除本插件创建的 DNS 记录与隧道，并清除已保存的连接器令牌。

机密保存在 Harness 凭据库（`CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_TUNNEL_TOKEN`），**不进配置、不进任何响应**；其余每个值都写进你自己的 profile patch 层。

唯一 API 做不到的一步是注册商处的 NS 修改——包括腾讯云/DNSPod 注册的域名：先在 Cloudflare 添加域名，再把 DNSPod 的 DNS 服务器换成 Cloudflare 分配的那两个。留在 DNSPod 的记录会随之失效，所以企业邮箱/其它站点要先导入 Cloudflare（添加站点时它提供导入）。等 zone 状态变成 **Active**（几分钟到 24 小时）后，自动配置才能找到它。

### Harness 重启后手机需要重新授权吗？

**不需要。** 启动令牌是每次进程生成的，但它只用于**首次**换取 Cookie：那个 Cookie 用持久化在 `$DSH_HOME/.credentials.yaml` 的密钥签名，所以已配对的手机在重启后依然有效，直到 `cookieMaxAgeDays`（默认 30 天）到期。只有这些情况才需要重新配对：Cookie 到期、你按了"撤销全部已配对浏览器会话"、凭据文件被删除、域名变了（Cookie 绑定 authority），或 Cloudflare Access 会话到期——而最后这一种要的是重新过一次邮箱验证码，不是重新配对。

### Cloudflare 配置步骤

1. **域名。** 在任何注册商注册的域名都可以，只要它的 DNS 由 Cloudflare 托管：在 Cloudflare 控制台把域名添加为 zone，然后到注册商处把 NS 改成 Cloudflare 分配的那两个。Cloudflare 本身不赠送域名，它只是托管你拥有的那个域名的 DNS。
2. **隧道。** `cloudflared tunnel login`、`cloudflared tunnel create dsh-mobile`，再把域名路由过去（`cloudflared tunnel route dns dsh-mobile dsh.example.com`）。把 `tunnel run dsh-mobile` 填进 `config.cloudflared.args`，面板就能替你管理这个进程。
3. **信任该域名。** 打开面板，点"把这个域名加入 trustedHosts"。不做这一步，界面能加载但每次 `/api` 调用都会 403：平台的栅栏只接受回环、监听自身的绑定地址，或已声明的域名。
4. **可选 —— Cloudflare Access。** 在 Zero Trust 里为 `dsh.example.com` 建一个自托管 Access 应用，用 One-time PIN 策略只允许你自己的邮箱，并设置会话时长（默认 24 小时，最长 1 个月）。这样边缘侧会先认证设备，而在那里撤销会话就是你"按身份撤销"的手段。

### 需要公网服务器吗？

不需要。`cloudflared` 从这台机器**向外**连接 Cloudflare 边缘，Cloudflare 再把域名顺着这条连接送回来。没有入站端口、没有公网 IP、不需要 VPS。隧道真正需要的只是一个 **DNS 由 Cloudflare 托管**的域名——所以域名是唯一必须有 的东西。Cloudflare 本身不赠送域名；便宜注册一个就够，第三方免费域名只有在允许你把 NS 委派给 Cloudflare 时才可用。

如果完全没有域名，还剩两条路：

- **快速隧道。** `cloudflared tunnel --url http://127.0.0.1:3080` 会给出一个随机 `*.trycloudflare.com` 地址，不需要账号也不需要域名。平台栅栏会拒绝没人声明过的域名，所以在面板上点"信任这个临时域名"：插件会通过 Config Editor 把该域名写进 `trustedHosts`，并就地重建那一行。域名每次启动都会变，因此手机每次都要重新配对——测试够用，日常很烦。
- **Tailscale。** tailnet 会给机器一个稳定的 `机器名.tailnet-name.ts.net` 域名，自动签发受信任证书，不用买域名。声明一次即可长期有效；手机需要装 Tailscale App。

### 哪几条访问路径能同时存在

平台的监听只绑定**一个**具体地址且拒绝通配地址，所以下面三条路径里你最多同时拿到两条——推荐组合是"回环 + 隧道"：

| 配置 | 桌面走 `127.0.0.1` | 手机走公网 | 手机在同一 Wi-Fi 直连 |
|---|---|---|---|
| `host: 127.0.0.1`，隧道连 `127.0.0.1` | 可以 | 可以（经 Cloudflare） | 只能走隧道 |
| `host: 10.0.161.47`，隧道连 `10.0.161.47` | **不行** | 可以 | 可以直连 |

第一行就是面板上"恢复回环绑定"按钮带你回到的状态，也是唯一能让桌面端继续用默认地址的配置。第二行只有在"局域网直连的速度比回环更重要"时才值得——绑定到某个具体地址的监听不会响应 `127.0.0.1`。

### 为什么不做"是否在家"的自动切换

三条硬约束让它无法诚实地实现：

1. **一个监听只能绑一个地址。** 不存在"同时监听回环和局域网字面量"的配置，插件也无法为平台的 `/api` 路由再加一个监听（路由表拒绝重复前缀）。
2. **DNS 早就答过了。** 手机打开 `https://win.example.com` 时，这个名字已经解析到 Cloudflare 边缘，请求早就出过公网了。服务端重定向最多让**后续**请求走直连，而且会落到第二个 authority（`http://10.0.161.47:3080`）——等于第二份 Cookie、第二次配对。
3. **公开的切换入口等于泄权。** 一条"把带令牌的局域网地址交给手机"的插件路由，会把令牌交给任何能访问该路由的人。要堵住它就得引入配对码，而那正是本插件刻意不做的第二条鉴权路径。

面板改为如实报告：**本面板当前的访问方式**（你眼前这个浏览器），以及每台设备的**接入方式**列（`隧道` / `局域网` / `本机`），并在手机地址与本机某个地址同 /24 时打上"同网段"标记。

### 局域网入口，以及它的代价

平台的监听只绑定**一个具体地址**，且拒绝通配地址，所以**绑定局域网地址会顶掉回环监听**：重启后 `http://127.0.0.1:3080` 不再响应，桌面端也必须改用那个地址。这是实测结论而非推测——绑在 `10.0.161.47` 上的监听会拒绝 `127.0.0.1`。

用隧道时**根本不需要**绑定局域网地址，因为 `cloudflared` 就跑在这台机器上、直接连 `127.0.0.1`。因此"保持默认回环"正是同时拿到本地与远程访问的做法。只有当你还想让同一 Wi-Fi 下的手机直连时，才需要绑定局域网地址；面板上有"恢复回环绑定"按钮，改主意了随时可以退回来。

### 两台电脑（比如 Windows 台式机 + Mac）

给每台机器**各自的域名**和**各自的隧道**：

| 机器 | 隧道 | DNS 路由 | Access 应用 | `tunnelHost` |
|---|---|---|---|---|
| Windows | `dsh-win` | `win.example.com` | `win.example.com`（或一个通配 `*.example.com`） | `win.example.com` |
| Mac | `dsh-mac` | `mac.example.com` | `mac.example.com` | `mac.example.com` |

每台机器各跑自己的 Harness 与自己的 `cloudflared`，所以每台的面板只把**自己**的域名写进**自己**的 `trustedHosts`。不要把两个域名指向同一条隧道：Harness 是有状态的，请求落到错误的机器上就会看到错误的会话。Cookie 绑定 authority，因此两台机器各自独立配对——这正是你想要的，因为两台 Harness 的会话本来就不同。

## 安全模型

- **鉴权由平台完成，不是本插件。** 面板的每个请求都先调用 `ctx.connection.requestRejection(req)`——平台的 Host/Origin 栅栏加登录令牌/Cookie 校验——并在读取任何请求体之前返回它的状态。这与平台自带的 open-in-app 插件遵循同一约定，没有手搓鉴权。
- **令牌是每次进程生成的。** `dsh web` 启动时会打印带令牌的 URL，本插件通过 `ctx.connection.authenticatedUrl()` 生成同样的 URL。重新打开一次新的入口链接即重新配对，也是手机续期过期 Cookie 的方式。
- **Cookie 绑定 authority。** 同一台手机经隧道配对与经局域网配对持有不同的 Cookie；隧道域名一改，旧 Cookie 立即失效。
- **Harness 内部的撤销是全有或全无。** "撤销全部已配对浏览器会话"删除 `client-connection/browser-session` 凭据记录；运行中的进程仍持有内存里的签名密钥，所以效果在下次启动时落地——面板会明确这么写。要按身份撤销，请撤销 Cloudflare Access 会话。
- **心跳脚本是公开静态资源。** `/mobile-console/heartbeat.js` 与其它静态资源一样公开：它不含任何机密，且只在页面本身已通过鉴权时才会打点；它背后的心跳接口是受栅栏保护的。
- **配置写入是显式的。** 所有写入都经 `ctx.configEditor`，落进你自己的 profile patch 层，并通过正常 Loader 路径就地重建。会"固化"继承值的写入（`webserver` 行的 `host`）会一并复述当前生效值，面板也标注了需要重启。

## 测试

```sh
npm run check
```

- `test/qr.test.mjs` —— 手写的 QR 编码器。它的黄金矩阵由参考实现 `qrcode` npm 包生成（byte 模式、固定 mask），并与本编码器在**全部纠错等级、版本 1–10、全部 8 个 mask** 下逐格一致（152 个矩阵）。该套件还校验功能图形、恒定暗模块、剩余位，以及 Reed–Solomon 的根性质。
- `test/trusted-hosts.test.mjs` —— 配置归一化、绑定地址准入（拒绝通配）、信任探测的 403/401/抛异常三种情形、设备标签，以及设备视图的 upsert/prune/上限规则。
- `test/client-load.test.mjs` —— 在最小 module-loader 与 React stub 中运行 `lib/client.js`，断言模块 id、inject 列表、唯一一处 `settings.section` 注册、两张样式表与本地化词典。

本插件**没有运行时依赖**：不 import 任何 `@deepseek-ai/*`、不用 zod、不用打包器。QR 编码器之所以手写，是因为整个 Harness 安装里没有任何 QR 库，而携带启动令牌的配对 URL 绝不能交给在线二维码服务。

## 已知限制

- 窄屏微调是纯 CSS，且在页面加载时决定，所以桌面窗口在加载后再缩小到手机宽度，会保留桌面尺寸直到刷新。
- 设备列表只知道"在插件已安装且心跳可达主机"期间加载过界面的手机。
- cloudflared 子进程只在本 Harness 进程运行期间被管理；在面板外启动的隧道会被显示为"未配置"，而不会被接管。
- 审批卡片等交互都是平台自带界面，本插件不添加手机专属交互。

## 许可证

MIT。
