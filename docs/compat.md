# 与原始 subconverter 的差异

本仓库用 Go 重写了 [tindy2013/subconverter](https://github.com/tindy2013/subconverter)，保留 `/sub` 的查询参数形状，让老链接可以直接替换。这一页只列**行为上会让人踩坑**的差异。以本仓库代码为准；上游能力请对照上游文档。

## 直接可用

- `target` 名称与常见别名（`clash.meta`、`clashr`、`mihomo`、`sing-box`、`quantumultx`、`surfboard`、`mixed` 等）
- 常用参数：`url`、`config`、`include`/`exclude`、`emoji`、`add_emoji`、`remove_emoji`、`append_type`、`sort`、`dedup`、`udp`、`tfo`、`scv`、`fdn`、`list`、`expand`、`insert`、`interval`、`filename`、`template`、`flushcache`
- 外部 INI 配置的 `[custom]` 段：`enable_rule_generator`、`rename`、`custom_proxy_group`、`ruleset`

## 本仓库新增

| 参数 / 能力 | 用途 |
|---|---|
| `&check=true` | 不返回配置，返回本次转换的 JSON 诊断（空分组、丢弃的规则、未解析行数） |
| `&provider=true` `&provider_interval=` | Clash proxy-provider 模式：只输出骨架，节点由 mihomo 自己拉 |
| `&ua=` `&proxy=` | 按请求覆盖抓取 UA 与上游代理 |
| `&nocache=1` | 绕过共享缓存重抓 |
| `&tailscale` | 前置 Tailscale 直连规则 |
| `target=ssd` | 输出 SSD 订阅 |
| `target=singbox/1.13` | 按目标内核版本门控协议与 schema |

## 协议与 target 支持

本表列出新增协议与传输在各 target 的支持情况。转换器丢弃 target 不支持的节点，并记入日志。

| 协议 / 特性 | clash（mihomo） | sing-box | Surge | Shadowrocket | Loon | v2ray 链接 |
|---|---|---|---|---|---|---|
| Snell | 输出 | 仅 v4/v6，最低 1.14 | 输出 | 输出 | — | 输出 |
| ShadowTLS | 输出（原生） | ss + shadowtls 链 | ss/snell 参数 | — | — | ss 插件 |
| SSH | 输出 | 输出，最低 1.5 | 输出 | — | — | 输出 |
| naive | 跳过（mihomo 不支持 naive） | 输出，最低 1.13 | — | — | — | 输出 |
| Mieru | 输出 | 跳过 | — | — | — | — |
| MASQUE | 输出 | 跳过（sing-box 不把它当作节点） | 输出 | — | — | — |
| TrustTunnel | 输出 | 跳过 | 输出 | — | — | — |
| XHTTP | 输出 | 跳过节点 | 仅 VLESS | — | — | VLESS/VMess |
| HTTPUpgrade | 输出 | 输出 | VLESS/VMess/Trojan | — | — | VLESS/VMess |
| AmneziaWG | 输出 | 跳过节点 | 跳过节点 | 跳过节点 | 跳过节点 | 输出参数 |
| TUIC v4 | 跳过（仅 v5） | 跳过（仅 v5） | 输出 tuic + token | — | — | 输出 v4 链接 |
| AnyTLS 分享链接 | 输出 | 输出 | 输出 | — | — | 输出 |

图例：「输出」表示该 target 生成此协议。「跳过」表示转换器丢弃该节点并记入日志。「—」表示该 target 不提供此协议。

- Juicity 不受支持。没有 target 客户端加载它。
- Mieru 只在 mihomo 中可用。MASQUE 与 TrustTunnel 只在 mihomo 与 Surge 中可用。
- 在 target 配置中，只有 sing-box 加载 naive。clash target 跳过 naive 节点。
- 在 target 配置中，只有 Surge 加载 TUIC v4，使用 token 握手。mihomo 与 sing-box 只支持 TUIC v5。
- 在 target 配置中，只有 mihomo 加载 AmneziaWG。
- sing-box 跳过 XHTTP 节点。
- Surge 只为 VLESS 使用 XHTTP。
- sing-box 列中的版本号是该协议要求的最低 sing-box 版本。

## 不支持

| 上游能力 | 说明 |
|---|---|
| `GET /getruleset` | 规则集代理端点 |
| `GET /render` | 模板渲染端点 |
| `GET /refreshrules`、`/upload` | 规则刷新与配置上传 |
| `filter_script` / `&fscript=` | JS 脚本过滤节点。用 `&include=` / `&exclude=` 正则代替；复杂逻辑请先在源头处理 |
| `&preview=` | 预览模式，用 `&check=true` 代替 |

依赖这些能力的链接会返回 404 或参数被忽略，不会静默产出错误配置。

## 行为差异

**严格失败，不猜。** 参数写错就是错误，不回落到默认配置：

| 情况 | 响应 |
|---|---|
| 未知 `target`、非法版本、`template` 不可用、provider 模式缺订阅 URL | `400` |
| 订阅内容里没有可用节点 | `422` |
| 上游抓取失败（订阅 / 配置 / 规则集） | `424` |

**配置里的正则支持 PCRE 语法。** 分组选择器、`include`/`exclude`、`rename`、`emoji` 都先用 Go RE2 编译，失败再换 PCRE 引擎，覆盖 lookahead、lookbehind 与反向引用。上游文档里的 `(^(?!.*(美国|日本)).*)` 这类排除式分组可以正常匹配。两种引擎都编译失败、或匹配超过 100ms 超时时返回 `400`，错误里带分组名与选择器。provider 模式下 `include`/`exclude` 会写进客户端 `filter`，因此还必须能被 PCRE 引擎编译。属性选择器：`!!TYPE=` 对协议名全匹配，带 TLS 的 HTTP 节点是 `HTTPS`，明文是 `HTTP`；`!!PORT=` 支持 `443`、`1000-2000`、`1000-`、`1000+`、`!443`、`!1000-2000`，多项用逗号分隔并允许空格；`!1000-`、`!1000+`、`+5` 返回 `400`，上游对它们的解读不同；`!!SERVER=` 与 `!!GROUP=` 按子串匹配，`!!GROUP=` 读取 `tag:<组名>,` 前缀，无 tag 的节点组名为空，IPv6 地址同时接受 `::1` 与 `[::1]`；`!!GROUPID=` 对 `url=` 从 0 计数，`!!INSERT=` 对 `insert_url` 从 1 计数。每项都可以再跟 `!!<正则>` 按节点名过滤。空值或未知属性返回 `400`。`!!PROVIDER=` 未支持（provider 名自动生成为 `sub-N`）；provider 模式下任何 `!!` 选择器都无法写进客户端 `filter`，这两种情况都返回 `400`；provider 模式下带 `tag:` 的来源同样返回 `400`。

**`clash_rule_base` 保留原文件布局。** 只替换生成段：`proxies`、`proxy-groups`、`rules`，provider 模式另加 `proxy-providers`，`expand=false` 时另加 `rule-providers`。其余键序、引号与注释保持原样；缩进沿用 base 的宽度（2 到 9 空格，超出范围回落 2 空格）；顶部的 `%YAML 1.1` 或 `%YAML 1.2` 指令会去掉（yaml.v3 拒绝该指令），`%TAG` 指令保留；其他版本、其他指令、或指令块后没有 `---` 都返回 `400`；空行不保留。base 抓取或解析失败时返回错误，不回落内置骨架。

**缓存按「UA + 上游代理 + URL」区分。** 带 `&ua=` 的请求不读写共享缓存（UA 是无界键空间）。需要缓存就把 UA 写进服务端 `user_agent`。

**sing-box 输出随内核版本变化。** 未声明版本时按当前 sing-box schema 输出；老内核用 `target=singbox/1.11` 这类写法。同一份配置在不同 sing-box 大版本之间不保证通用，这是上游内核的 schema 变化，不是转换器的可选行为。

**emoji 默认开启。** 与原版一致的全局默认（`add_emoji` 与 `remove_emoji` 都为 true），但外部 INI 与 URL 参数的优先级是：全局默认 < 外部配置 < URL `add_emoji`/`remove_emoji` < URL `emoji`。
