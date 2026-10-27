# URL 参数

`GET /sub` 的查询参数，尽量与 [tindy2013/subconverter](https://github.com/tindy2013/subconverter) 保持兼容，老链接可直接替换。

## target 取值

`target` 选择输出格式，支持 `name[/version]` 语法附带目标内核版本（见下方「版本门控」）。支持的值（含常见别名）：

| target | 别名 | 输出 | Content-Type |
|---|---|---|---|
| `clash` | `clash.meta` `clashr` | Clash.Meta / mihomo YAML | `text/yaml` |
| `singbox` | `sing-box` | sing-box JSON | `application/json` |
| `surge` | | Surge `.conf`（含 `[Proxy]`/`[Proxy Group]`/`[Rule]`） | `text/plain` |
| `shadowrocket` | `shadow-rocket` | Surge 风格托管 conf（Shadowrocket 可直接导入） | `text/plain` |
| `quanx` | `quantumultx` `quantumult-x` | Quantumult X 资源配置 | `text/plain` |
| `loon` | | Loon `.conf` | `text/plain` |
| `v2ray` | `mixed` `v2rayn` | base64 节点订阅（ss/vmess/vless/trojan/hysteria2/tuic 分享链接） | `text/plain` |

!!! note "协议覆盖"
    各 target 优先输出常见协议（ss/vmess/vless/trojan/hysteria2/tuic）。某 target 无法表达的协议（如
    Surge 没有 VLESS、QuanX/Surge 没有 hysteria2/tuic 时）会被**跳过并在日志中列出**，不会让整份配置失败。

### 版本门控（`target=name[/version]`）

`target` 可带版本后缀，如 `target=singbox/1.3.xx`（`xx` 等非数字尾段被忽略，等价于 `1.3`）或 `target=singbox/1.13.11`（即 `1.13.11`）。版本当前仅 `singbox` 消费：按协议门控，剔除老内核不支持的协议节点并计入 `SkippedNodes` / 日志（原因 `requires sing-box >= 1.x`）。未声明版本时不门控（行为不变）；非法版本（如 `singbox/abc`）报错；其它 target 带版本会被接受并忽略。

sing-box 协议能力表（best-effort，依据 sing-box 官方 release notes）：

| 协议 | 最低 sing-box 版本 |
|---|---|
| `ss` / `socks` / `vmess` / `vless` / `trojan` / `wireguard` | 1.0 |
| `hysteria` | 1.1 |
| `tuic` | 1.2 |
| `hysteria2` | 1.5 |
| `anytls` | 1.12 |

!!! note "已知边界"
    hysteria1（v1）暂无 sing-box 出站渲染分支——无论声明的版本如何，都会以 unsupported 跳过；anytls 已支持（需 sing-box ≥ 1.12）。

#### schema 切换

除协议门控外，声明的版本还决定 sing-box 配置 schema（依据 sing-box 官方 deprecated 文档）：

| 声明版本 | schema 行为 |
|---|---|
| ≥ 1.11 | 启用规则动作：DNS 劫持 / 拒绝类规则改写为 `action: hijack-dns` / `action: reject`，不再输出 `block` / `dns` 特殊出站（1.13 起已移除，老内核会加载失败） |
| ≥ 1.12 | 启用 `rule_set` 与新 DNS 格式：`GEOSITE` / `GEOIP` 规则迁移为远程 `.srs` 规则集引用（顶层 `rule_set` 数组），`geoip: private` 特例迁移为 `ip_is_private: true`；DNS server 改为 `{type, server}` 新格式（1.14 移除 legacy 格式） |
| 未声明版本 | 保持 legacy 输出（兼容 ≤ 1.11 老内核），行为与旧版本工具完全一致 |

!!! note
    `direct` 出站从未弃用，所有版本均保留；`rule_set` 引用不写 `download_detour`（1.14 已弃用）。

!!! note "rule_set 映射细节"
    `GEOIP` 规则仅支持两字母国家码（SagerNet/sing-geoip 只发布国家码类目）；`GEOIP,PRIVATE/LAN` 映射为内置规则项 `ip_is_private: true`，其余非国家码类目（如 `GEOIP,TWITTER`）会被跳过并在诊断中报告，避免生成 404 的 rule_set 导致内核启动失败。`GEOSITE` 类目与 sing-geosite 仓库一一对应，上游已更名的类目自动映射（`google-cn` → `google@cn`）。GEOIP/IP-CIDR 等规则尾参（`no-resolve`、`src`）会被剥离保留，其它未知尾参（如旧式 `policy` 标记）会被丢弃。

## 通用参数（对所有 target 有效）

| 参数 | 说明 | 状态 |
|---|---|---|
| `target` | 输出目标（见上表），缺省 `clash` | :material-check: |
| `url` | 订阅链接，多个用 `\|` 分隔（必填）；也支持直接粘贴节点链接（如 `vless://…`、`ss://…`），单个或多个节点可不用订阅直接转换 | :material-check: |
| `config` | 外部 INI 配置 URL（分组与规则来源）；省略时用服务端 `default_config_url`（若未配置则无分组无规则） | :material-check: |
| `template` | 用内置/远程 sing-box 模板渲染**完整配置**：`momo` = 路由器 momo 模板（自带入站、DNS/fake-ip、rule_set 与分流规则），节点与 `NotesName` 分组自动注入；指定后 target 固定为 `singbox`（扩展参数） | :material-check: |
| `insert` | 是否合并服务端配置的 `insert_url` 节点；覆盖配置默认值（见下方说明） | :material-check: |
| `sort` | 按节点名排序 | :material-check: |
| `dedup` | 去除重复节点：连接字段（类型/地址/端口/凭据/传输）完全相同的节点只保留第一个 | :material-check: |
| `append_type` | 节点名前加 `[类型]`（如 `[SS] 香港 01`） | :material-check: |
| `tailscale` | 在规则最前置入 Tailscale 直连规则（`100.64.0.0/10` 与 `fd7a:115c:a1e0::/48` 直连且 `no-resolve`） | :material-check: |
| `emoji` | 快捷开关：`true`=去旧 emoji 后按规则统一加旗；`false`=去除 emoji 不再加。等价于 `add_emoji=<值>` 且 `remove_emoji=true` | :material-check: |
| `add_emoji` | 是否按规则给节点名前加国旗 emoji（默认 `true`） | :material-check: |
| `remove_emoji` | 是否先移除节点名中已有的 emoji（默认 `true`） | :material-check: |
| `filename` | 设置下载文件名（`Content-Disposition`） | :material-check: |
| `interval` | 客户端订阅自动更新间隔（小时，默认 24，`Profile-Update-Interval` 头） | :material-check: |
| `proxy` | **本次请求**的上游代理，覆盖全局配置（扩展参数） | :material-check: |
| `source` | 按请求指定订阅源格式预设，映射对应抓取 UA（扩展参数，见下方「source 预设」） | :material-check: |
| `ua` | 按请求覆盖抓取 UA，对本次请求的全部远程抓取（订阅 / 规则 / 外部配置）生效（扩展参数） | :material-check: |
| `nocache` | `1` 时绕过本次请求的 TTL 缓存，强制重新抓取 | :material-check: |
| `flushcache` | `1` 时先清空整个共享缓存再处理本次请求（另有 `GET /flushcache` 端点） | :material-check: |

## source 预设（订阅源格式）

`&source=<预设>`（扩展参数）按请求指定订阅源格式，映射为对应客户端的抓取 UA（无需手记 UA 字符串）。未知预设返回 400 并列出支持值。

| 预设 | 映射 UA |
|---|---|
| `clash.meta` / `clash` / `mihomo` | `clash.meta/1.18.0 mihomo/1.18.0` |
| `v2ray` / `v2rayn` | `v2rayN/6.45` |
| `singbox` / `sing-box` | `sing-box/1.3.0` |
| `surge` | `Surge/5.9.0` |
| `shadowrocket` | `Shadowrocket/2.2.50` |
| `quanx` | `Quantumult X/1.0.30` |
| `loon` | `Loon/3.2.4` |

!!! warning "⚠️ 可解析性"
    只有返回 **Clash YAML 或 base64 分享链接**的预设（`clash.meta`、`v2ray`，以及部分面板对其它 UA
    也返回兼容载荷）当前可被本工具解析；`singbox` / `surge` / `quanx` / `loon` 等原始格式订阅本工具
    暂不能解析，此类预设仅供面板返回兼容载荷时使用。

## 节点处理参数（部分 target 有效）

| 参数 | 说明 | 适用 target |
|---|---|---|
| `udp` | 强制所有节点开启 UDP | clash / surge 系 / sing-box |
| `tfo` | TCP Fast Open | clash（其余 target 暂不体现） |
| `scv` | skip-cert-verify（跳过证书校验） | clash / surge 系 / sing-box；v2ray 体现为分享链接的 `insecure` |
| `fdn` | 过滤 Clash.Meta 不支持的节点（如已废弃加密的 Shadowsocks） | 主要针对 clash |

## 仅 Clash 有效

| 参数 | 说明 | 状态 |
|---|---|---|
| `list` | 仅输出节点列表（`proxies:`），不含分组与规则 | :material-check: |
| `expand` | `true`（默认）把规则内联进配置；`false` 改为输出 `rule-providers` 引用远程规则 | :material-check: |

!!! note "其它 target 的规则处理"
    surge 系 / quanx / sing-box 统一把规则**展开为内联规则**（远程规则集会被抓取并逐条转换为目标语法）；
    目标格式不支持的规则类型（如 Surge 无 `GEOSITE`/`IP-SUFFIX`）会被丢弃并记入日志。v2ray base64 订阅**不含规则**，由客户端自行管理。

## insert_url（节点插入）

服务端可在配置里固定一组「插入节点」，每次转换时合并进结果（subconverter 的 `insert_url`）。
常用于把自己的中转/落地节点固定排在机场节点前面。

```yaml
# config.example.yaml
insert:
  urls:
    - https://example.com/my-extra-nodes
  prepend: true    # true=插到订阅节点前，false=插到后
  enabled: true    # 默认是否插入
```

- URL 参数 `insert` 覆盖 `enabled`：`&insert=false` 本次不插入，`&insert=true` 强制插入。
- 插入节点同样会经过过滤 / 去重 / emoji / 重命名等处理。
- 插入源抓取失败不影响主订阅转换（静默跳过）。
- 环境变量：`SUBNG_INSERT_URLS`（逗号分隔）、`SUBNG_INSERT_PREPEND`、`SUBNG_INSERT_ENABLED`。

## 兼容性接收但当前无效果

| 参数 | 说明 |
|---|---|
| `new_name` | subconverter 的旧/新命名开关；本项目默认即为新式命名，无需切换 |

!!! note "重命名 / 缓存 / 限流"
    - **rename**：外部配置里写 `rename=<正则>@<替换>`（支持 `\1` / `$1` 反向引用、空替换），批量改节点名。处理顺序：去 emoji → 重命名 → 加 emoji。
    - **缓存**：订阅与规则列表按 URL 做内存 TTL 缓存（默认 300s），避免每次 `/sub` 都去 GitHub 拉规则列表被限流。缓存键含 UA，同一 URL 不同 UA 的响应互不串缓存。`cache_ttl: -1s` 可关闭。
    - **限流**：`/sub` 按客户端 IP 限流（默认 30/min、burst 10），超限返回 `429 + Retry-After`；`/version` 与 Web 界面不受限。详见 `config.example.yaml`。
    - **Subscription-Userinfo**：机场返回的流量 / 到期头会透传给客户端。

!!! note "emoji 行为（对齐 subconverter）"
    处理顺序：**先 `remove_emoji` 去旧 → 再 `add_emoji` 按正则规则加新旗**。规则取自外部配置的
    `emoji=<正则>,<emoji>` 行；未配置时使用内置默认规则集（移植自 subconverter，95 条，已适配 Go RE2）。
    优先级：`emoji` 快捷参数 > `add_emoji`/`remove_emoji` > 外部配置 > 默认（均为 `true`）。
    想**完全保留原始名字**：`add_emoji=false&remove_emoji=false`。

!!! note "布尔参数取值"
    `true / 1 / yes / on` 为真，`false / 0 / no / off` 为假，其余按默认值处理。

## 编码提醒

`url` 和 `config` 都是完整链接，作为参数传入时**必须 URL 编码**。例如：

- 原始：`https://github.com/you/clash-rule/raw/main/config.init`
- 编码后：`https%3A%2F%2Fgithub.com%2Fyou%2Fclash-rule%2Fraw%2Fmain%2Fconfig.init`

大多数客户端会自动处理；手动拼接时记得编码。
