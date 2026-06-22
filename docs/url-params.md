# URL 参数

`GET /sub` 的查询参数，尽量与 [tindy2013/subconverter](https://github.com/tindy2013/subconverter) 保持兼容，老链接可直接替换。

## target 取值

`target` 选择输出格式。支持的值（含常见别名）：

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

## 通用参数（对所有 target 有效）

| 参数 | 说明 | 状态 |
|---|---|---|
| `target` | 输出目标（见上表），缺省 `clash` | :material-check: |
| `url` | 订阅链接，多个用 `\|` 分隔（必填） | :material-check: |
| `config` | 外部 INI 配置 URL（分组与规则来源） | :material-check: |
| `insert` | 是否合并服务端配置的 `insert_url` 节点；覆盖配置默认值（见下方说明） | :material-check: |
| `sort` | 按节点名排序 | :material-check: |
| `dedup` | 去除重复节点：连接字段（类型/地址/端口/凭据/传输）完全相同的节点只保留第一个 | :material-check: |
| `append_type` | 节点名前加 `[类型]`（如 `[SS] 香港 01`） | :material-check: |
| `emoji` | 快捷开关：`true`=去旧 emoji 后按规则统一加旗；`false`=去除 emoji 不再加。等价于 `add_emoji=<值>` 且 `remove_emoji=true` | :material-check: |
| `add_emoji` | 是否按规则给节点名前加国旗 emoji（默认 `true`） | :material-check: |
| `remove_emoji` | 是否先移除节点名中已有的 emoji（默认 `true`） | :material-check: |
| `filename` | 设置下载文件名（`Content-Disposition`） | :material-check: |
| `interval` | 客户端订阅自动更新间隔（小时，默认 24，`Profile-Update-Interval` 头） | :material-check: |
| `proxy` | **本次请求**的上游代理，覆盖全局配置（扩展参数） | :material-check: |
| `nocache` | `1` 时绕过本次请求的 TTL 缓存，强制重新抓取 | :material-check: |
| `flushcache` | `1` 时先清空整个共享缓存再处理本次请求（另有 `GET /flushcache` 端点） | :material-check: |

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
    - **缓存**：订阅与规则列表按 URL 做内存 TTL 缓存（默认 300s），避免每次 `/sub` 都去 GitHub 拉规则列表被限流。`cache_ttl: -1s` 可关闭。
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
