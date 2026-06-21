# URL 参数

`GET /sub` 的查询参数，尽量与 [tindy2013/subconverter](https://github.com/tindy2013/subconverter) 保持兼容，老链接可直接替换。

## 支持的参数

| 参数 | 说明 | 状态 |
|---|---|---|
| `target` | 输出目标，目前仅 `clash` | :material-check: |
| `url` | 订阅链接，多个用 `\|` 分隔（必填） | :material-check: |
| `config` | 外部 INI 配置 URL | :material-check: |
| `sort` | 按节点名排序 | :material-check: |
| `udp` | 强制所有节点开启 UDP | :material-check: |
| `tfo` | TCP Fast Open | :material-check: |
| `scv` | skip-cert-verify（跳过证书校验） | :material-check: |
| `emoji` | subconverter 快捷开关：`true`=去旧 emoji 后按规则统一加旗；`false`=去除 emoji 不再加（给不支持 emoji 的客户端）。等价于同时设 `add_emoji=<值>` 且 `remove_emoji=true` | :material-check: |
| `add_emoji` | 是否按规则给节点名前加国旗 emoji（默认 `true`） | :material-check: |
| `remove_emoji` | 是否先移除节点名中已有的 emoji（默认 `true`） | :material-check: |
| `proxy` | **本次请求**的上游代理，覆盖全局配置（扩展参数） | :material-check: |
| `expand` | `true`（默认）把规则内联进配置；`false` 改为输出 `rule-providers` 引用远程规则，配置体积大幅减小、规则自动更新 | :material-check: |
| `nocache` | `1` 时绕过本次请求的 TTL 缓存，强制重新抓取 | :material-check: |
| `flushcache` | `1` 时先清空整个共享缓存再处理本次请求（另有 `GET /flushcache` 端点） | :material-check: |

!!! note "重命名 / 缓存 / 限流"
    - **rename**：外部配置里写 `rename=<正则>@<替换>`（支持 `\1` / `$1` 反向引用、空替换），批量改节点名。处理顺序：去 emoji → 重命名 → 加 emoji。
    - **缓存**：订阅与规则列表按 URL 做内存 TTL 缓存（默认 300s），避免每次 `/sub` 都去 GitHub 拉 ~25 个规则列表被限流。`cache_ttl: -1s` 可关闭。
    - **限流**：`/sub` 按客户端 IP 限流（默认 30/min、burst 10），超限返回 `429 + Retry-After`；`/version` 与 Web 界面不受限。详见 `config.example.yaml`。
    - **Subscription-Userinfo**：机场返回的流量 / 到期头会透传给客户端，Clash 里直接显示。

!!! note "emoji 行为（对齐 subconverter）"
    处理顺序：**先 `remove_emoji` 去旧 → 再 `add_emoji` 按正则规则加新旗**。规则取自外部配置的
    `emoji=<正则>,<emoji>` 行；未配置时使用内置默认规则集（移植自 subconverter，95 条，已适配 Go RE2）。
    优先级：`emoji` 快捷参数 > `add_emoji`/`remove_emoji` > 外部配置 > 默认（均为 `true`）。
    想**完全保留原始名字**：`add_emoji=false&remove_emoji=false`。

## 暂未实现的参数

以下参数会被识别但走默认值，不影响主流程，后续版本逐步补全：

| 参数 | 说明 |
|---|---|
| `new_name` | 新版节点命名 |
| `list` | 仅输出节点列表 |
| `fdn` | filter deprecated nodes |
| `insert` | 插入节点 |

!!! note "布尔参数取值"
    `true / 1 / yes / on` 为真，`false / 0 / no / off` 为假，其余按默认值处理。

## 编码提醒

`url` 和 `config` 都是完整链接，作为参数传入时**必须 URL 编码**。例如：

- 原始：`https://github.com/you/clash-rule/raw/main/config.init`
- 编码后：`https%3A%2F%2Fgithub.com%2Fyou%2Fclash-rule%2Fraw%2Fmain%2Fconfig.init`

大多数客户端会自动处理；手动拼接时记得编码。
