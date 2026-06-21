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
| `emoji` | 是否**允许** emoji（默认 `true` 保留）。`emoji=false` 时**移除节点名称中的 emoji**，给不支持 emoji 的 Clash 客户端用 | :material-check: |
| `proxy` | **本次请求**的上游代理，覆盖全局配置（扩展参数） | :material-check: |

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
