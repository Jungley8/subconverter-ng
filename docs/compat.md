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

**缓存按「UA + 上游代理 + URL」区分。** 带 `&ua=` 的请求不读写共享缓存（UA 是无界键空间）。需要缓存就把 UA 写进服务端 `user_agent`。

**sing-box 输出随内核版本变化。** 未声明版本时按当前 sing-box schema 输出；老内核用 `target=singbox/1.11` 这类写法。同一份配置在不同 sing-box 大版本之间不保证通用，这是上游内核的 schema 变化，不是转换器的可选行为。

**emoji 默认开启。** 与原版一致的全局默认（`add_emoji` 与 `remove_emoji` 都为 true），但外部 INI 与 URL 参数的优先级是：全局默认 < 外部配置 < URL `add_emoji`/`remove_emoji` < URL `emoji`。
