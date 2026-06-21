# 快速开始

`subconverter-ng` 是单个二进制，既能起 HTTP 服务（兼容 subconverter 接口），也能 CLI 单次转换。

## 方式一：HTTP 服务

```bash
# 二进制
subconverter-ng serve --listen :25500

# 或 Docker
docker run -d -p 25500:25500 ghcr.io/jungley8/subconverter-ng:latest
```

然后用与 subconverter 完全相同的方式访问（注意 `url` / `config` 要做 URL 编码）：

```
http://127.0.0.1:25500/sub?target=clash&url=<订阅URL编码>&config=<规则URL编码>
```

把这个地址填进 Clash.Meta / mihomo / clash-verge 的订阅栏即可。

!!! example "完整示例"
    ```
    http://127.0.0.1:25500/sub?target=clash
      &url=https%3A%2F%2Fyour-airport.com%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3Dxxx
      &config=https%3A%2F%2Fgithub.com%2Fyou%2Fclash-rule%2Fraw%2Fmain%2Fconfig.init
    ```

支持的全部参数见 [URL 参数](url-params.md)。

## 方式二：CLI 单次转换

适合本地生成一份配置文件，或在脚本里用：

```bash
subconverter-ng convert \
  --url 'https://your-airport.com/api/v1/client/subscribe?token=xxx' \
  --config 'https://github.com/you/clash-rule/raw/main/config.init' \
  -o clash.yaml
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--url` | 订阅链接，多个用 `\|` 分隔（必填） |
| `--config` | subconverter 外部 INI 配置 URL |
| `-o` | 输出文件（默认打印到 stdout） |
| `--proxy` | 上游代理 `http://` 或 `socks5://` |
| `--flaresolverr` | FlareSolverr 端点（过 CF 盾） |
| `--ua` | 自定义 User-Agent |
| `--sort` `--udp` `--tfo` `--scv` | 节点处理开关 |

## 外部配置（config）

`subconverter-ng` 解析 subconverter 的 INI 外部配置，兼容主流 **ACL4SSR** 规则，支持：

- `ruleset=` —— 远程规则列表，以及 `[]GEOIP,CN`、`[]FINAL` 等内联规则
- `custom_proxy_group=` —— backtick 分隔的分组（`select` / `url-test` / 正则筛选 / `[]` 组引用）
- `exclude_remarks=` / `include_remarks=` —— 节点名过滤
- `enable_rule_generator` / `overwrite_original_rules`
- `clash_rule_base=` —— 自定义 Clash 基础模板

直接复用你现有的 `config.init` 即可，无需改动。

## 下一步

- 机场访问受限 → [上游代理与 UA](proxy.md)
- 机场套了 Cloudflare → [绕过 Cloudflare](cloudflare.md)
- 生产部署 → [Docker 部署](docker.md)
