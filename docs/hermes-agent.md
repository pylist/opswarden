# Hermes Agent 接入 OpsWarden

OpsWarden 在 `/mcp` 提供 Streamable HTTP MCP 服务。它只接受以 `owat_`
开头的 Agent Bearer Token；浏览器 JWT、Cookie 和用户密码都不能用于此端点。

## 1. 创建最小权限 Agent

在 OpsWarden 中创建一个专用于 Hermes 的 Agent，然后只授予它实际需要的
Space、scope 和标签条件。建议先只授予：

- `credential:list`、`credential:read`
- `asset:list`、`asset:read`

只有确实需要自动变更凭据时，才增加 `credential:create`、
`credential:update` 或 `credential:delete`。不同环境或不同 Hermes 实例应使用
不同 Agent，不要共用 Token。

签发 Token 后，OpsWarden 只显示一次完整 Token。立即把它写入 Hermes 的
`~/.hermes/.env`，不要写进 `config.yaml`、聊天内容、脚本参数或日志：

```dotenv
OPSWARDEN_AGENT_TOKEN=owat_REPLACE_WITH_THE_ONE_TIME_VALUE
```

上面的值只是占位符，不是真实 Token。

## 2. 配置 Hermes

在 `~/.hermes/config.yaml` 中加入：

```yaml
mcp_servers:
  opswarden:
    url: "https://opswarden.internal.example/mcp"
    headers:
      Authorization: "Bearer ${OPSWARDEN_AGENT_TOKEN}"
    enabled: true
    connect_timeout: 30
    timeout: 60
    supports_parallel_tool_calls: false
    tools:
      include:
        - credential_list
        - credential_get
        - totp_generate
        - asset_list
        - asset_get
      resources: false
      prompts: false
    sampling:
      enabled: false
```

OpsWarden 的 MCP 端点只接受经过认证的 POST。不要把
`supports_parallel_tool_calls` 改为 `true`，因为凭据读写共享授权状态、审计和
SQLite。

如果确实允许写操作，再把以下工具逐项加入 `tools.include`：

- `credential_create`
- `credential_update`
- `credential_delete`

写工具每次都要求 `reason`、唯一 `idempotency_key`；更新和删除还要求当前
`expected_version`。

修改配置后运行 `/reload-mcp`，或重启 `hermes chat`。可以让 Hermes 列出当前
可用的 MCP 工具，确认工具集与 `include` 一致。

## 3. 使用与撤销

- `credential_list` 只返回元数据，不返回明文。
- `credential_get` 和 `totp_generate` 的结果属于敏感数据，禁止写入日志、记忆、
  提示词文件或其他工具参数。
- `totp_generate` 只返回当前验证码和到期时间，不返回 TOTP seed。
- OpsWarden 会在返回凭据明文前持久化审计；审计不可用时调用失败。
- 所有 MCP 响应均为 `Cache-Control: no-store`。

如怀疑 Token 泄露，立即在 OpsWarden 中撤销对应 Token。撤销即时生效，现有
Hermes 会话的后续请求也会失败。然后签发新 Token、更新
`OPSWARDEN_AGENT_TOKEN`，并重载 MCP。不要重新启用旧 Token。

生产环境必须使用有效证书的 HTTPS；不要把 OpsWarden 直接暴露到公网，也不要
在 Hermes 配置中关闭 TLS 校验。
