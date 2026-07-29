# OpsWarden

OpsWarden 是一个面向公司内部和个人团队的轻量凭据管理服务。它使用 Go、React、
SQLite 和 Caddy 构建，为成员与 Hermes 等 AI Agent 提供统一、可审计、可撤销的
凭据访问能力。

## 主要能力

- 管理登录账号、API Token、SSH 密钥、数据库凭据和 TOTP 五类凭据。
- 管理服务器、数据库、服务等资产，并建立资产与凭据的双向关联。
- 使用 Space 隔离团队、环境和权限边界。
- React 管理界面支持凭据、资产、成员、Agent、审计和回收站操作。
- 提供 Hermes 兼容的 Streamable HTTP MCP 服务。
- Agent 支持凭据 list、get、create、update 和软删除，并可按 Space、scope 和标签
  限制权限。
- 使用幂等键和版本检查避免 Agent 重试造成重复写入或静默覆盖。
- 支持会话与 Agent Token 即时吊销、在线备份及隔离恢复演练。

## 架构

```text
浏览器 / Hermes Agent
          |
       HTTPS 443
          |
        Caddy
          |
   内部网络 :8080
          |
      OpsWarden
          |
        SQLite

独立主密钥文件 --只读挂载--> OpsWarden
```

生产 Compose 仅向宿主机发布 TCP 443。OpsWarden 后端只存在于 Docker 内部网络，
不直接暴露端口。

## 安全设计

- 浏览器使用短时 JWT Bearer；JWT 仅保存在 React 进程内存，不写入 Cookie、
  localStorage、sessionStorage 或 IndexedDB。
- 密码使用 Argon2id；登录要求 TOTP 或一次性恢复码。
- 凭据和 TOTP seed 使用 XChaCha20-Poly1305 信封加密。
- Agent 使用独立随机 Token；数据库只保存 Token 哈希。
- 凭据读取与写入均写审计事件；审计不可用时敏感操作失败关闭。
- 容器使用非 root 用户、只读根文件系统、`cap_drop: ALL` 和
  `no-new-privileges`。
- 数据库快照和主密钥必须分开保存；任何一方丢失都不能单独恢复明文。

完整边界和已知风险参见
[安全模型](docs/security-model.md)。

## 生产部署

要求：

- Linux 主机
- Docker Engine 与 Docker Compose v2
- 可解析到主机的正式域名
- TCP 443 入站访问

克隆仓库并准备配置：

```bash
git clone git@github.com:pylist/opswarden.git
cd opswarden
cp deploy/.env.example deploy/.env
```

编辑 `deploy/.env`，填写域名、TLS 邮箱、固定版本和提交 SHA，以及宿主机上的状态、
主密钥和 Caddy 目录。

主密钥生成、目录权限、安全初始化、启动、升级、备份、恢复及紧急吊销必须按照
[单机运维手册](docs/operations.md)执行。不要把主密钥、密码、JWT、TOTP seed 或
Agent Token 写入 `.env`、命令行、日志或 Git。

## Hermes Agent

OpsWarden 在以下地址提供 MCP：

```text
https://你的域名/mcp
```

为 Hermes 创建独立的最小权限 Agent，将一次性显示的 Token 写入 Hermes 私有
环境文件，再在 Hermes MCP 配置中使用：

```yaml
mcp_servers:
  opswarden:
    url: "https://opswarden.internal.example/mcp"
    headers:
      Authorization: "Bearer ${OPSWARDEN_AGENT_TOKEN}"
    enabled: true
    supports_parallel_tool_calls: false
```

完整的 scope、工具白名单、写入参数和吊销流程参见
[Hermes Agent 接入指南](docs/hermes-agent.md)。

## 开发与验证

Go 后端测试：

```bash
go test -race ./...
```

React 测试与构建：

```bash
cd web
npm ci
npm test -- --run
npm run build
```

安装 Playwright 浏览器依赖：

```bash
make e2e-bootstrap
```

运行完整发布门禁：

```bash
make verify
```

`make verify` 会执行 Go 静态检查与竞态测试、依赖漏洞审计、React 测试、生产镜像
构建、Caddy 配置验证、完整 HTTPS Compose E2E、备份恢复验证及敏感制品扫描。

## 文档

- [单机运维手册](docs/operations.md)
- [安全模型](docs/security-model.md)
- [Hermes Agent 接入指南](docs/hermes-agent.md)
- [v1 设计规格](docs/superpowers/specs/2026-07-28-opswarden-design.md)

## 当前范围

OpsWarden v1 是单机 SQLite 服务，不提供高可用或在线主密钥轮换。宿主机 root、
Docker daemon 或主密钥与数据库同时失陷不在其防护边界内。正式保存高价值生产
凭据前，仍应完成独立的代码、镜像、主机和运维安全评审。
