# OpsWarden 轻量凭据与资产管理服务器设计

日期：2026-07-28
状态：待用户书面审阅
目标版本：v1

## 1. 目标

OpsWarden 是面向公司内部小团队的自托管管理服务器。它集中管理服务器与设备资产，以及与这些资产相关的登录账号、API Token、SSH 私钥、数据库连接和 TOTP 凭据。

系统同时服务两类主体：

1. 团队成员通过 React 管理界面使用本地账号、密码和 TOTP 登录。
2. Hermes Agent 等 AI 工具通过 REST API 或 MCP Server 使用独立 Agent Token，并按授权对凭据执行增、删、改、查。

v1 的成功标准：

- 使用 Docker Compose 在单台 Linux 主机上部署。
- 公网和公司内网均可通过 HTTPS 访问。
- 成员、REST 客户端和 MCP Agent 共用同一套授权与审计规则。
- SQLite 数据库或数据库备份单独泄露时，攻击者无法得到凭据明文。
- Agent 的重试、并发修改和删除操作不会造成重复数据或静默覆盖。
- 数据库与主密钥分开备份后，可以在新环境完成恢复演练。

## 2. 明确不做

v1 不包含：

- 文件附件或通用加密文件存储。
- 远程脚本执行、服务启停、SSH 跳板机或命令编排。
- Kubernetes、高可用集群或多节点 SQLite。
- SSO、OIDC、LDAP、Google 或 Microsoft 登录。
- 浏览器扩展、原生移动端或桌面端。
- 自动轮换第三方密码、API Token 或数据库口令。
- 人工审批工作流。
- Agent 批量删除、批量明文导出或永久删除凭据。
- 零知识架构。服务端在完成获授权请求时能够解密凭据。
- 对宿主机 root 权限失陷的防护。

## 3. 已确认的技术决策

| 项目 | 决策 |
| --- | --- |
| 后端 | Go 模块化单体 |
| 前端 | React SPA |
| 数据库 | SQLite |
| 部署 | Docker Compose |
| 入口 | Caddy，统一处理公网与内网 HTTPS |
| 成员认证 | 本地密码 + TOTP |
| 浏览器会话 | 服务端会话 + `HttpOnly` Cookie |
| Agent 认证 | 独立 Bearer Token；预留短期 JWT 交换接口 |
| AI 接口 | REST API + MCP Streamable HTTP |
| 主密钥 | 宿主机受限文件，只读挂载到应用容器 |
| 中文领域术语 | 模块叫“凭据库”，单个对象叫“凭据” |

## 4. 总体架构

Docker Compose 运行两个容器：

1. `opswarden`
   - 托管构建后的 React 静态文件。
   - 提供浏览器 API、REST API 和 MCP endpoint。
   - 执行认证、授权、凭据 CRUD、资产管理、加解密、审计和备份。
   - 独占访问 SQLite 文件。
2. `caddy`
   - 对外只暴露 443。
   - 终止 TLS，强制 HTTPS，并添加安全响应头和请求大小限制。
   - 将请求转发给内部网络中的 `opswarden`。

SQLite、WAL 文件和本地备份位于独立持久化卷。主密钥从宿主机文件以只读方式挂载，不能位于持久化卷、镜像、源码仓库或数据库备份中。

React、REST 与 MCP 不分别实现业务规则。三种入口都调用同一组应用服务、授权器、加密器和审计器。

## 5. 后端模块边界

Go 单体按领域分为以下模块：

- `identity`：用户、密码、TOTP、恢复码和会话。
- `spaces`：Space、成员关系和角色。
- `agents`：Agent、Token、Scope、有效期和吊销。
- `assets`：服务器与设备资产。
- `credentials`：类型化凭据、版本、软删除和恢复。
- `authorization`：主体、Space、动作和资源范围校验。
- `crypto`：数据密钥、信封加密、主密钥加载和轮换。
- `audit`：不含敏感值的审计事件。
- `api`：浏览器与 REST HTTP handler。
- `mcp`：MCP tools 与 REST 应用服务之间的薄适配层。
- `storage`：SQLite schema、事务、迁移、在线备份和完整性检查。
- `health`：数据库、磁盘、备份和运行状态。

模块只能通过明确接口调用。API 和 MCP 层不得直接执行 SQL 或直接解密凭据。

## 6. 领域模型

### 6.1 Space

Space 是成员、Agent、资产和凭据的最小共享与授权边界。例如：

- 基础设施
- 研发环境
- 生产环境

成员具有 Space 角色：

- `Owner`：管理 Space 成员、Agent 授权、资产和凭据。
- `Editor`：创建、读取、修改和软删除资产及凭据，不能修改权限或永久删除。
- `Reader`：查看资产和读取凭据，不能写入。

系统级角色只有：

- `System Owner`：首次初始化产生，拥有系统设置与所有 Space 的管理能力。
- `System Admin`：管理用户、健康状态、备份和全局安全策略。
- `Member`：权限完全来自 Space 成员关系。

### 6.2 资产

资产保存非敏感元数据：

- 名称、类型、IP、域名、端口。
- 操作系统、环境、状态、标签和备注。
- 创建者、更新者和时间戳。

一项资产可以关联多个凭据；一个凭据也可以关联多项资产。资产与凭据必须属于同一个 Space 才能建立关联。

Agent 在 v1 可以列出和读取资产元数据，不能创建、修改或删除资产。

### 6.3 凭据

v1 支持五类凭据：

1. 登录账号：网址、用户名、密码和可选关联 TOTP。
2. API Token：服务、Token、可选 Header 名称和到期时间。
3. SSH 密钥：用户名、私钥、公钥、指纹和可选口令。
4. 数据库连接：引擎、主机、端口、数据库名、用户名、密码、参数和可选完整连接串。
5. TOTP：issuer、account、seed、算法、位数和周期。

显示名称、类型、Space、标签、资产关联、版本号和删除时间是可索引元数据。用户名、密码、Token、私钥、数据库敏感字段、连接串和 TOTP seed 属于加密载荷。

显示名称和资产元数据保持明文，以支持快速列表与搜索。该取舍意味着数据库泄露者可能得知系统名称、标签和资产地址，但不能得到凭据载荷。

### 6.4 概念表

SQLite 至少包含：

- `users`
- `user_totp`
- `recovery_codes`
- `sessions`
- `spaces`
- `space_memberships`
- `agents`
- `agent_tokens`
- `agent_space_grants`
- `assets`
- `credentials`
- `credential_versions`
- `asset_credentials`
- `audit_events`
- `idempotency_records`
- `backup_runs`
- `schema_migrations`

`credentials` 保存当前版本、元数据和软删除状态。`credential_versions` 保存每一版的加密载荷、被包裹的数据密钥、随机 nonce 和创建信息。

## 7. 成员认证与浏览器会话

### 7.1 密码与 TOTP

- 密码使用 Argon2id。
- 初始参数为：64 MiB memory、3 iterations、parallelism 2、32-byte output、每个用户独立 16-byte salt。
- 参数随哈希一起保存，登录成功时允许透明升级。
- TOTP 登录默认使用 6 位、30 秒周期，并允许当前时间窗口前后各一个窗口。
- 成员登录所用的 TOTP seed 也必须使用主密钥保护的信封加密，不得以明文保存在 `user_totp`。
- 开启 TOTP 时生成一次性恢复码；恢复码以哈希形式保存，使用后立即失效。
- 首次 `System Owner` 只能从本机或明确配置的内网网段创建。

### 7.2 服务端会话

- 登录完成后生成至少 256 bit 的随机会话 ID。
- 浏览器只获得 `__Host-opswarden_session` Cookie。
- Cookie 属性为 `Secure; HttpOnly; SameSite=Strict; Path=/`，且不设置 `Domain`。
- SQLite 只保存会话 ID 的 SHA-256 哈希。
- 会话空闲 8 小时失效，绝对期限为 24 小时。
- 修改权限、永久删除、导出审计和重置他人认证要求最近 5 分钟内重新验证 TOTP。
- 退出登录、禁用用户、密码重置和角色变更立即吊销相关会话。

### 7.3 CSRF 与前端安全

- 所有状态变更请求必须提供与会话绑定的 CSRF Token。
- React 不在 `localStorage`、`sessionStorage` 或 IndexedDB 保存认证 Token。
- Caddy 设置严格 CSP；前端禁止 `dangerouslySetInnerHTML`，除非经过单独安全评审。
- API 响应包含 `Cache-Control: no-store`，凭据明文不得进入 Service Worker、浏览器缓存或前端持久化状态。

浏览器应用不直接保存 Bearer Token，依据是浏览器持久化存储无法防止同源恶意 JavaScript 读取 Token；服务端会话能避免 Token 被直接复制到其他设备继续使用。参考 [RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html) 与 [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)。

## 8. Agent 认证与授权

### 8.1 Agent Token

- 每个 Agent 必须单独注册，不能共享成员会话或其他 Agent 的 Token。
- Token 格式包含不敏感前缀与至少 256 bit 随机值。
- 完整 Token 只在创建时显示一次；SQLite 只保存 SHA-256 哈希、前缀、创建时间、到期时间和最后使用时间。
- Token 可以立即吊销。每次请求都检查 Agent 状态、Token 状态和到期时间。
- v1 使用不透明 Bearer Token。后端预留 Token exchange 接口，以后可换取 10 分钟有效的 Ed25519 签名 JWT；v1 不依赖 JWT。

### 8.2 Scope

Agent 按 Space 分别授予：

- `credential:list`
- `credential:read`
- `credential:create`
- `credential:update`
- `credential:delete`
- `asset:list`
- `asset:read`

授权还可以增加允许标签条件。例如 Agent 只能管理 `environment=dev` 的凭据。标签条件只能收窄 Space 权限，不能扩大权限。

Agent 永远不能：

- 管理成员与权限。
- 永久删除凭据。
- 批量返回凭据明文。
- 读取其他 Space 的对象。
- 修改或删除资产。

### 8.3 写操作保护

- Agent 的创建、修改和删除必须携带 `Idempotency-Key`。
- 同一 Agent、endpoint 和 key 在保留期内只能产生一个业务结果。
- 幂等记录只保存请求指纹、资源 ID、版本和状态码，不保存凭据请求或响应载荷。
- 修改必须提交 `expected_version`。
- 删除必须提交精确的凭据 ID 与 `expected_version`，只执行软删除。
- Agent 的写操作必须包含简短 `reason`，作为不敏感审计元数据。
- Agent 不得使用批量写入或通配符目标。

## 9. 加密设计

### 9.1 主密钥

- 主密钥是 32-byte 随机值，以受限宿主机文件提供。
- 文件权限要求仅部署用户可读，并以只读方式挂载。
- 启动时若文件缺失、权限过宽、内容格式错误或长度错误，服务拒绝启动。
- 主密钥不得写入日志、环境诊断、数据库、镜像或备份。

该方案不抵御宿主机 root 失陷，也不抵御主密钥与 SQLite 同时泄露。

### 9.2 信封加密

- 每个凭据版本生成独立 32-byte 数据密钥。
- 成员 TOTP seed 使用相同的信封加密模型，但使用独立的数据密钥与身份领域 AAD。
- 凭据载荷使用 XChaCha20-Poly1305 加密，并为每次加密生成新的 24-byte nonce。
- 主密钥使用相同 AEAD 机制包裹数据密钥，并使用独立 nonce。
- Additional Authenticated Data 至少绑定 credential ID、version、Space ID 和 credential type，防止密文被移动到其他记录。
- 明文只在 Go 进程内完成当前请求所需的短暂处理，不缓存到磁盘或跨请求缓存。
- 主密钥轮换只重新包裹数据密钥，不需要重新加密全部凭据载荷。

不得自行实现密码算法。实现使用经过维护的 Go 密码库和操作系统安全随机源。

## 10. REST API 与 MCP

### 10.1 REST 资源

REST API 使用 `/api/v1` 前缀。核心资源包括：

- `/spaces`
- `/spaces/{spaceID}/assets`
- `/spaces/{spaceID}/credentials`
- `/agents`
- `/audit-events`
- `/health`
- `/backups`

凭据列表默认只返回元数据。只有读取单个凭据且通过 `credential:read` 校验后才返回解密载荷。

创建、更新和删除 Agent 请求必须带 `Idempotency-Key`。更新和删除 body 必须带 `expectedVersion`。

### 10.2 MCP Server

远程 MCP endpoint 为 `/mcp`，使用 Streamable HTTP 与 `Authorization: Bearer <agent-token>`。

v1 暴露以下工具：

- `credential_list`
- `credential_get`
- `credential_create`
- `credential_update`
- `credential_delete`
- `totp_generate`
- `asset_list`
- `asset_get`

所有工具使用明确 JSON Schema。工具描述必须说明：

- `credential_list` 不返回敏感载荷。
- `credential_get` 会返回明文并产生审计记录。
- 写操作需要 `reason`、`idempotency_key` 和适用时的 `expected_version`。
- `credential_delete` 只进入回收站。

Hermes Agent 当前同时支持本地 stdio 和远程 HTTP MCP，并允许通过 `headers` 配置 Bearer Token，因此 OpsWarden 直接提供远程 HTTP endpoint，不需要额外 stdio 代理。示例配置：

```yaml
mcp_servers:
  opswarden:
    url: "https://opswarden.example.com/mcp"
    headers:
      Authorization: "Bearer ${OPSWARDEN_AGENT_TOKEN}"
    tools:
      include:
        - credential_list
        - credential_get
        - credential_create
        - credential_update
        - credential_delete
        - totp_generate
        - asset_list
        - asset_get
```

Hermes 的远程 HTTP、Header 和工具筛选能力以其[官方 MCP 文档](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md)为准。

Hermes 配置中的 `include` 只用于减少模型可见工具，不能代替 OpsWarden 服务端授权。

### 10.3 TOTP 行为

- `credential_get` 在拥有 `credential:read` 时可以返回 TOTP seed。
- `totp_generate` 只返回当前验证码和剩余有效秒数，不返回 seed。
- 两种调用都记录凭据读取审计事件。

## 11. 审计

每个凭据查看、创建、修改、删除、恢复、Token 管理、权限变更和认证事件均写入审计。

事件包含：

- request ID
- 时间
- 主体类型与 ID
- Agent Token 前缀或成员会话 ID 哈希前缀
- 动作
- Space、资源类型与资源 ID
- 来源 IP 与 User-Agent
- 成功或失败结果
- 错误码
- 变更字段名
- Agent 提供的 `reason`

事件绝不包含凭据值、旧值、新值、主密钥、完整 Agent Token、完整会话 ID 或 TOTP seed。

凭据写入与审计事件位于同一 SQLite 事务。凭据读取必须先成功写入审计事件，再向调用方返回明文。审计写入失败时，请求失败。

审计默认保留一年。v1 的本地审计不能抵御拥有宿主机 root 权限的管理员篡改；外部只写审计归档属于后续增强。

## 12. 删除、版本与并发

- 删除默认是软删除，设置 `deleted_at` 并进入 30 天回收站。
- Agent 重复删除同一版本返回成功，结果保持幂等。
- Space Owner 或 System Admin 可以恢复凭据。
- 只有 System Owner 可以永久删除，且必须重新验证 TOTP。
- Agent 无永久删除与恢复权限。
- 每次修改产生新的不可变 `credential_versions` 记录，并更新当前版本号。
- `expected_version` 不匹配时返回冲突，不修改数据。
- 旧版本用于审计定位和灾难恢复，不在普通 UI 或 Agent API 中直接返回明文。

## 13. 错误模型

REST 错误使用统一 envelope：

```json
{
  "error": {
    "code": "VERSION_CONFLICT",
    "message": "The credential changed since it was read.",
    "requestId": "req_...",
    "retryable": false,
    "details": {
      "currentVersion": 8
    }
  }
}
```

稳定错误码至少包括：

- `INVALID_REQUEST`
- `UNAUTHENTICATED`
- `PERMISSION_DENIED`
- `NOT_FOUND`
- `VERSION_CONFLICT`
- `IDEMPOTENCY_CONFLICT`
- `RATE_LIMITED`
- `CREDENTIAL_DELETED`
- `STORAGE_BUSY`
- `STORAGE_UNAVAILABLE`
- `MASTER_KEY_UNAVAILABLE`
- `INTERNAL_ERROR`

对调用方无权获知的资源返回 `NOT_FOUND`，避免枚举。错误、日志与 MCP tool error 不得回显敏感输入。

SQLite 繁忙时执行有上限的短暂退避。超过上限返回 `STORAGE_BUSY` 与可重试标志。所有请求携带 request ID，便于对照审计与日志。

## 14. React 信息架构

主导航：

- 概览
- 凭据库
- 资产
- Agent
- 审计日志
- 成员与权限
- 设置

全局顶部提供当前 Space 切换。

### 14.1 凭据库

- 页面标题使用“凭据”，按钮使用“新建凭据”。
- 支持按显示名称、类型、标签、资产和状态过滤。
- 列表只显示元数据。
- 点击一行打开右侧详情抽屉。
- 明文默认隐藏，用户主动点击“显示”时才调用读取接口并产生单独审计。
- 前端不把已显示明文写入 URL、浏览器存储、日志或错误监控。

### 14.2 资产

- 显示设备元数据、环境、状态和标签。
- 详情页反查所有关联凭据。
- 从资产页创建凭据时自动带入 Space 和资产关联。

### 14.3 Agent

- 创建 Agent、生成一次性 Token、设置到期时间。
- 按 Space 和 Scope 授权，并可增加标签约束。
- 显示最近调用、错误、最后使用时间和吊销状态。

### 14.4 危险操作

- 删除、权限变化和创建 Token 使用明确确认对话框。
- 永久删除与高权限管理要求重新验证 TOTP。
- UI 不提供批量显示、复制或导出明文凭据。

桌面端优先。移动端 v1 保证登录、列表、查看和审计可用，但不优化复杂批量管理。

## 15. 网络与部署

- 公网和内网使用同一规范域名。
- 推荐 split-horizon DNS：内网解析到内网地址，公网解析到公网地址。
- 两种入口都必须使用 HTTPS，不提供明文 HTTP API。
- 只公开 Caddy 443；Go 监听 Docker 内部网络；SQLite 不暴露任何网络端口。
- CORS 默认只允许规范 Web origin。
- 登录、TOTP、Agent Token 校验和凭据读取分别限速。
- 连续认证失败触发临时锁定，但不能形成永久拒绝服务。

部署必须提供：

- 版本固定的容器镜像。
- Compose healthcheck。
- 数据卷和主密钥文件权限检查。
- 数据库迁移前备份。
- 安全的初始管理员引导。

## 16. SQLite 策略

- 启用 WAL。
- 启用 foreign keys。
- 配置 busy timeout。
- 使用单写者友好的短事务，不在事务中执行网络 I/O。
- 应用启动时运行快速完整性检查和 schema 版本检查。
- 只允许 OpsWarden 进程打开数据库文件。
- 不通过共享网络文件系统运行 SQLite。

v1 面向小团队和单机部署。如果持续写并发、数据库体积或高可用要求超过单机 SQLite 能力，再设计 PostgreSQL 迁移；v1 不提前实现双数据库抽象。

## 17. 备份与恢复

- 使用 SQLite Online Backup API 创建一致性快照，不直接复制运行中的数据库文件。
- 默认每日备份。
- 默认保留 7 份每日、4 份每周和 6 份每月备份。
- 备份成功后运行完整性检查并记录大小与校验和。
- 数据库备份不包含主密钥。
- 主密钥与数据库备份必须存放在不同位置，并分别控制访问。
- 管理界面显示最近备份、完整性检查和最近恢复演练状态。

恢复流程：

1. 在隔离环境准备同版本或兼容版本 OpsWarden。
2. 恢复 SQLite 快照。
3. 单独提供匹配的主密钥文件。
4. 以不开放公网的方式启动。
5. 运行数据库完整性检查。
6. 验证至少一项测试凭据可解密、审计可查询。
7. 吊销恢复环境产生的全部会话和 Agent Token，除非该环境成为正式接管节点。

至少每季度执行一次真实恢复演练。

## 18. 健康状态与可观测性

健康状态包括：

- 应用版本和启动时间。
- SQLite 可读写状态、WAL 状态和完整性检查时间。
- 主密钥加载状态，但不暴露内容或指纹。
- 磁盘剩余空间。
- 最近备份结果。
- 最近迁移结果。

日志采用结构化格式。敏感字段在进入 logger 前过滤，不依赖输出端正则清洗。健康 endpoint 分为公开的存活检查和需管理员权限的详细检查。

## 19. 测试策略

### 19.1 单元测试

- Argon2id 密码校验与参数升级。
- TOTP 验证、恢复码和时间窗口。
- Session 与 Agent Token 生成、哈希、到期和吊销。
- Space 角色和 Agent Scope 权限矩阵。
- 信封加密、AAD 绑定、密文篡改检测和主密钥轮换。
- 领域验证和错误映射。

### 19.2 集成测试

- SQLite 迁移、外键、WAL、事务和在线备份。
- 凭据写入与审计的原子性。
- 读取审计失败时不返回明文。
- 幂等创建、修改和删除。
- 并发修改的版本冲突。
- 回收站恢复和永久删除权限。
- REST 与 MCP 对同一操作产生一致业务结果。

### 19.3 前端端到端测试

- 首次管理员初始化。
- 密码 + TOTP 登录。
- Space 切换和角色约束。
- 五类凭据 CRUD。
- 资产与凭据双向关联。
- Agent 创建、Token 一次性展示、授权和吊销。
- 凭据显隐与审计记录。
- 回收站、备份状态和健康状态。

### 19.4 安全与发布测试

- 验证数据库、备份、日志、审计和错误中不存在测试凭据明文。
- 登录、TOTP、Token 和读取限速。
- CSRF、CORS、CSP 和安全 Cookie 属性。
- Go race detector、静态分析和依赖漏洞扫描。
- 前端依赖审计和生产构建。
- 容器非 root 运行、只读根文件系统可行性和最小权限。
- 完整的备份到新环境恢复演练。

## 20. 验收条件

v1 只有在以下条件全部满足时才可声明完成：

1. Docker Compose 可在干净 Linux 主机启动，并完成安全初始化。
2. 五类凭据及资产关联可通过 React 完成 CRUD。
3. Hermes Agent 可使用官方支持的远程 HTTP MCP 配置连接。
4. 具备授权的 Agent 可分别执行凭据 list、get、create、update 和软 delete。
5. 无授权 Agent 无法通过 ID、搜索或错误差异枚举其他 Space 的凭据。
6. Agent 重试不产生重复写入，并发更新不静默覆盖。
7. 每次凭据读取与写入都有不含敏感值的审计事件。
8. SQLite 文件、备份、日志和错误响应不包含凭据明文。
9. Token 与成员会话可以立即吊销。
10. 数据库快照和独立主密钥能够在新环境成功恢复。
11. 自动化测试、静态检查和安全负面测试通过。

## 21. 已知风险

- 宿主机 root 失陷后，攻击者可以读取主密钥和进程内明文。
- 获得 `credential:read` 的 Agent 可以把明文发送到模型提供商、日志或外部工具。OpsWarden 只能最小化权限并记录访问，不能控制已返回的数据。
- 明文资产元数据和凭据显示名称会暴露基础设施轮廓。
- 本地审计记录不能对抗宿主机管理员篡改。
- 单机 SQLite 和单 Caddy/Go 实例没有高可用能力。
- 自研凭据管理系统在正式保存高价值生产凭据前需要独立安全评审。

这些风险在 v1 中通过最小权限、独立 Agent Token、标签范围、完整审计、分离备份和明确部署边界降低，但不会被完全消除。
