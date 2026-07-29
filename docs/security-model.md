# OpsWarden v1 安全模型

## 1. 保护目标与威胁主体

OpsWarden 保护凭据载荷、成员 TOTP seed、人工会话、Agent Token 和管理操作完整性。
主要威胁包括：未认证互联网客户端、低权限成员、scope 受限或已泄漏的 Agent
Token、跨 Space ID 枚举、重放/并发写入、XSS 后的 Token 获取、数据库或单份备份
泄漏、错误代理头、容器逃逸面和运维误操作。

以下不在 v1 防护边界内：

- 宿主机 root、Docker daemon 或内核失陷；
- 主密钥与 SQLite/备份同时泄漏；
- 已获 `credential:read` 的合法主体把明文发送到日志、模型提供商或其他工具；
- 本地主机管理员篡改 SQLite 审计记录；
- 单机故障、高可用和拒绝服务；
- 独立安全评审之前存放最高价值生产凭据。

## 2. 信任边界

```text
互联网/内网客户端
        |
   TLS TCP 443
        v
 Caddy（唯一公开端口、固定后端 IP）
        |
 internal Docker backend :8080
        v
 OpsWarden（认证、授权、审计、解密）
        |
 /var/lib/opswarden（SQLite + 在线备份）

宿主机受限 master.key --只读--> /run/secrets/master.key
```

Caddy 连接 edge 网络仅为证书申请提供出站能力；OpsWarden 只在
`internal: true` backend 上可见。应用只信任 Caddy 精确 `/32` 的
`X-Forwarded-For`，然后从右向左选择第一个非受信地址。攻击者直接伪造转发头不会
获得内部来源身份。首次 System Owner 还必须来自 loopback 或显式、短期配置的
内部 CIDR。

两个容器使用数值非 root 用户、只读根文件系统、受限 tmpfs、
`cap_drop: ALL` 和 `no-new-privileges`。OpsWarden 唯一的持久化读写挂载是
`/var/lib/opswarden`；主密钥是独立只读 secret。最终应用与 Caddy 镜像都基于固定
digest 的 distroless 静态层，只含静态服务程序、静态健康探针和最小运行时数据文件，
不含包管理器、shell、编译器、源代码或主密钥。Caddy 官方源镜像的
`cap_net_bind_service` 文件 capability 在构建阶段被移除；容器通过 namespaced
`ip_unprivileged_port_start=0` 以 UID 10002 绑定 443，仍保持 `cap_drop: ALL`。

## 3. TLS、反向代理与浏览器边界

Caddy 只发布宿主机 TCP `443:443`，不发布 80；自动 HTTPS 使用 443 上的
TLS-ALPN-01。规范主机名用于内外网，推荐 split-horizon DNS。响应去除 Server/Via
标识，并设置 HSTS、`nosniff`、`Referrer-Policy: no-referrer`、
`Permissions-Policy`、`X-Frame-Options: DENY` 与严格 CSP。

CSP 只允许同源脚本、样式、连接和字体；禁止 inline script/style、frame ancestor、
object、worker，限制 `base-uri` 与 `form-action`，并升级不安全请求。当前 Vite
产物只引用独立同源 JS/CSS 文件。Caddy 自动处理 WebSocket upgrade，并以立即 flush
方式代理 MCP streaming。应用的 `Cache-Control: no-store` API 响应原样保留。

请求体大小由理解 DTO 的应用层强制：一般 JSON 64 KiB，凭据 JSON 与 MCP 各
1 MiB。Caddy 不重复一套可能漂移的 body-limit 规则。CORS 默认不开放跨源。

## 4. 人工身份、JWT 与 TOTP

成员密码使用 Argon2id（64 MiB、3 iterations、parallelism 2、32-byte output、
独立 16-byte salt）。TOTP 默认 6 位/30 秒并限制时间窗口；seed 以身份领域独立
AAD 的信封加密保存。恢复码只保存 hash，使用一次立即失效。

登录返回最长 15 分钟的 HS256 JWT Bearer，签名 key 通过 HKDF-SHA256 从主密钥按
独立用途派生。验证固定 algorithm、issuer、audience、subject、session、签发和
到期 claims。浏览器不设置认证 Cookie；JWT 只在 React 进程内存中，不进入
`localStorage`、`sessionStorage`、IndexedDB 或 Service Worker。页面刷新/浏览器
重启需重新登录。

JWT 之外，每次请求仍查询服务端 session；数据库只保存随机 session ID/token 的
SHA-256 hash。退出、用户/角色变化、密码重置与显式吊销即时生效。会话有 8 小时
idle 与 24 小时 absolute expiry；权限、Token 和永久删除等高风险操作要求最近
5 分钟 TOTP。该设计降低持久化窃取面，但不能防止 XSS 在当前页面存活期间读取内存
Token，因此 CSP、短 JWT 和服务端即时吊销都不可省略。

## 5. 主密钥、信封加密与数据库泄漏

32 字节主密钥只存在受限宿主机文件并只读挂载。启动会检查文件类型、稳定 inode、
权限和 base64 长度；内容、fingerprint 与路径不会出现在健康响应或日志。JWT 派生
key 与数据加密用途分离。

每个凭据版本和成员 TOTP seed 使用独立随机 32 字节数据密钥。载荷通过
XChaCha20-Poly1305 加密，数据密钥再由主密钥封装；每层使用独立 24 字节 nonce。
AAD 绑定 credential ID、version、Space ID、类型或身份用途，防止密文跨记录移动。
明文只在获授权请求的 Go 进程内短暂存在。

单独泄漏 SQLite 或数据库备份不会直接暴露凭据载荷，但以下元数据保持明文：用户
邮箱、Space/资产/凭据显示名、标签、资产地址、审计动作、Token 前缀、时间与大小。
SQLite snapshot 因而仍是机密数据，必须加密传输、受限存储。主密钥与 snapshot
必须分开保管；同时泄漏即可解密。宿主机 root 可以读取文件和进程内明文，不在本
模型防护范围内。

## 6. Agent 授权、重试与撤销

每个 Agent 使用独立、至少 256 bit 随机的不透明 Bearer Token。完整值只在签发时
返回一次；数据库只保存 SHA-256 hash、短前缀、到期、吊销和最后使用时间。Token
每次请求都检查 Agent 与 token 状态，吊销即时生效。Agent 不复用人工 JWT。

授权是逐 Space scope，可再以必须匹配的 label 缩窄：

- `credential:list/read/create/update/delete`
- `asset:list/read`

Agent 不能管理成员/权限、永久删除、恢复、修改资产、批量读取明文或跨 Space 访问。
Hermes 的工具 include 只减少模型可见工具，不能替代服务端策略。

Agent 写入必须有唯一 `Idempotency-Key` 和不敏感 `reason`；update/delete 还必须带
`expected_version`。请求 fingerprint、结果资源 ID、version 与状态可进入幂等记录，
凭据请求/响应载荷不能进入。删除始终是单对象软删除。scope、label、版本和
idempotency 共同限制泄漏 Token 的破坏半径，但具备 `credential:read` 的 Agent
仍可外传已返回明文。

## 7. 审计链与 system actor 限制

凭据写入与对应审计在同一 SQLite transaction；读取必须先持久化审计事件才返回
明文，审计失败则读取失败。事件记录 request ID、主体、fingerprint/prefix、动作、
Space/资源、来源、结果、字段名和 Agent reason，不记录凭据值、主密钥、完整 Token、
完整 session ID 或 TOTP seed。

每日 maintenance 使用固定 system actor 与确定性 fingerprint，执行在线备份、
保留、30 天回收站清理、一年审计清理和过期 session/idempotency 清理。system
actor 不是可登录身份，也没有外部 Token。其确定性标识用于归因，不提供抗篡改性。

审计链保存在同一 SQLite，不能对抗宿主机管理员或离线数据库编辑。应急离线 session/
Token 吊销不会伪造应用审计，必须写入独立事故记录。需要抗管理员篡改时，应增加
外部 append-only 审计归档；这不属于 v1。

## 8. 备份、恢复与残余风险

运行中数据库只能由应用的 SQLite online backup 路径生成 snapshot；禁止直接复制
DB/WAL。备份使用私有 root-confined 目录、`0600` 文件、O_EXCL 临时文件、完整性
检查、SHA-256、fsync、无覆盖发布和严格 owner/type/mode/link 验证。恢复与升级前
离线快照使用 SQLite `.backup` API，而不是文件 copy。

恢复必须同时具有匹配 snapshot 与独立主密钥，在隔离网络以 snapshot 对应的同版本
或兼容版本启动，检查 integrity、测试凭据解密和审计，再决定接管。至少每季度演练。
恢复环境产生的会话与 Agent Token 必须吊销，除非环境正式成为生产。

残余风险包括：主密钥丢失不可恢复；v1 没有受支持的在线 key-rotation 接口；本地
审计可被 root 篡改；容器和单机 SQLite 无高可用；磁盘、内存、备份窗口和证书服务
可造成可用性故障；TLS 终止后的明文存在于同主机私有 backend；供应链仍依赖已固定
digest 的基础镜像与 npm/go lock 数据。生产上线前应进行独立代码、镜像、主机和
运维流程安全评审。
