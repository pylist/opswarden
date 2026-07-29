# OpsWarden 单机运维手册

本手册适用于 Linux 主机上的 Docker Engine 与 Docker Compose v2。示例假定仓库位于
`/opt/opswarden`，持久化目录位于 `/srv/opswarden`。如果修改路径，必须同时修改
`deploy/.env`。不要把主密钥、密码、TOTP seed、恢复码、浏览器 JWT 或 Agent Token
粘贴到聊天、命令参数、工单或终端历史中；使用受限文件、隐藏输入框或密码管理器。

## 1. 主机、DNS 与目录

最低前提：

- 64 位 Linux、Docker Engine、Docker Compose v2.24.4 或更高版本。
- 规范主机名同时用于内外网；推荐 split-horizon DNS。
- 入站只放行 TCP 443。Caddy 通过 443 上的 TLS-ALPN-01 获取证书，不要求映射 80。
- Caddy 需要出站 DNS 与 HTTPS 访问证书颁发机构。
- 主机安装 `openssl`、`sqlite3`、`sha256sum`、`python3`、`findmnt`；它们只用于
  主机运维，不进入应用镜像。

以 root 执行一次目录准备。`10001` 是 OpsWarden 容器 UID/GID，`10002` 是 Caddy
容器 UID/GID：

```bash
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/opswarden/state \
  /srv/opswarden/state/data \
  /srv/opswarden/state/backups \
  /srv/opswarden/secrets \
  /srv/opswarden/preupgrade
sudo install -d -o 10002 -g 10002 -m 0700 \
  /srv/opswarden/caddy \
  /srv/opswarden/caddy/data \
  /srv/opswarden/caddy/config
sudo find /srv/opswarden -maxdepth 3 -type d -exec stat -c '%u:%g %a %n' {} \;
if ! state_fstype="$(
  findmnt --noheadings --output FSTYPE --target /srv/opswarden/state
)"; then
  echo "无法识别 SQLite state 所在文件系统；拒绝继续部署" >&2
  exit 1
fi
case "$state_fstype" in
  ext2|ext3|ext4|xfs|btrfs|zfs|f2fs|bcachefs)
    ;;
  *)
    echo "未批准 SQLite state 文件系统：${state_fstype:-<empty>}" >&2
    exit 1
    ;;
esac
printf 'SQLite state filesystem: %s (local filesystem preflight passed)\n' \
  "$state_fstype"
```

数据库固定为 `/var/lib/opswarden/data/opswarden.db`，在线备份固定写入
`/var/lib/opswarden/backups`。二者在容器内是不同的 `0700` 私有目录，但共享唯一的
读写挂载 `/var/lib/opswarden`。上述检查只允许明确列出的本地文件系统，并对空值、
未知类型和网络/共享文件系统关闭失败。需要新增本地类型时，必须先由主机管理员确认
其 SQLite 锁与持久化语义，再显式加入允许列表。不要使用 NFS、SMB 或其他网络文件
系统保存 SQLite。

## 2. 生成主密钥与配置

以下命令直接把 32 字节随机值编码后写入文件，不会在终端显示密钥：

```bash
sudo -u '#10001' sh -c \
  'umask 077; openssl rand -base64 32 > /srv/opswarden/secrets/master.key'
sudo chown 10001:10001 /srv/opswarden/secrets/master.key
sudo chmod 0400 /srv/opswarden/secrets/master.key
sudo stat -c '%u:%g %a %n' /srv/opswarden/secrets/master.key
```

预期最后一行以 `10001:10001 400` 开头。Compose 本地 secret 实际使用只读 bind
mount；某些 Compose 实现不会应用 `uid/gid/mode` 字段，因此宿主机的所有权与
`0400` 权限是必要条件。应用还会拒绝符号链接、非普通文件、宽于 `0600` 的权限或
不是恰好 32 字节 base64 解码结果的内容。

把匹配主密钥的另一份副本存入独立的离线密钥保管系统；不要与数据库、在线备份或
Caddy 数据放在同一主机/介质。备份过程不会包含主密钥。

创建非敏感配置：

```bash
cd /opt/opswarden
cp deploy/.env.example deploy/.env
chmod 0600 deploy/.env
```

编辑 `deploy/.env`：

- `OPSWARDEN_HOSTNAME`：DNS 中的规范主机名，不含协议、端口或路径。
- `OPSWARDEN_TLS_EMAIL`：证书到期/故障通知邮箱。
- `OPSWARDEN_VERSION`：明确的发布版本，禁止使用 `latest`。
- `OPSWARDEN_REVISION`：该发布对应的完整 Git commit。
- `SOURCE_DATE_EPOCH`：建议填该 commit 的 Unix 时间戳。
- 四个 `*_PATH`：保持绝对 Linux 路径和上述所有权。
- 后端默认 `172.31.250.0/29`；如与现有 Docker 网段冲突，整体更换 subnet 和两个
  静态 IP。Compose 会从 `OPSWARDEN_CADDY_IP` 自动生成唯一受信代理 `/32`。
- `OPSWARDEN_INTERNAL_CIDRS`：正常运行留空；首次初始化时才临时设置。

Compose 向应用只传递严格解析器支持的七个变量：

| 变量 | 部署值 | 作用 |
| --- | --- | --- |
| `OPSWARDEN_LISTEN_ADDR` | `0.0.0.0:8080` | 仅在私有 Docker backend 监听 |
| `OPSWARDEN_DATA_DIR` | `/var/lib/opswarden/data` | SQLite 私有目录 |
| `OPSWARDEN_MASTER_KEY_FILE` | `/run/secrets/master.key` | 只读 Compose secret |
| `OPSWARDEN_BACKUP_DIR` | `/var/lib/opswarden/backups` | 与数据库目录分离 |
| `OPSWARDEN_TRUSTED_PROXY_CIDRS` | Caddy 静态 IP `/32` | 只信任 Caddy 的 X-Forwarded-For |
| `OPSWARDEN_INTERNAL_CIDRS` | 空或显式 CIDR | 仅控制首次 System Owner 来源 |
| `OPSWARDEN_DISABLE_AUDIT_RETENTION` | `false` | 保持一年审计清理 |

浏览器 JWT 没有配置项：它从主密钥按独立用途派生签名密钥，只存在浏览器内存，
不会设置 Cookie 或写入浏览器持久化存储。

## 3. 构建、启动与检查

先验证配置并构建固定版本：

```bash
cd /opt/opswarden
docker compose --env-file deploy/.env -f deploy/compose.yaml config --quiet
docker compose --env-file deploy/.env -f deploy/compose.yaml \
  build --pull=false opswarden caddy
docker image inspect "opswarden:$(sed -n 's/^OPSWARDEN_VERSION=//p' deploy/.env)" \
  --format 'user={{.Config.User}} entrypoint={{json .Config.Entrypoint}}'
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d
```

预期镜像用户是 `10001:10001`，entrypoint 是
`/usr/local/bin/opswarden`。状态、健康和日志：

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml ps
docker compose --env-file deploy/.env -f deploy/compose.yaml logs \
  --since=30m --no-color opswarden caddy
curl --fail --silent --show-error \
  "https://$(sed -n 's/^OPSWARDEN_HOSTNAME=//p' deploy/.env)/health/live"
docker compose --env-file deploy/.env -f deploy/compose.yaml port caddy 443
docker compose --env-file deploy/.env -f deploy/compose.yaml port opswarden 8080
```

最后一条应没有映射。只有 Caddy 发布宿主机 TCP `443:443`；应用 8080、SQLite 与
Docker backend 均不对宿主机发布。两个容器使用只读根文件系统、`cap_drop: ALL`、
`no-new-privileges`、数值 UID、受限 tmpfs 与自动重启。Caddy 通过独立 edge 网络
出站申请证书，OpsWarden 只连接 `internal: true` 的 backend。

## 4. 创建首次 System Owner

初始化接口只接受 loopback 或 `OPSWARDEN_INTERNAL_CIDRS` 中的真实客户端地址。
Caddy 只在固定 `/32` 后端地址上被信任，它会覆盖伪造的转发头。不要配置
`0.0.0.0/0`、`::/0`、整个 Docker bridge 或不必要的大网段。

在 `deploy/.env` 中临时填入执行初始化的工作站精确 IPv4 `/32` 或 IPv6 `/128`，
然后只重建应用容器：

```bash
cd /opt/opswarden
docker compose --env-file deploy/.env -f deploy/compose.yaml \
  up -d --force-recreate opswarden
curl --fail --silent --show-error \
  "https://$(sed -n 's/^OPSWARDEN_HOSTNAME=//p' deploy/.env)/api/v1/bootstrap/status"
```

在同一工作站浏览器打开规范 HTTPS 地址。设置页会在浏览器内生成 TOTP seed；使用
密码管理器和认证器完成创建，并立即把一次性恢复码保存到独立安全位置。不要通过
命令行 JSON、聊天或工单提交密码、seed 或恢复码。

创建成功后立刻把 `OPSWARDEN_INTERNAL_CIDRS=` 恢复为空并执行：

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml \
  up -d --force-recreate opswarden
docker compose --env-file deploy/.env -f deploy/compose.yaml ps
```

首次 Owner 已存在后接口也会拒绝再次初始化；清空 CIDR 仍可减少错误配置面。

## 5. 请求限制、MCP 与代理行为

Caddy 自动支持 WebSocket upgrade；`flush_interval -1` 让 MCP Streamable HTTP
响应低延迟透传。它不缓存或改写应用的 `Cache-Control: no-store` API 响应。
Caddy 不重复实现请求体限制，以免代理与应用规则分叉：

- 一般 JSON API：64 KiB。
- 凭据 JSON API：1 MiB。
- `/mcp`：1 MiB。
- 编码请求体、重复 JSON key、未知/非规范字段会被应用拒绝。

完整 MCP 配置和最小 scope 建议见 `docs/hermes-agent.md`。

## 6. 在线备份、列表与验证

应用启动 24 小时后执行第一次维护，以后每 24 小时使用 SQLite 在线备份机制生成
一致快照，并执行 `integrity_check`、SHA-256、权限/所有权检查和保留策略。默认保留
7 个日窗口、4 个 ISO 周窗口、6 个月窗口。新安装在首次成功备份前，详细健康状态
显示 degraded 是预期行为。

v1 没有手动备份 trigger API，也没有容器内备份 CLI；不要伪造 POST endpoint，
不要在应用运行时 `cp` 数据库/WAL。System Owner/Admin 可在“设置”页查看实际的
`GET /api/v1/backups` 和 `GET /api/v1/health` 结果。确认最近记录同时满足：

- `status` 为 `succeeded`；
- `verificationStatus` 为 `passed`；
- `retained` 为 `true`；
- 文件名、大小、checksum 与时间均存在；
- 详细健康中的数据库为 `ok`、journal mode 为 `wal`。

宿主机只读复核（不会打开运行中的数据库）：

```bash
sudo -u '#10001' find /srv/opswarden/state/backups -maxdepth 1 \
  -type f -name 'opswarden-*.sqlite3' -printf '%u:%g %m %s %TY-%Tm-%TdT%TH:%TM:%TSZ %f\n'
sudo -u '#10001' sha256sum /srv/opswarden/state/backups/opswarden-*.sqlite3
```

列表 API 只接受浏览器 Bearer JWT。优先使用设置页；如自动化调用，必须通过权限为
`0600` 的临时 curl config 文件注入 Authorization header，调用后立即删除，不能把
JWT 写入命令参数、历史或长期文件。

## 7. 升级前备份、升级与回滚

升级前先在设置页确认最近在线备份已验证。为得到与升级时刻一致的额外快照，优雅
停止应用后使用 `sqlite3 .backup`（SQLite Backup API），不要直接复制数据库文件：

```bash
set -euo pipefail
cd /opt/opswarden
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
docker compose --env-file deploy/.env -f deploy/compose.yaml stop opswarden
sudo -u '#10001' env \
  DATABASE=/srv/opswarden/state/data/opswarden.db \
  SNAPSHOT="/srv/opswarden/preupgrade/opswarden-${stamp}.sqlite3" \
  sh -c 'umask 077; sqlite3 "$DATABASE" ".timeout 5000" ".backup $SNAPSHOT"'
sudo -u '#10001' chmod 0600 \
  "/srv/opswarden/preupgrade/opswarden-${stamp}.sqlite3"
sudo -u '#10001' sqlite3 \
  "file:/srv/opswarden/preupgrade/opswarden-${stamp}.sqlite3?mode=ro&immutable=1" \
  'PRAGMA integrity_check;'
sudo -u '#10001' env SNAPSHOT="/srv/opswarden/preupgrade/opswarden-${stamp}.sqlite3" \
  sh -c 'sha256sum "$SNAPSHOT" > "$SNAPSHOT.sha256"'
```

`integrity_check` 必须只输出 `ok`。然后检出已审核的固定 release，填写其真实版本、
commit 和 commit 时间，验证后启动：

```bash
git fetch --tags --force
git checkout --detach '<approved-release-tag>'
git verify-tag '<approved-release-tag>'
git rev-parse HEAD
git show -s --format=%ct HEAD
# 将上两条输出分别写入 deploy/.env 的 OPSWARDEN_REVISION 与 SOURCE_DATE_EPOCH，
# 并把 OPSWARDEN_VERSION 写为该固定 release；不要使用 latest。
docker compose --env-file deploy/.env -f deploy/compose.yaml config --quiet
docker compose --env-file deploy/.env -f deploy/compose.yaml \
  build --pull=false opswarden caddy
docker compose --env-file deploy/.env -f deploy/compose.yaml \
  up -d --force-recreate opswarden caddy
docker compose --env-file deploy/.env -f deploy/compose.yaml ps
```

检查 `/health/live`、登录、详细健康、审计和一项测试凭据。应用启动会自动迁移 schema。
未确认旧版本支持新 schema 时，禁止只把镜像 tag 改回旧版并继续使用已迁移数据库。

需要回滚时，先停止应用，把迁移后的数据库/WAL/SHM 可恢复地移入事故目录，再恢复
升级前快照与旧的固定版本：

```bash
set -euo pipefail
cd /opt/opswarden
rollback_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -o 10001 -g 10001 -m 0700 \
  "/srv/opswarden/preupgrade/failed-${rollback_stamp}"
docker compose --env-file deploy/.env -f deploy/compose.yaml stop opswarden
sudo -u '#10001' env \
  ROLLBACK_DIR="/srv/opswarden/preupgrade/failed-${rollback_stamp}" \
  sh -eu -c 'for f in /srv/opswarden/state/data/opswarden.db /srv/opswarden/state/data/opswarden.db-wal /srv/opswarden/state/data/opswarden.db-shm; do
    if [ -e "$f" ]; then mv "$f" "$ROLLBACK_DIR/"; fi
  done'
sudo -u '#10001' install -m 0600 \
  '/srv/opswarden/preupgrade/<verified-preupgrade-file>.sqlite3' \
  /srv/opswarden/state/data/opswarden.db
# 检出旧的已验证 release，并把 deploy/.env 恢复到对应 version/revision/epoch。
docker compose --env-file deploy/.env -f deploy/compose.yaml \
  build --pull=false opswarden caddy
docker compose --env-file deploy/.env -f deploy/compose.yaml \
  up -d --force-recreate opswarden caddy
```

占位文件名必须由运维人员从已验证清单中明确替换，不能用“最新文件”通配符。主密钥
没有变化；如果同时更换了主密钥，必须恢复与该数据库快照匹配的独立密钥。

## 8. 每季度隔离恢复演练

演练使用独立 Compose project、独立后端网段、独立目录、从离线保管恢复的匹配密钥，
并只把 Caddy 暴露到 loopback `127.0.0.1:8443`。绝不能复用生产在线密钥文件或
生产读写目录。

```bash
sudo install -d -o 10001 -g 10001 -m 0700 \
  /srv/opswarden-restore/state/data \
  /srv/opswarden-restore/state/backups \
  /srv/opswarden-restore/secrets
sudo install -d -o 10002 -g 10002 -m 0700 \
  /srv/opswarden-restore/caddy/data \
  /srv/opswarden-restore/caddy/config
sudo -u '#10001' install -m 0600 \
  '/srv/opswarden/state/backups/<selected-verified-snapshot>.sqlite3' \
  /srv/opswarden-restore/state/data/opswarden.db
sudo install -o 10001 -g 10001 -m 0400 \
  '/path/from/independent-key-backup/matching-master.key' \
  /srv/opswarden-restore/secrets/master.key
sudo install -o "$(id -u)" -g "$(id -g)" -m 0600 \
  /opt/opswarden/deploy/.env.example /srv/opswarden-restore/.env
```

在 `/srv/opswarden-restore/.env` 中写入被恢复版本对应的固定
`OPSWARDEN_VERSION/REVISION/SOURCE_DATE_EPOCH`，并写入：

```dotenv
OPSWARDEN_HOSTNAME=localhost
OPSWARDEN_TLS_EMAIL=ops@example.com
OPSWARDEN_STATE_PATH=/srv/opswarden-restore/state
OPSWARDEN_MASTER_KEY_PATH=/srv/opswarden-restore/secrets/master.key
CADDY_DATA_PATH=/srv/opswarden-restore/caddy/data
CADDY_CONFIG_PATH=/srv/opswarden-restore/caddy/config
OPSWARDEN_BACKEND_SUBNET=172.31.251.0/29
OPSWARDEN_APP_IP=172.31.251.2
OPSWARDEN_CADDY_IP=172.31.251.3
OPSWARDEN_INTERNAL_CIDRS=
```

创建 `/srv/opswarden-restore/Caddyfile`：

```caddyfile
{
	admin off
	auto_https disable_redirects
	servers {
		protocols h1 h2
	}
}
localhost {
	tls internal
	header {
		-Server
		-Via
		Strict-Transport-Security "max-age=300"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		Permissions-Policy "camera=(), geolocation=(), microphone=()"
		X-Frame-Options "DENY"
		Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"
	}
	reverse_proxy opswarden:8080 {
		header_up X-Forwarded-For {remote_host}
		header_up X-Forwarded-Proto https
		flush_interval -1
	}
}
```

创建 `/srv/opswarden-restore/override.yaml`；`!override` 需要前述 Compose 版本：

```yaml
services:
  caddy:
    ports: !override
      - "127.0.0.1:8443:443/tcp"
    volumes: !override
      - /srv/opswarden-restore/Caddyfile:/etc/caddy/Caddyfile:ro
      - /srv/opswarden-restore/caddy/data:/data
      - /srv/opswarden-restore/caddy/config:/config
```

启动并验证：

```bash
cd /opt/opswarden
docker compose -p opswarden-restore \
  --env-file /srv/opswarden-restore/.env \
  -f deploy/compose.yaml -f /srv/opswarden-restore/override.yaml \
  config --quiet
docker compose -p opswarden-restore \
  --env-file /srv/opswarden-restore/.env \
  -f deploy/compose.yaml -f /srv/opswarden-restore/override.yaml \
  up -d --build
curl --insecure --fail --silent --show-error https://127.0.0.1:8443/health/live
```

浏览器只访问 `https://localhost:8443`，接受本次隔离演练的 Caddy 本地 CA。使用专用
演练账号验证：数据库完整性为 `ok`、至少一项指定测试凭据可解密、审计可查询。
不要在演练中创建真实 Token。记录演练日期、版本、snapshot checksum 和结论；若演练
产生任何会话/Token，在销毁前先通过 UI 吊销。

结束时先停止项目，再由两人复核准确路径后删除演练副本与演练密钥：

```bash
set -euo pipefail
docker compose -p opswarden-restore \
  --env-file /srv/opswarden-restore/.env \
  -f /opt/opswarden/deploy/compose.yaml \
  -f /srv/opswarden-restore/override.yaml down
remaining="$(
  docker compose -p opswarden-restore \
    --env-file /srv/opswarden-restore/.env \
    -f /opt/opswarden/deploy/compose.yaml \
    -f /srv/opswarden-restore/override.yaml \
    ps --status running --quiet
)"
if [ -n "$remaining" ]; then
  echo "恢复演练容器仍在运行；拒绝删除演练 state 或密钥" >&2
  exit 1
fi
sudo rm -f /srv/opswarden-restore/secrets/master.key
sudo rm -rf /srv/opswarden-restore/state \
  /srv/opswarden-restore/caddy \
  /srv/opswarden-restore/.env \
  /srv/opswarden-restore/Caddyfile \
  /srv/opswarden-restore/override.yaml
```

上述删除不可从应用恢复；数据库快照与匹配密钥的权威副本必须仍在独立备份系统。

## 9. 紧急吊销

当前人工会话：在 UI 选择“退出”，服务端会立即吊销当前 session，浏览器同时清空
内存 JWT。角色变更、成员移除和密码重置也会吊销相关会话，但 v1 没有“吊销该用户
全部会话”的管理 API。

Agent Token：如果创建 Token 的一次性对话框仍打开，输入最近 TOTP 后选择“立即吊销
Token”；调用实际的 `DELETE /api/v1/agents/{agentID}/tokens/{tokenID}`，后续请求立即
失败。v1 列表只显示汇总，不能从 UI 找回旧 Token ID。

如果 UI/API 不可用或无法定位泄漏 Token，只能执行以下离线、事务化应急流程。它不
伪造应用审计事件；必须同步记录到外部事故日志。先停止应用，脚本只显示非敏感 ID、
邮箱、Agent 名称和 Token 前缀，然后通过隐藏输入选择用户邮箱或 Agent ID：

```bash
set -euo pipefail
cd /opt/opswarden
docker compose --env-file deploy/.env -f deploy/compose.yaml stop opswarden
if sudo -u '#10001' python3 - /srv/opswarden/state/data/opswarden.db <<'PY'
import datetime
import getpass
import sqlite3
import sys

db = sys.argv[1]
conn = sqlite3.connect(f"file:{db}?mode=rw", uri=True, isolation_level=None)
conn.execute("PRAGMA foreign_keys=ON")
print("Users:")
for row in conn.execute("SELECT id, email FROM users WHERE deleted_at IS NULL ORDER BY email"):
    print(row)
print("Agents and token prefixes:")
for row in conn.execute("""
    SELECT a.id, a.name, t.id, t.token_prefix, t.revoked_at
      FROM agents a JOIN agent_tokens t ON t.agent_id = a.id
     ORDER BY a.name, t.created_at
"""):
    print(row)
with open("/dev/tty", "r", encoding="utf-8") as tty:
    print("revoke kind [user/agent]: ", end="", flush=True)
    kind = tty.readline().strip()
value = getpass.getpass("user email or exact agent id (hidden): ").strip()
now = datetime.datetime.now(datetime.timezone.utc).isoformat(
    timespec="microseconds"
).replace("+00:00", "Z")
conn.execute("BEGIN IMMEDIATE")
if kind == "user":
    cur = conn.execute("""
        UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?)
         WHERE user_id = (
             SELECT id FROM users WHERE normalized_email = lower(trim(?))
         )
           AND revoked_at IS NULL
    """, (now, value))
elif kind == "agent":
    cur = conn.execute("""
        UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?)
         WHERE agent_id = ?
           AND revoked_at IS NULL
    """, (now, value))
else:
    conn.rollback()
    raise SystemExit("invalid kind")
if cur.rowcount <= 0:
    conn.rollback()
    raise SystemExit("no active rows matched; application remains stopped")
conn.commit()
print(f"revoked rows: {cur.rowcount}")
conn.close()
PY
then
  docker compose --env-file deploy/.env -f deploy/compose.yaml up -d
else
  echo "吊销失败或没有活动记录；应用保持停止，请核对目标后重试。" >&2
  exit 1
fi
```

必须确认 `revoked rows` 大于 0，并在启动后检查登录/Agent 请求已经失败。该流程不会
读取、输出或修改凭据载荷，不会在应用运行时直接编辑 SQLite。

## 10. 主密钥丢失、轮换限制与灾难恢复

主密钥丢失且没有独立副本时，现有凭据和 TOTP seed 无法恢复；数据库备份、密码
hash 和密文都不能重建密钥。不要生成新密钥覆盖原文件，这只会让服务无法解密。
v1 内部具备数据密钥 rewrap 原语，但没有经过支持的在线轮换 API/CLI；不要手工修改
密文或数据库。轮换需要单独发布流程、安全评审、全量验证和可回滚计划。

灾难恢复使用与季度演练相同的顺序：在隔离主机部署快照对应的固定版本，恢复已验证
SQLite snapshot，从独立保管恢复匹配主密钥，以不开放公网的方式启动，验证
`integrity_check`、测试凭据解密和审计查询。确认接管后再切换规范 DNS/443；如果
恢复环境成为生产，立即吊销恢复期间产生的会话与 Agent Token，签发新 Token，并
重新建立独立数据库备份和主密钥备份。未经验证不得删除原主机、原 snapshot 或原
密钥副本。
