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
- 主机在标准 `/usr/bin` 安装 `git`、`gpg`、`sqlite3`，并安装 `openssl`、
  `sha256sum`、`python3`、`findmnt`；它们只用于主机运维，不进入应用镜像。release
  tag 使用受信 OpenPGP key 验证。

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

### 固定的 root-owned 运维辅助程序

任何以 root 或 `10001` 身份运行的 Python 辅助程序都只能来自固定 trust anchor，
不得直接执行 Git checkout/worktree 中的脚本。首次安装或每次升级 trust anchor
前，由非 root 部署操作员在固定、只读的
`/etc/opswarden/release-gnupg` keyring 中导入并人工核对发布公钥。以下函数以
`env -i` 建立完全显式的 Git 环境：固定绝对二进制、HOME/PATH/locale/keyring，
关闭 system/global config、replace-object、hooks、fsmonitor、外部 diff 与全局
attributes，并固定 OpenPGP verifier 和 fully-trusted key 策略。它不继承
`GIT_DIR`、`GIT_WORK_TREE`、object/alternate object directory、
`GIT_CONFIG_COUNT`、`GNUPGHOME` 或其他 `GIT_*` 注入。仓库本地
`.gitattributes` 仍可能存在，因此验证后只使用不运行 clean/smudge/diff 的
`cat-file`/`ls-tree` 原始对象 plumbing；绝不运行 checkout、worktree add、status
或 diff：

```bash
set -euo pipefail
cd /opt/opswarden
release_ref='<approved-signed-release-tag>'
expected_revision='<approved-full-revision>'
SAFE_GIT_CONFIG=(
  -c safe.directory=/opt/opswarden
  -c core.hooksPath=/dev/null
  -c core.fsmonitor=false
  -c core.attributesFile=/dev/null
  -c diff.external=
  -c fsck.skipList=/dev/null
  -c receive.fsck.skipList=/dev/null
  -c fetch.fsck.skipList=/dev/null
  -c gpg.format=openpgp
  -c gpg.program=/usr/bin/gpg
  -c gpg.minTrustLevel=fully
)
safe_git() {
  env -i \
    HOME=/nonexistent PATH=/usr/bin:/bin LC_ALL=C \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GNUPGHOME=/etc/opswarden/release-gnupg \
    /usr/bin/git --no-replace-objects \
    "${SAFE_GIT_CONFIG[@]}" -C /opt/opswarden "$@"
}
verified_blob_sha256() {
  local object_id="$1" object_size
  object_size="$(safe_git cat-file -s "$object_id")"
  safe_git cat-file blob "$object_id" |
    env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -c '
import hashlib, sys
object_id, size = sys.argv[1], int(sys.argv[2])
raw = sys.stdin.buffer.read(size + 1)
if len(raw) != size:
    raise SystemExit("raw blob size mismatch")
git_hash = hashlib.sha1() if len(object_id) == 40 else hashlib.sha256()
git_hash.update(b"blob " + str(size).encode("ascii") + b"\0" + raw)
if git_hash.hexdigest() != object_id:
    raise SystemExit("raw blob object ID mismatch")
print(hashlib.sha256(raw).hexdigest())
' "$object_id" "$object_size"
}
# 在进入此信任流程前，以已批准的普通 HTTPS/SSH 传输取得对象；这里不运行 fetch，
# 避免使用仓库中可能被篡改的 remote helper/URL 配置。
[ -z "$(safe_git for-each-ref --format='%(refname)' refs/replace/)" ] || {
  echo "repository 存在 refs/replace；拒绝信任或安装辅助程序" >&2
  exit 1
}
[ "$(safe_git cat-file -t "refs/tags/$release_ref")" = tag ] || {
  echo "release 必须是 annotated tag" >&2
  exit 1
}
safe_git verify-tag "refs/tags/$release_ref"
[ "$(safe_git rev-parse "refs/tags/${release_ref}^{commit}")" = "$expected_revision" ]
safe_git fsck --strict --no-reflogs "$expected_revision"
expected_tree="$(safe_git rev-parse "${expected_revision}^{tree}")"
expected_epoch="$(safe_git show -s --format=%ct "$expected_revision")"

# 每个 helper 只从已验证 commit 的 blob OID 流入固定 root installer。installer
# 从 stdin 写 root-owned 同目录临时文件，校验 size/SHA-256，fsync、fchown/fchmod，
# 再 atomic rename 并复核最终文件；它永不重读 operator-writable 路径。
sudo install -d -o root -g root -m 0755 /usr/local/libexec/opswarden
install_signed_blob() {
  local object_id="$1" destination="$2" expected_size expected_sha256
  [ "$(safe_git cat-file -t "$object_id")" = blob ]
  expected_size="$(safe_git cat-file -s "$object_id")"
  expected_sha256="$(verified_blob_sha256 "$object_id")"
  safe_git cat-file blob "$object_id" |
    sudo /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
      /usr/bin/python3 -I -c '
import hashlib, os, pathlib, stat, sys, tempfile
destination = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
size = int(sys.argv[3])
object_id = sys.argv[4]
fd, name = tempfile.mkstemp(prefix="." + destination.name + ".", dir=destination.parent)
try:
    digest = hashlib.sha256()
    git_hash = hashlib.sha1() if len(object_id) == 40 else hashlib.sha256()
    git_hash.update(b"blob " + str(size).encode("ascii") + b"\0")
    total = 0
    while total <= size:
        chunk = os.read(0, min(1048576, size + 1 - total))
        if not chunk:
            break
        digest.update(chunk)
        git_hash.update(chunk)
        total += len(chunk)
        view = memoryview(chunk)
        while view:
            view = view[os.write(fd, view):]
    if (total != size or digest.hexdigest() != expected or
        git_hash.hexdigest() != object_id):
        raise SystemExit("signed blob stream mismatch")
    os.fchown(fd, 0, 0)
    os.fchmod(fd, 0o755)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(name, destination)
    directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(directory_fd)
    os.close(directory_fd)
    metadata = os.lstat(destination)
    payload = destination.read_bytes()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
        metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o755 or
        len(payload) != size or hashlib.sha256(payload).hexdigest() != expected):
        raise SystemExit("installed trust anchor verification failed")
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(name)
    except FileNotFoundError:
        pass
' "$destination" "$expected_sha256" "$expected_size" "$object_id"
}
ops_blob="$(safe_git rev-parse "${expected_revision}:deploy/offline_ops.py")"
revoke_blob="$(safe_git rev-parse "${expected_revision}:deploy/offline_revoke.py")"
export_blob="$(safe_git rev-parse "${expected_revision}:deploy/release_export.py")"
install_signed_blob "$ops_blob" \
  /usr/local/libexec/opswarden/offline_ops.py
install_signed_blob "$revoke_blob" \
  /usr/local/libexec/opswarden/offline_revoke.py
install_signed_blob "$export_blob" \
  /usr/local/libexec/opswarden/release_export.py
sudo stat -c '%U:%G %a %n' \
  /usr/local/libexec/opswarden/offline_ops.py \
  /usr/local/libexec/opswarden/offline_revoke.py \
  /usr/local/libexec/opswarden/release_export.py
```

预期三行均为 `root:root 755`。辅助程序启动时还会自行拒绝符号链接、非普通文件、
非固定路径、非 root 所有或 group/other 可写的副本。不能先 `cmp` worktree 文件再
`sudo install` 同一路径；即使该路径在比较后被并发替换，以上安装器读取的仍是
`cat-file blob <OID>` 的单一对象流。

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
停止应用后运行仓库内受测试的离线辅助程序。辅助程序只接受规范绝对路径上的
`10001:10001`、`0600`、非空普通文件，拒绝符号链接、缺失/空文件、错误权限和损坏
数据库；它捕获 `PRAGMA integrity_check` 的完整输出并要求字节级恰好为 `ok\n`。
随后用 SQLite Backup API 建立 `0600` 快照，再次执行相同完整性检查，最后以独占
创建的 `0600` 文件保存 SHA-256 清单并同步到磁盘。任何一步失败都会删除不完整输出
并以非零状态退出，应用保持停止：

```bash
set -euo pipefail
cd /opt/opswarden
docker compose --env-file deploy/.env -f deploy/compose.yaml stop opswarden
sudo -u '#10001' -- /usr/bin/env -i \
  HOME=/nonexistent PATH=/usr/bin:/bin LC_ALL=C \
  /usr/bin/python3 -I \
  /usr/local/libexec/opswarden/offline_ops.py snapshot
```

命令只在源库、快照、清单三者都验证成功后输出两个明确文件名。立即把这两个文件名、
清单中的 SHA-256、当前完整 `git rev-parse HEAD` 和当前已验证 release tag 写入变更
记录；不得用“最新文件”通配符代替明确文件名。然后检出已审核的固定 release，填写
其真实版本、commit 和 commit 时间，验证后启动：

```bash
release_ref='<approved-release-tag>'
expected_revision='<approved-full-revision>'
# 在新的 shell 中逐字重新执行第 1 节的 SAFE_GIT_CONFIG、safe_git、
# annotated tag 验证和 install_signed_blob 流程。禁止 checkout/worktree/status/diff，
# 也禁止从当前目录复制 helper。记录其 expected_tree 与 expected_epoch。
# 将 expected_revision 与 expected_epoch 分别写入 deploy/.env 的
# OPSWARDEN_REVISION 与 SOURCE_DATE_EPOCH，
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
并只把 Caddy 暴露到 loopback `127.0.0.1:8443`。绝不能复用生产在线密钥文件、生产
读写目录或当前工作副本。选择快照时必须同时取得备份时记录的 SHA-256、与该快照
schema 兼容的签名 release tag，以及该 tag 对应的完整 HEAD revision；缺少任一项
就拒绝恢复。

使用已安装的 root-owned exporter，但以非 root 操作员身份和 isolated Python
执行。exporter 自己建立 hermetic Git 环境，验证 captured annotated tag OID 的
签名，逐个读取并立即重算 tag/commit/tree/blob 的 Git object ID，递归解析 canonical
tree，并从同一批已验证 blob 建立私有 staging。完成的 V2 manifest（object format、
tag/commit/tree/blob OID、mode、size、SHA-256、raw path）只经 stdout pipe 进入固定
root installer，不落到 operator-writable 文件：

```bash
set -euo pipefail
cd /opt/opswarden
release_ref='<recorded-signed-release-tag>'
expected_revision='<recorded-full-head-revision>'
recorded_sha256='<recorded-lowercase-snapshot-sha256>'
RESTORE_OPERATOR_UID="$(id -u)"
RESTORE_OPERATOR_GID="$(id -g)"
[ "$RESTORE_OPERATOR_UID" -ne 0 ] || {
  echo "release staging 必须由非 root 部署操作员创建" >&2
  exit 1
}
case "$expected_revision" in
  ''|*[!0-9a-f]*) echo "完整 revision 格式无效" >&2; exit 1 ;;
esac
case "${#expected_revision}" in 40|64) ;; *) echo "必须使用完整 revision" >&2; exit 1 ;; esac
case "$recorded_sha256" in
  ''|*[!0-9a-f]*) echo "SHA-256 格式无效" >&2; exit 1 ;;
esac
[ "${#recorded_sha256}" -eq 64 ] || { echo "SHA-256 长度无效" >&2; exit 1; }
[ ! -e /srv/opswarden-restore ] &&
  [ ! -e /srv/opswarden-restore-staging ] || {
  echo "隔离恢复目录已存在；先人工调查并按本节清理流程处理" >&2
  exit 1
}
sudo install -d -o root -g root -m 0755 /srv/opswarden-restore
sudo install -d -o "$RESTORE_OPERATOR_UID" -g "$RESTORE_OPERATOR_GID" -m 0700 \
  /srv/opswarden-restore-staging
install -d -m 0700 /srv/opswarden-restore-staging/release
sudo -u "#${RESTORE_OPERATOR_UID}" -- /usr/bin/env -i \
  HOME=/nonexistent PATH=/usr/bin:/bin LC_ALL=C \
  /usr/bin/python3 -I /usr/local/libexec/opswarden/release_export.py \
  "$release_ref" "$expected_revision" |
  sudo -- /usr/bin/env -i \
    HOME=/nonexistent PATH=/usr/bin:/bin LC_ALL=C \
    /usr/bin/python3 -I /usr/local/libexec/opswarden/offline_ops.py \
    install-manifest "$release_ref" "$expected_revision"
sudo -- /usr/bin/env -i \
  HOME=/nonexistent PATH=/usr/bin:/bin LC_ALL=C \
  /usr/bin/python3 -I /usr/local/libexec/opswarden/offline_ops.py \
  seal-release "$release_ref" "$expected_revision" \
  "$RESTORE_OPERATOR_UID" "$RESTORE_OPERATOR_GID"

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
sudo install -o "$RESTORE_OPERATOR_UID" -g "$RESTORE_OPERATOR_GID" -m 0600 \
  /dev/null /srv/opswarden-restore/restore.env
```

在 `/srv/opswarden-restore/restore.env` 中逐行写入以下完整内容。禁止从生产模板
直接复制后“稍后再改”；值不支持 shell 引号、展开或重复 key：

```dotenv
OPSWARDEN_HOSTNAME=localhost
OPSWARDEN_TLS_EMAIL=ops@example.com
OPSWARDEN_VERSION=<release-tag-without-leading-v>
OPSWARDEN_REVISION=<recorded-full-head-revision>
SOURCE_DATE_EPOCH=<exact-release-commit-epoch>
OPSWARDEN_STATE_PATH=/srv/opswarden-restore/state
OPSWARDEN_MASTER_KEY_PATH=/srv/opswarden-restore/secrets/master.key
CADDY_DATA_PATH=/srv/opswarden-restore/caddy/data
CADDY_CONFIG_PATH=/srv/opswarden-restore/caddy/config
OPSWARDEN_BACKEND_SUBNET=172.31.251.0/29
OPSWARDEN_APP_IP=172.31.251.2
OPSWARDEN_CADDY_IP=172.31.251.3
OPSWARDEN_INTERNAL_CIDRS=
OPSWARDEN_RESTORE_HOST_PORT=127.0.0.1:8443:443/tcp
```

写完后立即把实际文件封存。helper 从单一 `O_NOFOLLOW` fd 复制并验证，写入
root-owned、`0444`、规范固定的 `restore.sealed.env`；之后即使操作员替换
`restore.env`、符号链接或修改 shell 环境也不会改变有效 Compose 输入：

```bash
sudo -- /usr/bin/env -i \
  HOME=/nonexistent PATH=/usr/bin:/bin LC_ALL=C \
  /usr/bin/python3 -I /usr/local/libexec/opswarden/offline_ops.py \
  seal-env "$release_ref" "$expected_revision" \
  "$RESTORE_OPERATOR_UID" "$RESTORE_OPERATOR_GID"
```

隔离 Caddy 配置与 Compose override 固定为 immutable release 中的
`deploy/RestoreCaddyfile` 和 `deploy/restore.override.yaml`。不要在
`/srv/opswarden-restore` 另建或修改 override；preflight 验证 manifest-exact export，
而 host port 只能来自已严格验证的 `OPSWARDEN_RESTORE_HOST_PORT`。

在任何 Compose 配置、构建或启动之前执行统一 preflight。root helper 在整个
seal/preflight 生命周期中不执行任何 Git 命令；它只读取 root-owned `0444`
manifest 与 root-owned `0555` release，验证完整路径集合和每个 raw blob 的 mode、
size、SHA-256。因此恶意 local/system/global Git config、hooks、fsmonitor、
clean/smudge/diff filter、`.gitattributes`、`GIT_*` 环境与 replace ref 都不可能在
root 身份执行，Dockerfile、Compose、Caddy 和全部 build context 都来自已签名 tree。
它还验证恢复副本是
`10001:10001`、`0600`、规范、非空、
非符号链接的普通文件；实际 SHA-256 必须与记录值恒定时间比较相等，SQLite 完整性
输出必须恰好为 `ok\n`。它还以无 shell evaluation 的严格 parser 读取随后 Compose
使用的同一个 root-owned `restore.sealed.env`，拒绝重复/未知 key、模板默认值、生产 state/key、错误
revision/version/epoch、非私有文件、非 loopback 端口、错误私网/IP 或非空 bootstrap
CIDR。任一步不满足都会非零退出，且此时还没有启动任何容器：

```bash
sudo -- /usr/bin/env -i \
  HOME=/nonexistent PATH=/usr/bin:/bin LC_ALL=C \
  /usr/bin/python3 -I /usr/local/libexec/opswarden/offline_ops.py \
  restore-preflight "$release_ref" "$expected_revision" "$recorded_sha256"
```

preflight 成功后，只从 immutable release 构建和启动，不能引用
`/opt/opswarden/deploy/compose.yaml`：

```bash
/usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin \
  /usr/bin/docker compose -p opswarden-restore \
  --env-file /srv/opswarden-restore/restore.sealed.env \
  -f /srv/opswarden-restore/release/deploy/compose.yaml \
  -f /srv/opswarden-restore/release/deploy/restore.override.yaml \
  config --quiet
/usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin \
  /usr/bin/docker compose -p opswarden-restore \
  --env-file /srv/opswarden-restore/restore.sealed.env \
  -f /srv/opswarden-restore/release/deploy/compose.yaml \
  -f /srv/opswarden-restore/release/deploy/restore.override.yaml \
  up -d --build --wait --wait-timeout 120
curl --insecure --fail --silent --show-error \
  --resolve localhost:8443:127.0.0.1 \
  https://localhost:8443/health/live
```

浏览器只访问 `https://localhost:8443`，接受本次隔离演练的 Caddy 本地 CA。使用专用
演练账号验证：数据库完整性为 `ok`、至少一项指定测试凭据可解密、审计可查询。
不要在演练中创建真实 Token。记录演练日期、版本、snapshot checksum 和结论；若演练
产生任何会话/Token，在销毁前先通过 UI 吊销。

结束时先停止项目，再由两人复核准确路径后删除演练副本与演练密钥：

```bash
set -euo pipefail
/usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin \
  /usr/bin/docker compose -p opswarden-restore \
  --env-file /srv/opswarden-restore/restore.sealed.env \
  -f /srv/opswarden-restore/release/deploy/compose.yaml \
  -f /srv/opswarden-restore/release/deploy/restore.override.yaml down
remaining="$(
  /usr/bin/env -i HOME=/nonexistent PATH=/usr/bin:/bin \
    /usr/bin/docker compose -p opswarden-restore \
    --env-file /srv/opswarden-restore/restore.sealed.env \
    -f /srv/opswarden-restore/release/deploy/compose.yaml \
    -f /srv/opswarden-restore/release/deploy/restore.override.yaml \
    ps --all --quiet
)"
if [ -n "$remaining" ]; then
  echo "恢复演练仍有关联容器；拒绝删除 release、state 或密钥" >&2
  exit 1
fi
restore_root="$(readlink -f -- /srv/opswarden-restore)"
[ "$restore_root" = /srv/opswarden-restore ] &&
  [ -d /srv/opswarden-restore ] &&
  [ ! -L /srv/opswarden-restore ] || {
    echo "恢复根目录不是预期的规范非符号链接目录；拒绝删除" >&2
    exit 1
  }
if findmnt --noheadings --mountpoint /srv/opswarden-restore >/dev/null 2>&1; then
  echo "恢复根目录仍是挂载点；拒绝删除" >&2
  exit 1
fi
staging_root="$(readlink -f -- /srv/opswarden-restore-staging)"
[ "$staging_root" = /srv/opswarden-restore-staging ] &&
  [ -d /srv/opswarden-restore-staging ] &&
  [ ! -L /srv/opswarden-restore-staging ] || {
    echo "staging 根目录不是预期规范目录；拒绝清理" >&2
    exit 1
  }
sudo rm -f -- /srv/opswarden-restore/secrets/master.key
sudo rm -rf -- /srv/opswarden-restore/state \
  /srv/opswarden-restore/secrets \
  /srv/opswarden-restore/caddy \
  /srv/opswarden-restore/release
sudo rm -f -- /srv/opswarden-restore/restore.env \
  /srv/opswarden-restore/restore.sealed.env \
  /srv/opswarden-restore/release.manifest
sudo rmdir -- /srv/opswarden-restore
sudo rm -rf -- /srv/opswarden-restore-staging/release
sudo rmdir -- /srv/opswarden-restore-staging
```

上述删除不可从应用恢复；数据库快照、其受保护 checksum 记录、对应
release/revision/tree 和匹配密钥的权威副本必须仍在独立备份系统。任何 seal 或
preflight 失败都先保留 staging/release 现场调查，不要直接删除重试。

## 9. 紧急吊销

当前人工会话：在 UI 选择“退出”，服务端会立即吊销当前 session，浏览器同时清空
内存 JWT。角色变更、成员移除和密码重置也会吊销相关会话，但 v1 没有“吊销该用户
全部会话”的管理 API。

Agent Token：如果创建 Token 的一次性对话框仍打开，输入最近 TOTP 后选择“立即吊销
Token”；调用实际的 `DELETE /api/v1/agents/{agentID}/tokens/{tokenID}`，后续请求立即
失败。v1 列表只显示汇总，不能从 UI 找回旧 Token ID。

如果 UI/API 不可用或无法定位泄漏 Token，只能执行以下离线、事务化应急流程。它不
伪造应用审计事件；必须同步记录到外部事故日志。正常运行期间，授权管理员应在成员
加入时从成员 API/UI 对应记录中把稳定 user ID 写入受保护的应急身份清单，并在 Token
签发记录中保存 UI 显示的 token ID；不要保存原始 Token。user ID 是应用实际生成的
22 字符 canonical base64url（16 字节），token ID 是 `tok_` 加 32 位小写十六进制。
离线流程不接受邮箱、姓名、Agent ID、Token 前缀或近似 Unicode normalization。
不要把选择值放入参数、环境变量、shell history、管道或日志。
辅助程序必须以 root 启动：它先由 root 打开 root-owned `/dev/tty`，关闭回显并读取
kind 与选择值；随后依次清空 supplementary groups、降 GID/UID 至 `10001:10001` 并
验证实际/有效 UID、GID 和 groups，最后才打开规范、非符号链接、`10001:10001`、
`0600` 的 SQLite 文件。

```bash
set -euo pipefail
cd /opt/opswarden
docker compose --env-file deploy/.env -f deploy/compose.yaml stop opswarden
if sudo -- /usr/bin/env -i \
  HOME=/nonexistent PATH=/usr/bin:/bin LC_ALL=C \
  /usr/bin/python3 -I /usr/local/libexec/opswarden/offline_revoke.py
then
  docker compose --env-file deploy/.env -f deploy/compose.yaml up -d
else
  echo "吊销失败或没有活动记录；应用保持停止，请核对目标后重试。" >&2
  exit 1
fi
```

程序在 `BEGIN IMMEDIATE` 中先计算仍未吊销的匹配行，要求数量大于 0，随后更新并
要求实际 row count 完全相同；零行、计数变化、SQL/commit 错误或输入错误都会
rollback 并返回失败。只有确认 commit 后程序才以 0 退出，因此上面的 `then` 才会
重启服务。必须确认输出的 `revoked active rows` 大于 0，并在启动后检查登录/Agent
请求已经失败。选择值从不出现在 argv、env 或成功/失败输出；该流程不会读取、输出
或修改凭据载荷，也不会在应用运行时直接编辑 SQLite。

## 10. 主密钥丢失、轮换限制与灾难恢复

主密钥丢失且没有独立副本时，现有凭据和 TOTP seed 无法恢复；数据库备份、密码
hash 和密文都不能重建密钥。不要生成新密钥覆盖原文件，这只会让服务无法解密。
v1 内部具备数据密钥 rewrap 原语，但没有经过支持的在线轮换 API/CLI；不要手工修改
密文或数据库。轮换需要单独发布流程、安全评审、全量验证和可回滚计划。

灾难恢复必须逐条执行第 8 节的同一顺序和同一个 `offline_ops.py
restore-preflight`，不能简化为从当前 source 构建：先取得快照记录的 SHA-256、
签名 release tag 和完整 revision；由 root-owned exporter 在 isolated 非 root
Python 中验证 tag 并从同一批重哈希 raw objects 建立 pipe-only manifest 与
staging，再由固定 root helper seal 成 immutable root-owned release；恢复匹配密钥、
快照并封存实际 Compose env；在任何 Compose 启动前验证
release/revision、checksum 和字节级恰好为 `ok\n` 的完整性结果；最后只从该
immutable release 构建。先以不开放公网的方式验证测试凭据解密和审计查询，确认接管后再切换规范
DNS/443。如果恢复环境成为生产，立即吊销恢复期间产生的会话与 Agent Token，签发
新 Token，并重新建立独立数据库备份、受保护 checksum/版本记录和主密钥备份。
未经验证不得删除原主机、原 snapshot 或原密钥副本。

全新灾难主机还没有 trust anchor 时，先安装操作系统发行版提供的
`/usr/bin/git`、`/usr/bin/gpg` 和受信 release 公钥；把核对过的公钥导入固定
`/etc/opswarden/release-gnupg`，不执行任何仓库文件。以非 root 操作员逐字执行第
1 节的 `env -i` hermetic Git、拒绝 replace refs、annotated tag 验证和 raw
`cat-file blob <OID>` 流程；三个 helper 都只能经固定 stdin atomic installer
写入 `/usr/local/libexec/opswarden/`，不能从 checkout/worktree 路径复制。第一次
export 必须以非 root isolated Python 执行固定 exporter；privileged
install-manifest/seal-env/seal-release/preflight 只能执行固定 root-owned helper，
且 root helper 自身绝不运行 Git。任何一步失败都不得安装辅助程序、启动 Compose
或接触生产 DNS。

## 11. 一键发布验证

发布候选必须从仓库根目录执行 `make verify`。前置条件是 Go 1.24、Node.js 22、
npm、Python 3、可用的 Docker/Compose，以及可访问 Playwright 和已锁定基础镜像的
网络；首次运行会按 `tests/e2e/package-lock.json` 安装测试依赖和对应 Chromium。
不要预先创建 `.tmp/e2e` 或 `.artifacts/e2e`，harness 只会清理并重建这两个仓库内
专用目录。

验证顺序固定为 Go vet/race 与部署辅助程序测试、React 单测和生产构建、Compose
解析、固定参数镜像构建、三个串行 Playwright 场景及敏感值扫描。场景覆盖：

- 浏览器创建凭据，Hermes 风格 MCP Agent 读取、更新、软删除，随后在 UI 回收站和
  审计事件中验证同一资源；
- 对当前 Space 中不存在的 ID 与另一个 Space 中真实 ID 比较一致的 404 安全响应；
- 使用 SQLite 在线 Backup API 产生一致快照，将快照和独立保存的匹配 key 副本放入
  独立 Compose project，验证解密，再离线吊销恢复环境中的浏览器会话和 Agent Token。

成功时最后一行是
`sensitive fixture scan: clean (7 required artifact classes)`。扫描器以 `grep -q`
读取仅限当前用户的随机值文件，不会把密码、Token、私钥片段、连接串、TOTP seed、
session ID 或主密钥写入参数和输出；它检查运行中 SQLite、在线备份、应用/恢复日志、
审计导出、浏览器存储和捕获的 REST/MCP 错误体，并额外检查 Git 跟踪文件。

失败时先保留 `.artifacts/e2e` 和 `.tmp/e2e` 调查：

- `application.log` 用于本地测试服务启动问题；
- `restore-compose.log` 用于恢复容器、权限或 key 不匹配问题；
- Playwright trace 位于 `tests/e2e/test-results`；
- 扫描失败只报告“发现泄漏”，不会打印匹配内容。此时把整套产物视为敏感材料，
  不要上传 CI artifact 或粘贴日志，定位后删除专用目录并重新运行。

Playwright 的 webServer 退出时会终止本地服务；恢复测试的 `finally` 无条件执行
`docker compose down --volumes --remove-orphans`。若进程被强制杀死，可用
`docker compose -p opswarden-e2e-restore down --volumes --remove-orphans` 清理，
确认没有 `opswarden-e2e-restore` 容器或网络后，再删除 `.tmp/e2e` 和
`.artifacts/e2e`。
