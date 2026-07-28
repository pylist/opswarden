import { useEffect, useState } from "react";

import { ApiError, apiPath, formatApiError } from "../api/client";
import type { Me, Space } from "../api/types";
import type { WorkflowAPI } from "../workflow-api";
import {
  parseBackupRuns,
  parseHealthDetail,
  type BackupRun,
  type HealthDetail,
} from "./contracts";

type Props = {
  api: WorkflowAPI;
  space: Space | null;
  principal: Me;
  sessionActive?: boolean;
};

type EndpointState<T> =
  | { kind: "loading" }
  | { kind: "available"; data: T }
  | { kind: "unavailable"; message: string }
  | { kind: "error"; message: string };

export function SettingsPage({
  api,
  space,
  principal,
  sessionActive = true,
}: Props) {
  const [health, setHealth] = useState<EndpointState<HealthDetail>>({
    kind: "loading",
  });
  const [backups, setBackups] = useState<EndpointState<BackupRun[]>>({
    kind: "loading",
  });
  const allowed =
    principal.systemRole === "system_owner" ||
    principal.systemRole === "system_admin";

  useEffect(() => {
    if (!allowed || !sessionActive) return;
    const controller = new AbortController();
    let active = true;
    setHealth({ kind: "loading" });
    setBackups({ kind: "loading" });

    void loadEndpoint(
      api,
      apiPath(["health"]),
      controller.signal,
      parseHealthDetail,
    )
      .then((state) => {
        if (active) setHealth(state);
      });
    void loadEndpoint(
      api,
      apiPath(["backups"]),
      controller.signal,
      (value) => parseBackupRuns(value)?.items ?? null,
    )
      .then((state) => {
        if (active) setBackups(state);
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [allowed, api, sessionActive]);

  if (!allowed) {
    return (
      <section className="content-card empty-state">
        <h2>系统设置</h2>
        <p>当前账号没有查看系统设置的权限。</p>
      </section>
    );
  }

  const roleLabel =
    principal.systemRole === "system_owner" ? "系统所有者" : "系统管理员";

  return (
    <>
      <section className="metric-grid settings-summary" aria-label="管理状态">
        <article className="metric-card">
          <p>系统角色</p>
          <strong className="metric-text">{roleLabel}</strong>
          <span>来自当前已验证会话</span>
        </article>
        <article className="metric-card">
          <p>当前空间</p>
          <strong className="metric-text">{space?.name ?? "未选择"}</strong>
          <span>{space ? `空间角色：${space.role}` : "请选择空间查看空间能力"}</span>
        </article>
        <article className="metric-card">
          <p>系统能力</p>
          <strong className="metric-text">管理</strong>
          <span>健康状态、备份与全局安全设置</span>
        </article>
      </section>
      <section className="settings-grid">
        <HealthCard state={health} />
        <BackupsCard state={backups} />
      </section>
      <section className="content-card">
        <h2>安全边界</h2>
        <dl className="detail-list">
          <div>
            <dt>浏览器认证</dt>
            <dd>短期 JWT 仅保存在当前页面内存，不使用认证 Cookie。</dd>
          </div>
          <div>
            <dt>权限来源</dt>
            <dd>系统角色与空间角色由服务端在每次请求中校验。</dd>
          </div>
          <div>
            <dt>高风险操作</dt>
            <dd>权限、Agent Token 和永久删除要求最近 TOTP 验证。</dd>
          </div>
        </dl>
      </section>
    </>
  );
}

async function loadEndpoint<T>(
  api: WorkflowAPI,
  path: string,
  signal: AbortSignal,
  parse: (value: unknown) => T | null,
): Promise<EndpointState<T>> {
  try {
    const response = await api.request<unknown>(path, { signal });
    const parsed = parse(response);
    if (!parsed) {
      throw new ApiError("INVALID_RESPONSE", "", 502);
    }
    return { kind: "available", data: parsed };
  } catch (caught) {
    if (caught instanceof ApiError && caught.status === 404) {
      return { kind: "unavailable", message: "" };
    }
    if (
      caught instanceof ApiError &&
      (caught.status === 401 || caught.status === 403)
    ) {
      return {
        kind: "unavailable",
        message: "当前账号没有查看该管理状态的权限。",
      };
    }
    return { kind: "error", message: formatApiError(caught) };
  }
}

function HealthCard({
  state,
}: {
  state: EndpointState<HealthDetail>;
}) {
  return (
    <section className="content-card settings-card">
      <h2>服务健康</h2>
      {state.kind === "loading" ? (
        <p className="muted" role="status">正在检查服务能力…</p>
      ) : state.kind === "available" ? (
        <dl className="detail-list">
          <Detail label="总体状态" value={state.data.status === "ok" ? "正常" : "降级"} />
          <Detail label="数据库" value={`${state.data.database} / ${state.data.journalMode}`} />
          <Detail
            label="数据库可用磁盘"
            value={formatBytes(state.data.databaseDiskFreeBytes)}
          />
          <Detail
            label="备份可用磁盘"
            value={formatBytes(state.data.backupDiskFreeBytes)}
          />
          <Detail label="迁移版本" value={String(state.data.migrationVersion)} />
          <Detail
            label="最近备份"
            value={state.data.lastBackup
              ? `${formatDate(state.data.lastBackup.completedAt)} / ${
                verificationStatus(state.data.lastBackup.verificationStatus)
              }`
              : "尚无成功备份"}
          />
          <Detail
            label="维护任务"
            value={state.data.maintenance?.running
              ? "正在运行"
              : state.data.maintenance?.errorCodes.length
                ? "最近一次部分失败"
                : "就绪"}
          />
        </dl>
      ) : state.kind === "unavailable" ? (
        <>
          <p className="settings-state-title">
            {state.message || "健康检查尚未配置"}
          </p>
          {!state.message && <p className="muted">当前没有可用的健康状态。</p>}
        </>
      ) : (
        <p className="form-error" role="alert">{state.message}</p>
      )}
    </section>
  );
}

function BackupsCard({ state }: { state: EndpointState<BackupRun[]> }) {
  return (
    <section className="content-card settings-card">
      <h2>备份管理</h2>
      {state.kind === "loading" ? (
        <p className="muted" role="status">正在读取备份记录…</p>
      ) : state.kind === "available" ? (
        state.data.length ? (
          <div className="settings-backup-list">
            {state.data.slice(0, 5).map((run) => (
              <div key={run.id} className="settings-backup-row">
                <span>{backupStatus(run.status)}</span>
                <strong>{run.completedAt ? formatDate(run.completedAt) : "进行中"}</strong>
                <small>
                  {run.sizeBytes ? formatBytes(run.sizeBytes) : run.errorCode ?? ""}
                  {" / "}
                  {verificationStatus(run.verificationStatus)}
                </small>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted">尚无备份运行记录。</p>
        )
      ) : state.kind === "unavailable" ? (
        <>
          <p className="settings-state-title">
            {state.message || "备份管理尚未配置"}
          </p>
          {!state.message && <p className="muted">当前没有可用的备份数据。</p>}
        </>
      ) : (
        <p className="form-error" role="alert">{state.message}</p>
      )}
    </section>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = -1;
  do {
    amount /= 1024;
    unit += 1;
  } while (amount >= 1024 && unit < units.length - 1);
  return `${amount.toFixed(1)} ${units[unit]}`;
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function backupStatus(status: BackupRun["status"]) {
  if (status === "succeeded") return "成功";
  if (status === "failed") return "失败";
  return "进行中";
}

function verificationStatus(
  status: BackupRun["verificationStatus"] | "passed" | "failed",
) {
  if (status === "passed") return "验证通过";
  if (status === "failed") return "验证失败";
  if (status === "retired") return "已清理";
  return "待验证";
}
