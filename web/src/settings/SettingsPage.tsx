import { useEffect, useState } from "react";

import { ApiError, apiPath, formatApiError } from "../api/client";
import type { Me, Space } from "../api/types";
import type { WorkflowAPI } from "../workflow-api";

type Props = {
  api: WorkflowAPI;
  space: Space | null;
  principal: Me;
  sessionActive?: boolean;
};

type EndpointState =
  | { kind: "loading" }
  | { kind: "available" }
  | { kind: "unavailable"; message: string }
  | { kind: "error"; message: string };

export function SettingsPage({
  api,
  space,
  principal,
  sessionActive = true,
}: Props) {
  const [health, setHealth] = useState<EndpointState>({ kind: "loading" });
  const [backups, setBackups] = useState<EndpointState>({ kind: "loading" });
  const allowed =
    principal.systemRole === "system_owner" ||
    principal.systemRole === "system_admin";

  useEffect(() => {
    if (!allowed || !sessionActive) return;
    const controller = new AbortController();
    let active = true;
    setHealth({ kind: "loading" });
    setBackups({ kind: "loading" });

    void probe(api, apiPath(["health"]), controller.signal)
      .then((state) => {
        if (active) setHealth(state);
      });
    void probe(api, apiPath(["backups"]), controller.signal)
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
        <EndpointCard
          title="服务健康"
          state={health}
          unavailableTitle="健康检查尚未配置"
          unavailableCopy="Task 15 将接入数据库、磁盘、备份与运行状态；当前不展示推测指标。"
        />
        <EndpointCard
          title="备份管理"
          state={backups}
          unavailableTitle="备份管理尚未配置"
          unavailableCopy="Task 15 将接入在线备份、保留策略与恢复验证；当前没有可用备份数据。"
        />
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

async function probe(
  api: WorkflowAPI,
  path: string,
  signal: AbortSignal,
): Promise<EndpointState> {
  try {
    await api.request<unknown>(path, { signal });
    return { kind: "available" };
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

function EndpointCard({
  title,
  state,
  unavailableTitle,
  unavailableCopy,
}: {
  title: string;
  state: EndpointState;
  unavailableTitle: string;
  unavailableCopy: string;
}) {
  return (
    <section className="content-card settings-card">
      <h2>{title}</h2>
      {state.kind === "loading" ? (
        <p className="muted" role="status">正在检查服务能力…</p>
      ) : state.kind === "available" ? (
        <>
          <p className="status-success">管理端点已启用</p>
          <p className="muted">等待 Task 15 的已验证响应模型接入后展示数据。</p>
        </>
      ) : state.kind === "unavailable" ? (
        <>
          <p className="settings-state-title">
            {state.message || unavailableTitle}
          </p>
          {!state.message && <p className="muted">{unavailableCopy}</p>}
        </>
      ) : (
        <p className="form-error" role="alert">{state.message}</p>
      )}
    </section>
  );
}
