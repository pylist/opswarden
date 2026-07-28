import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  parseAuditRow,
  parseCursorItems,
  type AuditRow,
} from "../admin-api";
import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import { CursorFlow, mergeUniqueByID } from "../pagination";
import type { WorkflowAPI } from "../workflow-api";

type Props = {
  api: WorkflowAPI;
  space: Space | null;
  systemRole: string;
  sessionActive?: boolean;
};

type SupportedFilters = {
  actorType: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
};

const actionOptions = [
  "credential.read",
  "credential.create",
  "credential.update",
  "credential.delete",
  "credential.restore",
  "credential.purge",
  "agent.create",
  "agent.token.issue",
  "agent.token.revoke",
  "agent.grant.set",
  "membership.add",
  "membership.role.change",
  "membership.remove",
  "auth.login",
  "auth.totp.reverify",
];

export function AuditPage({
  api,
  space,
  systemRole,
  sessionActive = true,
}: Props) {
  const [items, setItems] = useState<AuditRow[]>([]);
  const [filters, setFilters] = useState<SupportedFilters>({
    actorType: "",
    actorId: "",
    action: "",
    resourceType: "",
    resourceId: "",
  });
  const [requestID, setRequestID] = useState("");
  const [result, setResult] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [nextCursor, setNextCursor] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const cursorFlow = useRef(new CursorFlow());
  const allowed = Boolean(space) && (
    space?.role === "owner" ||
    systemRole === "system_owner" ||
    systemRole === "system_admin"
  );

  const load = useCallback(async (after = "") => {
    if (!allowed || !space || !sessionActive) return;
    if (!after) {
      cursorFlow.current.reset();
      setItems([]);
      setNextCursor("");
    }
    const attempt = cursorFlow.current.begin(after);
    if (!attempt) {
      setError("请求失败，请检查网络连接后重试。");
      return;
    }
    const current = ++generation.current;
    controller.current?.abort();
    const request = new AbortController();
    controller.current = request;
    setLoading(true);
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["audit-events"], {
          spaceId: space.id,
          actorType: filters.actorType || undefined,
          actorId: filters.actorId || undefined,
          action: filters.action || undefined,
          resourceType: filters.resourceType || undefined,
          resourceId: filters.resourceId || undefined,
          after: after || undefined,
          limit: 100,
        }),
        { signal: request.signal },
      );
      if (current !== generation.current) return;
      const parsed = parseCursorItems(value, parseAuditRow);
      if (!parsed) throw new Error("invalid response");
      if (!cursorFlow.current.complete(attempt, parsed.nextCursor)) {
        throw new Error("invalid response");
      }
      setItems((existing) =>
        mergeUniqueByID(after ? existing : [], parsed.items)
      );
      setNextCursor(parsed.nextCursor ?? "");
    } catch (caught) {
      if (current === generation.current) setError(formatApiError(caught));
    } finally {
      cursorFlow.current.fail(attempt);
      if (controller.current === request) controller.current = null;
      if (current === generation.current) setLoading(false);
    }
  }, [
    allowed,
    api,
    filters.action,
    filters.actorId,
    filters.actorType,
    filters.resourceId,
    filters.resourceType,
    sessionActive,
    space,
  ]);

  useEffect(() => {
    if (allowed && sessionActive) void load();
    return () => {
      generation.current += 1;
      controller.current?.abort();
      cursorFlow.current.reset();
    };
  }, [allowed, load, sessionActive]);

  useEffect(() => {
    setItems([]);
    setNextCursor("");
    setRequestID("");
    setResult("");
    setFrom("");
    setTo("");
  }, [space?.id, sessionActive]);

  const visible = useMemo(() => {
    const after = from ? new Date(from).getTime() : Number.NEGATIVE_INFINITY;
    const before = to ? new Date(to).getTime() : Number.POSITIVE_INFINITY;
    return items.filter((item) => {
      const timestamp = new Date(item.createdAt).getTime();
      return (
        (!requestID || item.requestId.includes(requestID.trim())) &&
        (!result ||
          (result === "success" ? item.success : !item.success)) &&
        timestamp >= after &&
        timestamp <= before
      );
    });
  }, [from, items, requestID, result, to]);

  function changeFilter(key: keyof SupportedFilters, value: string) {
    const normalized = value.trim();
    if (filters[key] === normalized) return;
    generation.current += 1;
    controller.current?.abort();
    controller.current = null;
    cursorFlow.current.reset();
    setItems([]);
    setNextCursor("");
    setError("");
    setLoading(true);
    setFilters((current) => ({ ...current, [key]: normalized }));
  }

  if (!space) {
    return (
      <section className="content-card empty-state">
        <h2>审计日志</h2>
        <p>请先选择空间。</p>
      </section>
    );
  }
  if (!allowed) {
    return (
      <section className="content-card empty-state">
        <h2>审计日志</h2>
        <p>当前账号没有查看审计日志的权限。</p>
      </section>
    );
  }

  return (
    <>
      <section className="workflow-toolbar audit-toolbar">
        <div>
          <h2>审计事件</h2>
          <p className="muted">
            服务端筛选主体、动作和资源；请求 ID、时间与结果筛选当前已加载页。
          </p>
        </div>
      </section>
      <section className="content-card audit-filters" aria-label="审计筛选">
        <div className="filter-grid">
          <div>
            <label htmlFor="audit-actor-type">主体类型</label>
            <select
              id="audit-actor-type"
              value={filters.actorType}
              onChange={(event) => changeFilter("actorType", event.target.value)}
            >
              <option value="">全部</option>
              <option value="user">成员</option>
              <option value="agent">Agent</option>
              <option value="anonymous">匿名</option>
              <option value="system">系统维护</option>
            </select>
          </div>
          <div>
            <label htmlFor="audit-actor-id">主体 ID</label>
            <input
              id="audit-actor-id"
              value={filters.actorId}
              maxLength={256}
              autoComplete="off"
              onChange={(event) => changeFilter("actorId", event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="audit-action">动作</label>
            <select
              id="audit-action"
              value={filters.action}
              onChange={(event) => changeFilter("action", event.target.value)}
            >
              <option value="">全部</option>
              {actionOptions.map((action) => (
                <option key={action} value={action}>{action}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="audit-resource-type">资源类型</label>
            <input
              id="audit-resource-type"
              value={filters.resourceType}
              maxLength={128}
              autoComplete="off"
              onChange={(event) => changeFilter("resourceType", event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="audit-resource-id">资源 ID</label>
            <input
              id="audit-resource-id"
              value={filters.resourceId}
              maxLength={256}
              autoComplete="off"
              onChange={(event) => changeFilter("resourceId", event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="audit-request-id">请求 ID（当前页）</label>
            <input
              id="audit-request-id"
              value={requestID}
              maxLength={256}
              autoComplete="off"
              onChange={(event) => setRequestID(event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="audit-result">结果（当前页）</label>
            <select
              id="audit-result"
              value={result}
              onChange={(event) => setResult(event.target.value)}
            >
              <option value="">全部</option>
              <option value="success">成功</option>
              <option value="failure">失败</option>
            </select>
          </div>
          <div>
            <label htmlFor="audit-from">开始时间（当前页）</label>
            <input
              id="audit-from"
              type="datetime-local"
              value={from}
              onChange={(event) => setFrom(event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="audit-to">结束时间（当前页）</label>
            <input
              id="audit-to"
              type="datetime-local"
              value={to}
              onChange={(event) => setTo(event.target.value)}
            />
          </div>
        </div>
      </section>
      {error && <p className="form-error" role="alert">{error}</p>}
      <section className="table-card audit-table" aria-label="审计事件">
        {loading && items.length === 0 ? (
          <p className="table-status" role="status">正在加载审计事件…</p>
        ) : visible.length === 0 ? (
          <p className="table-status empty-state">没有符合条件的审计事件。</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>请求 ID</th>
                  <th>主体</th>
                  <th>动作</th>
                  <th>资源</th>
                  <th>结果</th>
                  <th>来源 IP</th>
                  <th>时间</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((item) => (
                  <tr key={item.id}>
                    <td><code>{item.requestId}</code></td>
                    <td>{actorLabel(item)}</td>
                    <td><code>{item.action}</code></td>
                    <td>{resourceLabel(item)}</td>
                    <td>
                      <span className={item.success ? "status-success" : "status-failure"}>
                        {item.success ? "成功" : `失败${item.errorCode ? ` · ${item.errorCode}` : ""}`}
                      </span>
                    </td>
                    <td>{item.sourceIp}</td>
                    <td>{formatTime(item.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {nextCursor && (
        <button
          className="secondary-button top-gap"
          type="button"
          disabled={loading}
          onClick={() => void load(nextCursor)}
        >
          {loading ? "正在加载…" : "加载更多审计事件"}
        </button>
      )}
      {error && !nextCursor && (
        <button
          className="secondary-button top-gap"
          type="button"
          disabled={loading}
          onClick={() => void load()}
        >
          重新加载审计
        </button>
      )}
    </>
  );
}

function actorLabel(item: AuditRow) {
  const type = item.actorType === "user"
    ? "成员"
    : item.actorType === "agent"
      ? "Agent"
      : item.actorType === "system"
        ? "系统维护"
        : "匿名";
  return item.actorId ? `${type} · ${item.actorId}` : type;
}

function resourceLabel(item: AuditRow) {
  return item.resourceId
    ? `${item.resourceType} · ${item.resourceId}`
    : item.resourceType;
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}
