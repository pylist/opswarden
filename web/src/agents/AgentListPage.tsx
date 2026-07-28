import { useCallback, useEffect, useRef, useState } from "react";

import {
  parseAgentUsage,
  parseItems,
  type AgentRecord,
  type AgentUsage,
} from "../admin-api";
import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import type { WorkflowAPI } from "../workflow-api";
import { AgentForm, AgentGrantForm } from "./AgentForm";
import { TokenRevealDialog } from "./TokenRevealDialog";

type Props = {
  api: WorkflowAPI;
  space: Space | null;
  systemRole: string;
  sessionActive?: boolean;
};

export function AgentListPage({
  api,
  space,
  systemRole,
  sessionActive = true,
}: Props) {
  const [items, setItems] = useState<AgentUsage[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [issuing, setIssuing] = useState<AgentUsage | null>(null);
  const [granting, setGranting] = useState<AgentUsage | null>(null);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const allowed =
    systemRole === "system_owner" || systemRole === "system_admin";

  const load = useCallback(async () => {
    if (!allowed || !sessionActive) return;
    const current = ++generation.current;
    controller.current?.abort();
    const request = new AbortController();
    controller.current = request;
    setState("loading");
    setError("");
    try {
      const value = await api.request<unknown>(apiPath(["agents"]), {
        signal: request.signal,
      });
      if (current !== generation.current) return;
      const parsed = parseItems(value, parseAgentUsage);
      if (!parsed) throw new Error("invalid response");
      setItems(parsed);
      setState("ready");
    } catch (caught) {
      if (current === generation.current) {
        setError(formatApiError(caught));
        setState("error");
      }
    } finally {
      if (controller.current === request) controller.current = null;
    }
  }, [allowed, api, sessionActive]);

  useEffect(() => {
    if (allowed && sessionActive) void load();
    return () => {
      generation.current += 1;
      controller.current?.abort();
      setIssuing(null);
      setGranting(null);
      setCreating(false);
    };
  }, [allowed, load, sessionActive]);

  useEffect(() => {
    setIssuing(null);
    setGranting(null);
  }, [space?.id, sessionActive]);

  function addCreated(agent: AgentRecord) {
    setItems((current) => [
      ...current,
      {
        agentId: agent.id,
        name: agent.name,
        tokenCount: 0,
        activeTokens: 0,
      },
    ].sort((left, right) => left.name.localeCompare(right.name, "zh-CN")));
  }

  if (!allowed) {
    return (
      <section className="content-card empty-state">
        <h2>Agent 管理</h2>
        <p>当前账号没有管理 Agent 的权限。</p>
      </section>
    );
  }

  return (
    <>
      <section className="workflow-toolbar">
        <div>
          <h2>Agent 身份</h2>
          <p className="muted">
            为 Hermes 等工具分配独立 Token，并按空间限制访问范围。
          </p>
        </div>
        <button
          className="primary-button"
          type="button"
          onClick={() => setCreating(true)}
        >
          创建 Agent
        </button>
      </section>
      {error && <p className="form-error" role="alert">{error}</p>}
      <section className="table-card" aria-label="Agent 列表">
        {state === "loading" ? (
          <p className="table-status" role="status">正在加载 Agent…</p>
        ) : items.length === 0 ? (
          <p className="table-status empty-state">尚未创建 Agent。</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>名称</th>
                  <th>Token</th>
                  <th>活跃 Token</th>
                  <th>最近使用</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.agentId}>
                    <td><strong>{item.name}</strong></td>
                    <td>{item.tokenCount}</td>
                    <td>{item.activeTokens}</td>
                    <td>{item.lastUsedAt ? formatTime(item.lastUsedAt) : "从未"}</td>
                    <td>
                      <div className="table-actions">
                        <button
                          className="text-button"
                          type="button"
                          onClick={() => setIssuing(item)}
                        >
                          创建 Token
                        </button>
                        {space && (
                          <button
                            className="text-button"
                            type="button"
                            onClick={() => setGranting(item)}
                          >
                            配置授权
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {state === "error" && (
        <button className="secondary-button top-gap" type="button" onClick={() => void load()}>
          重新加载
        </button>
      )}
      {creating && (
        <AgentForm
          api={api}
          onClose={() => setCreating(false)}
          onCreated={addCreated}
        />
      )}
      {issuing && (
        <TokenRevealDialog
          key={`${space?.id ?? "none"}:${issuing.agentId}`}
          api={api}
          agentID={issuing.agentId}
          agentName={issuing.name}
          onClose={() => setIssuing(null)}
          onChanged={() => void load()}
        />
      )}
      {granting && space && (
        <AgentGrantForm
          key={`${space.id}:${granting.agentId}`}
          api={api}
          agentID={granting.agentId}
          agentName={granting.name}
          space={space}
          onClose={() => setGranting(null)}
          onSaved={() => void load()}
        />
      )}
    </>
  );
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}
