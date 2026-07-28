import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { parseItems, parseMember, type Member } from "../admin-api";
import { apiPath, formatApiError } from "../api/client";
import type { Me, Space, SpaceRole } from "../api/types";
import { Modal } from "../layout/Modal";
import { safeID, type WorkflowAPI } from "../workflow-api";

type Props = {
  api: WorkflowAPI;
  space: Space;
  principal: Me;
  sessionActive?: boolean;
};

type Dialog =
  | { kind: "add" }
  | { kind: "change"; member: Member }
  | { kind: "remove"; member: Member };

type Operation = {
  generation: number;
  controller: AbortController;
  phase: "reverify" | "mutation";
};

const roleLabels: Record<SpaceRole, string> = {
  owner: "所有者",
  editor: "编辑者",
  reader: "只读",
};

export function MembersPage({
  api,
  space,
  principal,
  sessionActive = true,
}: Props) {
  const [members, setMembers] = useState<Member[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [userID, setUserID] = useState("");
  const [role, setRole] = useState<SpaceRole>("reader");
  const [totp, setTotp] = useState("");
  const [phase, setPhase] = useState<"idle" | "reverify" | "mutation">("idle");
  const generation = useRef(0);
  const requestController = useRef<AbortController | null>(null);
  const operationGeneration = useRef(0);
  const operation = useRef<Operation | null>(null);
  const submitting = useRef(false);
  const canManage =
    space.role === "owner" || principal.systemRole === "system_owner";

  const invalidateOperation = useCallback((force = false) => {
    if (operation.current?.phase === "mutation" && !force) return false;
    operationGeneration.current += 1;
    operation.current?.controller.abort();
    operation.current = null;
    submitting.current = false;
    setPhase("idle");
    return true;
  }, []);

  const load = useCallback(async () => {
    if (!sessionActive) return;
    const current = ++generation.current;
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setState("loading");
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "members"]),
        { signal: controller.signal },
      );
      if (current !== generation.current) return;
      const parsed = parseItems(value, parseMember);
      if (!parsed) throw new Error("invalid response");
      setMembers(parsed);
      setState("ready");
    } catch (caught) {
      if (current === generation.current) {
        setError(formatApiError(caught));
        setState("error");
      }
    } finally {
      if (requestController.current === controller) {
        requestController.current = null;
      }
    }
  }, [api, sessionActive, space.id]);

  useEffect(() => {
    if (sessionActive) void load();
    return () => {
      generation.current += 1;
      requestController.current?.abort();
      invalidateOperation(true);
      setDialog(null);
      setTotp("");
      setUserID("");
    };
  }, [invalidateOperation, load, sessionActive]);

  useEffect(() => {
    invalidateOperation(true);
    setDialog(null);
    setTotp("");
    setUserID("");
  }, [invalidateOperation, sessionActive, space.id]);

  function closeDialog() {
    if (!invalidateOperation()) return;
    setDialog(null);
    setTotp("");
    setUserID("");
    setRole("reader");
    setError("");
  }

  function openChange(member: Member) {
    setRole(member.role);
    setDialog({ kind: "change", member });
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (
      !dialog ||
      submitting.current ||
      !/^\d{6,8}$/.test(totp)
    ) {
      return;
    }
    const targetUserID =
      dialog.kind === "add" ? userID.trim() : dialog.member.userId;
    if (!safeID.test(targetUserID)) return;
    const current: Operation = {
      generation: ++operationGeneration.current,
      controller: new AbortController(),
      phase: "reverify",
    };
    operation.current?.controller.abort();
    operation.current = current;
    submitting.current = true;
    setPhase("reverify");
    setError("");
    try {
      await api.reverifyTOTP(totp, current.controller.signal);
      if (!operationCurrent(operation.current, current)) return;
      current.phase = "mutation";
      setPhase("mutation");
      if (dialog.kind === "add") {
        const value = await api.request<unknown>(
          apiPath(["spaces", space.id, "members"]),
          {
            method: "POST",
            body: { userId: targetUserID, role },
            signal: current.controller.signal,
          },
        );
        if (!operationCurrent(operation.current, current)) return;
        const created = parseMember(value);
        if (
          !created ||
          created.userId !== targetUserID ||
          created.role !== role
        ) {
          throw new Error("invalid response");
        }
        setMembers((existing) => [...existing, created]);
      } else if (dialog.kind === "change") {
        const value = await api.request<unknown>(
          apiPath([
            "spaces", space.id, "members", dialog.member.userId,
          ]),
          {
            method: "PATCH",
            body: {
              role,
              expectedVersion: dialog.member.version,
            },
            signal: current.controller.signal,
          },
        );
        if (!operationCurrent(operation.current, current)) return;
        const changed = parseMember(value);
        if (
          !changed ||
          changed.userId !== dialog.member.userId ||
          changed.role !== role ||
          changed.version <= dialog.member.version
        ) {
          throw new Error("invalid response");
        }
        setMembers((existing) =>
          existing.map((member) =>
            member.userId === changed.userId ? changed : member
          )
        );
      } else {
        await api.request(
          apiPath([
            "spaces", space.id, "members", dialog.member.userId,
          ]),
          {
            method: "DELETE",
            body: { expectedVersion: dialog.member.version },
            signal: current.controller.signal,
          },
        );
        if (!operationCurrent(operation.current, current)) return;
        setMembers((existing) =>
          existing.filter((member) => member.userId !== dialog.member.userId)
        );
      }
      operation.current = null;
      operationGeneration.current += 1;
      submitting.current = false;
      setPhase("idle");
      setTotp("");
      setUserID("");
      setDialog(null);
    } catch (caught) {
      if (operationCurrent(operation.current, current)) {
        setError(formatApiError(caught));
      }
    } finally {
      if (operationCurrent(operation.current, current)) {
        operation.current = null;
        operationGeneration.current += 1;
        submitting.current = false;
        setPhase("idle");
      }
    }
  }

  const ownerCount = members.filter((member) => member.role === "owner").length;

  return (
    <>
      <section className="workflow-toolbar">
        <div>
          <h2>空间成员</h2>
          <p className="muted">
            角色变更会立即影响权限并吊销相关会话。
          </p>
        </div>
        {canManage && (
          <button
            className="primary-button"
            type="button"
            onClick={() => {
              setRole("reader");
              setDialog({ kind: "add" });
            }}
          >
            添加成员
          </button>
        )}
      </section>
      {error && !dialog && <p className="form-error" role="alert">{error}</p>}
      <section className="table-card" aria-label="空间成员">
        {state === "loading" ? (
          <p className="table-status" role="status">正在加载成员…</p>
        ) : members.length === 0 ? (
          <p className="table-status empty-state">当前空间没有成员。</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>成员</th>
                  <th>用户 ID</th>
                  <th>角色</th>
                  <th>加入时间</th>
                  {canManage && <th>操作</th>}
                </tr>
              </thead>
              <tbody>
                {members.map((member) => {
                  const self = member.userId === principal.userId;
                  const onlyOwner =
                    member.role === "owner" && ownerCount === 1;
                  const protectedMember = self || onlyOwner;
                  return (
                    <tr key={member.userId}>
                      <td>
                        <strong>{member.email}</strong>
                        {protectedMember && (
                          <span className="member-note">
                            {self && onlyOwner
                              ? "当前账号 · 唯一所有者"
                              : self
                                ? "当前账号"
                                : "唯一所有者"}
                          </span>
                        )}
                      </td>
                      <td><code>{member.userId}</code></td>
                      <td>{roleLabels[member.role]}</td>
                      <td>{formatTime(member.createdAt)}</td>
                      {canManage && (
                        <td>
                          {!protectedMember && (
                            <div className="table-actions">
                              <button
                                className="text-button"
                                type="button"
                                aria-label={`修改 ${member.email} 的角色`}
                                onClick={() => openChange(member)}
                              >
                                修改角色
                              </button>
                              <button
                                className="danger-link"
                                type="button"
                                aria-label={`移除 ${member.email}`}
                                onClick={() => setDialog({ kind: "remove", member })}
                              >
                                移除
                              </button>
                            </div>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
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
      {dialog && (
        <Modal labelledBy="member-dialog-title" onClose={closeDialog} compact>
          <h2 id="member-dialog-title">
            {dialog.kind === "remove"
              ? "重新验证 TOTP"
              : dialog.kind === "change"
                ? "修改成员角色"
                : "添加成员"}
          </h2>
          <p className="muted">
            {dialog.kind === "remove"
              ? `确认从 ${space.name} 移除 ${dialog.member.email}。`
              : "权限操作需要最近五分钟内的 TOTP 验证。"}
          </p>
          <form className="workflow-form" onSubmit={(event) => void submit(event)}>
            {dialog.kind === "add" && (
              <>
                <label htmlFor="member-user-id">用户 ID</label>
                <input
                  id="member-user-id"
                  value={userID}
                  autoComplete="off"
                  required
                  onChange={(event) => setUserID(event.target.value)}
                />
              </>
            )}
            {dialog.kind !== "remove" && (
              <>
                <label htmlFor="member-role">角色</label>
                <select
                  id="member-role"
                  value={role}
                  onChange={(event) => setRole(event.target.value as SpaceRole)}
                >
                  <option value="reader">只读</option>
                  <option value="editor">编辑者</option>
                  <option value="owner">所有者</option>
                </select>
              </>
            )}
            <label htmlFor="member-totp">TOTP 验证码</label>
            <input
              id="member-totp"
              value={totp}
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6,8}"
              required
              onChange={(event) => setTotp(event.target.value)}
            />
            {error && <p className="form-error" role="alert">{error}</p>}
            <div className="button-row">
              <button
                className={dialog.kind === "remove" ? "danger-button" : "primary-button"}
                type="submit"
                disabled={phase !== "idle"}
              >
                {phase === "reverify"
                  ? "正在验证…"
                  : phase === "mutation"
                    ? "正在保存…"
                    : dialog.kind === "remove"
                      ? "验证并移除"
                      : dialog.kind === "change"
                        ? "验证并保存"
                        : "验证并添加"}
              </button>
              <button
                className="secondary-button"
                type="button"
                disabled={phase === "mutation"}
                onClick={closeDialog}
              >
                取消
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function operationCurrent(active: Operation | null, candidate: Operation) {
  return (
    active === candidate &&
    active.generation === candidate.generation &&
    !candidate.controller.signal.aborted
  );
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
  }).format(new Date(value));
}
