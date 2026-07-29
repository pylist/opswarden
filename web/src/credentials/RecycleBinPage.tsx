import { useCallback, useEffect, useRef, useState } from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import { CursorFlow, mergeUniqueByID } from "../pagination";
import {
  credentialTypeLabels,
  parseCredentialMetadata,
  parseList,
  type CredentialMetadata,
  type WorkflowAPI,
} from "../workflow-api";
import { Modal } from "../layout/Modal";

type Props = {
  api: WorkflowAPI;
  space: Space;
  systemRole: string;
  sessionActive?: boolean;
  onBack?: () => void;
};

type PurgeOperation = {
  generation: number;
  controller: AbortController;
  phase: "reverify" | "purge";
  credentialID: string;
};

export function RecycleBinPage({
  api,
  space,
  systemRole,
  sessionActive = true,
  onBack,
}: Props) {
  const [items, setItems] = useState<CredentialMetadata[]>([]);
  const [error, setError] = useState("");
  const [busyID, setBusyID] = useState("");
  const [purging, setPurging] = useState<CredentialMetadata | null>(null);
  const [totp, setTotp] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [nextCursor, setNextCursor] = useState("");
  const [loadingMore, setLoadingMore] = useState(false);
  const generation = useRef(0);
  const requestController = useRef<AbortController | null>(null);
  const cursorFlow = useRef(new CursorFlow());
  const submitting = useRef(false);
  const operationGeneration = useRef(0);
  const purgeOperation = useRef<PurgeOperation | null>(null);
  const [purgePhase, setPurgePhase] = useState<
    "idle" | "reverify" | "purge"
  >("idle");

  const invalidatePurge = useCallback((force = false) => {
    const current = purgeOperation.current;
    if (current?.phase === "purge" && !force) return false;
    operationGeneration.current += 1;
    current?.controller.abort();
    purgeOperation.current = null;
    submitting.current = false;
    setPurgePhase("idle");
    setBusyID("");
    return true;
  }, []);

  const closePurge = useCallback(() => {
    if (!invalidatePurge()) return;
    setPurging(null);
    setTotp("");
    setConfirmation("");
  }, [invalidatePurge]);

  const load = useCallback(async (after = "") => {
    if (!after) {
      cursorFlow.current.reset();
      setNextCursor("");
    }
    const attempt = cursorFlow.current.begin(after);
    if (!attempt) {
      setError("请求失败，请检查网络连接后重试。");
      return;
    }
    const current = ++generation.current;
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    if (after) setLoadingMore(true);
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "credentials"], {
          deletedOnly: "true",
          limit: 100,
          ...(after ? { after } : {}),
        }),
        { signal: controller.signal },
      );
      if (current !== generation.current) return;
      const parsed = parseList(value, parseCredentialMetadata);
      if (
        !parsed ||
        parsed.items.some(
          (item) => item.spaceId !== space.id || !item.deletedAt,
        )
      ) {
        throw new Error("invalid response");
      }
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
      if (requestController.current === controller) {
        requestController.current = null;
      }
      if (current === generation.current) setLoadingMore(false);
    }
  }, [api, space.id]);

  useEffect(() => {
    void load();
    return () => {
      generation.current += 1;
      requestController.current?.abort();
      cursorFlow.current.reset();
      invalidatePurge(true);
      setPurging(null);
      setTotp("");
      setConfirmation("");
    };
  }, [invalidatePurge, load]);

  useEffect(() => {
    invalidatePurge(true);
    setPurging(null);
    setTotp("");
    setConfirmation("");
    if (!sessionActive) {
      generation.current += 1;
      requestController.current?.abort();
      cursorFlow.current.reset();
      setNextCursor("");
    }
  }, [invalidatePurge, sessionActive, space.id]);

  async function restore(item: CredentialMetadata) {
    if (busyID) return;
    setBusyID(item.id);
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "credentials", item.id, "restore"]),
        { method: "POST", body: { expectedVersion: item.version } },
      );
      const restored = parseCredentialMetadata(value);
      if (!restored || restored.id !== item.id || restored.spaceId !== space.id) {
        throw new Error("invalid response");
      }
      await load();
    } catch (caught) {
      setError(formatApiError(caught));
    } finally {
      setBusyID("");
    }
  }

  async function purge() {
    if (
      !purging ||
      submitting.current ||
      confirmation !== purging.displayName ||
      !/^\d{6,8}$/.test(totp)
    ) {
      return;
    }
    const target = purging;
    const operation: PurgeOperation = {
      generation: ++operationGeneration.current,
      controller: new AbortController(),
      phase: "reverify",
      credentialID: target.id,
    };
    purgeOperation.current?.controller.abort();
    purgeOperation.current = operation;
    submitting.current = true;
    setBusyID(target.id);
    setPurgePhase("reverify");
    setError("");
    try {
      await api.reverifyTOTP(totp, operation.controller.signal);
      if (!purgeOperationIsCurrent(purgeOperation.current, operation)) return;
      operation.phase = "purge";
      setPurgePhase("purge");
      await api.request(
        apiPath(["spaces", space.id, "credentials", target.id, "purge"]),
        {
          method: "POST",
          body: { expectedVersion: target.version },
          signal: operation.controller.signal,
        },
      );
      if (!purgeOperationIsCurrent(purgeOperation.current, operation)) return;
      purgeOperation.current = null;
      operationGeneration.current += 1;
      submitting.current = false;
      setPurgePhase("idle");
      setBusyID("");
      setPurging(null);
      setTotp("");
      setConfirmation("");
      await load();
    } catch (caught) {
      if (purgeOperationIsCurrent(purgeOperation.current, operation)) {
        setError(formatApiError(caught));
      }
    } finally {
      if (purgeOperationIsCurrent(purgeOperation.current, operation)) {
        purgeOperation.current = null;
        operationGeneration.current += 1;
        submitting.current = false;
        setPurgePhase("idle");
        setBusyID("");
      }
    }
  }

  const canRestore =
    space.role === "owner" ||
    systemRole === "system_admin" ||
    systemRole === "system_owner";

  return (
    <>
      <section className="workflow-toolbar">
        <div>
          <h2>回收站</h2>
          <p className="muted">软删除的凭据在保留期内可恢复。</p>
        </div>
        {onBack && <button className="secondary-button" type="button" onClick={onBack}>返回凭据列表</button>}
      </section>
      {error && <p className="form-error" role="alert">{error}</p>}
      <section className="table-card" aria-label="已删除凭据">
        {items.length === 0 ? (
          <p className="table-status empty-state">回收站为空。</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>显示名称</th><th>类型</th><th>删除时间</th><th>操作</th></tr></thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td>{item.displayName}</td>
                    <td>{credentialTypeLabels[item.type]}</td>
                    <td>{formatDate(item.deletedAt!)}</td>
                    <td className="table-actions">
                      {canRestore && (
                        <button className="text-button" type="button" disabled={Boolean(busyID)} onClick={() => void restore(item)}>
                          恢复
                        </button>
                      )}
                      {systemRole === "system_owner" && (
                        <button className="danger-link" type="button" disabled={Boolean(busyID)} onClick={() => setPurging(item)}>
                          永久删除
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {nextCursor && (
        <button
          className="secondary-button"
          type="button"
          disabled={loadingMore || Boolean(busyID)}
          onClick={() => void load(nextCursor)}
        >
          {loadingMore ? "正在加载…" : "加载更多已删除凭据"}
        </button>
      )}
      {purging && (
        <Modal labelledBy="purge-title" compact onClose={closePurge}>
            <h2 id="purge-title">重新验证 TOTP</h2>
            <p className="warning-copy">永久删除不可恢复。验证后将仅删除当前这项凭据。</p>
            <label htmlFor="purge-totp">TOTP 验证码</label>
            <input
              id="purge-totp"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={totp}
              onChange={(event) => setTotp(event.target.value.replace(/\D/g, "").slice(0, 8))}
            />
            <label htmlFor="purge-confirmation">输入凭据名称以确认</label>
            <input
              id="purge-confirmation"
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
            />
            <div className="button-row">
              <button
                className="danger-button"
                type="button"
                disabled={
                  purgePhase !== "idle" ||
                  confirmation !== purging.displayName ||
                  !/^\d{6,8}$/.test(totp)
                }
                onClick={() => void purge()}
              >
                {purgePhase === "purge" ? "正在永久删除…" : "确认永久删除"}
              </button>
              <button
                className="secondary-button"
                type="button"
                data-modal-initial-focus
                disabled={purgePhase === "purge"}
                onClick={closePurge}
              >
                取消
              </button>
            </div>
        </Modal>
      )}
    </>
  );
}

function purgeOperationIsCurrent(
  current: PurgeOperation | null,
  candidate: PurgeOperation,
) {
  return (
    current === candidate &&
    current.generation === candidate.generation &&
    !candidate.controller.signal.aborted
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}
