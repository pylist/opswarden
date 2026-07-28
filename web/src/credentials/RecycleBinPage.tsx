import { useCallback, useEffect, useRef, useState } from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import {
  credentialTypeLabels,
  isCredentialMetadata,
  parseList,
  type CredentialMetadata,
  type WorkflowAPI,
} from "../workflow-api";
import { Modal } from "../layout/Modal";

type Props = {
  api: WorkflowAPI;
  space: Space;
  systemRole: string;
  onBack?: () => void;
};

export function RecycleBinPage({ api, space, systemRole, onBack }: Props) {
  const [items, setItems] = useState<CredentialMetadata[]>([]);
  const [error, setError] = useState("");
  const [busyID, setBusyID] = useState("");
  const [purging, setPurging] = useState<CredentialMetadata | null>(null);
  const [totp, setTotp] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const generation = useRef(0);
  const requestController = useRef<AbortController | null>(null);
  const submitting = useRef(false);

  const load = useCallback(async () => {
    const current = ++generation.current;
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "credentials"], {
          deletedOnly: 1,
          limit: 100,
        }),
        { signal: controller.signal },
      );
      if (current !== generation.current) return;
      const parsed = parseList(value, isCredentialMetadata);
      if (
        !parsed ||
        parsed.items.some(
          (item) => item.spaceId !== space.id || !item.deletedAt,
        )
      ) {
        throw new Error("invalid response");
      }
      setItems(parsed.items);
    } catch (caught) {
      if (current === generation.current) setError(formatApiError(caught));
    } finally {
      if (requestController.current === controller) {
        requestController.current = null;
      }
    }
  }, [api, space.id]);

  useEffect(() => {
    void load();
    return () => {
      generation.current += 1;
      requestController.current?.abort();
      setPurging(null);
      setTotp("");
      setConfirmation("");
    };
  }, [load]);

  async function restore(item: CredentialMetadata) {
    if (busyID) return;
    setBusyID(item.id);
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "credentials", item.id, "restore"]),
        { method: "POST", body: { expectedVersion: item.version } },
      );
      if (!isCredentialMetadata(value) || value.id !== item.id || value.spaceId !== space.id) {
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
    submitting.current = true;
    setBusyID(purging.id);
    setError("");
    try {
      await api.reverifyTOTP(totp);
      await api.request(
        apiPath(["spaces", space.id, "credentials", purging.id, "purge"]),
        {
          method: "POST",
          body: { expectedVersion: purging.version },
        },
      );
      setPurging(null);
      setTotp("");
      setConfirmation("");
      await load();
    } catch (caught) {
      setError(formatApiError(caught));
    } finally {
      submitting.current = false;
      setBusyID("");
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
      {purging && (
        <Modal labelledBy="purge-title" compact onClose={() => {
          setPurging(null);
          setTotp("");
          setConfirmation("");
        }}>
            <h2 id="purge-title">重新验证 TOTP</h2>
            <p className="warning-copy">永久删除不可恢复。验证后将仅删除当前这项凭据。</p>
            <label htmlFor="purge-totp">TOTP 验证码</label>
            <input
              id="purge-totp"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={totp}
              onChange={(event) => setTotp(event.target.value.replace(/\D/g, "").slice(0, 8))}
              autoFocus
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
                  busyID === purging.id ||
                  confirmation !== purging.displayName ||
                  !/^\d{6,8}$/.test(totp)
                }
                onClick={() => void purge()}
              >
                确认永久删除
              </button>
              <button className="secondary-button" type="button" onClick={() => {
                setPurging(null);
                setTotp("");
                setConfirmation("");
              }}>
                取消
              </button>
            </div>
        </Modal>
      )}
    </>
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}
