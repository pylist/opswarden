import {
  useEffect,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import {
  credentialTypeLabels,
  isCredentialDraft,
  isCredentialMetadata,
  type CredentialDraft,
  type CredentialMetadata,
  type WorkflowAPI,
} from "../workflow-api";
import { CredentialForm } from "./CredentialForm";
import { Modal } from "../layout/Modal";

type Props = {
  api: WorkflowAPI;
  metadata: CredentialMetadata;
  space: Space;
  sessionActive: boolean;
  onClose: () => void;
  onChanged: () => void;
  onOpenAsset?: (assetId: string) => void;
};

type Revealed = { metadata: CredentialMetadata; draft: CredentialDraft };

export function CredentialDrawer({
  api,
  metadata,
  space,
  sessionActive,
  onClose,
  onChanged,
  onOpenAsset,
}: Props) {
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "editing">("idle");
  const [error, setError] = useState("");
  const [copiedField, setCopiedField] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [deleting, setDeleting] = useState(false);
  const closeButton = useRef<HTMLButtonElement>(null);
  const lastButton = useRef<HTMLButtonElement>(null);
  const generation = useRef(0);
  const requestController = useRef<AbortController | null>(null);

  useEffect(() => {
    closeButton.current?.focus();
  }, []);

  useEffect(() => {
    generation.current += 1;
    requestController.current?.abort();
    setRevealed(null);
    setState("idle");
    setError("");
    setCopiedField("");
    setConfirmDelete(false);
    setConfirmation("");
  }, [metadata.id, sessionActive, space.id]);

  useEffect(() => {
    if (!sessionActive) onClose();
  }, [onClose, sessionActive]);

  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", close);
    return () => {
      generation.current += 1;
      requestController.current?.abort();
      setRevealed(null);
      document.removeEventListener("keydown", close);
    };
  }, [onClose]);

  async function reveal() {
    if (state === "loading") return;
    const current = ++generation.current;
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setState("loading");
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "credentials", metadata.id]),
        { signal: controller.signal },
      );
      if (current !== generation.current || !sessionActive) return;
      const parsed = parseDecrypted(value, metadata.id, space.id);
      if (!parsed) throw new Error("invalid response");
      setRevealed(parsed);
      setState("idle");
    } catch (caught) {
      if (current !== generation.current) return;
      setState("idle");
      setError(formatApiError(caught));
    } finally {
      if (requestController.current === controller) {
        requestController.current = null;
      }
    }
  }

  async function copy(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(key);
    } catch {
      setCopiedField("");
      setError("复制失败，请使用系统提供的安全复制方式。");
    }
  }

  async function remove() {
    if (deleting || confirmation !== metadata.displayName) return;
    setDeleting(true);
    setError("");
    try {
      await api.request(
        apiPath(["spaces", space.id, "credentials", metadata.id]),
        {
          method: "DELETE",
          body: {
            credentialId: metadata.id,
            expectedVersion: metadata.version,
          },
        },
      );
      setRevealed(null);
      onChanged();
      onClose();
    } catch (caught) {
      setError(formatApiError(caught));
    } finally {
      setDeleting(false);
    }
  }

  function trapFocus(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Tab") return;
    if (event.shiftKey && document.activeElement === closeButton.current) {
      event.preventDefault();
      lastButton.current?.focus();
    } else if (!event.shiftKey && document.activeElement === lastButton.current) {
      event.preventDefault();
      closeButton.current?.focus();
    }
  }

  const canWrite = space.role === "owner" || space.role === "editor";
  return (
    <>
      <button className="panel-backdrop" type="button" aria-label="关闭详情遮罩" onClick={onClose} />
      <aside
        className="detail-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="credential-drawer-title"
        onKeyDown={trapFocus}
      >
        <div className="drawer-header">
          <div>
            <p className="eyebrow">{credentialTypeLabels[metadata.type]}</p>
            <h2 id="credential-drawer-title">{metadata.displayName}</h2>
          </div>
          <button
            ref={closeButton}
            className="icon-button"
            type="button"
            aria-label="关闭凭据详情"
            onClick={onClose}
          >
            ×
          </button>
        </div>
        {state === "editing" && revealed ? (
          <CredentialForm
            api={api}
            space={space}
            initial={revealed}
            onCancel={() => setState("idle")}
            onSaved={() => {
              setRevealed(null);
              setState("idle");
              onChanged();
            }}
          />
        ) : (
          <>
            <dl className="detail-list">
              <div><dt>版本</dt><dd>{metadata.version}</dd></div>
              <div><dt>Space</dt><dd>{space.name}</dd></div>
              <div>
                <dt>标签</dt>
                <dd>{formatTags(metadata.tags)}</dd>
              </div>
              <div>
                <dt>关联资产</dt>
                <dd className="inline-links">
                  {metadata.assetIds.length
                    ? metadata.assetIds.map((id) => (
                        <button key={id} className="text-button" type="button" onClick={() => onOpenAsset?.(id)}>
                          {id}
                        </button>
                      ))
                    : "无"}
                </dd>
              </div>
            </dl>
            <section className="payload-panel" aria-label="凭据值">
              <div className="section-heading">
                <div>
                  <h3>凭据值</h3>
                  <p>默认隐藏；显示操作将写入审计日志。</p>
                </div>
                {!revealed && (
                  <button
                    className="secondary-button"
                    type="button"
                    disabled={state === "loading"}
                    onClick={() => void reveal()}
                  >
                    {state === "loading" ? "正在读取…" : "显示"}
                  </button>
                )}
              </div>
              {revealed && (
                <div className="revealed-fields">
                  {Object.entries(revealed.draft.payload).map(([key, raw]) => {
                    const value =
                      typeof raw === "object" ? JSON.stringify(raw) : String(raw ?? "");
                    return (
                      <div className="revealed-field" key={key}>
                        <label htmlFor={`revealed-${key}`}>{payloadLabel(key)}</label>
                        <div>
                          <input id={`revealed-${key}`} value={value} readOnly />
                          <button type="button" onClick={() => void copy(key, value)}>
                            {copiedField === key ? "已复制" : "复制"}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
            {canWrite && !metadata.deletedAt && (
              <div className="drawer-actions">
                <button
                  className="secondary-button"
                  type="button"
                  disabled={!revealed}
                  title={!revealed ? "请先显示凭据值" : undefined}
                  onClick={() => setState("editing")}
                >
                  编辑凭据
                </button>
                <button className="danger-button" type="button" onClick={() => setConfirmDelete(true)}>
                  移至回收站
                </button>
              </div>
            )}
            {error && <p className="form-error" role="alert">{error}</p>}
          </>
        )}
        <button
          ref={lastButton}
          className="sr-only"
          type="button"
          onClick={onClose}
        >
          关闭详情
        </button>
      </aside>
      {confirmDelete && (
        <Modal labelledBy="delete-title" compact onClose={() => setConfirmDelete(false)}>
            <h2 id="delete-title">确认移至回收站</h2>
            <p className="muted">输入凭据名称“{metadata.displayName}”以确认。此操作不会立即永久删除。</p>
            <label htmlFor="delete-confirmation">输入凭据名称以确认</label>
            <input
              id="delete-confirmation"
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
              autoFocus
            />
            <div className="button-row">
              <button
                className="danger-button"
                type="button"
                disabled={deleting || confirmation !== metadata.displayName}
                onClick={() => void remove()}
              >
                {deleting ? "正在删除…" : "确认删除"}
              </button>
              <button className="secondary-button" type="button" onClick={() => setConfirmDelete(false)}>
                取消
              </button>
            </div>
        </Modal>
      )}
    </>
  );
}

function parseDecrypted(
  value: unknown,
  credentialID: string,
  spaceID: string,
): Revealed | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as { metadata?: unknown; payload?: unknown };
  if (
    !isCredentialMetadata(candidate.metadata) ||
    candidate.metadata.id !== credentialID ||
    candidate.metadata.spaceId !== spaceID ||
    !isCredentialDraft(candidate.metadata.type, candidate.payload)
  ) {
    return null;
  }
  return {
    metadata: candidate.metadata,
    draft: {
      credentialType: candidate.metadata.type,
      payload: candidate.payload,
    } as CredentialDraft,
  };
}

function formatTags(tags: Record<string, string>) {
  const entries = Object.entries(tags);
  return entries.length ? entries.map(([key, value]) => `${key}=${value}`).join("、") : "无";
}

function payloadLabel(key: string) {
  const labels: Record<string, string> = {
    url: "网址", username: "用户名", password: "密码",
    totp_credential_id: "关联 TOTP", service: "服务", token: "Token",
    header_name: "Header 名称", expires_at: "到期时间", private_key: "私钥",
    public_key: "公钥", fingerprint: "指纹", passphrase: "口令",
    engine: "数据库引擎", host: "主机", port: "端口", database: "数据库名",
    parameters: "参数", connection_string: "完整连接串", issuer: "签发方",
    account: "账号", seed: "Seed", algorithm: "算法", digits: "位数", period: "周期",
  };
  return labels[key] ?? "字段";
}
