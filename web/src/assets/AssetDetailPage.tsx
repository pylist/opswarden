import { useCallback, useEffect, useRef, useState } from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import {
  credentialTypeLabels,
  parseAsset,
  parseCredentialMetadata,
  parseList,
  safeID,
  type Asset,
  type CredentialMetadata,
  type WorkflowAPI,
} from "../workflow-api";
import { CredentialForm } from "../credentials/CredentialForm";
import { AssetForm } from "./AssetForm";
import { Modal } from "../layout/Modal";

type Props = {
  api: WorkflowAPI;
  assetId: string;
  space: Space;
  onBack?: () => void;
  onDeleted?: () => void;
  onOpenCredential?: (credentialId: string) => void;
};

export function AssetDetailPage({
  api,
  assetId,
  space,
  onBack,
  onDeleted,
  onOpenCredential,
}: Props) {
  const [asset, setAsset] = useState<Asset | null>(null);
  const [credentials, setCredentials] = useState<CredentialMetadata[]>([]);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(false);
  const [creatingCredential, setCreatingCredential] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [credentialCursor, setCredentialCursor] = useState("");
  const [loadingMoreCredentials, setLoadingMoreCredentials] = useState(false);
  const generation = useRef(0);
  const requestController = useRef<AbortController | null>(null);
  const credentialGeneration = useRef(0);
  const credentialController = useRef<AbortController | null>(null);
  const requestedCredentialCursors = useRef(new Set<string>());

  const load = useCallback(async () => {
    if (!safeID.test(assetId) || !safeID.test(space.id)) return;
    const current = ++generation.current;
    credentialGeneration.current += 1;
    credentialController.current?.abort();
    requestedCredentialCursors.current.clear();
    setCredentialCursor("");
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    setError("");
    try {
      const [assetValue, credentialValue] = await Promise.all([
        api.request<unknown>(
          apiPath(["spaces", space.id, "assets", assetId]),
          { signal: controller.signal },
        ),
        api.request<unknown>(
          apiPath(["spaces", space.id, "assets", assetId, "credentials"], {
            limit: 100,
          }),
          { signal: controller.signal },
        ),
      ]);
      if (current !== generation.current) return;
      const linked = parseList(credentialValue, parseCredentialMetadata);
      const parsedAsset = parseAsset(assetValue);
      if (
        !parsedAsset ||
        parsedAsset.id !== assetId ||
        parsedAsset.spaceId !== space.id ||
        !linked ||
        linked.items.some((item) => item.spaceId !== space.id)
      ) {
        throw new Error("invalid response");
      }
      if (linked.nextCursor && requestedCredentialCursors.current.has(linked.nextCursor)) {
        throw new Error("invalid response");
      }
      setAsset(parsedAsset);
      setCredentials(linked.items);
      setCredentialCursor(linked.nextCursor ?? "");
    } catch (caught) {
      if (current === generation.current) setError(formatApiError(caught));
    } finally {
      if (requestController.current === controller) {
        requestController.current = null;
      }
    }
  }, [api, assetId, space.id]);

  useEffect(() => {
    void load();
    return () => {
      generation.current += 1;
      credentialGeneration.current += 1;
      requestController.current?.abort();
      credentialController.current?.abort();
      requestedCredentialCursors.current.clear();
      setAsset(null);
      setCredentials([]);
    };
  }, [load]);

  async function loadMoreCredentials() {
    const after = credentialCursor;
    if (!after || requestedCredentialCursors.current.has(after)) {
      setError("请求失败，请检查网络连接后重试。");
      return;
    }
    requestedCredentialCursors.current.add(after);
    const current = ++credentialGeneration.current;
    credentialController.current?.abort();
    const controller = new AbortController();
    credentialController.current = controller;
    setLoadingMoreCredentials(true);
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "assets", assetId, "credentials"], {
          limit: 100,
          after,
        }),
        { signal: controller.signal },
      );
      if (current !== credentialGeneration.current) return;
      const parsed = parseList(value, parseCredentialMetadata);
      if (
        !parsed ||
        parsed.items.some((item) => item.spaceId !== space.id) ||
        (parsed.nextCursor &&
          (parsed.nextCursor === after ||
            requestedCredentialCursors.current.has(parsed.nextCursor)))
      ) {
        throw new Error("invalid response");
      }
      setCredentials((existing) => mergeByID(existing, parsed.items));
      setCredentialCursor(parsed.nextCursor ?? "");
    } catch (caught) {
      if (current === credentialGeneration.current) {
        setError(formatApiError(caught));
      }
    } finally {
      if (credentialController.current === controller) {
        credentialController.current = null;
      }
      if (current === credentialGeneration.current) {
        setLoadingMoreCredentials(false);
      }
    }
  }

  async function remove() {
    if (!asset || deleting || confirmation !== asset.name) return;
    setDeleting(true);
    setError("");
    try {
      await api.request(apiPath(["spaces", space.id, "assets", asset.id]), {
        method: "DELETE",
        body: { assetId: asset.id, expectedVersion: asset.version },
      });
      onDeleted?.();
      onBack?.();
    } catch (caught) {
      setError(formatApiError(caught));
    } finally {
      setDeleting(false);
    }
  }

  if (!safeID.test(assetId)) {
    return <section className="content-card empty-state">资产标识无效</section>;
  }
  if (!asset) {
    return (
      <section className="content-card">
        {error ? <p className="form-error" role="alert">{error}</p> : <p role="status">正在加载资产…</p>}
      </section>
    );
  }

  const canWrite = space.role === "owner" || space.role === "editor";
  return (
    <>
      <section className="workflow-toolbar">
        <div>
          {onBack && <button className="text-button" type="button" onClick={onBack}>← 返回资产列表</button>}
          <h2>{asset.name}</h2>
          <p className="muted">{asset.hostname || "未设置主机名"} · {asset.environment || "未设置环境"}</p>
        </div>
        {canWrite && (
          <div className="button-row compact">
            <button className="secondary-button" type="button" onClick={() => setEditing(true)}>编辑资产</button>
            <button className="danger-button" type="button" onClick={() => setConfirmDelete(true)}>删除资产</button>
          </div>
        )}
      </section>
      {error && <p className="form-error" role="alert">{error}</p>}
      <section className="detail-grid">
        <article className="content-card detail-card">
          <h3>资产信息</h3>
          <dl className="detail-list">
            <div><dt>类型</dt><dd>{asset.type}</dd></div>
            <div><dt>操作系统</dt><dd>{asset.os || "—"}</dd></div>
            <div><dt>状态</dt><dd>{asset.status || "—"}</dd></div>
            <div><dt>IP</dt><dd>{asset.ips.join("、") || "—"}</dd></div>
            <div><dt>端口</dt><dd>{asset.ports.join("、") || "—"}</dd></div>
            <div><dt>备注</dt><dd>{asset.notes || "—"}</dd></div>
          </dl>
        </article>
        <article className="content-card detail-card">
          <div className="section-heading">
            <div><h3>关联凭据</h3><p>这里只展示元数据，不读取凭据值。</p></div>
            {canWrite && (
              <button className="primary-button" type="button" onClick={() => setCreatingCredential(true)}>
                新建凭据
              </button>
            )}
          </div>
          {credentials.length === 0 ? (
            <p className="empty-state">尚未关联凭据。</p>
          ) : (
            <ul className="linked-list">
              {credentials.map((item) => (
                <li key={item.id}>
                  <button type="button" onClick={() => onOpenCredential?.(item.id)}>
                    <span>{item.displayName}</span>
                    <small>{credentialTypeLabels[item.type]} · v{item.version}</small>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {credentialCursor && (
            <button
              className="secondary-button"
              type="button"
              disabled={loadingMoreCredentials}
              onClick={() => void loadMoreCredentials()}
            >
              {loadingMoreCredentials ? "正在加载…" : "加载更多关联凭据"}
            </button>
          )}
        </article>
      </section>
      {editing && (
        <Modal labelledBy="edit-asset-title" onClose={() => setEditing(false)}>
            <h2 id="edit-asset-title">编辑资产</h2>
            <AssetForm api={api} space={space} initial={asset} onCancel={() => setEditing(false)} onSaved={(next) => {
              setAsset(next);
              setEditing(false);
            }} />
        </Modal>
      )}
      {creatingCredential && (
        <Modal labelledBy="asset-credential-title" onClose={() => setCreatingCredential(false)}>
            <h2 id="asset-credential-title">新建凭据</h2>
            <CredentialForm
              api={api}
              space={space}
              prefillAssetId={asset.id}
              onCancel={() => setCreatingCredential(false)}
              onSaved={() => {
                setCreatingCredential(false);
                void load();
              }}
            />
        </Modal>
      )}
      {confirmDelete && (
        <Modal labelledBy="delete-asset-title" compact onClose={() => setConfirmDelete(false)}>
            <h2 id="delete-asset-title">确认删除资产</h2>
            <p className="muted">输入资产名称“{asset.name}”以确认。</p>
            <label htmlFor="asset-delete-confirmation">输入资产名称以确认</label>
            <input id="asset-delete-confirmation" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
            <div className="button-row">
              <button className="danger-button" type="button" disabled={deleting || confirmation !== asset.name} onClick={() => void remove()}>
                {deleting ? "正在删除…" : "确认删除"}
              </button>
              <button className="secondary-button" type="button" data-modal-initial-focus onClick={() => setConfirmDelete(false)}>取消</button>
            </div>
        </Modal>
      )}
    </>
  );
}

function mergeByID<T extends { id: string }>(existing: T[], incoming: T[]) {
  const ids = new Set(existing.map((item) => item.id));
  return [...existing, ...incoming.filter((item) => !ids.has(item.id))];
}
