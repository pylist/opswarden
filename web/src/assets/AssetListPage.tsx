import { useCallback, useEffect, useRef, useState } from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import { CursorFlow, mergeUniqueByID } from "../pagination";
import {
  parseAsset,
  parseList,
  type Asset,
  type WorkflowAPI,
} from "../workflow-api";
import { AssetDetailPage } from "./AssetDetailPage";
import { AssetForm } from "./AssetForm";
import { Modal } from "../layout/Modal";

type Props = {
  api: WorkflowAPI;
  space: Space;
  initialAssetId?: string;
  onSelectionConsumed?: () => void;
  onCreateCredential?: (assetId: string) => void;
  onOpenCredential?: (credentialId: string) => void;
};

export function AssetListPage({
  api,
  space,
  initialAssetId,
  onSelectionConsumed,
  onCreateCredential,
  onOpenCredential,
}: Props) {
  const [items, setItems] = useState<Asset[]>([]);
  const [selectedID, setSelectedID] = useState(initialAssetId ?? "");
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const [type, setType] = useState("");
  const [environment, setEnvironment] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [nextCursor, setNextCursor] = useState("");
  const [loadingMore, setLoadingMore] = useState(false);
  const generation = useRef(0);
  const requestController = useRef<AbortController | null>(null);
  const cursorFlow = useRef(new CursorFlow());

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
    else setLoading(true);
    setError("");
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "assets"], {
          limit: 100,
          ...(after ? { after } : {}),
          ...(type ? { type } : {}),
          ...(environment ? { environment } : {}),
          ...(status ? { status } : {}),
        }),
        { signal: controller.signal },
      );
      if (current !== generation.current) return;
      const parsed = parseList(value, parseAsset);
      if (!parsed || parsed.items.some((item) => item.spaceId !== space.id || item.deletedAt)) {
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
      if (current === generation.current) setLoading(false);
      if (current === generation.current) setLoadingMore(false);
      if (requestController.current === controller) {
        requestController.current = null;
      }
    }
  }, [api, environment, space.id, status, type]);

  useEffect(() => {
    void load();
    return () => {
      generation.current += 1;
      requestController.current?.abort();
      cursorFlow.current.reset();
      setSelectedID("");
    };
  }, [load]);

  useEffect(() => {
    if (initialAssetId) setSelectedID(initialAssetId);
  }, [initialAssetId]);

  if (selectedID) {
    return (
      <AssetDetailPage
        api={api}
        assetId={selectedID}
        space={space}
        onBack={() => {
          setSelectedID("");
          onSelectionConsumed?.();
        }}
        onDeleted={() => void load()}
        onOpenCredential={onOpenCredential}
      />
    );
  }

  const canWrite = space.role === "owner" || space.role === "editor";
  const visible = items.filter((item) =>
    !search.trim() ||
    [item.name, item.hostname, item.environment, item.status, ...Object.entries(item.tags).flat()]
      .join(" ")
      .toLocaleLowerCase("zh-CN")
      .includes(search.trim().toLocaleLowerCase("zh-CN")),
  );
  return (
    <>
      <section className="workflow-toolbar" aria-label="资产操作">
        <div className="filter-row">
          <label className="sr-only" htmlFor="asset-search">搜索资产</label>
          <input id="asset-search" type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索名称、主机名或标签" />
          <label className="sr-only" htmlFor="asset-type-filter">资产类型</label>
          <input id="asset-type-filter" value={type} onChange={(event) => setType(event.target.value)} placeholder="类型" />
          <label className="sr-only" htmlFor="asset-environment-filter">环境</label>
          <input id="asset-environment-filter" value={environment} onChange={(event) => setEnvironment(event.target.value)} placeholder="环境" />
          <label className="sr-only" htmlFor="asset-status-filter">状态</label>
          <input id="asset-status-filter" value={status} onChange={(event) => setStatus(event.target.value)} placeholder="状态" />
        </div>
        {canWrite && (
          <button className="primary-button" type="button" onClick={() => setCreating(true)}>新建资产</button>
        )}
      </section>
      {error && <p className="form-error" role="alert">{error}</p>}
      <section className="table-card" aria-label="资产列表">
        <p className="muted">搜索仅筛选当前已加载的资产。</p>
        {loading ? <p className="table-status" role="status">正在加载资产…</p> : visible.length === 0 ? (
          <p className="table-status empty-state">没有符合条件的资产。</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>资产名称</th><th>类型</th><th>主机名</th><th>环境</th><th>状态</th></tr></thead>
              <tbody>
                {visible.map((item) => (
                  <tr key={item.id}>
                    <td><button className="row-link" type="button" onClick={() => setSelectedID(item.id)}>{item.name}</button></td>
                    <td>{item.type}</td><td>{item.hostname || "—"}</td><td>{item.environment || "—"}</td><td>{item.status || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {nextCursor && !loading && (
        <button
          className="secondary-button"
          type="button"
          disabled={loadingMore}
          onClick={() => void load(nextCursor)}
        >
          {loadingMore ? "正在加载…" : "加载更多资产"}
        </button>
      )}
      {creating && (
        <Modal labelledBy="new-asset-title" onClose={() => setCreating(false)}>
            <h2 id="new-asset-title">新建资产</h2>
            <AssetForm api={api} space={space} onCancel={() => setCreating(false)} onSaved={(asset) => {
              setCreating(false);
              setItems((current) => [asset, ...current]);
            }} />
        </Modal>
      )}
    </>
  );
}
