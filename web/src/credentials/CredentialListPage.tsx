import { useCallback, useEffect, useRef, useState } from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import { CursorFlow, mergeUniqueByID } from "../pagination";
import {
  credentialTypeLabels,
  credentialTypes,
  parseCredentialMetadata,
  parseList,
  type CredentialMetadata,
  type CredentialType,
  type WorkflowAPI,
} from "../workflow-api";
import { CredentialDrawer } from "./CredentialDrawer";
import { CredentialForm } from "./CredentialForm";
import { RecycleBinPage } from "./RecycleBinPage";
import { Modal } from "../layout/Modal";

type Props = {
  api: WorkflowAPI;
  space: Space;
  systemRole: string;
  sessionActive: boolean;
  prefillAssetId?: string;
  initialCredentialId?: string;
  onPrefillConsumed?: () => void;
  onSelectionConsumed?: () => void;
  onOpenAsset?: (assetId: string) => void;
};

export function CredentialListPage({
  api,
  space,
  systemRole,
  sessionActive,
  prefillAssetId,
  initialCredentialId,
  onPrefillConsumed,
  onSelectionConsumed,
  onOpenAsset,
}: Props) {
  const [items, setItems] = useState<CredentialMetadata[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<CredentialMetadata | null>(null);
  const [creating, setCreating] = useState(Boolean(prefillAssetId));
  const [recycle, setRecycle] = useState(false);
  const [search, setSearch] = useState("");
  const [type, setType] = useState<CredentialType | "">("");
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
    else setState("loading");
    setError("");
    setSelected(null);
    try {
      const value = await api.request<unknown>(
        apiPath(["spaces", space.id, "credentials"], {
          limit: 100,
          ...(after ? { after } : {}),
          ...(type ? { type } : {}),
        }),
        { signal: controller.signal },
      );
      if (current !== generation.current || !sessionActive) return;
      const parsed = parseList(value, parseCredentialMetadata);
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
      setState("ready");
    } catch (caught) {
      if (current !== generation.current) return;
      setError(formatApiError(caught));
      if (!after) setState("error");
    } finally {
      cursorFlow.current.fail(attempt);
      if (requestController.current === controller) {
        requestController.current = null;
      }
      if (current === generation.current) setLoadingMore(false);
    }
  }, [api, sessionActive, space.id, type]);

  useEffect(() => {
    void load();
    return () => {
      generation.current += 1;
      requestController.current?.abort();
      cursorFlow.current.reset();
      setSelected(null);
    };
  }, [load]);

  useEffect(() => {
    if (!sessionActive) {
      generation.current += 1;
      requestController.current?.abort();
      cursorFlow.current.reset();
      setNextCursor("");
      setSelected(null);
      setCreating(false);
    }
  }, [sessionActive]);

  useEffect(() => {
    if (prefillAssetId) setCreating(true);
  }, [prefillAssetId]);

  useEffect(() => {
    if (!initialCredentialId || state !== "ready") return;
    const requested = items.find((item) => item.id === initialCredentialId);
    if (requested) setSelected(requested);
    onSelectionConsumed?.();
  }, [initialCredentialId, items, onSelectionConsumed, state]);

  const canWrite = space.role === "owner" || space.role === "editor";
  const visible = items.filter((item) => {
    const needle = search.trim().toLocaleLowerCase("zh-CN");
    if (!needle) return true;
    return (
      item.displayName.toLocaleLowerCase("zh-CN").includes(needle) ||
      Object.entries(item.tags).some(([key, value]) =>
        `${key}=${value}`.toLocaleLowerCase("zh-CN").includes(needle),
      ) ||
      item.assetIds.some((id) => id.toLocaleLowerCase("zh-CN").includes(needle))
    );
  });

  if (recycle) {
    return (
      <RecycleBinPage
        api={api}
        space={space}
        systemRole={systemRole}
        sessionActive={sessionActive}
        onBack={() => setRecycle(false)}
      />
    );
  }

  return (
    <>
      <section className="workflow-toolbar" aria-label="凭据操作">
        <div className="filter-row">
          <label className="sr-only" htmlFor="credential-search">搜索凭据</label>
          <input
            id="credential-search"
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="搜索名称、标签或资产"
          />
          <label className="sr-only" htmlFor="credential-type-filter">按类型筛选</label>
          <select
            id="credential-type-filter"
            value={type}
            onChange={(event) => setType(event.target.value as CredentialType | "")}
          >
            <option value="">全部类型</option>
            {credentialTypes.map((item) => (
              <option key={item} value={item}>{credentialTypeLabels[item]}</option>
            ))}
          </select>
        </div>
        <div className="button-row compact">
          {(space.role === "owner" ||
            systemRole === "system_admin" ||
            systemRole === "system_owner") && (
            <button className="secondary-button" type="button" onClick={() => setRecycle(true)}>
              回收站
            </button>
          )}
          {canWrite && (
            <button className="primary-button" type="button" onClick={() => setCreating(true)}>
              新建凭据
            </button>
          )}
        </div>
      </section>
      <section className="table-card" aria-label="凭据列表">
        <p className="muted">搜索仅筛选当前已加载的凭据。</p>
        {state === "ready" && error && <p className="form-error" role="alert">{error}</p>}
        {state === "loading" && <p className="table-status" role="status">正在加载凭据元数据…</p>}
        {state === "error" && (
          <div className="table-status">
            <p className="form-error" role="alert">{error}</p>
            <button className="secondary-button" type="button" onClick={() => void load()}>重试</button>
          </div>
        )}
        {state === "ready" && visible.length === 0 && (
          <p className="table-status empty-state">没有符合条件的凭据。</p>
        )}
        {state === "ready" && visible.length > 0 && (
          <div className="table-scroll">
            <table>
              <thead><tr><th>显示名称</th><th>类型</th><th>标签</th><th>关联资产</th><th>版本</th></tr></thead>
              <tbody>
                {visible.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <button className="row-link" type="button" onClick={() => setSelected(item)}>
                        {item.displayName}
                      </button>
                    </td>
                    <td>{credentialTypeLabels[item.type]}</td>
                    <td>{Object.keys(item.tags).length || "—"}</td>
                    <td>{item.assetIds.length || "—"}</td>
                    <td>v{item.version}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {nextCursor && state === "ready" && (
        <button
          className="secondary-button"
          type="button"
          disabled={loadingMore}
          onClick={() => void load(nextCursor)}
        >
          {loadingMore ? "正在加载…" : "加载更多凭据"}
        </button>
      )}
      {selected && (
        <CredentialDrawer
          api={api}
          metadata={selected}
          space={space}
          sessionActive={sessionActive}
          onClose={() => setSelected(null)}
          onChanged={() => void load()}
          onOpenAsset={onOpenAsset}
        />
      )}
      {creating && (
        <Modal labelledBy="new-credential-title" onClose={() => {
          setCreating(false);
          onPrefillConsumed?.();
        }}>
            <h2 id="new-credential-title">新建凭据</h2>
            <CredentialForm
              api={api}
              space={space}
              prefillAssetId={prefillAssetId}
              onCancel={() => {
                setCreating(false);
                onPrefillConsumed?.();
              }}
              onSaved={() => {
                setCreating(false);
                onPrefillConsumed?.();
                void load();
              }}
            />
        </Modal>
      )}
    </>
  );
}
