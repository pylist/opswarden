import { useCallback, useEffect, useState, type FormEvent } from "react";

import type { ApiClient } from "../api/client";
import type { ListResponse, Space, SpaceRole } from "../api/types";

const roleLabels: Record<SpaceRole, string> = {
  owner: "所有者",
  editor: "编辑者",
  reader: "只读",
};

type SpaceSwitcherProps = {
  api: ApiClient;
  currentSpace: Space | null;
  onChange: (space: Space | null) => void;
};

export function SpaceSwitcher({
  api,
  currentSpace,
  onChange,
}: SpaceSwitcherProps) {
  const [spaces, setSpaces] = useState<Space[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [initialName, setInitialName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");

  const load = useCallback(async () => {
    setState("loading");
    try {
      const response = await api.request<ListResponse<Space>>("/api/v1/spaces");
      setSpaces(response.items);
      const requested = new URL(window.location.href).searchParams.get("space");
      const selected =
        response.items.find((space) => space.id === requested) ??
        response.items.find((space) => space.id === currentSpace?.id) ??
        response.items[0] ??
        null;
      onChange(selected);
      setState("ready");
    } catch {
      setState("error");
    }
  }, [api, currentSpace?.id, onChange]);

  useEffect(() => {
    void load();
    // A space reload is explicit after initial authentication.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function select(id: string) {
    const selected = spaces.find((space) => space.id === id) ?? null;
    onChange(selected);
    const url = new URL(window.location.href);
    if (selected) {
      url.searchParams.set("space", selected.id);
    } else {
      url.searchParams.delete("space");
    }
    window.history.replaceState({}, "", `${url.pathname}${url.search}`);
  }

  async function createInitialSpace(event: FormEvent) {
    event.preventDefault();
    if (!initialName.trim()) return;
    setCreating(true);
    setCreateError("");
    try {
      const created = await api.request<Space>("/api/v1/spaces", {
        method: "POST",
        body: { name: initialName.trim() },
      });
      setSpaces([created]);
      setInitialName("");
      onChange(created);
      const url = new URL(window.location.href);
      url.searchParams.set("space", created.id);
      window.history.replaceState({}, "", `${url.pathname}${url.search}`);
    } catch (error) {
      setCreateError(String(error));
    } finally {
      setCreating(false);
    }
  }

  if (state === "loading") {
    return <p className="switcher-status" role="status">正在加载空间…</p>;
  }
  if (state === "error") {
    return (
      <div className="switcher-error">
        <span>空间加载失败</span>
        <button type="button" onClick={() => void load()}>重新加载空间</button>
      </div>
    );
  }
  if (!spaces.length) {
    return (
      <form className="initial-space-form" onSubmit={createInitialSpace}>
        <label htmlFor="initial-space-name">初始空间名称</label>
        <input
          id="initial-space-name"
          value={initialName}
          onChange={(event) => setInitialName(event.target.value)}
          placeholder="例如：内部工具"
          required
        />
        <button className="primary-button" disabled={creating} type="submit">
          {creating ? "正在创建…" : "创建空间"}
        </button>
        {createError && <span className="inline-error" role="alert">{createError}</span>}
      </form>
    );
  }
  return (
    <div className="space-switcher">
      <label htmlFor="space-select">当前空间</label>
      <select
        id="space-select"
        value={currentSpace?.id ?? ""}
        onChange={(event) => select(event.target.value)}
      >
        {spaces.map((space) => (
          <option key={space.id} value={space.id}>{space.name}</option>
        ))}
      </select>
      {currentSpace && (
        <span className="role-badge">{roleLabels[currentSpace.role]}</span>
      )}
      <button className="sr-only" type="button" onClick={() => void load()}>
        重新加载空间
      </button>
    </div>
  );
}
