import { useCallback, useEffect, useState, type FormEvent } from "react";

import { apiPath, formatApiError, type ApiClient } from "../api/client";
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
  systemRole: string;
};

export function SpaceSwitcher({
  api,
  currentSpace,
  onChange,
  systemRole,
}: SpaceSwitcherProps) {
  const [spaces, setSpaces] = useState<Space[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [loadError, setLoadError] = useState("");
  const [initialName, setInitialName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");

  const load = useCallback(async () => {
    setState("loading");
    setLoadError("");
    try {
      const response = await api.request<ListResponse<Space>>(apiPath(["spaces"]));
      if (
        !Array.isArray(response.items) ||
        !response.items.every(isSpace)
      ) {
        throw new Error("invalid response");
      }
      setSpaces(response.items);
      const selected = selectFromLocation(response.items, currentSpace);
      onChange(selected);
      writeSelectedSpace(selected);
      setState("ready");
    } catch (error) {
      setLoadError(formatApiError(error));
      setState("error");
    }
  }, [api, currentSpace?.id, onChange]);

  useEffect(() => {
    void load();
    // A space reload is explicit after initial authentication.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (state !== "ready") return;
    const sync = () => {
      const selected = selectFromLocation(spaces, currentSpace);
      onChange(selected);
      writeSelectedSpace(selected);
    };
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, [currentSpace, onChange, spaces, state]);

  function select(id: string) {
    const selected = spaces.find((space) => space.id === id) ?? null;
    onChange(selected);
    writeSelectedSpace(selected);
  }

  async function createInitialSpace(event: FormEvent) {
    event.preventDefault();
    if (!initialName.trim()) return;
    setCreating(true);
    setCreateError("");
    try {
      const created = await api.request<Space>(apiPath(["spaces"]), {
        method: "POST",
        body: { name: initialName.trim() },
      });
      if (!isSpace(created)) {
        throw new Error("invalid response");
      }
      setSpaces([created]);
      setInitialName("");
      onChange(created);
      writeSelectedSpace(created);
    } catch (error) {
      setCreateError(formatApiError(error));
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
        <span>{loadError || "空间加载失败"}</span>
        <button type="button" onClick={() => void load()}>重新加载空间</button>
      </div>
    );
  }
  if (!spaces.length) {
    if (systemRole !== "system_owner") {
      return <p className="switcher-status">当前账号尚未加入任何空间。</p>;
    }
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

function selectFromLocation(spaces: Space[], current: Space | null) {
  const requested = new URL(window.location.href).searchParams.get("space");
  return (
    spaces.find((space) => space.id === requested) ??
    spaces.find((space) => space.id === current?.id) ??
    spaces[0] ??
    null
  );
}

function writeSelectedSpace(selected: Space | null) {
  const url = new URL(window.location.href);
  if (selected) {
    url.searchParams.set("space", selected.id);
  } else {
    url.searchParams.delete("space");
  }
  window.history.replaceState({}, "", `${url.pathname}${url.search}`);
}

function isSpace(value: unknown): value is Space {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<Space>;
  return (
    typeof candidate.id === "string" &&
    /^[A-Za-z0-9_-]+$/.test(candidate.id) &&
    typeof candidate.name === "string" &&
    (candidate.role === "owner" ||
      candidate.role === "editor" ||
      candidate.role === "reader")
  );
}
