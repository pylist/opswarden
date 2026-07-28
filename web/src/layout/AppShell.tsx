import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

import { apiPath } from "../api/client";
import type { ListResponse, Space } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SpaceSwitcher } from "../spaces/SpaceSwitcher";
import { CredentialListPage } from "../credentials/CredentialListPage";
import { AssetListPage } from "../assets/AssetListPage";
import { Sidebar, type View } from "./Sidebar";

const viewTitles: Record<View, string> = {
  overview: "概览",
  credentials: "凭据库",
  assets: "资产",
  agents: "Agent",
  audit: "审计日志",
  members: "成员与权限",
  settings: "设置",
};
const views = new Set<View>(Object.keys(viewTitles) as View[]);

function initialView(): View {
  const value = new URL(window.location.href).searchParams.get("view");
  return value && views.has(value as View) ? (value as View) : "overview";
}

export function AppShell() {
  const { api, logout, principal } = useAuth();
  const [view, setView] = useState<View>(initialView);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [currentSpace, setCurrentSpace] = useState<Space | null>(null);
  const [selectedAssetID, setSelectedAssetID] = useState("");
  const [selectedCredentialID, setSelectedCredentialID] = useState("");
  const menuButton = useRef<HTMLButtonElement>(null);
  const restoreMenuFocus = useRef(false);
  const isMobile = useMobileLayout();
  const consumeAssetSelection = useCallback(() => setSelectedAssetID(""), []);
  const consumeCredentialSelection = useCallback(
    () => setSelectedCredentialID(""),
    [],
  );

  const closeDrawer = useCallback(() => {
    restoreMenuFocus.current = isMobile;
    setDrawerOpen(false);
  }, [isMobile]);

  useLayoutEffect(() => {
    if (!drawerOpen && restoreMenuFocus.current) {
      restoreMenuFocus.current = false;
      menuButton.current?.focus();
    }
  }, [drawerOpen]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && drawerOpen) {
        closeDrawer();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [closeDrawer, drawerOpen]);

  useEffect(() => {
    const sync = () => {
      const next = initialView();
      setView(next);
      setSelectedAssetID("");
      setSelectedCredentialID("");
      const url = new URL(window.location.href);
      const raw = url.searchParams.get("view");
      if (raw && !views.has(raw as View)) {
        url.searchParams.set("view", next);
        window.history.replaceState({}, "", `${url.pathname}${url.search}`);
      }
    };
    sync();
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, []);

  useEffect(() => {
    if (!isMobile) setDrawerOpen(false);
  }, [isMobile]);

  function navigate(next: View) {
    setView(next);
    setSelectedAssetID("");
    setSelectedCredentialID("");
    const url = new URL(window.location.href);
    url.searchParams.set("view", next);
    window.history.pushState({}, "", `${url.pathname}${url.search}`);
  }

  function openAsset(assetID: string) {
    setSelectedCredentialID("");
    setSelectedAssetID(assetID);
    navigateWithoutClearing("assets");
  }

  function openCredential(credentialID: string) {
    setSelectedAssetID("");
    setSelectedCredentialID(credentialID);
    navigateWithoutClearing("credentials");
  }

  function navigateWithoutClearing(next: View) {
    setView(next);
    const url = new URL(window.location.href);
    url.searchParams.set("view", next);
    window.history.pushState({}, "", `${url.pathname}${url.search}`);
  }

  useEffect(() => {
    setSelectedAssetID("");
    setSelectedCredentialID("");
  }, [currentSpace?.id]);

  return (
    <div className="app-frame">
      <Sidebar
        current={view}
        open={drawerOpen}
        mobile={isMobile}
        onNavigate={navigate}
        onClose={closeDrawer}
      />
      <div className="app-column" inert={isMobile && drawerOpen ? true : undefined}>
        <header className="app-header">
          <button
            ref={menuButton}
            className="menu-button"
            type="button"
            aria-label="打开导航"
            aria-expanded={drawerOpen}
            onClick={() => setDrawerOpen(true)}
          >
            <span aria-hidden="true">☰</span>
          </button>
          <SpaceSwitcher
            api={api}
            currentSpace={currentSpace}
            onChange={setCurrentSpace}
            systemRole={principal?.systemRole ?? ""}
          />
          <div className="header-account">
            <span className="account-id">{principal?.userId}</span>
            <button className="secondary-button" type="button" onClick={() => void logout()}>
              退出
            </button>
          </div>
        </header>
        <main className="page-content" tabIndex={-1}>
          <div className="page-heading">
            <div>
              <p className="eyebrow">{currentSpace?.name ?? "OpsWarden"}</p>
              <h1>{viewTitles[view]}</h1>
            </div>
          </div>
          {view === "overview" ? (
            <Overview api={api} space={currentSpace} />
          ) : view === "credentials" && currentSpace ? (
            <CredentialListPage
              key={currentSpace.id}
              api={api}
              space={currentSpace}
              systemRole={principal?.systemRole ?? ""}
              sessionActive={Boolean(principal)}
              initialCredentialId={selectedCredentialID || undefined}
              onSelectionConsumed={consumeCredentialSelection}
              onOpenAsset={openAsset}
            />
          ) : view === "assets" && currentSpace ? (
            <AssetListPage
              key={currentSpace.id}
              api={api}
              space={currentSpace}
              initialAssetId={selectedAssetID || undefined}
              onSelectionConsumed={consumeAssetSelection}
              onOpenCredential={openCredential}
            />
          ) : (
            <EmptyView view={view} />
          )}
        </main>
      </div>
    </div>
  );
}

function Overview({
  api,
  space,
}: {
  api: ReturnType<typeof useAuth>["api"];
  space: Space | null;
}) {
  const [metrics, setMetrics] = useState({
    credentials: "—",
    assets: "—",
    agents: "—",
    audit: "—",
  });

  useEffect(() => {
    setMetrics({
      credentials: "—",
      assets: "—",
      agents: "—",
      audit: "—",
    });
    if (!space) {
      return;
    }
    const controller = new AbortController();
    let active = true;
    async function load() {
      const requests: Array<Promise<ListResponse<unknown>>> = [
        api.request(apiPath(["spaces", space!.id, "credentials"]), {
          signal: controller.signal,
        }),
        api.request(apiPath(["spaces", space!.id, "assets"]), {
          signal: controller.signal,
        }),
        api.request(apiPath(["agents"]), { signal: controller.signal }),
        api.request(
          apiPath(["audit-events"], { spaceId: space!.id }),
          { signal: controller.signal },
        ),
      ];
      const results = await Promise.allSettled(requests);
      if (!active) return;
      const count = (index: number) => {
        const result = results[index];
        return result.status === "fulfilled" &&
          Array.isArray(result.value.items)
          ? String(result.value.items.length)
          : "受限";
      };
      setMetrics({
        credentials: count(0),
        assets: count(1),
        agents: count(2),
        audit: count(3),
      });
    }
    void load();
    return () => {
      active = false;
      controller.abort();
    };
  }, [api, space?.id]);

  const cards = [
    ["当前页凭据", metrics.credentials, "仅统计已加载的元数据"],
    ["当前页资产", metrics.assets, "当前空间可见范围"],
    ["全局 Agent 数量", metrics.agents, "跨空间，受系统权限约束"],
    ["近期审计", metrics.audit, "最近一页事件"],
  ];
  return (
    <>
      <section className="metric-grid" aria-label="空间摘要">
        {cards.map(([label, value, caption]) => (
          <article className="metric-card" key={label}>
            <p>{label}</p>
            <strong>{value}</strong>
            <span>{caption}</span>
          </article>
        ))}
      </section>
      <section className="content-card">
        <div>
          <h2>开始管理</h2>
          <p className="muted">
            使用左侧导航管理凭据、关联资产和 Agent 授权。敏感凭据值不会进入概览缓存。
          </p>
        </div>
        {!space && <p className="empty-state">当前账号尚未加入任何空间。</p>}
      </section>
    </>
  );
}

function useMobileLayout() {
  const query = "(max-width: 720px)";
  const [mobile, setMobile] = useState(
    () => window.matchMedia?.(query).matches ?? false,
  );
  useEffect(() => {
    if (!window.matchMedia) return;
    const media = window.matchMedia(query);
    const update = () => setMobile(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  return mobile;
}

function EmptyView({ view }: { view: View }) {
  return (
    <section className="content-card empty-state">
      <h2>{viewTitles[view]}</h2>
      <p>该模块的完整工作区将在后续界面中显示。</p>
    </section>
  );
}
