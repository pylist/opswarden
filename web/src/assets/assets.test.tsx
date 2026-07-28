import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { WorkflowAPI } from "../workflow-api";
import { AssetDetailPage } from "./AssetDetailPage";
import { AssetListPage } from "./AssetListPage";

const asset = {
  id: "ast_orders",
  spaceId: "spc_prod",
  name: "orders-01",
  type: "server",
  hostname: "orders.internal",
  os: "Linux",
  environment: "prod",
  status: "online",
  ips: ["10.0.0.8"],
  ports: [22, 5432],
  tags: { team: "platform" },
  notes: "订单数据库",
  version: 2,
  createdAt: "2026-07-01T00:00:00Z",
  updatedAt: "2026-07-02T00:00:00Z",
};

function apiFor(
  implementation: (path: string, options?: unknown) => Promise<unknown>,
) {
  return { request: vi.fn(implementation) } as unknown as WorkflowAPI;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("asset workflows", () => {
  it("lists and opens asset detail with linked credential metadata", async () => {
    const api = apiFor(async (path) => {
      if (path.endsWith("/assets?limit=100")) return { items: [asset] };
      if (path.endsWith("/assets/ast_orders")) return asset;
      if (path.endsWith("/assets/ast_orders/credentials?limit=100")) {
        return {
          items: [{
            id: "crd_orders",
            spaceId: "spc_prod",
            displayName: "orders database",
            type: "database",
            version: 3,
            tags: {},
            assetIds: ["ast_orders"],
          }],
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
      />,
    );
    fireEvent.click(await screen.findByText("orders-01"));
    expect(await screen.findByText("orders database")).toBeVisible();
    expect(api.request).not.toHaveBeenCalledWith(
      expect.stringContaining("/credentials/crd_orders"),
      expect.anything(),
    );
  });

  it("paginates assets and deduplicates IDs", async () => {
    const second = { ...asset, id: "ast_cache", name: "cache-01" };
    const api = apiFor(async (path) => {
      if (path.endsWith("/assets?limit=100")) {
        return { items: [asset], nextCursor: "asset_1" };
      }
      if (path.endsWith("/assets?limit=100&after=asset_1")) {
        return { items: [asset, second] };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "加载更多资产" }));
    expect(await screen.findByText("cache-01")).toBeVisible();
    expect(screen.getAllByText("orders-01")).toHaveLength(1);
  });

  it("retries failed asset cursors, rejects cycles, dedupes every page, and ignores stale retries", async () => {
    const second = { ...asset, id: "ast_cache", name: "cache-01" };
    const stalePage = deferred<unknown>();
    let firstContinuation = 0;
    let secondContinuation = 0;
    const api = apiFor(async (path) => {
      if (path.endsWith("/assets?limit=100")) {
        return { items: [asset, asset], nextCursor: "asset_1" };
      }
      if (path.endsWith("/assets?limit=100&after=asset_1")) {
        firstContinuation += 1;
        if (firstContinuation === 1) throw new Error("transient");
        return { items: [asset, second, second], nextCursor: "asset_2" };
      }
      if (path.endsWith("/assets?limit=100&after=asset_2")) {
        secondContinuation += 1;
        if (secondContinuation === 1) {
          return {
            items: [{ ...asset, id: "ast_cycle", name: "cycle asset" }],
            nextCursor: "asset_1",
          };
        }
        return stalePage.promise;
      }
      if (path.endsWith("/assets?limit=100&type=database")) {
        const filtered = { ...asset, id: "ast_filtered", name: "filtered asset", type: "database" };
        return { items: [filtered, filtered] };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
      />,
    );
    expect(await screen.findAllByText("orders-01")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "加载更多资产" }));
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "加载更多资产" }));
    expect(await screen.findAllByText("cache-01")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "加载更多资产" }));
    await waitFor(() => expect(secondContinuation).toBe(1));
    expect(screen.queryByText("cycle asset")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "加载更多资产" }));
    await waitFor(() => expect(secondContinuation).toBe(2));
    fireEvent.change(screen.getByLabelText("资产类型"), {
      target: { value: "database" },
    });
    expect(await screen.findAllByText("filtered asset")).toHaveLength(1);
    await act(async () => {
      stalePage.resolve({
        items: [{ ...asset, id: "ast_stale", name: "stale asset" }],
      });
      await stalePage.promise;
    });
    expect(screen.queryByText("stale asset")).toBeNull();
  });

  it("paginates linked credential metadata", async () => {
    const linked = {
      id: "crd_orders",
      spaceId: "spc_prod",
      displayName: "orders database",
      type: "database" as const,
      version: 3,
      tags: {},
      assetIds: ["ast_orders"],
    };
    const api = apiFor(async (path) => {
      if (path.endsWith("/assets/ast_orders")) return asset;
      if (path.endsWith("/assets/ast_orders/credentials?limit=100")) {
        return { items: [linked], nextCursor: "linked_1" };
      }
      if (path.endsWith("/assets/ast_orders/credentials?limit=100&after=linked_1")) {
        return {
          items: [{ ...linked, id: "crd_cache", displayName: "cache credential" }],
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetDetailPage
        api={api}
        assetId="ast_orders"
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "加载更多关联凭据" }));
    expect(await screen.findByText("cache credential")).toBeVisible();
  });

  it("retries failed linked cursors, rejects cycles, dedupes every page, and ignores stale retries", async () => {
    const linked = {
      id: "crd_orders",
      spaceId: "spc_prod",
      displayName: "orders database",
      type: "database" as const,
      version: 3,
      tags: {},
      assetIds: ["ast_orders"],
    };
    const second = { ...linked, id: "crd_cache", displayName: "cache credential" };
    const otherAsset = { ...asset, id: "ast_other", name: "other asset" };
    const otherLinked = {
      ...linked,
      id: "crd_other",
      displayName: "other credential",
      assetIds: ["ast_other"],
    };
    const stalePage = deferred<unknown>();
    let firstContinuation = 0;
    let secondContinuation = 0;
    const api = apiFor(async (path) => {
      if (path.endsWith("/assets/ast_orders")) return asset;
      if (path.endsWith("/assets/ast_other")) return otherAsset;
      if (path.endsWith("/assets/ast_other/credentials?limit=100")) {
        return { items: [otherLinked, otherLinked] };
      }
      if (path.endsWith("/assets/ast_orders/credentials?limit=100")) {
        return { items: [linked, linked], nextCursor: "linked_1" };
      }
      if (path.endsWith("/assets/ast_orders/credentials?limit=100&after=linked_1")) {
        firstContinuation += 1;
        if (firstContinuation === 1) throw new Error("transient");
        return { items: [linked, second, second], nextCursor: "linked_2" };
      }
      if (path.endsWith("/assets/ast_orders/credentials?limit=100&after=linked_2")) {
        secondContinuation += 1;
        if (secondContinuation === 1) {
          return {
            items: [{ ...linked, id: "crd_cycle", displayName: "cycle linked" }],
            nextCursor: "linked_1",
          };
        }
        return stalePage.promise;
      }
      throw new Error(`unexpected ${path}`);
    });
    const view = render(
      <AssetDetailPage
        api={api}
        assetId="ast_orders"
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
      />,
    );
    expect(await screen.findAllByText("orders database")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "加载更多关联凭据" }));
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "加载更多关联凭据" }));
    expect(await screen.findAllByText("cache credential")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "加载更多关联凭据" }));
    await waitFor(() => expect(secondContinuation).toBe(1));
    expect(screen.queryByText("cycle linked")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "加载更多关联凭据" }));
    await waitFor(() => expect(secondContinuation).toBe(2));
    view.rerender(
      <AssetDetailPage
        api={api}
        assetId="ast_other"
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
      />,
    );
    expect(await screen.findAllByText("other credential")).toHaveLength(1);
    await act(async () => {
      stalePage.resolve({
        items: [{ ...linked, id: "crd_stale_linked", displayName: "stale linked" }],
      });
      await stalePage.promise;
    });
    expect(screen.queryByText("stale linked")).toBeNull();
  });

  it("rejects hostile linked credential metadata containing payload", async () => {
    const api = apiFor(async (path) => {
      if (path.endsWith("/assets/ast_orders")) return asset;
      if (path.endsWith("/assets/ast_orders/credentials?limit=100")) {
        return {
          items: [{
            id: "crd_orders",
            spaceId: "spc_prod",
            displayName: "orders database",
            type: "database",
            version: 3,
            tags: {},
            assetIds: ["ast_orders"],
            payload: { password: "hostile-linked-plaintext" },
          }],
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetDetailPage
        api={api}
        assetId="ast_orders"
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
      />,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "请求失败，请检查网络连接后重试。",
    );
    expect(document.body).not.toHaveTextContent("hostile-linked-plaintext");
    expect(screen.queryByText("orders database")).toBeNull();
  });

  it("prefills Space and asset when creating a credential from detail", async () => {
    const api = apiFor(async (path) => {
      if (path.endsWith("/assets/ast_orders")) return asset;
      if (path.endsWith("/assets/ast_orders/credentials?limit=100")) {
        return { items: [] };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetDetailPage
        api={api}
        assetId="ast_orders"
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "新建凭据" }));
    expect(screen.getByLabelText("关联资产")).toHaveValue("ast_orders");
    expect(screen.getByLabelText("Space")).toHaveValue("spc_prod");
  });

  it("hides write controls from readers", async () => {
    const api = apiFor(async () => ({ items: [asset] }));
    render(
      <AssetListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
      />,
    );
    await screen.findByText("orders-01");
    expect(screen.queryByRole("button", { name: "新建资产" })).toBeNull();
  });

  it("creates an asset with the real REST DTO", async () => {
    const api = apiFor(async (path, options) => {
      if (path.endsWith("/assets?limit=100")) return { items: [] };
      if (
        path === "/api/v1/spaces/spc_prod/assets" &&
        (options as { method?: string } | undefined)?.method === "POST"
      ) {
        expect(options).toMatchObject({
          method: "POST",
          body: expect.objectContaining({
            name: "cache-01",
            type: "server",
            ips: [],
            ports: [],
            tags: {},
          }),
        });
        return { ...asset, id: "ast_cache", name: "cache-01" };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "新建资产" }));
    fireEvent.change(screen.getByLabelText("资产名称"), {
      target: { value: "cache-01" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));
    expect(await screen.findByText("cache-01")).toBeVisible();
  });

  it("does not let a completed save close a newly opened asset form", async () => {
    const save = deferred<unknown>();
    const api = apiFor(async (path, options) => {
      if (path.endsWith("/assets?limit=100")) return { items: [] };
      if ((options as { method?: string } | undefined)?.method === "POST") {
        return save.promise;
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "新建资产" }));
    fireEvent.change(screen.getByLabelText("资产名称"), { target: { value: "旧资产" } });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(api.request).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "取消" }));

    fireEvent.click(screen.getByRole("button", { name: "新建资产" }));
    fireEvent.change(screen.getByLabelText("资产名称"), { target: { value: "新资产保留" } });
    await act(async () => {
      save.resolve({ ...asset, id: "ast_old", name: "旧资产" });
      await save.promise;
    });

    await waitFor(() =>
      expect(screen.getByLabelText("资产名称")).toHaveValue("新资产保留"),
    );
  });

  it("restores focus to the trigger when an asset modal closes", async () => {
    const api = apiFor(async (path) => {
      if (path.endsWith("/assets?limit=100")) return { items: [] };
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
      />,
    );
    const trigger = await screen.findByRole("button", { name: "新建资产" });
    trigger.focus();
    fireEvent.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "新建资产" });
    expect(within(dialog).getByLabelText("资产名称")).toHaveFocus();
    fireEvent.click(within(dialog).getByRole("button", { name: "取消" }));
    expect(trigger).toHaveFocus();
  });

  it("requires the exact asset name before versioned deletion", async () => {
    const api = apiFor(async (path, options) => {
      if (path.endsWith("/assets/ast_orders/credentials?limit=100")) {
        return { items: [] };
      }
      if (
        path.endsWith("/assets/ast_orders") &&
        (options as { method?: string } | undefined)?.method === "DELETE"
      ) {
        expect(options).toMatchObject({
          method: "DELETE",
          body: { assetId: "ast_orders", expectedVersion: 2 },
        });
        return undefined;
      }
      if (path.endsWith("/assets/ast_orders")) return asset;
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AssetDetailPage
        api={api}
        assetId="ast_orders"
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "删除资产" }));
    const confirm = screen.getByRole("button", { name: "确认删除" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText("输入资产名称以确认"), {
      target: { value: "orders-01" },
    });
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(api.request).toHaveBeenCalledWith(
        "/api/v1/spaces/spc_prod/assets/ast_orders",
        expect.objectContaining({
          method: "DELETE",
          body: { assetId: "ast_orders", expectedVersion: 2 },
        }),
      ),
    );
  });

  it("does not request a malformed asset id", async () => {
    const api = apiFor(async () => asset);
    render(
      <AssetDetailPage
        api={api}
        assetId="../credentials"
        space={{ id: "spc_prod", name: "生产", role: "owner" }}
      />,
    );
    expect(await screen.findByText("资产标识无效")).toBeVisible();
    await waitFor(() => expect(api.request).not.toHaveBeenCalled());
  });
});
