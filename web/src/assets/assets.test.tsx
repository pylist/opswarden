import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
