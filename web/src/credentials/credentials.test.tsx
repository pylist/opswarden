import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { WorkflowAPI } from "../workflow-api";
import { CredentialListPage } from "./CredentialListPage";
import { RecycleBinPage } from "./RecycleBinPage";

const metadata = {
  id: "crd_orders",
  spaceId: "spc_prod",
  displayName: "orders database",
  type: "database" as const,
  version: 3,
  tags: { environment: "prod" },
  assetIds: ["ast_orders"],
};

function response(body: unknown, status = 200) {
  if (status >= 400) {
    return Promise.reject(
      Object.assign(new Error("unsafe server text"), {
        code: status === 409 ? "VERSION_CONFLICT" : "INVALID_REQUEST",
      }),
    );
  }
  return Promise.resolve(body);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function apiFor(
  implementation: (path: string, options?: unknown) => Promise<unknown>,
) {
  return { request: vi.fn(implementation) } as unknown as WorkflowAPI;
}

describe("credential workflows", () => {
  it("lists metadata and opens the drawer without fetching a payload", async () => {
    const api = apiFor((path) => {
      expect(path).toBe("/api/v1/spaces/spc_prod/credentials?limit=100");
      return response({ items: [metadata] });
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
        sessionActive
        systemRole="member"
      />,
    );

    fireEvent.click(await screen.findByText("orders database"));
    expect(api.request).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "显示" })).toBeVisible();
    expect(screen.queryByText("hunter2-fixture")).toBeNull();
  });

  it("paginates credential metadata, deduplicates IDs, and filters loaded pages", async () => {
    const second = { ...metadata, id: "crd_cache", displayName: "cache token", type: "api_token" as const };
    const api = apiFor(async (path) => {
      if (path.endsWith("/credentials?limit=100")) {
        return { items: [metadata], nextCursor: "cursor_1" };
      }
      if (path.endsWith("/credentials?limit=100&after=cursor_1")) {
        return { items: [metadata, second] };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "加载更多凭据" }));
    expect(await screen.findByText("cache token")).toBeVisible();
    expect(screen.getAllByText("orders database")).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("搜索凭据"), { target: { value: "cache" } });
    expect(screen.queryByText("orders database")).toBeNull();
    expect(screen.getByText("cache token")).toBeVisible();
  });

  it("ignores a delayed credential page after the server-side filter changes", async () => {
    const page = deferred<unknown>();
    const filtered = { ...metadata, id: "crd_login", displayName: "filtered login", type: "login" as const };
    const api = apiFor(async (path) => {
      if (path.endsWith("/credentials?limit=100")) {
        return { items: [metadata], nextCursor: "cursor_1" };
      }
      if (path.includes("after=cursor_1")) return page.promise;
      if (path.endsWith("/credentials?limit=100&type=login")) {
        return { items: [filtered] };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "加载更多凭据" }));
    fireEvent.change(screen.getByLabelText("按类型筛选"), { target: { value: "login" } });
    expect(await screen.findByText("filtered login")).toBeVisible();
    await act(async () => {
      page.resolve({ items: [{ ...metadata, id: "crd_stale", displayName: "stale page" }] });
      await page.promise;
    });
    expect(screen.queryByText("stale page")).toBeNull();
  });

  it("rejects hostile metadata list items instead of retaining extra payload fields", async () => {
    const api = apiFor(() =>
      response({
        items: [{
          ...metadata,
          payload: { password: "hostile-list-plaintext" },
        }],
      }),
    );
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
        sessionActive
        systemRole="member"
      />,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "请求失败，请检查网络连接后重试。",
    );
    expect(screen.queryByText("orders database")).toBeNull();
    expect(document.body).not.toHaveTextContent("hostile-list-plaintext");
  });

  it("fetches a decrypted payload only after 显示 and clears it on close", async () => {
    const api = apiFor((path) => {
      if (path.endsWith("/credentials?limit=100")) {
        return response({ items: [metadata] });
      }
      if (path.endsWith("/credentials/crd_orders")) {
        return response({
          metadata,
          payload: {
            engine: "postgres",
            host: "db.internal",
            username: "orders",
            password: "hunter2-fixture",
          },
        });
      }
      throw new Error(`unexpected ${path}`);
    });
    const view = render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByText("orders database"));
    expect(api.request).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "显示" }));
    expect(await screen.findByDisplayValue("hunter2-fixture")).toBeVisible();
    expect(api.request).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("button", { name: "关闭凭据详情" }));
    expect(screen.queryByDisplayValue("hunter2-fixture")).toBeNull();
    view.unmount();
    expect(document.body).not.toHaveTextContent("hunter2-fixture");
  });

  it("clears a revealed payload when the Space or session changes", async () => {
    const api = apiFor((path) => {
      if (path.includes("/spaces/spc_other/credentials")) {
        return response({ items: [] });
      }
      if (path.endsWith("/credentials?limit=100")) {
        return response({ items: [metadata] });
      }
      if (path.endsWith("/credentials/crd_orders")) {
        return response({
          metadata,
          payload: {
            engine: "postgres",
            host: "db.internal",
            password: "space-switch-fixture",
          },
        });
      }
      throw new Error(`unexpected ${path}`);
    });
    const view = render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "reader" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByText("orders database"));
    fireEvent.click(screen.getByRole("button", { name: "显示" }));
    expect(await screen.findByDisplayValue("space-switch-fixture")).toBeVisible();

    view.rerender(
      <CredentialListPage
        api={api}
        space={{ id: "spc_other", name: "开发", role: "reader" }}
        sessionActive
        systemRole="member"
      />,
    );
    await waitFor(() =>
      expect(screen.queryByDisplayValue("space-switch-fixture")).toBeNull(),
    );

    view.rerender(
      <CredentialListPage
        api={api}
        space={{ id: "spc_other", name: "开发", role: "reader" }}
        sessionActive={false}
        systemRole="member"
      />,
    );
    expect(document.body).not.toHaveTextContent("space-switch-fixture");
  });

  it("never uses the domain term 秘密", async () => {
    const api = apiFor(() => response({ items: [] }));
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    expect(await screen.findByRole("button", { name: "新建凭据" })).toBeVisible();
    expect(document.body).not.toHaveTextContent("秘密");
  });

  it("creates a typed API Token using the exact REST payload shape", async () => {
    const api = apiFor(async (path, options) => {
      if (path.endsWith("/credentials?limit=100")) return { items: [] };
      if (
        path === "/api/v1/spaces/spc_prod/credentials" &&
        (options as { method?: string } | undefined)?.method === "POST"
      ) {
        expect(options).toMatchObject({
          method: "POST",
          body: {
            displayName: "发布机器人",
            type: "api_token",
            tags: {},
            assetIds: [],
            payload: { service: "registry", token: "typed-token-fixture" },
          },
        });
        return { id: "crd_registry", version: 1 };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "新建凭据" }));
    fireEvent.change(screen.getByLabelText("显示名称"), {
      target: { value: "发布机器人" },
    });
    fireEvent.change(screen.getByLabelText("凭据类型"), {
      target: { value: "api_token" },
    });
    fireEvent.change(screen.getByLabelText("服务"), {
      target: { value: "registry" },
    });
    fireEvent.change(screen.getByLabelText("Token"), {
      target: { value: "typed-token-fixture" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() =>
      expect(api.request).toHaveBeenCalledWith(
        "/api/v1/spaces/spc_prod/credentials",
        expect.objectContaining({ method: "POST" }),
      ),
    );
  });

  it("does not let a completed save close a newly opened credential form", async () => {
    const save = deferred<unknown>();
    const api = apiFor(async (path, options) => {
      if (path.endsWith("/credentials?limit=100")) return { items: [] };
      if ((options as { method?: string } | undefined)?.method === "POST") {
        return save.promise;
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "新建凭据" }));
    fireEvent.change(screen.getByLabelText("显示名称"), { target: { value: "旧表单" } });
    fireEvent.change(screen.getByLabelText("网址"), { target: { value: "https://old.example" } });
    fireEvent.change(screen.getByLabelText("用户名"), { target: { value: "old" } });
    fireEvent.change(screen.getByLabelText("密码"), { target: { value: "old-password" } });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(api.request).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "取消" }));

    fireEvent.click(screen.getByRole("button", { name: "新建凭据" }));
    fireEvent.change(screen.getByLabelText("显示名称"), { target: { value: "新表单保留" } });
    await act(async () => {
      save.resolve({ id: "crd_old", version: 1 });
      await save.promise;
    });

    await waitFor(() =>
      expect(screen.getByLabelText("显示名称")).toHaveValue("新表单保留"),
    );
  });

  it("edits database parameters as validated key-value rows", async () => {
    const api = apiFor(async (path, options) => {
      if (path.endsWith("/credentials?limit=100")) return { items: [] };
      if ((options as { method?: string } | undefined)?.method === "POST") {
        expect(options).toMatchObject({
          body: {
            type: "database",
            payload: {
              engine: "postgres",
              host: "db.internal",
              parameters: { sslmode: "require" },
            },
          },
        });
        return { id: "crd_database", version: 1 };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "新建凭据" }));
    fireEvent.change(screen.getByLabelText("显示名称"), { target: { value: "数据库" } });
    fireEvent.change(screen.getByLabelText("凭据类型"), { target: { value: "database" } });
    fireEvent.change(screen.getByLabelText("数据库引擎"), { target: { value: "postgres" } });
    fireEvent.change(screen.getByLabelText("主机"), { target: { value: "db.internal" } });
    fireEvent.click(screen.getByRole("button", { name: "添加参数" }));
    fireEvent.change(screen.getByLabelText("参数键 1"), { target: { value: "sslmode" } });
    fireEvent.change(screen.getByLabelText("参数值 1"), { target: { value: "require" } });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() =>
      expect(api.request).toHaveBeenCalledWith(
        "/api/v1/spaces/spc_prod/credentials",
        expect.objectContaining({ method: "POST" }),
      ),
    );
  });

  it("rejects duplicate and prototype-sensitive database parameter keys", async () => {
    const api = apiFor(async (path) => {
      if (path.endsWith("/credentials?limit=100")) return { items: [] };
      throw new Error("must not save invalid parameters");
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "新建凭据" }));
    fireEvent.change(screen.getByLabelText("显示名称"), { target: { value: "数据库" } });
    fireEvent.change(screen.getByLabelText("凭据类型"), { target: { value: "database" } });
    fireEvent.change(screen.getByLabelText("数据库引擎"), { target: { value: "postgres" } });
    fireEvent.change(screen.getByLabelText("主机"), { target: { value: "db.internal" } });
    fireEvent.click(screen.getByRole("button", { name: "添加参数" }));
    fireEvent.change(screen.getByLabelText("参数键 1"), { target: { value: "__proto__" } });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("数据库参数");
    expect(api.request).toHaveBeenCalledTimes(1);
  });

  it("preserves edits and shows safe guidance on a version conflict", async () => {
    const api = apiFor((path, options) => {
      if (path.endsWith("/credentials?limit=100")) {
        return response({ items: [metadata] });
      }
      if (
        path.endsWith("/credentials/crd_orders") &&
        !(options as { method?: string } | undefined)?.method
      ) {
        return response({
          metadata,
          payload: {
            engine: "postgres",
            host: "db.internal",
            username: "orders",
            password: "fixture-password",
          },
        });
      }
      return response({}, 409);
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByText("orders database"));
    fireEvent.click(screen.getByRole("button", { name: "显示" }));
    await screen.findByDisplayValue("fixture-password");
    fireEvent.click(screen.getByRole("button", { name: "编辑凭据" }));
    fireEvent.change(screen.getByLabelText("显示名称"), {
      target: { value: "orders database revised" },
    });
    fireEvent.change(screen.getByLabelText("变更原因"), {
      target: { value: "轮换数据库口令" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));

    expect(await screen.findByText(/版本冲突/)).toBeVisible();
    expect(screen.getByDisplayValue("orders database revised")).toBeVisible();
    expect(document.body).not.toHaveTextContent("unsafe server text");
  });

  it("keeps an edit open when mutation success targets a different credential", async () => {
    const api = apiFor((path, options) => {
      if (path.endsWith("/credentials?limit=100")) {
        return response({ items: [metadata] });
      }
      if (
        path.endsWith("/credentials/crd_orders") &&
        !(options as { method?: string } | undefined)?.method
      ) {
        return response({
          metadata,
          payload: {
            engine: "postgres",
            host: "db.internal",
            password: "mismatch-edit-fixture",
          },
        });
      }
      return response({ id: "crd_other", version: 4 });
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByText("orders database"));
    fireEvent.click(screen.getByRole("button", { name: "显示" }));
    await screen.findByDisplayValue("mismatch-edit-fixture");
    fireEvent.click(screen.getByRole("button", { name: "编辑凭据" }));
    fireEvent.change(screen.getByLabelText("变更原因"), {
      target: { value: "测试目标绑定" },
    });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "请求失败，请检查网络连接后重试。",
    );
    expect(screen.getByLabelText("变更原因")).toHaveValue("测试目标绑定");
  });

  it("requires typed confirmation before soft deletion", async () => {
    const api = apiFor((path) => {
      if (path.endsWith("/credentials?limit=100")) {
        return response({ items: [metadata] });
      }
      return response(undefined);
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByText("orders database"));
    fireEvent.click(screen.getByRole("button", { name: "移至回收站" }));
    const dialog = screen.getByRole("dialog", { name: "确认移至回收站" });
    const confirm = within(dialog).getByRole("button", { name: "确认删除" });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("输入凭据名称以确认"), {
      target: { value: "orders database" },
    });
    expect(confirm).toBeEnabled();
  });

  it("closes only the nested confirmation on Escape and restores drawer focus", async () => {
    const api = apiFor((path) => {
      if (path.endsWith("/credentials?limit=100")) return response({ items: [metadata] });
      return response(undefined);
    });
    render(
      <CredentialListPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "editor" }}
        sessionActive
        systemRole="member"
      />,
    );
    const trigger = await screen.findByRole("button", { name: "orders database" });
    trigger.focus();
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole("button", { name: "移至回收站" }));
    const confirmationDialog = screen.getByRole("dialog", { name: "确认移至回收站" });
    expect(within(confirmationDialog).getByRole("button", { name: "取消" })).toHaveFocus();

    fireEvent.keyDown(confirmationDialog, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "确认移至回收站" })).toBeNull();
    const drawer = screen.getByRole("dialog", { name: "orders database" });
    expect(drawer).toBeVisible();

    fireEvent.keyDown(drawer, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "orders database" })).toBeNull();
    expect(trigger).toHaveFocus();
  });

  it("shows permanent purge only to System Owner and challenges for TOTP", async () => {
    const api = apiFor(() =>
      response({ items: [{ ...metadata, deletedAt: "2026-07-01T00:00:00Z" }] }),
    );
    const view = render(
      <RecycleBinPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "owner" }}
        systemRole="member"
      />,
    );
    await screen.findByText("orders database");
    expect(screen.queryByRole("button", { name: "永久删除" })).toBeNull();

    view.rerender(
      <RecycleBinPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "owner" }}
        systemRole="system_owner"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "永久删除" }));
    expect(
      screen.getByRole("dialog", { name: "重新验证 TOTP" }),
    ).toBeVisible();
  });

  it("restores a soft-deleted credential with its current version", async () => {
    let restored = false;
    const api = apiFor(async (path, options) => {
      if (path.endsWith("/credentials?deletedOnly=1&limit=100")) {
        return restored
          ? { items: [] }
          : { items: [{ ...metadata, deletedAt: "2026-07-01T00:00:00Z" }] };
      }
      if (path.endsWith("/credentials/crd_orders/restore")) {
        expect(options).toMatchObject({
          method: "POST",
          body: { expectedVersion: 3 },
        });
        restored = true;
        return metadata;
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <RecycleBinPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "owner" }}
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "恢复" }));
    await waitFor(() =>
      expect(api.request).toHaveBeenCalledWith(
        "/api/v1/spaces/spc_prod/credentials/crd_orders/restore",
        expect.objectContaining({
          method: "POST",
          body: { expectedVersion: 3 },
        }),
      ),
    );
  });

  it("paginates the recycle bin", async () => {
    const deleted = { ...metadata, deletedAt: "2026-07-01T00:00:00Z" };
    const api = apiFor(async (path) => {
      if (path.endsWith("/credentials?deletedOnly=1&limit=100")) {
        return { items: [deleted], nextCursor: "deleted_1" };
      }
      if (path.endsWith("/credentials?deletedOnly=1&limit=100&after=deleted_1")) {
        return {
          items: [{ ...deleted, id: "crd_deleted_2", displayName: "deleted second" }],
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <RecycleBinPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "owner" }}
        systemRole="member"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "加载更多已删除凭据" }));
    expect(await screen.findByText("deleted second")).toBeVisible();
  });

  it("renews the JWT before a single exact permanent-purge request", async () => {
    let listed = false;
    const request = vi.fn(async (path: string, options?: unknown) => {
      if (path.endsWith("/credentials?deletedOnly=1&limit=100")) {
        if (listed) return { items: [] };
        listed = true;
        return {
          items: [{ ...metadata, deletedAt: "2026-07-01T00:00:00Z" }],
        };
      }
      if (path.endsWith("/credentials/crd_orders/purge")) {
        expect(options).toMatchObject({
          method: "POST",
          body: { expectedVersion: 3 },
        });
        return undefined;
      }
      throw new Error(`unexpected ${path}`);
    });
    const reverifyTOTP = vi.fn(async () => {});
    const api = { request, reverifyTOTP } as unknown as WorkflowAPI;
    render(
      <RecycleBinPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "owner" }}
        systemRole="system_owner"
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "永久删除" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.change(screen.getByLabelText("输入凭据名称以确认"), {
      target: { value: "orders database" },
    });
    fireEvent.click(screen.getByRole("button", { name: "确认永久删除" }));

    await waitFor(() =>
      expect(reverifyTOTP).toHaveBeenCalledWith(
        "123456",
        expect.any(AbortSignal),
      ),
    );
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith(
        "/api/v1/spaces/spc_prod/credentials/crd_orders/purge",
        expect.objectContaining({
          method: "POST",
          body: { expectedVersion: 3 },
        }),
      ),
    );
  });

  it.each(["cancel", "escape", "unmount", "space"] as const)(
    "does not purge after a delayed TOTP verification is invalidated by %s",
    async (mode) => {
      const verification = deferred<void>();
      const request = vi.fn(async (path: string) => {
        if (path.includes("/credentials?deletedOnly=1&limit=100")) {
          return {
            items: [{
              ...metadata,
              spaceId: path.includes("spc_other") ? "spc_other" : "spc_prod",
              deletedAt: "2026-07-01T00:00:00Z",
            }],
          };
        }
        if (path.endsWith("/purge")) return undefined;
        throw new Error(`unexpected ${path}`);
      });
      const reverifyTOTP = vi.fn(() => verification.promise);
      const api = { request, reverifyTOTP } as unknown as WorkflowAPI;
      const props = {
        api,
        space: { id: "spc_prod", name: "生产", role: "owner" as const },
        systemRole: "system_owner",
      };
      const view = render(<RecycleBinPage {...props} />);
      fireEvent.click(await screen.findByRole("button", { name: "永久删除" }));
      fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
        target: { value: "123456" },
      });
      fireEvent.change(screen.getByLabelText("输入凭据名称以确认"), {
        target: { value: "orders database" },
      });
      fireEvent.click(screen.getByRole("button", { name: "确认永久删除" }));
      await waitFor(() => expect(reverifyTOTP).toHaveBeenCalledOnce());

      if (mode === "cancel") {
        fireEvent.click(screen.getByRole("button", { name: "取消" }));
      } else if (mode === "escape") {
        fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
      } else if (mode === "unmount") {
        view.unmount();
      } else {
        view.rerender(
          <RecycleBinPage
            api={api}
            space={{ id: "spc_other", name: "开发", role: "owner" }}
            systemRole="system_owner"
          />,
        );
      }
      verification.resolve();
      await Promise.resolve();
      await Promise.resolve();
      expect(
        request.mock.calls.filter(([path]) => String(path).endsWith("/purge")),
      ).toHaveLength(0);
    },
  );

  it("does not let an old verification response affect a newly opened purge modal", async () => {
    const first = deferred<void>();
    const second = deferred<void>();
    const request = vi.fn(async (path: string) => {
      if (path.endsWith("/credentials?deletedOnly=1&limit=100")) {
        return {
          items: [{ ...metadata, deletedAt: "2026-07-01T00:00:00Z" }],
        };
      }
      if (path.endsWith("/purge")) return undefined;
      throw new Error(`unexpected ${path}`);
    });
    const reverifyTOTP = vi.fn()
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const api = { request, reverifyTOTP } as unknown as WorkflowAPI;
    render(
      <RecycleBinPage
        api={api}
        space={{ id: "spc_prod", name: "生产", role: "owner" }}
        systemRole="system_owner"
      />,
    );
    const openAndSubmit = async (code: string) => {
      fireEvent.click(await screen.findByRole("button", { name: "永久删除" }));
      fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
        target: { value: code },
      });
      fireEvent.change(screen.getByLabelText("输入凭据名称以确认"), {
        target: { value: "orders database" },
      });
      fireEvent.click(screen.getByRole("button", { name: "确认永久删除" }));
    };
    await openAndSubmit("111111");
    await waitFor(() => expect(reverifyTOTP).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    await openAndSubmit("222222");
    await waitFor(() => expect(reverifyTOTP).toHaveBeenCalledTimes(2));

    first.resolve();
    await Promise.resolve();
    expect(screen.getByRole("dialog", { name: "重新验证 TOTP" })).toBeVisible();
    expect(
      request.mock.calls.filter(([path]) => String(path).endsWith("/purge")),
    ).toHaveLength(0);
    second.resolve();
    await waitFor(() =>
      expect(
        request.mock.calls.filter(([path]) => String(path).endsWith("/purge")),
      ).toHaveLength(1),
    );
  });
});
