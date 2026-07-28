import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Space } from "../api/types";
import type { WorkflowAPI } from "../workflow-api";
import { AgentListPage } from "./AgentListPage";

const space: Space = {
  id: "spc_prod",
  name: "生产环境",
  role: "owner",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function apiFor(
  implementation: (path: string, options?: {
    method?: string;
    body?: Record<string, unknown>;
    signal?: AbortSignal;
    headers?: HeadersInit;
  }) => Promise<unknown>,
) {
  const request = vi.fn(implementation);
  return {
    request,
    reverifyTOTP: vi.fn(async () => undefined),
  } as unknown as WorkflowAPI & { request: typeof request };
}

function idempotencyKey(options: { headers?: HeadersInit } | undefined) {
  return new Headers(options?.headers).get("Idempotency-Key");
}

describe("Agent administration", () => {
  it("creates an Agent through recent TOTP and an idempotent request", async () => {
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return { items: [] };
      }
      if (path === "/api/v1/agents" && options?.method === "POST") {
        return {
          id: "agt_AAAAAAAAAAAAAAAAAAAAAA",
          name: "Hermes",
          createdAt: "2026-07-28T12:00:00Z",
          updatedAt: "2026-07-28T12:00:00Z",
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Agent" }));
    fireEvent.change(screen.getByLabelText("Agent 名称"), {
      target: { value: "Hermes" },
    });
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    const dialog = screen.getByRole("dialog", { name: "创建 Agent" });
    fireEvent.click(within(dialog).getByRole("button", { name: "创建 Agent" }));
    expect(await screen.findByText("Hermes")).toBeVisible();
    expect(api.reverifyTOTP).toHaveBeenCalledTimes(1);
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/agents",
      expect.objectContaining({
        method: "POST",
        body: { name: "Hermes" },
        headers: expect.anything(),
      }),
    );
  });

  it("reveals a newly issued token once without refetching and erases it on close", async () => {
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens" &&
          options?.method === "POST") {
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          replayed: false,
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    expect(await screen.findByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBeVisible();
    expect(api.reverifyTOTP).toHaveBeenCalledTimes(1);
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens",
      expect.objectContaining({
        method: "POST",
        headers: expect.anything(),
      }),
    );

    fireEvent.click(screen.getByRole("button", { name: "关闭" }));
    expect(screen.queryByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBeNull();
    expect(
      api.request.mock.calls.filter(
        ([path]) => path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens",
      ),
    ).toHaveLength(1);
  });

  it("does not allow a delayed issue response to reveal a token after view cleanup", async () => {
    const issue = deferred<unknown>();
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens") return issue.promise;
      throw new Error(`unexpected ${path}`);
    });
    const rendered = render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    await waitFor(() => expect(api.reverifyTOTP).toHaveBeenCalled());
    rendered.unmount();
    await act(async () => {
      issue.resolve({
        id: "tok_stale",
        prefix: "owat_stale",
        token: "owat_stale_plaintext",
        replayed: false,
      });
      await issue.promise;
    });
    expect(document.body).not.toHaveTextContent("owat_stale_plaintext");
  });

  it("prevents duplicate privileged submits and sends scoped grants with labels", async () => {
    const grant = deferred<unknown>();
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 1,
            activeTokens: 1,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/grants") return grant.promise;
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "配置授权" }));
    fireEvent.click(screen.getByLabelText("读取凭据"));
    fireEvent.change(screen.getByLabelText("标签键"), {
      target: { value: "environment" },
    });
    fireEvent.change(screen.getByLabelText("标签值"), {
      target: { value: "prod" },
    });
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    const submit = screen.getByRole("button", { name: "保存授权" });
    fireEvent.click(submit);
    fireEvent.click(submit);
    await waitFor(() => expect(api.reverifyTOTP).toHaveBeenCalledTimes(1));
    expect(
      api.request.mock.calls.filter(
        ([path]) => path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/grants",
      ),
    ).toHaveLength(1);
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/grants",
      expect.objectContaining({
        method: "PUT",
        body: {
          spaceId: "spc_prod",
          scopes: ["credential:read"],
          requiredLabels: { environment: "prod" },
        },
      }),
    );
    await act(async () => {
      grant.resolve(undefined);
      await grant.promise;
    });
  });

  it("does not call or show Agent management for an unauthorized member", () => {
    const api = apiFor(async () => ({ items: [] }));
    render(
      <AgentListPage
        api={api}
        space={{ ...space, role: "editor" }}
        systemRole="member"
        sessionActive
      />,
    );
    expect(screen.queryByRole("button", { name: "创建 Agent" })).toBeNull();
    expect(screen.getByText("当前账号没有管理 Agent 的权限。")).toBeVisible();
    expect(api.request).not.toHaveBeenCalled();
  });

  it("rejects hostile Agent and Token DTO fields without rendering plaintext", async () => {
    let hostileList = true;
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        if (hostileList) {
          hostileList = false;
          return {
            items: [{
              agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
              name: "Hermes",
              tokenCount: 0,
              activeTokens: 0,
              token: "owat_hostile_list_plaintext",
            }],
          };
        }
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens") {
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "owat_hostile_issue_plaintext",
          replayed: false,
          tokenEcho: "owat_extra_plaintext",
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    expect(await screen.findByRole("alert")).toBeVisible();
    expect(document.body).not.toHaveTextContent("owat_hostile_list_plaintext");
    fireEvent.click(screen.getByRole("button", { name: "重新加载" }));
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    expect(await screen.findByRole("alert")).toBeVisible();
    expect(document.body).not.toHaveTextContent("owat_hostile_issue_plaintext");
    expect(document.body).not.toHaveTextContent("owat_extra_plaintext");
  });

  it("revokes the just-issued token through a nested recent-TOTP dialog", async () => {
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 1,
            activeTokens: 1,
          }],
        };
      }
      if (
        path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens" &&
        options?.method === "POST"
      ) {
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          replayed: false,
        };
      }
      if (
        path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens/tok_AAAAAAAAAAAAAAAAAAAAAA" &&
        options?.method === "DELETE"
      ) {
        return undefined;
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    await screen.findByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    fireEvent.click(screen.getByRole("button", { name: "立即吊销 Token" }));
    const revokeDialog = screen.getByRole("dialog", { name: "重新验证 TOTP" });
    expect(revokeDialog).toBeVisible();
    const tokenDialog = document.querySelector<HTMLElement>(
      '[role="dialog"][aria-labelledby="token-dialog-title"]',
    );
    expect(tokenDialog).not.toBeNull();
    expect(tokenDialog).toHaveAttribute("inert");
    expect(tokenDialog).toHaveAttribute("aria-hidden", "true");
    fireEvent.change(screen.getAllByLabelText("TOTP 验证码").at(-1)!, {
      target: { value: "654321" },
    });
    fireEvent.click(screen.getByRole("button", { name: "验证并吊销" }));
    await waitFor(() => {
      expect(api.request).toHaveBeenCalledWith(
        "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens/tok_AAAAAAAAAAAAAAAAAAAAAA",
        expect.objectContaining({ method: "DELETE" }),
      );
    });
    expect(screen.queryByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBeNull();
  });

  it("sends optional expiry in the backend's canonical RFC3339 form", async () => {
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens") {
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          expiresAt: "2030-01-02T03:04:00Z",
          replayed: false,
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("到期时间（可选）"), {
      target: { value: "2030-01-02T03:04" },
    });
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    await screen.findByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const canonicalExpiry = new Date("2030-01-02T03:04")
      .toISOString()
      .replace(/\.000Z$/u, "Z");
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens",
      expect.objectContaining({
        body: { expiresAt: canonicalExpiry },
      }),
    );
  });

  it("restores the underlying Token dialog and trigger when nested revoke closes", async () => {
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_AAAAAAAAAAAAAAAAAAAAAA/tokens") {
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          replayed: false,
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    await screen.findByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const trigger = screen.getByRole("button", { name: "立即吊销 Token" });
    trigger.focus();
    fireEvent.click(trigger);
    const nested = screen.getByRole("dialog", { name: "重新验证 TOTP" });
    fireEvent.keyDown(nested, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "重新验证 TOTP" })).toBeNull();
    const tokenDialog = screen.getByRole("dialog", {
      name: "Hermes · 创建 Token",
    });
    expect(tokenDialog).not.toHaveAttribute("inert");
    expect(trigger).toHaveFocus();
  });

  it("retries a lost Agent create response with the same idempotency key", async () => {
    const keys: Array<string | null> = [];
    let attempt = 0;
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) return { items: [] };
      if (path === "/api/v1/agents" && options?.method === "POST") {
        keys.push(idempotencyKey(options));
        attempt += 1;
        if (attempt === 1) throw new Error("lost response");
        return {
          id: "agt_AAAAAAAAAAAAAAAAAAAAAA",
          name: "Hermes",
          createdAt: "2026-07-28T12:00:00Z",
          updatedAt: "2026-07-28T12:00:00Z",
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Agent" }));
    fireEvent.change(screen.getByLabelText("Agent 名称"), {
      target: { value: "Hermes" },
    });
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    const dialog = screen.getByRole("dialog", { name: "创建 Agent" });
    const submit = within(dialog).getByRole("button", { name: "创建 Agent" });
    fireEvent.click(submit);
    expect(await within(dialog).findByRole("alert")).toBeVisible();
    fireEvent.click(submit);
    expect(await screen.findByText("Hermes")).toBeVisible();
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBeTruthy();
    expect(keys[1]).toBe(keys[0]);
  });

  it("retries a malformed issue success with the same key and handles the replay contract", async () => {
    const keys: Array<string | null> = [];
    let attempt = 0;
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path.endsWith("/tokens") && options?.method === "POST") {
        keys.push(idempotencyKey(options));
        attempt += 1;
        if (attempt === 1) {
          return {
            id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
            prefix: "owat_AAAAAAAA",
            token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            replayed: false,
            unexpected: true,
          };
        }
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "",
          replayed: true,
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    const submit = screen.getByRole("button", { name: "创建并显示 Token" });
    fireEvent.click(submit);
    expect(await screen.findByRole("alert")).toBeVisible();
    fireEvent.click(submit);
    expect(await screen.findByText(/首次响应中的完整 Token 已无法恢复/)).toBeVisible();
    expect(screen.getByText("tok_AAAAAAAAAAAAAAAAAAAAAA")).toBeVisible();
    expect(screen.getByText("owat_AAAAAAAA")).toBeVisible();
    expect(screen.getByRole("button", { name: "立即吊销 Token" })).toBeVisible();
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
  });

  it("rotates the issue idempotency key when the payload changes", async () => {
    const keys: Array<string | null> = [];
    let attempt = 0;
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path.endsWith("/tokens") && options?.method === "POST") {
        keys.push(idempotencyKey(options));
        attempt += 1;
        if (attempt === 1) throw new Error("lost response");
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          expiresAt: new Date("2030-01-02T03:04")
            .toISOString()
            .replace(/\.000Z$/u, "Z"),
          replayed: false,
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    const submit = screen.getByRole("button", { name: "创建并显示 Token" });
    fireEvent.click(submit);
    expect(await screen.findByRole("alert")).toBeVisible();
    fireEvent.change(screen.getByLabelText("到期时间（可选）"), {
      target: { value: "2030-01-02T03:04" },
    });
    fireEvent.click(submit);
    await screen.findByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expect(keys).toHaveLength(2);
    expect(keys[1]).not.toBe(keys[0]);
  });

  it("retries an unchanged grant with the same idempotency key", async () => {
    const keys: Array<string | null> = [];
    let attempt = 0;
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path.endsWith("/grants") && options?.method === "PUT") {
        keys.push(idempotencyKey(options));
        attempt += 1;
        if (attempt === 1) throw new Error("lost response");
        return undefined;
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "配置授权" }));
    fireEvent.click(screen.getByLabelText("读取凭据"));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    const submit = screen.getByRole("button", { name: "保存授权" });
    fireEvent.click(submit);
    expect(await screen.findByRole("alert")).toBeVisible();
    fireEvent.click(submit);
    await waitFor(() => expect(keys).toHaveLength(2));
    expect(keys[1]).toBe(keys[0]);
  });

  it("retries an unchanged revoke with the same idempotency key", async () => {
    const revokeKeys: Array<string | null> = [];
    let revokeAttempt = 0;
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 1,
            activeTokens: 1,
          }],
        };
      }
      if (path.endsWith("/tokens") && options?.method === "POST") {
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          replayed: false,
        };
      }
      if (path.endsWith("/tokens/tok_AAAAAAAAAAAAAAAAAAAAAA")) {
        revokeKeys.push(idempotencyKey(options));
        revokeAttempt += 1;
        if (revokeAttempt === 1) throw new Error("lost response");
        return undefined;
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    await screen.findByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    fireEvent.click(screen.getByRole("button", { name: "立即吊销 Token" }));
    fireEvent.change(screen.getAllByLabelText("TOTP 验证码").at(-1)!, {
      target: { value: "654321" },
    });
    const submit = screen.getByRole("button", { name: "验证并吊销" });
    fireEvent.click(submit);
    expect(await screen.findByRole("alert")).toBeVisible();
    fireEvent.click(submit);
    await waitFor(() => expect(revokeKeys).toHaveLength(2));
    expect(revokeKeys[1]).toBe(revokeKeys[0]);
  });

  it("rotates the issue key after explicit cancel starts a new operation", async () => {
    const keys: Array<string | null> = [];
    let attempt = 0;
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path.endsWith("/tokens") && options?.method === "POST") {
        keys.push(idempotencyKey(options));
        attempt += 1;
        if (attempt === 1) throw new Error("lost response");
        return {
          id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
          prefix: "owat_AAAAAAAA",
          token: "",
          replayed: true,
        };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    expect(await screen.findByRole("alert")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    fireEvent.click(screen.getByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    await screen.findByText(/首次响应中的完整 Token 已无法恢复/);
    expect(keys).toHaveLength(2);
    expect(keys[1]).not.toBe(keys[0]);
  });

  it.each([
    {
      name: "short Token ID",
      response: {
        id: "tok_1",
        prefix: "owat_AAAAAAAA",
        token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        replayed: false,
      },
    },
    {
      name: "prefix mismatch",
      response: {
        id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
        prefix: "owat_BBBBBBBB",
        token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        replayed: false,
      },
    },
    {
      name: "noncanonical expiry",
      response: {
        id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
        prefix: "owat_AAAAAAAA",
        token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        expiresAt: "2030-01-02T03:04:00+00:00",
        replayed: false,
      },
    },
  ])("rejects issued Token DTO with $name", async ({ response }) => {
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path.endsWith("/tokens")) return response;
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    expect(await screen.findByRole("alert")).toBeVisible();
    expect(document.body).not.toHaveTextContent(
      "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
  });

  it("rotates the issue key after confirmed success", async () => {
    const keys: Array<string | null> = [];
    let attempt = 0;
    const secondToken =
      `owat_${"B".repeat(42)}A`;
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_AAAAAAAAAAAAAAAAAAAAAA",
            name: "Hermes",
            tokenCount: attempt,
            activeTokens: attempt,
          }],
        };
      }
      if (path.endsWith("/tokens") && options?.method === "POST") {
        keys.push(idempotencyKey(options));
        attempt += 1;
        return attempt === 1
          ? {
              id: "tok_AAAAAAAAAAAAAAAAAAAAAA",
              prefix: "owat_AAAAAAAA",
              token: "owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              replayed: false,
            }
          : {
              id: `tok_${"B".repeat(21)}A`,
              prefix: "owat_BBBBBBBB",
              token: secondToken,
              replayed: false,
            };
      }
      throw new Error(`unexpected ${path}`);
    });
    render(
      <AgentListPage
        api={api}
        space={space}
        systemRole="system_owner"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    await screen.findByText("owat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    fireEvent.click(screen.getByRole("button", { name: "关闭" }));
    fireEvent.click(screen.getByRole("button", { name: "创建 Token" }));
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建并显示 Token" }));
    await screen.findByText(secondToken);
    expect(keys).toHaveLength(2);
    expect(keys[1]).not.toBe(keys[0]);
  });
});
