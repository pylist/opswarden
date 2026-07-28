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

describe("Agent administration", () => {
  it("creates an Agent through recent TOTP and an idempotent request", async () => {
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return { items: [] };
      }
      if (path === "/api/v1/agents" && options?.method === "POST") {
        return {
          id: "agt_1",
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
            agentId: "agt_1",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_1/tokens" &&
          options?.method === "POST") {
        return {
          id: "tok_1",
          prefix: "owat_12345678",
          token: "owat_fixture_once",
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
    expect(await screen.findByText("owat_fixture_once")).toBeVisible();
    expect(api.reverifyTOTP).toHaveBeenCalledTimes(1);
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/agents/agt_1/tokens",
      expect.objectContaining({
        method: "POST",
        headers: expect.anything(),
      }),
    );

    fireEvent.click(screen.getByRole("button", { name: "关闭" }));
    expect(screen.queryByText("owat_fixture_once")).toBeNull();
    expect(
      api.request.mock.calls.filter(
        ([path]) => path === "/api/v1/agents/agt_1/tokens",
      ),
    ).toHaveLength(1);
  });

  it("does not allow a delayed issue response to reveal a token after view cleanup", async () => {
    const issue = deferred<unknown>();
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_1",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_1/tokens") return issue.promise;
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
            agentId: "agt_1",
            name: "Hermes",
            tokenCount: 1,
            activeTokens: 1,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_1/grants") return grant.promise;
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
        ([path]) => path === "/api/v1/agents/agt_1/grants",
      ),
    ).toHaveLength(1);
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/agents/agt_1/grants",
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
              agentId: "agt_1",
              name: "Hermes",
              tokenCount: 0,
              activeTokens: 0,
              token: "owat_hostile_list_plaintext",
            }],
          };
        }
        return {
          items: [{
            agentId: "agt_1",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_1/tokens") {
        return {
          id: "tok_1",
          prefix: "owat_12345678",
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
            agentId: "agt_1",
            name: "Hermes",
            tokenCount: 1,
            activeTokens: 1,
          }],
        };
      }
      if (
        path === "/api/v1/agents/agt_1/tokens" &&
        options?.method === "POST"
      ) {
        return {
          id: "tok_1",
          prefix: "owat_12345678",
          token: "owat_fixture_once",
          replayed: false,
        };
      }
      if (
        path === "/api/v1/agents/agt_1/tokens/tok_1" &&
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
    await screen.findByText("owat_fixture_once");
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
        "/api/v1/agents/agt_1/tokens/tok_1",
        expect.objectContaining({ method: "DELETE" }),
      );
    });
    expect(screen.queryByText("owat_fixture_once")).toBeNull();
  });

  it("sends optional expiry in the backend's canonical RFC3339 form", async () => {
    const api = apiFor(async (path, options) => {
      if (path === "/api/v1/agents" && !options?.method) {
        return {
          items: [{
            agentId: "agt_1",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_1/tokens") {
        return {
          id: "tok_1",
          prefix: "owat_12345678",
          token: "owat_fixture_once",
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
    await screen.findByText("owat_fixture_once");
    const canonicalExpiry = new Date("2030-01-02T03:04")
      .toISOString()
      .replace(/\.000Z$/u, "Z");
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/agents/agt_1/tokens",
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
            agentId: "agt_1",
            name: "Hermes",
            tokenCount: 0,
            activeTokens: 0,
          }],
        };
      }
      if (path === "/api/v1/agents/agt_1/tokens") {
        return {
          id: "tok_1",
          prefix: "owat_12345678",
          token: "owat_fixture_once",
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
    await screen.findByText("owat_fixture_once");
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
});
