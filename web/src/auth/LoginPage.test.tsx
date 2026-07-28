import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "../App";
import { ApiClient, MemorySessionController } from "../api/client";
import { AuthProvider } from "./AuthProvider";
import { generateTOTPCode } from "./totp";

const originalMatchMedia = window.matchMedia;

type JsonResponse = {
  status?: number;
  body?: unknown;
};

function jsonResponse({ status = 200, body = {} }: JsonResponse = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function installAuthenticatedFetch() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const path = String(input);
    if (path === "/api/v1/bootstrap/status") {
      return jsonResponse({ body: { needsInitialOwner: false } });
    }
    if (path === "/api/v1/auth/login/begin") {
      return jsonResponse({
        body: {
          challengeId: "challenge-1",
          expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
        },
      });
    }
    if (path === "/api/v1/auth/login/complete") {
      return jsonResponse({
        body: {
          token: "eyJ.memory.only",
          tokenType: "Bearer",
          expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
        },
      });
    }
    if (path === "/api/v1/me") {
      return jsonResponse({
        body: {
          userId: "usr-owner",
          systemRole: "owner",
          issuedAt: "2026-07-28T00:00:00Z",
        },
      });
    }
    if (path === "/api/v1/spaces") {
      return jsonResponse({
        body: {
          items: [{ id: "spc-main", name: "生产环境", role: "owner" }],
        },
      });
    }
    throw new Error(`unexpected request: ${path} ${String(init?.method)}`);
  });
}

async function completePasswordAndTotpLogin() {
  await screen.findByLabelText("邮箱");
  fireEvent.change(screen.getByLabelText("邮箱"), {
    target: { value: "owner@example.com" },
  });
  fireEvent.change(screen.getByLabelText("密码"), {
    target: { value: "correct horse battery staple" },
  });
  fireEvent.click(screen.getByRole("button", { name: "继续" }));
  await screen.findByRole("textbox", { name: "动态验证码" });
  fireEvent.change(screen.getByRole("textbox", { name: "动态验证码" }), {
    target: { value: "123456" },
  });
  fireEvent.click(screen.getByRole("button", { name: "登录" }));
  await screen.findByRole("heading", { name: "概览" });
}

describe("JWT-only authentication", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("never writes or reads auth material from browser storage", async () => {
    installAuthenticatedFetch();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const getItem = vi.spyOn(Storage.prototype, "getItem");
    render(<App />);

    await completePasswordAndTotpLogin();

    expect(setItem).not.toHaveBeenCalled();
    expect(getItem).not.toHaveBeenCalled();
  });

  it("performs password then TOTP login and sends JWT only to protected API paths", async () => {
    const fetchMock = installAuthenticatedFetch();
    render(<App />);

    await completePasswordAndTotpLogin();

    const begin = fetchMock.mock.calls.find(([path]) =>
      String(path).endsWith("/auth/login/begin"),
    );
    const complete = fetchMock.mock.calls.find(([path]) =>
      String(path).endsWith("/auth/login/complete"),
    );
    const me = fetchMock.mock.calls.find(([path]) => String(path) === "/api/v1/me");
    expect(begin?.[1]).toMatchObject({ credentials: "omit" });
    expect(complete?.[1]).toMatchObject({ credentials: "omit" });
    expect(new Headers(begin?.[1]?.headers).has("Authorization")).toBe(false);
    expect(new Headers(complete?.[1]?.headers).has("Authorization")).toBe(false);
    expect(new Headers(me?.[1]?.headers).get("Authorization")).toBe(
      "Bearer eyJ.memory.only",
    );
  });

  it("switches between mobile-friendly TOTP and recovery-code inputs", async () => {
    installAuthenticatedFetch();
    render(<App />);
    await screen.findByLabelText("邮箱");
    fireEvent.change(screen.getByLabelText("邮箱"), {
      target: { value: "owner@example.com" },
    });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "继续" }));

    expect(
      await screen.findByRole("textbox", { name: "动态验证码" }),
    ).toHaveAttribute(
      "inputmode",
      "numeric",
    );
    fireEvent.click(screen.getByRole("radio", { name: "恢复码" }));
    expect(screen.getByRole("textbox", { name: "恢复码" })).toHaveAttribute(
      "inputmode",
      "text",
    );
    expect(screen.getByRole("textbox", { name: "恢复码" })).toHaveAttribute(
      "autocapitalize",
      "characters",
    );
  });

  it("clears an authenticated session on 401", async () => {
    const fetchMock = installAuthenticatedFetch();
    render(<App />);
    await completePasswordAndTotpLogin();

    await screen.findByLabelText("当前空间");
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([path]) => String(path).startsWith("/api/v1/audit-events?spaceId="),
        ),
      ).toBe(true),
    );
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse({
        status: 401,
        body: {
          error: {
            code: "UNAUTHENTICATED",
            message: "raw server message",
            requestId: "req-support-401",
            details: { token: "must-not-render" },
          },
        },
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "重新加载空间" }));

    expect(await screen.findByRole("heading", { name: "登录 OpsWarden" })).toBeVisible();
    expect(screen.queryByText("must-not-render")).not.toBeInTheDocument();
  });

  it("coalesces near-expiry refreshes and never authorizes an arbitrary URL", async () => {
    let refreshes = 0;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input) === "/api/v1/auth/refresh") {
        refreshes += 1;
        return jsonResponse({ body: { token: "new-token" } });
      }
      return jsonResponse({ body: { userId: "usr-owner" } });
    });
    const sessions = new MemorySessionController();
    sessions.allocate("old-token", Date.now() + 1_000);
    const client = new ApiClient(sessions);

    await Promise.all([
      client.request("/api/v1/me"),
      client.request("/api/v1/me"),
    ]);
    expect(refreshes).toBe(1);
    expect(sessions.readSession()?.token).toBe("new-token");
    await expect(client.request("https://attacker.example/collect")).rejects.toThrow(
      "仅允许访问同源 API",
    );
  });

  it("renders stable errors with requestId but never raw details", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      jsonResponse({
        status: 400,
        body: {
          error: {
            code: "INVALID_REQUEST",
            message: "raw message must stay hidden",
            requestId: "req-safe-123",
            details: { password: "do-not-display" },
          },
        },
      }),
    );
    const client = new ApiClient();

    await expect(
      client.publicRequest("/api/v1/auth/login/begin", {
        method: "POST",
        body: { email: "x", password: "y" },
      }),
    ).rejects.toEqual(
      expect.objectContaining({
        code: "INVALID_REQUEST",
        requestId: "req-safe-123",
      }),
    );
    try {
      await client.publicRequest("/api/v1/auth/login/begin");
    } catch (error) {
      expect(String(error)).toContain("req-safe-123");
      expect(String(error)).not.toContain("raw message");
      expect(String(error)).not.toContain("do-not-display");
    }
  });
});

describe("application shell", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: originalMatchMedia,
    });
  });

  it("renders approved primary navigation and current Space role", async () => {
    installAuthenticatedFetch();
    render(<App />);
    await completePasswordAndTotpLogin();

    for (const name of [
      "概览",
      "凭据库",
      "资产",
      "Agent",
      "审计日志",
      "成员与权限",
      "设置",
    ]) {
      expect(screen.getByRole("link", { name })).toBeVisible();
    }
    expect(await screen.findByLabelText("当前空间")).toHaveValue("spc-main");
    expect(screen.getByText("所有者")).toBeVisible();
    expect(screen.getByText("全局 Agent 数量")).toBeVisible();
  });

  it("supports a keyboard-dismissable mobile navigation drawer", async () => {
    installMobileMatchMedia();
    installAuthenticatedFetch();
    render(<App />);
    await completePasswordAndTotpLogin();

    const navigation = document.querySelector('nav[aria-label="主导航"]');
    expect(navigation).not.toBeNull();
    expect(navigation).toHaveAttribute("aria-hidden", "true");
    expect(navigation).toHaveAttribute("inert");
    fireEvent.click(screen.getByRole("button", { name: "打开导航" }));
    expect(screen.getByRole("navigation", { name: "主导航" })).not.toHaveAttribute(
      "aria-hidden",
    );
    expect(document.querySelector(".app-column")).toHaveAttribute("inert");
    const first = screen.getByRole("link", { name: "概览" });
    const last = screen.getByRole("link", { name: "设置" });
    last.focus();
    fireEvent.keyDown(last, { key: "Tab" });
    expect(first).toHaveFocus();
    first.focus();
    fireEvent.keyDown(first, { key: "Tab", shiftKey: true });
    expect(last).toHaveFocus();
    const appColumn = document.querySelector(".app-column");
    const menuButton = screen.getByRole("button", { name: "打开导航" });
    const focus = vi.spyOn(menuButton, "focus").mockImplementation(() => {
      expect(appColumn).not.toHaveAttribute("inert");
    });
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() =>
      expect(
        document.querySelector('nav[aria-label="主导航"]'),
      ).toHaveAttribute("aria-hidden", "true"),
    );
    expect(focus).toHaveBeenCalledOnce();
  });

  it("uses exact route names and synchronizes view and validated Space on popstate", async () => {
    installAuthenticatedFetch();
    render(<App />);
    await completePasswordAndTotpLogin();
    await screen.findByLabelText("当前空间");

    window.history.pushState({}, "", "/?view=assets&space=spc-main");
    window.dispatchEvent(new PopStateEvent("popstate"));
    expect(
      await screen.findByRole("heading", { name: "资产", level: 1 }),
    ).toBeVisible();
    expect(screen.getByLabelText("当前空间")).toHaveValue("spc-main");

    window.history.pushState({}, "", "/?view=toString&space=spc-untrusted");
    window.dispatchEvent(new PopStateEvent("popstate"));
    expect(await screen.findByRole("heading", { name: "概览" })).toBeVisible();
    await waitFor(() =>
      expect(new URL(window.location.href).searchParams.get("space")).toBe(
        "spc-main",
      ),
    );
  });

  it("scopes audit metrics to the selected Space and aborts stale metric work", async () => {
    const firstAudit = deferredResponse();
    let firstAuditSignal: AbortSignal | null = null;
    const fetchMock = installAuthenticatedFetch();
    fetchMock.mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/api/v1/bootstrap/status") {
        return jsonResponse({ body: { needsInitialOwner: false } });
      }
      if (path === "/api/v1/auth/login/begin") {
        return jsonResponse({
          body: { challengeId: "c", expiresAt: "2099-01-01T00:00:00Z" },
        });
      }
      if (path === "/api/v1/auth/login/complete") {
        return jsonResponse({
          body: {
            token: "memory-token",
            expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
          },
        });
      }
      if (path === "/api/v1/me") {
        return jsonResponse({
          body: {
            userId: "u",
            systemRole: "system_owner",
            issuedAt: "2026-07-28T00:00:00Z",
          },
        });
      }
      if (path === "/api/v1/spaces") {
        return jsonResponse({
          body: {
            items: [
              { id: "spc-a", name: "A", role: "owner" },
              { id: "spc-b", name: "B", role: "owner" },
            ],
          },
        });
      }
      if (path === "/api/v1/audit-events?spaceId=spc-a") {
        firstAuditSignal = init?.signal ?? null;
        return firstAudit.promise;
      }
      if (path === "/api/v1/audit-events?spaceId=spc-b") {
        return jsonResponse({ body: { items: [{}, {}] } });
      }
      return jsonResponse({ body: { items: [] } });
    });
    render(<App />);
    await completePasswordAndTotpLogin();
    const select = await screen.findByLabelText("当前空间");
    await waitFor(() => expect(firstAuditSignal).not.toBeNull());

    fireEvent.change(select, { target: { value: "spc-b" } });

    await waitFor(() => expect(firstAuditSignal?.aborted).toBe(true));
    expect(await screen.findByText("2")).toBeVisible();
    firstAudit.resolve(jsonResponse({ body: { items: [{}] } }));
    await Promise.resolve();
    expect(screen.getByText("2")).toBeVisible();
  });
});

describe("initial setup", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("requires a locally verified TOTP code and guards pending bootstrap navigation", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.setSystemTime(new Date("2026-07-28T00:00:00Z"));
    installDeterministicRandom(0);
    window.history.replaceState({}, "", "/setup");
    const bootstrap = deferredResponse();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input) === "/api/v1/bootstrap/status") {
        return jsonResponse({ body: { needsInitialOwner: true } });
      }
      return bootstrap.promise;
    });
    render(<App />);

    fireEvent.change(await screen.findByLabelText("管理员邮箱"), {
      target: { value: "owner@example.com" },
    });
    fireEvent.change(screen.getByLabelText("管理员密码"), {
      target: { value: "a-long-local-password" },
    });
    const submit = screen.getByRole("button", { name: "创建初始管理员" });
    expect(submit).toBeDisabled();
    fireEvent.submit(submit.closest("form")!);
    expect(
      vi.mocked(fetch).mock.calls.filter(
        ([path]) => String(path) === "/api/v1/bootstrap/initial-owner",
      ),
    ).toHaveLength(0);
    fireEvent.change(screen.getByRole("textbox", { name: "动态验证码" }), {
      target: { value: "578926" },
    });
    fireEvent.click(screen.getByRole("button", { name: "验证动态验证码" }));
    expect(await screen.findByText("动态验证码已验证")).toBeVisible();
    expect(submit).toBeEnabled();

    fireEvent.click(submit);
    expect(
      screen.queryByRole("button", { name: "返回登录" }),
    ).not.toBeInTheDocument();
    const unload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(true);
    window.history.pushState({}, "", "/");
    window.dispatchEvent(new PopStateEvent("popstate"));
    expect(window.location.pathname).toBe("/setup");
    expect(screen.getByRole("heading", { name: "设置初始管理员" })).toBeVisible();

    bootstrap.resolve(
      jsonResponse({ status: 201, body: { userId: "u", recoveryCodes: ["one"] } }),
    );
    expect(await screen.findByText("one")).toBeVisible();
    const settledUnload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(settledUnload);
    expect(settledUnload.defaultPrevented).toBe(false);
  });

  it("shows recovery codes once and clears them when leaving setup", async () => {
    installDeterministicRandom(7);
    window.history.replaceState({}, "", "/setup");
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input) === "/api/v1/bootstrap/status") {
        return jsonResponse({ body: { needsInitialOwner: true } });
      }
      return jsonResponse({
          status: 201,
          body: {
            userId: "usr-owner",
            recoveryCodes: ["recovery-one", "recovery-two"],
          },
        });
    });
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    render(<App />);

    fireEvent.change(await screen.findByLabelText("管理员邮箱"), {
      target: { value: "owner@example.com" },
    });
    fireEvent.change(screen.getByLabelText("管理员密码"), {
      target: { value: "a-long-local-password" },
    });
    expect(screen.getByLabelText("TOTP 种子")).toHaveAttribute("readonly");
    expect(screen.getByLabelText("TOTP 种子")).toHaveAttribute("type", "password");
    fireEvent.click(screen.getByRole("button", { name: "显示种子" }));
    expect(screen.getByLabelText("TOTP 种子")).toHaveAttribute("type", "text");
    await verifyDisplayedTOTP();
    fireEvent.click(screen.getByRole("button", { name: "创建初始管理员" }));

    expect(await screen.findByText("recovery-one")).toBeVisible();
    expect(screen.queryByLabelText("TOTP 种子")).not.toBeInTheDocument();
    expect(setItem).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("checkbox", { name: /我已离线保存/ }));
    fireEvent.click(screen.getByRole("button", { name: "前往登录" }));
    expect(await screen.findByRole("heading", { name: "登录 OpsWarden" })).toBeVisible();
    expect(screen.queryByText("recovery-one")).not.toBeInTheDocument();
  });

  it("generates a 160-bit seed and synchronously blocks duplicate bootstrap posts", async () => {
    installDeterministicRandom(0);
    window.history.replaceState({}, "", "/setup");
    const bootstrap = deferredResponse();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
      async (input) => {
        if (String(input) === "/api/v1/bootstrap/status") {
          return jsonResponse({ body: { needsInitialOwner: true } });
        }
        return bootstrap.promise;
      },
    );
    render(<App />);
    fireEvent.change(await screen.findByLabelText("管理员邮箱"), {
      target: { value: "owner@example.com" },
    });
    fireEvent.change(screen.getByLabelText("管理员密码"), {
      target: { value: "a-long-local-password" },
    });
    const submit = screen.getByRole("button", { name: "创建初始管理员" });

    await verifyDisplayedTOTP();
    fireEvent.click(submit);
    fireEvent.submit(submit.closest("form")!);

    const posts = fetchMock.mock.calls.filter(
      ([path]) => String(path) === "/api/v1/bootstrap/initial-owner",
    );
    expect(posts).toHaveLength(1);
    const body = JSON.parse(String(posts[0][1]?.body)) as Record<string, unknown>;
    expect(body.totpSeed).toBe("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expect(body).not.toHaveProperty("totpCode");
    expect(body).not.toHaveProperty("verificationCode");
    bootstrap.resolve(
      jsonResponse({ status: 201, body: { userId: "u", recoveryCodes: ["one"] } }),
    );
    expect(await screen.findByText("one")).toBeVisible();
  });

  it("never renders unknown network or malformed-success secrets", async () => {
    installDeterministicRandom(1);
    window.history.replaceState({}, "", "/setup");
    let attempts = 0;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input) === "/api/v1/bootstrap/status") {
        return jsonResponse({ body: { needsInitialOwner: true } });
      }
      attempts += 1;
      if (attempts === 1) throw new Error("network-secret-value");
      return new Response("success-secret-value{", { status: 201 });
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("管理员邮箱"), {
      target: { value: "owner@example.com" },
    });
    fireEvent.change(screen.getByLabelText("管理员密码"), {
      target: { value: "a-long-local-password" },
    });
    await verifyDisplayedTOTP();
    fireEvent.click(screen.getByRole("button", { name: "创建初始管理员" }));
    expect(await screen.findByRole("alert")).not.toHaveTextContent("network-secret-value");
    fireEvent.change(screen.getByLabelText("管理员密码"), {
      target: { value: "a-long-local-password" },
    });
    await verifyDisplayedTOTP();
    fireEvent.click(screen.getByRole("button", { name: "创建初始管理员" }));
    expect(await screen.findByRole("alert")).not.toHaveTextContent("success-secret-value");
  });

  it("only exposes setup when the internal status endpoint reports no owner", async () => {
    window.history.replaceState({}, "", "/");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ body: { needsInitialOwner: true } }),
    );
    render(<App />);

    expect(await screen.findByRole("button", { name: "初始化管理员" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "初始化管理员" }));
    expect(await screen.findByRole("heading", { name: "设置初始管理员" })).toBeVisible();
  });

  it("never enables setup for a malformed bootstrap status boolean", async () => {
    window.history.replaceState({}, "", "/setup");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ body: { needsInitialOwner: "false" } }),
    );
    render(<App />);

    expect(await screen.findByRole("heading", { name: "登录 OpsWarden" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "初始化管理员" })).not.toBeInTheDocument();
  });

  it("hides setup and keeps login available when status is forbidden", async () => {
    window.history.replaceState({}, "", "/setup");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        status: 403,
        body: {
          error: {
            code: "PERMISSION_DENIED",
            requestId: "req-external",
          },
        },
      }),
    );
    render(<App />);

    expect(await screen.findByRole("heading", { name: "登录 OpsWarden" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "初始化管理员" })).not.toBeInTheDocument();
    expect(screen.getByText(/联系管理员/)).toBeVisible();
    expect(screen.queryByText(/是否已有管理员/)).not.toBeInTheDocument();
  });

  it("lets the first owner create and select an initial Space after login", async () => {
    window.history.replaceState({}, "", "/");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
      async (input, init) => {
        const path = String(input);
        if (path === "/api/v1/bootstrap/status") {
          return jsonResponse({ body: { needsInitialOwner: false } });
        }
        if (path === "/api/v1/auth/login/begin") {
          return jsonResponse({
            body: { challengeId: "challenge-1", expiresAt: "2099-01-01T00:00:00Z" },
          });
        }
        if (path === "/api/v1/auth/login/complete") {
          return jsonResponse({
            body: {
              token: "memory-token",
              expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
            },
          });
        }
        if (path === "/api/v1/me") {
          return jsonResponse({
            body: {
              userId: "usr-owner",
              systemRole: "system_owner",
              issuedAt: "2026-07-28T00:00:00Z",
            },
          });
        }
        if (path === "/api/v1/spaces") {
          if (init?.method !== "POST") {
            return jsonResponse({ body: { items: [] } });
          }
          return jsonResponse({
            status: 201,
            body: { id: "spc-first", name: "内部工具", role: "owner" },
          });
        }
        throw new Error(`unexpected request: ${path}`);
      },
    );
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse({ body: { needsInitialOwner: false } }),
    );
    render(<App />);
    await completePasswordAndTotpLogin();

    fireEvent.change(await screen.findByLabelText("初始空间名称"), {
      target: { value: "内部工具" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建空间" }));

    expect(await screen.findByLabelText("当前空间")).toHaveValue("spc-first");
    const createCall = fetchMock.mock.calls.find(
      ([path, init]) =>
        String(path) === "/api/v1/spaces" && init?.method === "POST",
    );
    expect(new Headers(createCall?.[1]?.headers).get("Authorization")).toBe(
      "Bearer memory-token",
    );
  });

  it("rejects a malformed initial Space response without changing the URL", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/api/v1/bootstrap/status") {
        return jsonResponse({ body: { needsInitialOwner: false } });
      }
      if (path === "/api/v1/auth/login/begin") {
        return jsonResponse({
          body: { challengeId: "c", expiresAt: "2099-01-01T00:00:00Z" },
        });
      }
      if (path === "/api/v1/auth/login/complete") {
        return jsonResponse({
          body: {
            token: "memory-token",
            expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
          },
        });
      }
      if (path === "/api/v1/me") {
        return jsonResponse({
          body: {
            userId: "usr-owner",
            systemRole: "system_owner",
            issuedAt: "2026-07-28T00:00:00Z",
          },
        });
      }
      if (path === "/api/v1/spaces" && init?.method !== "POST") {
        return jsonResponse({ body: { items: [] } });
      }
      if (path === "/api/v1/spaces") {
        return jsonResponse({
          status: 201,
          body: { id: "//", name: "malformed", role: "owner" },
        });
      }
      return jsonResponse({ body: { items: [] } });
    });
    window.history.replaceState({}, "", "/");
    render(<App />);
    await completePasswordAndTotpLogin();
    fireEvent.change(await screen.findByLabelText("初始空间名称"), {
      target: { value: "内部工具" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建空间" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "请求失败，请检查网络连接后重试。",
    );
    expect(window.location.search).not.toContain("space=");
    expect(screen.queryByLabelText("当前空间")).not.toBeInTheDocument();
  });
});

function installDeterministicRandom(byte: number) {
  return vi
    .spyOn(globalThis.crypto, "getRandomValues")
    .mockImplementation(((array: Uint8Array) => {
      expect(array.byteLength).toBe(20);
      array.fill(byte);
      return array;
    }) as typeof globalThis.crypto.getRandomValues);
}

async function verifyDisplayedTOTP() {
  const seed = (screen.getByLabelText("TOTP 种子") as HTMLInputElement).value;
  const code = await generateTOTPCode(seed);
  fireEvent.change(screen.getByRole("textbox", { name: "动态验证码" }), {
    target: { value: code },
  });
  fireEvent.click(screen.getByRole("button", { name: "验证动态验证码" }));
  await screen.findByText("动态验证码已验证");
}

function deferredResponse() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function installMobileMatchMedia() {
  const listeners = new Set<(event: MediaQueryListEvent) => void>();
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: query === "(max-width: 720px)",
      media: query,
      onchange: null,
      addEventListener: (_: string, listener: (event: MediaQueryListEvent) => void) =>
        listeners.add(listener),
      removeEventListener: (
        _: string,
        listener: (event: MediaQueryListEvent) => void,
      ) => listeners.delete(listener),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}
