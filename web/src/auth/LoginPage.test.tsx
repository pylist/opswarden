import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "../App";
import { ApiClient } from "../api/client";
import { AuthProvider } from "./AuthProvider";

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
          expiresAt: "2099-01-01T00:00:00Z",
        },
      });
    }
    if (path === "/api/v1/auth/login/complete") {
      return jsonResponse({
        body: {
          token: "eyJ.memory.only",
          tokenType: "Bearer",
          expiresAt: "2099-01-01T00:00:00Z",
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
  await screen.findByLabelText("动态验证码或恢复码");
  fireEvent.change(screen.getByLabelText("动态验证码或恢复码"), {
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

  it("clears an authenticated session on 401", async () => {
    const fetchMock = installAuthenticatedFetch();
    render(<App />);
    await completePasswordAndTotpLogin();

    await screen.findByLabelText("当前空间");
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([path]) => String(path) === "/api/v1/audit-events",
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
    let token = "old-token";
    let expiresAt = Date.now() + 1_000;
    let refreshes = 0;
    const onSession = vi.fn((nextToken: string, nextExpiry: number) => {
      token = nextToken;
      expiresAt = nextExpiry;
    });
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input) === "/api/v1/auth/refresh") {
        refreshes += 1;
        return jsonResponse({ body: { token: "new-token" } });
      }
      return jsonResponse({ body: { userId: "usr-owner" } });
    });
    const client = new ApiClient({
      readSession: () => ({ token, expiresAt }),
      replaceSession: onSession,
      clearSession: vi.fn(),
    });

    await Promise.all([
      client.request("/api/v1/me"),
      client.request("/api/v1/me"),
    ]);
    expect(refreshes).toBe(1);
    expect(onSession).toHaveBeenCalledWith(
      "new-token",
      expect.any(Number),
    );
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
  afterEach(() => {
    vi.restoreAllMocks();
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
  });

  it("supports a keyboard-dismissable mobile navigation drawer", async () => {
    installAuthenticatedFetch();
    render(<App />);
    await completePasswordAndTotpLogin();

    fireEvent.click(screen.getByRole("button", { name: "打开导航" }));
    expect(screen.getByRole("navigation", { name: "主导航" })).toHaveClass("is-open");
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() =>
      expect(screen.getByRole("navigation", { name: "主导航" })).not.toHaveClass(
        "is-open",
      ),
    );
  });
});

describe("initial setup", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows recovery codes once and clears them when leaving setup", async () => {
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
    fireEvent.change(screen.getByLabelText("TOTP 种子"), {
      target: { value: "JBSWY3DPEHPK3PXP" },
    });
    fireEvent.click(screen.getByRole("button", { name: "创建初始管理员" }));

    expect(await screen.findByText("recovery-one")).toBeVisible();
    expect(setItem).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("checkbox", { name: /我已离线保存/ }));
    fireEvent.click(screen.getByRole("button", { name: "前往登录" }));
    expect(await screen.findByRole("heading", { name: "登录 OpsWarden" })).toBeVisible();
    expect(screen.queryByText("recovery-one")).not.toBeInTheDocument();
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
              expiresAt: "2099-01-01T00:00:00Z",
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
});
