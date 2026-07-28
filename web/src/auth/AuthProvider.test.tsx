import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthProvider, useAuth } from "./AuthProvider";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function Probe() {
  const auth = useAuth();
  return (
    <div>
      <output aria-label="状态">{auth.status}</output>
      <output aria-label="用户">{auth.principal?.userId ?? "none"}</output>
      <button
        type="button"
        onClick={() => void auth.completeLogin("old", "111111").catch(() => {})}
      >
        旧登录
      </button>
      <button
        type="button"
        onClick={() => void auth.completeLogin("new", "222222").catch(() => {})}
      >
        新登录
      </button>
      <button type="button" onClick={() => void auth.logout()}>退出测试</button>
    </div>
  );
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("AuthProvider generation guards", () => {
  it("authenticates through a refresh triggered by a short-lived login token", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.setSystemTime(new Date("2026-07-28T00:00:00Z"));
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/api/v1/auth/login/complete") {
        return json({
          token: "short-token",
          expiresAt: new Date(Date.now() + 10_000).toISOString(),
        });
      }
      if (path === "/api/v1/auth/refresh") {
        expect(new Headers(init?.headers).get("Authorization")).toBe(
          "Bearer short-token",
        );
        return json({ token: "refreshed-token" });
      }
      if (path === "/api/v1/me") {
        expect(new Headers(init?.headers).get("Authorization")).toBe(
          "Bearer refreshed-token",
        );
        return json({
          userId: "refreshed-user",
          systemRole: "member",
          issuedAt: "2026-07-28T00:00:00Z",
        });
      }
      throw new Error(`unexpected ${path}`);
    });
    render(<AuthProvider><Probe /></AuthProvider>);

    fireEvent.click(screen.getByRole("button", { name: "旧登录" }));

    expect(await screen.findByText("refreshed-user")).toBeVisible();
    expect(screen.getByLabelText("状态")).toHaveTextContent("authenticated");
  });

  it("does not let a refreshing old login clear a newer account", async () => {
    const oldRefresh = deferred<Response>();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/api/v1/auth/login/complete") {
        const challenge = (JSON.parse(String(init?.body)) as { challengeId: string })
          .challengeId;
        return json({
          token: `${challenge}-token`,
          expiresAt: new Date(
            Date.now() + (challenge === "old" ? 10_000 : 5 * 60_000),
          ).toISOString(),
        });
      }
      if (path === "/api/v1/auth/refresh") return oldRefresh.promise;
      if (path === "/api/v1/me") {
        return json({
          userId: "new-user",
          systemRole: "member",
          issuedAt: "2026-07-28T00:00:00Z",
        });
      }
      throw new Error(`unexpected ${path}`);
    });
    render(<AuthProvider><Probe /></AuthProvider>);

    fireEvent.click(screen.getByRole("button", { name: "旧登录" }));
    await waitFor(() =>
      expect(
        vi.mocked(fetch).mock.calls.some(
          ([path]) => String(path) === "/api/v1/auth/refresh",
        ),
      ).toBe(true),
    );
    fireEvent.click(screen.getByRole("button", { name: "新登录" }));
    expect(await screen.findByText("new-user")).toBeVisible();

    oldRefresh.resolve(json({ token: "stale-refreshed-token" }));
    await Promise.resolve();
    expect(screen.getByLabelText("用户")).toHaveTextContent("new-user");
    expect(screen.getByLabelText("状态")).toHaveTextContent("authenticated");
  });

  it("redirects on current expiry and ignores a replaced session timer", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.setSystemTime(new Date("2026-07-28T00:00:00Z"));
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      if (String(input) === "/api/v1/auth/login/complete") {
        const challenge = (JSON.parse(String(init?.body)) as { challengeId: string })
          .challengeId;
        return json({
          token: `${challenge}-token`,
          expiresAt: new Date(
            Date.now() + (challenge === "old" ? 31_000 : 5 * 60_000),
          ).toISOString(),
        });
      }
      if (String(input) === "/api/v1/me") {
        return json({
          userId: new Headers(init?.headers)
            .get("Authorization")
            ?.includes("new")
            ? "new-user"
            : "old-user",
          systemRole: "member",
          issuedAt: "2026-07-28T00:00:00Z",
        });
      }
      throw new Error("unexpected request");
    });
    render(<AuthProvider><Probe /></AuthProvider>);
    fireEvent.click(screen.getByRole("button", { name: "旧登录" }));
    expect(await screen.findByText("old-user")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "新登录" }));
    expect(await screen.findByText("new-user")).toBeVisible();

    act(() => vi.advanceTimersByTime(31_000));
    expect(screen.getByLabelText("状态")).toHaveTextContent("authenticated");
    expect(screen.getByLabelText("用户")).toHaveTextContent("new-user");
    act(() => vi.advanceTimersByTime(5 * 60_000 - 31_000));
    expect(screen.getByLabelText("状态")).toHaveTextContent("anonymous");
    expect(screen.getByLabelText("用户")).toHaveTextContent("none");
  });

  it("keeps the new account principal when an old /me finishes later", async () => {
    const oldMe = deferred<Response>();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/api/v1/auth/login/complete") {
        const challenge = (JSON.parse(String(init?.body)) as { challengeId: string })
          .challengeId;
        return json({
          token: `${challenge}-token`,
          expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
        });
      }
      if (path === "/api/v1/me") {
        const token = new Headers(init?.headers).get("Authorization");
        if (token === "Bearer old-token") return oldMe.promise;
        return json({
          userId: "new-user",
          systemRole: "member",
          issuedAt: "2026-07-28T00:00:00Z",
        });
      }
      throw new Error(`unexpected ${path}`);
    });
    render(<AuthProvider><Probe /></AuthProvider>);

    fireEvent.click(screen.getByRole("button", { name: "旧登录" }));
    await waitFor(() =>
      expect(
        vi.mocked(fetch).mock.calls.some(
          ([path, init]) =>
            String(path) === "/api/v1/me" &&
            new Headers(init?.headers).get("Authorization") === "Bearer old-token",
        ),
      ).toBe(true),
    );
    fireEvent.click(screen.getByRole("button", { name: "新登录" }));
    expect(await screen.findByText("new-user")).toBeVisible();
    expect(screen.getByLabelText("状态")).toHaveTextContent("authenticated");

    oldMe.resolve(
      json({
        userId: "old-user",
        systemRole: "system_owner",
        issuedAt: "2026-07-28T00:00:00Z",
      }),
    );
    await Promise.resolve();
    expect(screen.getByLabelText("用户")).toHaveTextContent("new-user");
    expect(screen.getByLabelText("状态")).toHaveTextContent("authenticated");
  });

  it("logout and unmount abort pending account work without restoring state", async () => {
    const oldMe = deferred<Response>();
    let oldSignal: AbortSignal | null = null;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/api/v1/auth/login/complete") {
        return json({
          token: "old-token",
          expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
        });
      }
      if (path === "/api/v1/me") {
        oldSignal = init?.signal ?? null;
        return oldMe.promise;
      }
      if (path === "/api/v1/auth/logout") return new Response(null, { status: 204 });
      throw new Error(`unexpected ${path}`);
    });
    const view = render(<AuthProvider><Probe /></AuthProvider>);
    fireEvent.click(screen.getByRole("button", { name: "旧登录" }));
    await waitFor(() => expect(oldSignal).not.toBeNull());

    fireEvent.click(screen.getByRole("button", { name: "退出测试" }));
    expect(screen.getByLabelText("状态")).toHaveTextContent("anonymous");
    expect((oldSignal as AbortSignal | null)?.aborted).toBe(true);
    oldMe.resolve(
      json({
        userId: "old-user",
        systemRole: "system_owner",
        issuedAt: "2026-07-28T00:00:00Z",
      }),
    );
    await Promise.resolve();
    expect(screen.getByLabelText("用户")).toHaveTextContent("none");

    fireEvent.click(screen.getByRole("button", { name: "旧登录" }));
    view.unmount();
    expect((oldSignal as AbortSignal | null)?.aborted).toBe(true);
  });
});
