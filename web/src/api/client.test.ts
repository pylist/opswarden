import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ApiClient,
  ApiError,
  MemorySessionController,
  formatApiError,
  parseTokenExpiry,
} from "./client";

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

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("canonical API paths", () => {
  it.each([
    "https://attacker.example/api/v1/me",
    "//attacker.example/api/v1/me",
    "/api/v1/../admin",
    "/api/v1/%2e%2e/admin",
    "/api/v1/a%2Fb",
    "/api/v1/a%5Cb",
    "/api/v1\\me",
    "/api/v1/me#token",
    "/api/v1/%00me",
    "/api/v1/%0ame",
    "/api/v1/%7fme",
    "/api/v1/%252e%252e/admin",
    "/api/v1/me ",
    "/api/v1",
  ])("rejects %s before fetch", async (path) => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const sessions = new MemorySessionController();
    sessions.allocate("session-token", Date.now() + 60_000);
    const client = new ApiClient(sessions);

    await expect(client.request(path)).rejects.toThrow("仅允许访问同源 API");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("preserves a canonical query and blocks redirects and cookie credentials", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ items: [] }));
    const sessions = new MemorySessionController();
    sessions.allocate("session-token", Date.now() + 60_000);

    await new ApiClient(sessions).request(
      "/api/v1/audit-events?spaceId=spc_123&limit=20",
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/audit-events?spaceId=spc_123&limit=20",
      expect.objectContaining({
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
      }),
    );
    expect(
      new Headers(fetchMock.mock.calls[0][1]?.headers).get("Authorization"),
    ).toBe("Bearer session-token");
  });
});

describe("session generations", () => {
  it("does not let an old delayed 401 clear a newer login", async () => {
    const oldResponse = deferred<Response>();
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => oldResponse.promise);
    const sessions = new MemorySessionController();
    const old = sessions.allocate("old-token", Date.now() + 60_000);
    const client = new ApiClient(sessions);

    const oldRequest = client.request("/api/v1/me");
    const current = sessions.allocate("new-token", Date.now() + 60_000);
    oldResponse.resolve(
      json({ error: { code: "UNAUTHENTICATED", requestId: "req-old" } }, 401),
    );

    await expect(oldRequest).rejects.toMatchObject({ name: "SessionSupersededError" });
    expect(sessions.isCurrent(old)).toBe(false);
    expect(sessions.isCurrent(current)).toBe(true);
    expect(sessions.readSession()?.token).toBe("new-token");
  });

  it("does not let an old delayed refresh replace a newer account token", async () => {
    const refreshResponse = deferred<Response>();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
      async (input) => {
        if (String(input) === "/api/v1/auth/refresh") return refreshResponse.promise;
        return json({ userId: "new-user" });
      },
    );
    const sessions = new MemorySessionController();
    sessions.allocate("old-token", Date.now() + 1_000);
    const client = new ApiClient(sessions);

    const oldRequest = client.request("/api/v1/me");
    const current = sessions.allocate("new-account-token", Date.now() + 60_000);
    refreshResponse.resolve(json({ token: "refreshed-old-token" }));

    await expect(oldRequest).rejects.toMatchObject({ name: "SessionSupersededError" });
    expect(sessions.isCurrent(current)).toBe(true);
    expect(sessions.readSession()?.token).toBe("new-account-token");
    expect(
      fetchMock.mock.calls.filter(
        ([input]) => String(input) === "/api/v1/auth/refresh",
      ),
    ).toHaveLength(1);
  });

  it("aborts old work and invalidates its generation on clear", () => {
    const sessions = new MemorySessionController();
    const old = sessions.allocate("old-token", Date.now() + 60_000);
    const abort = vi.fn();
    old.signal.addEventListener("abort", abort);

    expect(sessions.clearIfCurrent(old)).toBe(true);

    expect(abort).toHaveBeenCalledOnce();
    expect(sessions.readSession()).toBeNull();
    expect(sessions.isCurrent(old)).toBe(false);
  });
});

describe("expiry and safe errors", () => {
  it("expires the current session while an old timer cannot clear a replacement", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-28T00:00:00Z"));
    const sessions = new MemorySessionController();
    const old = sessions.allocate("old-token", Date.now() + 1_000);
    setTimeout(() => sessions.clearIfCurrent(old), 1_000);
    const replacement = sessions.allocate("new-token", Date.now() + 2_000);

    vi.advanceTimersByTime(1_000);
    expect(sessions.isCurrent(replacement)).toBe(true);
    setTimeout(() => sessions.clearIfCurrent(replacement), 1_000);
    vi.advanceTimersByTime(1_000);
    expect(sessions.readSession()).toBeNull();
  });

  it("accepts only finite, future, server-bounded token expiries", () => {
    const now = Date.parse("2026-07-28T00:00:00Z");
    expect(parseTokenExpiry("2026-07-28T00:15:00Z", now)).toBe(
      now + 15 * 60_000,
    );
    for (const value of [
      "",
      "not-a-date",
      "2026-07-27T23:59:59Z",
      "2026-07-28T00:17:00Z",
    ]) {
      expect(() => parseTokenExpiry(value, now)).toThrow(ApiError);
    }
  });

  it("wraps malformed successful JSON without exposing its body", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify("secret-success-body"), { status: 200 }),
    );
    const client = new ApiClient();

    let caught: unknown;
    try {
      await client.publicRequest("/api/v1/bootstrap/status");
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ code: "INVALID_RESPONSE" });
    expect(formatApiError(caught)).not.toContain("secret-success-body");
  });

  it("formats unknown errors with fixed client-owned text", () => {
    expect(formatApiError(new Error("network secret: hunter2"))).toBe(
      "请求失败，请检查网络连接后重试。",
    );
  });
});
