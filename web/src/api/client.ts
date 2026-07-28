import type { APIErrorEnvelope } from "./types";

type RequestBody = Record<string, unknown> | undefined;

export type RequestOptions = Omit<
  RequestInit,
  "body" | "credentials" | "redirect" | "referrerPolicy"
> & {
  body?: RequestBody;
};

export type SessionSnapshot = {
  readonly token: string;
  readonly expiresAt: number;
  readonly generation: number;
  readonly lineage: number;
  readonly signal: AbortSignal;
};

export interface SessionAccess {
  readSession(): SessionSnapshot | null;
  isCurrent(snapshot: SessionSnapshot): boolean;
  replaceIfCurrent(
    snapshot: SessionSnapshot,
    token: string,
    expiresAt: number,
  ): SessionSnapshot | null;
  clearIfCurrent(snapshot?: SessionSnapshot): boolean;
}

const publicPaths = new Set([
  "/api/v1/bootstrap/status",
  "/api/v1/auth/login/begin",
  "/api/v1/auth/login/complete",
  "/api/v1/bootstrap/initial-owner",
]);

const safeMessages: Record<string, string> = {
  INVALID_REQUEST: "请求内容无效，请检查后重试。",
  INVALID_RESPONSE: "服务返回了无法识别的响应。",
  UNAUTHENTICATED: "登录状态已失效，请重新登录。",
  PERMISSION_DENIED: "当前账号没有执行此操作的权限。",
  NOT_FOUND: "请求的资源不存在。",
  VERSION_CONFLICT: "数据已被更新，请刷新后重试。",
  RATE_LIMITED: "请求过于频繁，请稍后重试。",
  STORAGE_BUSY: "服务暂时繁忙，请稍后重试。",
  STORAGE_UNAVAILABLE: "服务暂时不可用，请稍后重试。",
  INTERNAL_ERROR: "服务发生内部错误。",
};

const refreshWindowMs = 30_000;
export const jwtLifetimeMs = 15 * 60_000;
const maximumExpiryMs = jwtLifetimeMs + 60_000;

export class ApiError extends Error {
  readonly code: string;
  readonly requestId: string;
  readonly status: number;

  constructor(code: string, requestId: string, status: number) {
    const safeMessage = safeMessages[code] ?? "请求未能完成。";
    super(requestId ? `${safeMessage}（请求编号：${requestId}）` : safeMessage);
    this.name = "ApiError";
    this.code = code;
    this.requestId = requestId;
    this.status = status;
  }
}

export class SessionSupersededError extends Error {
  constructor() {
    super("session superseded");
    this.name = "SessionSupersededError";
  }
}

export function formatApiError(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  return "请求失败，请检查网络连接后重试。";
}

export function parseTokenExpiry(value: string, now = Date.now()): number {
  const expiry = Date.parse(value);
  if (
    !Number.isFinite(expiry) ||
    expiry <= now ||
    expiry > now + maximumExpiryMs
  ) {
    throw new ApiError("INVALID_RESPONSE", "", 502);
  }
  return expiry;
}

export class MemorySessionController implements SessionAccess {
  private generation = 0;
  private current: SessionSnapshot | null = null;
  private listeners = new Set<(snapshot: SessionSnapshot | null) => void>();

  readSession() {
    return this.current;
  }

  isCurrent(snapshot: SessionSnapshot) {
    return (
      this.current === snapshot &&
      this.current.generation === snapshot.generation &&
      this.current.token === snapshot.token
    );
  }

  allocate(token: string, expiresAt: number): SessionSnapshot {
    return this.allocateForLineage(token, expiresAt);
  }

  isCurrentLineage(snapshot: SessionSnapshot) {
    return this.current?.lineage === snapshot.lineage;
  }

  clearLineageIfCurrent(snapshot: SessionSnapshot) {
    if (!this.isCurrentLineage(snapshot)) {
      return false;
    }
    return this.clearIfCurrent(this.current ?? undefined);
  }

  private allocateForLineage(
    token: string,
    expiresAt: number,
    lineage?: number,
  ): SessionSnapshot {
    if (
      token.length === 0 ||
      token.length > 16_384 ||
      !Number.isFinite(expiresAt) ||
      expiresAt <= Date.now()
    ) {
      throw new ApiError("INVALID_RESPONSE", "", 502);
    }
    this.abortCurrent();
    const controller = new AbortController();
    const snapshot: SessionSnapshot = Object.freeze({
      token,
      expiresAt,
      generation: ++this.generation,
      lineage: lineage ?? this.generation,
      signal: controller.signal,
    });
    this.current = snapshot;
    sessionControllers.set(snapshot, controller);
    this.emit();
    return snapshot;
  }

  replaceIfCurrent(
    snapshot: SessionSnapshot,
    token: string,
    expiresAt: number,
  ) {
    if (!this.isCurrent(snapshot)) {
      return null;
    }
    return this.allocateForLineage(token, expiresAt, snapshot.lineage);
  }

  clearIfCurrent(snapshot?: SessionSnapshot) {
    if (snapshot && !this.isCurrent(snapshot)) {
      return false;
    }
    if (!this.current) {
      return false;
    }
    this.abortCurrent();
    this.current = null;
    this.generation += 1;
    this.emit();
    return true;
  }

  subscribe(listener: (snapshot: SessionSnapshot | null) => void) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private abortCurrent() {
    if (!this.current) return;
    sessionControllers.get(this.current)?.abort();
    sessionControllers.delete(this.current);
  }

  private emit() {
    for (const listener of this.listeners) {
      listener(this.current);
    }
  }
}

const sessionControllers = new WeakMap<SessionSnapshot, AbortController>();

export class ApiClient {
  private session?: SessionAccess;
  private refreshFlight:
    | { generation: number; promise: Promise<SessionSnapshot> }
    | undefined;

  constructor(session?: SessionAccess) {
    this.session = session;
  }

  publicRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
    assertCanonicalAPIPath(path);
    if (!publicPaths.has(path)) {
      return Promise.reject(new ApiError("NOT_FOUND", "", 404));
    }
    return this.send<T>(path, options);
  }

  async request<T = unknown>(
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    assertCanonicalAPIPath(path);
    let snapshot = this.session?.readSession();
    if (!snapshot) {
      throw new ApiError("UNAUTHENTICATED", "", 401);
    }
    if (snapshot.expiresAt - Date.now() <= refreshWindowMs) {
      snapshot = await this.refresh(snapshot);
    }
    try {
      const result = await this.send<T>(
        path,
        { ...options, signal: combineSignals(snapshot.signal, options.signal) },
        snapshot.token,
      );
      if (!this.session?.isCurrent(snapshot)) {
        throw new SessionSupersededError();
      }
      return result;
    } catch (error) {
      if (!this.session?.isCurrent(snapshot)) {
        throw new SessionSupersededError();
      }
      if (error instanceof ApiError && error.status === 401) {
        this.session.clearIfCurrent(snapshot);
      }
      throw error;
    }
  }

  async closeSession(): Promise<void> {
    const snapshot = this.session?.readSession();
    if (!snapshot) return;
    this.session?.clearIfCurrent(snapshot);
    try {
      await this.send(
        "/api/v1/auth/logout",
        { method: "POST" },
        snapshot.token,
      );
    } catch {
      // Local invalidation is authoritative; the server session expires/revokes.
    }
  }

  async reverifyTOTP(code: string, signal?: AbortSignal): Promise<void> {
    if (!/^\d{6,8}$/.test(code)) {
      throw new ApiError("INVALID_REQUEST", "", 400);
    }
    let snapshot = this.session?.readSession();
    if (!snapshot) {
      throw new ApiError("UNAUTHENTICATED", "", 401);
    }
    if (snapshot.expiresAt - Date.now() <= refreshWindowMs) {
      snapshot = await this.refresh(snapshot);
    }
    try {
      const response = await this.send<{
        token: string;
        expiresAt: string;
      }>(
        "/api/v1/auth/reverify",
        {
          method: "POST",
          body: { code },
          signal: combineSignals(snapshot.signal, signal),
        },
        snapshot.token,
      );
      if (
        typeof response.token !== "string" ||
        response.token.length === 0 ||
        typeof response.expiresAt !== "string" ||
        !this.session?.isCurrent(snapshot)
      ) {
        throw new SessionSupersededError();
      }
      const replacement = this.session.replaceIfCurrent(
        snapshot,
        response.token,
        parseTokenExpiry(response.expiresAt),
      );
      if (!replacement) {
        throw new SessionSupersededError();
      }
    } catch (error) {
      if (!this.session?.isCurrent(snapshot)) {
        throw new SessionSupersededError();
      }
      if (error instanceof ApiError && error.status === 401) {
        this.session.clearIfCurrent(snapshot);
      }
      throw error;
    }
  }

  private refresh(snapshot: SessionSnapshot): Promise<SessionSnapshot> {
    if (
      this.refreshFlight &&
      this.refreshFlight.generation === snapshot.generation
    ) {
      return this.refreshFlight.promise;
    }
    const promise = this.performRefresh(snapshot).finally(() => {
      if (this.refreshFlight?.generation === snapshot.generation) {
        this.refreshFlight = undefined;
      }
    });
    this.refreshFlight = { generation: snapshot.generation, promise };
    return promise;
  }

  private async performRefresh(snapshot: SessionSnapshot) {
    try {
      const response = await this.send<{ token: string }>(
        "/api/v1/auth/refresh",
        { method: "POST", signal: snapshot.signal },
        snapshot.token,
      );
      if (
        typeof response.token !== "string" ||
        response.token.length === 0 ||
        !this.session?.isCurrent(snapshot)
      ) {
        throw new SessionSupersededError();
      }
      const replacement = this.session.replaceIfCurrent(
        snapshot,
        response.token,
        Date.now() + jwtLifetimeMs,
      );
      if (!replacement) {
        throw new SessionSupersededError();
      }
      return replacement;
    } catch (error) {
      if (!this.session?.isCurrent(snapshot)) {
        throw new SessionSupersededError();
      }
      this.session.clearIfCurrent(snapshot);
      throw error;
    }
  }

  private async send<T>(
    path: string,
    options: RequestOptions,
    token?: string,
  ): Promise<T> {
    assertCanonicalAPIPath(path);
    const headers = new Headers(options.headers);
    headers.set("Accept", "application/json");
    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
    }
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
    const response = await fetch(path, {
      ...options,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers,
    });
    if (!response.ok) {
      throw await decodeError(response);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    try {
      const value: unknown = await response.json();
      if (
        value === null ||
        typeof value !== "object" ||
        Array.isArray(value)
      ) {
        throw new ApiError("INVALID_RESPONSE", "", 502);
      }
      return value as T;
    } catch {
      throw new ApiError("INVALID_RESPONSE", "", 502);
    }
  }
}

export function assertCanonicalAPIPath(path: string) {
  if (
    typeof path !== "string" ||
    !path.startsWith("/api/v1/") ||
    path.startsWith("//") ||
    path.includes("\\") ||
    path.includes("#") ||
    /[\u0000-\u001f\u007f\s]/u.test(path)
  ) {
    throw new Error("仅允许访问同源 API");
  }
  const queryIndex = path.indexOf("?");
  const rawPath = queryIndex === -1 ? path : path.slice(0, queryIndex);
  if (
    rawPath.includes("%") ||
    rawPath.includes("//") ||
    rawPath.endsWith("/") ||
    rawPath.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    throw new Error("仅允许访问同源 API");
  }
  const parsed = new URL(path, window.location.origin);
  const canonical = `${parsed.pathname}${parsed.search}`;
  if (
    parsed.origin !== window.location.origin ||
    parsed.username ||
    parsed.password ||
    canonical !== path
  ) {
    throw new Error("仅允许访问同源 API");
  }
}

export function apiPath(
  segments: readonly string[],
  query: Record<string, string | number | undefined> = {},
) {
  if (
    segments.length === 0 ||
    segments.some((segment) => !/^[A-Za-z0-9_-]+$/.test(segment))
  ) {
    throw new Error("无效的 API 路径段");
  }
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (!/^[A-Za-z][A-Za-z0-9]*$/.test(key) || value === undefined) continue;
    parameters.set(key, String(value));
  }
  const suffix = parameters.size ? `?${parameters.toString()}` : "";
  const path = `/api/v1/${segments.join("/")}${suffix}`;
  assertCanonicalAPIPath(path);
  return path;
}

async function decodeError(response: Response): Promise<ApiError> {
  let envelope: APIErrorEnvelope = {};
  try {
    envelope = (await response.json()) as APIErrorEnvelope;
  } catch {
    // Error bodies are never surfaced.
  }
  const code =
    typeof envelope.error?.code === "string"
      ? envelope.error.code
      : "INTERNAL_ERROR";
  const requestId =
    typeof envelope.error?.requestId === "string"
      ? envelope.error.requestId
      : response.headers.get("X-Request-ID") ?? "";
  return new ApiError(code, requestId, response.status);
}

function combineSignals(
  sessionSignal: AbortSignal,
  requestSignal?: AbortSignal | null,
) {
  if (!requestSignal) return sessionSignal;
  if (typeof AbortSignal.any === "function") {
    return AbortSignal.any([sessionSignal, requestSignal]);
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  sessionSignal.addEventListener("abort", abort, { once: true });
  requestSignal.addEventListener("abort", abort, { once: true });
  if (sessionSignal.aborted || requestSignal.aborted) controller.abort();
  return controller.signal;
}
