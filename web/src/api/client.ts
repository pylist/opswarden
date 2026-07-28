import type { APIErrorEnvelope } from "./types";

type RequestBody = Record<string, unknown> | undefined;

export type RequestOptions = Omit<RequestInit, "body" | "credentials"> & {
  body?: RequestBody;
};

type SessionSnapshot = {
  token: string;
  expiresAt: number;
};

type SessionAccess = {
  readSession: () => SessionSnapshot | null;
  replaceSession: (token: string, expiresAt: number) => void;
  clearSession: () => void;
};

const publicPaths = new Set([
  "/api/v1/bootstrap/status",
  "/api/v1/auth/login/begin",
  "/api/v1/auth/login/complete",
  "/api/v1/bootstrap/initial-owner",
]);

const safeMessages: Record<string, string> = {
  INVALID_REQUEST: "请求内容无效，请检查后重试。",
  UNAUTHENTICATED: "登录状态已失效，请重新登录。",
  PERMISSION_DENIED: "当前账号没有执行此操作的权限。",
  NOT_FOUND: "请求的资源不存在。",
  VERSION_CONFLICT: "数据已被更新，请刷新后重试。",
  RATE_LIMITED: "请求过于频繁，请稍后重试。",
  STORAGE_BUSY: "服务暂时繁忙，请稍后重试。",
  STORAGE_UNAVAILABLE: "服务暂时不可用，请稍后重试。",
  INTERNAL_ERROR: "服务发生内部错误。",
};

const apiPathPattern = /^\/api\/v1(?:\/|$)/;
const refreshWindowMs = 30_000;
const refreshedTokenLifetimeMs = 15 * 60_000;

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

export class ApiClient {
  private session?: SessionAccess;
  private refreshPromise: Promise<void> | null = null;

  constructor(session?: SessionAccess) {
    this.session = session;
  }

  publicRequest<T>(
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    if (!publicPaths.has(path)) {
      return Promise.reject(new Error("仅允许访问公开认证 API"));
    }
    return this.send<T>(path, options);
  }

  async request<T = unknown>(
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    this.assertSafePath(path);
    const session = this.session?.readSession();
    if (!session?.token) {
      throw new ApiError("UNAUTHENTICATED", "", 401);
    }
    if (session.expiresAt - Date.now() <= refreshWindowMs) {
      await this.refresh();
    }
    const current = this.session?.readSession();
    if (!current?.token) {
      throw new ApiError("UNAUTHENTICATED", "", 401);
    }
    try {
      return await this.send<T>(path, options, current.token);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        this.session?.clearSession();
      }
      throw error;
    }
  }

  private async refresh() {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }
    this.refreshPromise = this.performRefresh().finally(() => {
      this.refreshPromise = null;
    });
    return this.refreshPromise;
  }

  private async performRefresh() {
    const session = this.session?.readSession();
    if (!session?.token) {
      throw new ApiError("UNAUTHENTICATED", "", 401);
    }
    try {
      const response = await this.send<{ token: string }>(
        "/api/v1/auth/refresh",
        { method: "POST" },
        session.token,
      );
      if (!response.token) {
        throw new ApiError("UNAUTHENTICATED", "", 401);
      }
      this.session?.replaceSession(
        response.token,
        Date.now() + refreshedTokenLifetimeMs,
      );
    } catch (error) {
      this.session?.clearSession();
      throw error;
    }
  }

  private assertSafePath(path: string) {
    if (!apiPathPattern.test(path) || path.startsWith("//")) {
      throw new Error("仅允许访问同源 API");
    }
  }

  private async send<T>(
    path: string,
    options: RequestOptions,
    token?: string,
  ): Promise<T> {
    this.assertSafePath(path);
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
      headers,
    });
    if (!response.ok) {
      throw await decodeError(response);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }
}

async function decodeError(response: Response): Promise<ApiError> {
  let envelope: APIErrorEnvelope = {};
  try {
    envelope = (await response.json()) as APIErrorEnvelope;
  } catch {
    // Error responses are intentionally reduced to stable client-owned text.
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
