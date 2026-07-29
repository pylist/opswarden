export const REQUEST_BUDGETS = Object.freeze({
  human_credential_list: 30,
  human_credential_read: 12,
  human_credential_write: 15,
  human_generic_read: 80,
  human_generic_write: 30,
});

export function classifyHumanRequest(method, rawURL) {
  const pathname = new URL(rawURL).pathname;
  if (!pathname.startsWith("/api/v1/") || pathname.startsWith("/api/v1/auth/")) {
    return null;
  }
  const credential = pathname.match(/^\/api\/v1\/spaces\/[^/]+\/credentials(?:\/([^/]+))?$/u);
  if (credential) {
    if (method === "GET") {
      return credential[1] ? "human_credential_read" : "human_credential_list";
    }
    return "human_credential_write";
  }
  return method === "GET" || method === "HEAD"
    ? "human_generic_read"
    : "human_generic_write";
}

function sanitizedRoute(method, rawURL) {
  const pathname = new URL(rawURL).pathname;
  if (pathname === "/api/v1/spaces") return `${method}:spaces`;
  if (pathname === "/api/v1/audit-events") return `${method}:audit_events`;
  if (pathname === "/api/v1/agents") return `${method}:agents`;
  if (/^\/api\/v1\/spaces\/[^/]+\/assets(?:\/[^/]+)?$/u.test(pathname)) {
    return `${method}:space_assets`;
  }
  if (/^\/api\/v1\/spaces\/[^/]+\/credentials(?:\/[^/]+)?$/u.test(pathname)) {
    return `${method}:space_credentials`;
  }
  return `${method}:other_api`;
}

export class HumanRequestBudget {
  #counts = new Map();
  #failure;
  #resolveFailure;

  constructor() {
    this.failure = new Promise((resolve) => {
      this.#resolveFailure = resolve;
    });
  }

  record(session, method, rawURL, status, retryAfter) {
    const bucket = classifyHumanRequest(method, rawURL);
    if (!bucket) return;
    const key = `${session}:${bucket}`;
    const count = (this.#counts.get(key) ?? 0) + 1;
    this.#counts.set(key, count);
    if (status === 429 && !this.#failure) {
      const retry = /^[0-9]{1,6}$/u.test(retryAfter ?? "") ? Number(retryAfter) : null;
      this.#failure = new Error(
        `production limiter returned 429: session=${session} bucket=${bucket}` +
        ` route=${sanitizedRoute(method, rawURL)} request_count=${count}` +
        ` retry_after_seconds=${retry ?? "unknown"}`,
      );
      this.#resolveFailure(this.#failure);
    }
  }

  assertWithinLimits() {
    for (const [key, count] of this.#counts) {
      const bucket = key.slice(key.indexOf(":") + 1);
      const budget = REQUEST_BUDGETS[bucket];
      if (count > budget) {
        throw new Error(`E2E request budget exceeded: bucket=${bucket} count=${count} budget=${budget}`);
      }
    }
  }

  snapshot() {
    const sessions = {};
    for (const [key, count] of [...this.#counts].sort()) {
      const separator = key.indexOf(":");
      const session = key.slice(0, separator);
      const bucket = key.slice(separator + 1);
      sessions[session] ??= {};
      sessions[session][bucket] = count;
    }
    return { budgets: REQUEST_BUDGETS, sessions };
  }
}
