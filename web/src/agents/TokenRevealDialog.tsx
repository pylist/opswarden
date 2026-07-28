import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { newIdempotencyKey } from "../admin-api";
import { apiPath, formatApiError } from "../api/client";
import { Modal } from "../layout/Modal";
import type { WorkflowAPI } from "../workflow-api";

type Props = {
  api: WorkflowAPI;
  agentID: string;
  agentName: string;
  onClose: () => void;
  onChanged: () => void;
};

type Operation = {
  generation: number;
  controller: AbortController;
  phase: "reverify" | "mutation";
};

export function TokenRevealDialog({
  api,
  agentID,
  agentName,
  onClose,
  onChanged,
}: Props) {
  const [rawToken, setRawToken] = useState("");
  const [tokenID, setTokenID] = useState("");
  const [prefix, setPrefix] = useState("");
  const [expiry, setExpiry] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const [replayed, setReplayed] = useState(false);
  const [phase, setPhase] = useState<
    "idle" | "reverify" | "mutation" | "revealed"
  >("idle");
  const [revoking, setRevoking] = useState(false);
  const [revokeTOTP, setRevokeTOTP] = useState("");
  const submitting = useRef(false);
  const generation = useRef(0);
  const operation = useRef<Operation | null>(null);

  const erase = useCallback(() => {
    setRawToken("");
    setTokenID("");
    setPrefix("");
    setCopyStatus("");
    setReplayed(false);
  }, []);

  const invalidate = useCallback((force = false) => {
    if (operation.current?.phase === "mutation" && !force) return false;
    generation.current += 1;
    operation.current?.controller.abort();
    operation.current = null;
    submitting.current = false;
    if (force) erase();
    return true;
  }, [erase]);

  useEffect(() => () => {
    invalidate(true);
    setTotp("");
    setRevokeTOTP("");
  }, [invalidate]);

  function close() {
    if (!invalidate()) return;
    erase();
    setTotp("");
    setRevokeTOTP("");
    onClose();
  }

  async function issue(event: FormEvent) {
    event.preventDefault();
    if (submitting.current || !/^\d{6,8}$/.test(totp)) return;
    let expiresAt: string | undefined;
    if (expiry) {
      const parsed = new Date(expiry);
      if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) {
        setError("到期时间必须晚于当前时间。");
        return;
      }
      expiresAt = parsed.toISOString().replace(/\.000Z$/u, "Z");
    }
    const current = beginOperation(operation, generation, submitting);
    setPhase("reverify");
    setError("");
    try {
      await api.reverifyTOTP(totp, current.controller.signal);
      if (!operationCurrent(operation.current, current)) return;
      current.phase = "mutation";
      setPhase("mutation");
      const value = await api.request<unknown>(
        apiPath(["agents", agentID, "tokens"]),
        {
          method: "POST",
          body: expiresAt ? { expiresAt } : {},
          headers: { "Idempotency-Key": newIdempotencyKey() },
          signal: current.controller.signal,
        },
      );
      if (!operationCurrent(operation.current, current)) return;
      const issued = parseIssuedAgentToken(value);
      if (!issued) throw new Error("invalid response");
      operation.current = null;
      generation.current += 1;
      submitting.current = false;
      setTokenID(issued.id);
      setPrefix(issued.prefix);
      setRawToken(issued.token);
      setReplayed(issued.replayed);
      setTotp("");
      setPhase("revealed");
      onChanged();
    } catch (caught) {
      if (operationCurrent(operation.current, current)) {
        setError(formatApiError(caught));
      }
    } finally {
      if (operationCurrent(operation.current, current)) {
        operation.current = null;
        generation.current += 1;
        submitting.current = false;
        setPhase("idle");
      }
    }
  }

  async function copyToken() {
    if (!rawToken) return;
    try {
      await navigator.clipboard.writeText(rawToken);
      setCopyStatus("已复制");
    } catch {
      setCopyStatus("复制失败，请手动选择");
    }
  }

  function closeRevoke() {
    if (operation.current?.phase === "mutation") return;
    operation.current?.controller.abort();
    operation.current = null;
    submitting.current = false;
    setRevoking(false);
    setRevokeTOTP("");
    setError("");
  }

  async function revoke(event: FormEvent) {
    event.preventDefault();
    if (
      submitting.current ||
      !tokenID ||
      !/^\d{6,8}$/.test(revokeTOTP)
    ) {
      return;
    }
    const current = beginOperation(operation, generation, submitting);
    setError("");
    try {
      await api.reverifyTOTP(revokeTOTP, current.controller.signal);
      if (!operationCurrent(operation.current, current)) return;
      current.phase = "mutation";
      await api.request(
        apiPath(["agents", agentID, "tokens", tokenID]),
        {
          method: "DELETE",
          headers: { "Idempotency-Key": newIdempotencyKey() },
          signal: current.controller.signal,
        },
      );
      if (!operationCurrent(operation.current, current)) return;
      operation.current = null;
      generation.current += 1;
      submitting.current = false;
      erase();
      setRevokeTOTP("");
      setRevoking(false);
      onChanged();
      onClose();
    } catch (caught) {
      if (operationCurrent(operation.current, current)) {
        setError(formatApiError(caught));
      }
    } finally {
      if (operationCurrent(operation.current, current)) {
        operation.current = null;
        generation.current += 1;
        submitting.current = false;
      }
    }
  }

  return (
    <>
      <Modal labelledBy="token-dialog-title" onClose={close} compact>
        <h2 id="token-dialog-title">{agentName} · 创建 Token</h2>
        {phase === "revealed" ? (
          <>
            {rawToken ? (
              <>
                <p className="warning-copy">
                  完整 Token 仅显示一次。关闭后无法再次查看，请立即安全保存。
                </p>
                <label htmlFor="issued-token">Agent Token</label>
                <div className="token-reveal-row">
                  <code id="issued-token">{rawToken}</code>
                  <button
                    className="secondary-button"
                    type="button"
                    onClick={() => void copyToken()}
                  >
                    复制
                  </button>
                </div>
                <p className="muted" role="status">
                  {copyStatus || `前缀：${prefix}`}
                </p>
              </>
            ) : replayed ? (
              <p className="warning-copy">
                该幂等请求已处理，完整 Token 不会再次返回。请关闭后创建新 Token。
              </p>
            ) : null}
            <div className="button-row">
              <button className="secondary-button" type="button" onClick={close}>
                关闭
              </button>
              {tokenID && (
                <button
                  className="danger-button"
                  type="button"
                  onClick={() => setRevoking(true)}
                >
                  立即吊销 Token
                </button>
              )}
            </div>
          </>
        ) : (
          <form className="workflow-form" onSubmit={(event) => void issue(event)}>
            <p className="muted">
              完整 Token 只在创建响应中出现，不会保存到浏览器存储。
            </p>
            <label htmlFor="token-expiry">到期时间（可选）</label>
            <input
              id="token-expiry"
              type="datetime-local"
              value={expiry}
              onChange={(event) => setExpiry(event.target.value)}
            />
            <label htmlFor="token-totp">TOTP 验证码</label>
            <input
              id="token-totp"
              value={totp}
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6,8}"
              required
              onChange={(event) => setTotp(event.target.value)}
            />
            {error && <p className="form-error" role="alert">{error}</p>}
            <div className="button-row">
              <button
                className="primary-button"
                type="submit"
                disabled={phase !== "idle"}
              >
                {phase === "reverify"
                  ? "正在验证…"
                  : phase === "mutation"
                    ? "正在创建…"
                    : "创建并显示 Token"}
              </button>
              <button
                className="secondary-button"
                type="button"
                disabled={phase === "mutation"}
                onClick={close}
              >
                取消
              </button>
            </div>
          </form>
        )}
      </Modal>
      {revoking && (
        <Modal labelledBy="revoke-token-title" onClose={closeRevoke} compact>
          <h2 id="revoke-token-title">重新验证 TOTP</h2>
          <p className="muted">
            吊销后，使用前缀 {prefix} 的 Agent 请求会立即失效。
          </p>
          <form className="workflow-form" onSubmit={(event) => void revoke(event)}>
            <label htmlFor="revoke-token-totp">TOTP 验证码</label>
            <input
              id="revoke-token-totp"
              value={revokeTOTP}
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6,8}"
              required
              onChange={(event) => setRevokeTOTP(event.target.value)}
            />
            {error && <p className="form-error" role="alert">{error}</p>}
            <div className="button-row">
              <button className="danger-button" type="submit">
                验证并吊销
              </button>
              <button
                className="secondary-button"
                type="button"
                disabled={operation.current?.phase === "mutation"}
                onClick={closeRevoke}
              >
                取消
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function beginOperation(
  operation: React.MutableRefObject<Operation | null>,
  generation: React.MutableRefObject<number>,
  submitting: React.MutableRefObject<boolean>,
) {
  operation.current?.controller.abort();
  const current: Operation = {
    generation: ++generation.current,
    controller: new AbortController(),
    phase: "reverify",
  };
  operation.current = current;
  submitting.current = true;
  return current;
}

function operationCurrent(active: Operation | null, candidate: Operation) {
  return (
    active === candidate &&
    active.generation === candidate.generation &&
    !candidate.controller.signal.aborted
  );
}

function parseIssuedAgentToken(value: unknown): {
  id: string;
  prefix: string;
  token: string;
  expiresAt?: string;
  replayed: boolean;
} | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const candidate = value as Record<string, unknown>;
  const allowed = new Set(["id", "prefix", "token", "expiresAt", "replayed"]);
  if (
    Object.keys(candidate).some((key) => !allowed.has(key)) ||
    typeof candidate.id !== "string" ||
    !/^[A-Za-z0-9_-]+$/.test(candidate.id) ||
    typeof candidate.prefix !== "string" ||
    !/^owat_[A-Za-z0-9_-]{1,64}$/.test(candidate.prefix) ||
    typeof candidate.token !== "string" ||
    candidate.token.length > 4096 ||
    typeof candidate.replayed !== "boolean" ||
    (candidate.expiresAt !== undefined &&
      (typeof candidate.expiresAt !== "string" ||
        !Number.isFinite(Date.parse(candidate.expiresAt)))) ||
    (!candidate.replayed &&
      !/^owat_[A-Za-z0-9_-]{8,}$/.test(candidate.token)) ||
    (candidate.replayed && candidate.token !== "")
  ) {
    return null;
  }
  return {
    id: candidate.id,
    prefix: candidate.prefix,
    token: candidate.token,
    replayed: candidate.replayed,
    ...(typeof candidate.expiresAt === "string"
      ? { expiresAt: candidate.expiresAt }
      : {}),
  };
}
