import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import {
  MemoryIdempotencyIntent,
  parseAgentRecord,
  retainIdempotencyOnError,
  type AgentRecord,
} from "../admin-api";
import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import { Modal } from "../layout/Modal";
import type { WorkflowAPI } from "../workflow-api";

type AgentFormProps = {
  api: WorkflowAPI;
  onClose: () => void;
  onCreated: (agent: AgentRecord) => void;
};

type PrivilegedOperation = {
  generation: number;
  controller: AbortController;
  phase: "reverify" | "mutation";
};

export function AgentForm({ api, onClose, onCreated }: AgentFormProps) {
  const [name, setName] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  const [phase, setPhase] = useState<"idle" | "reverify" | "mutation">("idle");
  const submitting = useRef(false);
  const generation = useRef(0);
  const operation = useRef<PrivilegedOperation | null>(null);
  const idempotency = useRef(new MemoryIdempotencyIntent());

  const invalidate = useCallback((force = false) => {
    if (operation.current?.phase === "mutation" && !force) return false;
    generation.current += 1;
    operation.current?.controller.abort();
    operation.current = null;
    submitting.current = false;
    setPhase("idle");
    return true;
  }, []);

  useEffect(() => () => {
    invalidate(true);
    idempotency.current.clear();
    setName("");
    setTotp("");
  }, [invalidate]);

  function close() {
    if (!invalidate()) return;
    idempotency.current.clear();
    setName("");
    setTotp("");
    onClose();
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const trimmed = name.trim();
    if (
      submitting.current ||
      trimmed.length === 0 ||
      trimmed.length > 256 ||
      !/^\d{6,8}$/.test(totp)
    ) {
      return;
    }
    const current: PrivilegedOperation = {
      generation: ++generation.current,
      controller: new AbortController(),
      phase: "reverify",
    };
    operation.current?.controller.abort();
    operation.current = current;
    submitting.current = true;
    setPhase("reverify");
    setError("");
    const intentSignature = JSON.stringify({ name: trimmed });
    const idempotencyKey = idempotency.current.keyFor(intentSignature);
    try {
      await api.reverifyTOTP(totp, current.controller.signal);
      if (!operationCurrent(operation.current, current)) return;
      current.phase = "mutation";
      setPhase("mutation");
      const value = await api.request<unknown>(apiPath(["agents"]), {
        method: "POST",
        body: { name: trimmed },
        headers: { "Idempotency-Key": idempotencyKey },
        signal: current.controller.signal,
      });
      if (!operationCurrent(operation.current, current)) return;
      const created = parseAgentRecord(value);
      if (!created || created.name !== trimmed) {
        throw new Error("invalid response");
      }
      operation.current = null;
      generation.current += 1;
      submitting.current = false;
      setName("");
      setTotp("");
      idempotency.current.clear();
      onCreated(created);
      onClose();
    } catch (caught) {
      if (operationCurrent(operation.current, current)) {
        if (!retainIdempotencyOnError(caught)) {
          idempotency.current.clear();
        }
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

  return (
    <Modal labelledBy="agent-form-title" onClose={close} compact>
      <h2 id="agent-form-title">创建 Agent</h2>
      <p className="muted">
        为每个 AI 工具创建独立身份。保存前需要重新验证 TOTP。
      </p>
      <form className="workflow-form" onSubmit={(event) => void submit(event)}>
        <label htmlFor="agent-name">Agent 名称</label>
        <input
          id="agent-name"
          value={name}
          maxLength={256}
          autoComplete="off"
          required
          onChange={(event) => setName(event.target.value)}
        />
        <label htmlFor="agent-create-totp">TOTP 验证码</label>
        <input
          id="agent-create-totp"
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
                : "创建 Agent"}
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
    </Modal>
  );
}

const scopeOptions = [
  ["credential:list", "列出凭据"],
  ["credential:read", "读取凭据"],
  ["credential:create", "创建凭据"],
  ["credential:update", "修改凭据"],
  ["credential:delete", "删除凭据"],
  ["asset:list", "列出资产"],
  ["asset:read", "读取资产"],
] as const;

type GrantFormProps = {
  api: WorkflowAPI;
  agentID: string;
  agentName: string;
  space: Space;
  onClose: () => void;
  onSaved: () => void;
};

export function AgentGrantForm({
  api,
  agentID,
  agentName,
  space,
  onClose,
  onSaved,
}: GrantFormProps) {
  const [scopes, setScopes] = useState<string[]>([]);
  const [labelKey, setLabelKey] = useState("");
  const [labelValue, setLabelValue] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  const [phase, setPhase] = useState<"idle" | "reverify" | "mutation">("idle");
  const submitting = useRef(false);
  const generation = useRef(0);
  const operation = useRef<PrivilegedOperation | null>(null);
  const idempotency = useRef(new MemoryIdempotencyIntent());

  const invalidate = useCallback((force = false) => {
    if (operation.current?.phase === "mutation" && !force) return false;
    generation.current += 1;
    operation.current?.controller.abort();
    operation.current = null;
    submitting.current = false;
    setPhase("idle");
    return true;
  }, []);

  useEffect(() => () => {
    invalidate(true);
    idempotency.current.clear();
    setTotp("");
  }, [invalidate]);

  function close() {
    if (!invalidate()) return;
    idempotency.current.clear();
    setTotp("");
    onClose();
  }

  function toggle(scope: string) {
    setScopes((current) =>
      current.includes(scope)
        ? current.filter((candidate) => candidate !== scope)
        : [...current, scope]
    );
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const key = labelKey.trim();
    const value = labelValue.trim();
    if (
      submitting.current ||
      scopes.length === 0 ||
      !/^\d{6,8}$/.test(totp) ||
      (Boolean(key) !== Boolean(value)) ||
      key.length > 128 ||
      value.length > 256
    ) {
      return;
    }
    const current: PrivilegedOperation = {
      generation: ++generation.current,
      controller: new AbortController(),
      phase: "reverify",
    };
    operation.current?.controller.abort();
    operation.current = current;
    submitting.current = true;
    setPhase("reverify");
    setError("");
    const intentSignature = JSON.stringify({
      agentID,
      spaceID: space.id,
      scopes,
      requiredLabels: key ? { [key]: value } : {},
    });
    const idempotencyKey = idempotency.current.keyFor(intentSignature);
    try {
      await api.reverifyTOTP(totp, current.controller.signal);
      if (!operationCurrent(operation.current, current)) return;
      current.phase = "mutation";
      setPhase("mutation");
      await api.request(
        apiPath(["agents", agentID, "grants"]),
        {
          method: "PUT",
          body: {
            spaceId: space.id,
            scopes,
            requiredLabels: key ? { [key]: value } : {},
          },
          headers: { "Idempotency-Key": idempotencyKey },
          signal: current.controller.signal,
        },
      );
      if (!operationCurrent(operation.current, current)) return;
      operation.current = null;
      generation.current += 1;
      submitting.current = false;
      setTotp("");
      idempotency.current.clear();
      onSaved();
      onClose();
    } catch (caught) {
      if (operationCurrent(operation.current, current)) {
        if (!retainIdempotencyOnError(caught)) {
          idempotency.current.clear();
        }
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

  return (
    <Modal labelledBy="grant-form-title" onClose={close}>
      <h2 id="grant-form-title">配置 {agentName} 的授权</h2>
      <p className="muted">
        授权按空间分组；标签约束只会进一步收窄可访问范围。
      </p>
      <form className="workflow-form" onSubmit={(event) => void submit(event)}>
        <fieldset className="scope-fieldset">
          <legend>{space.name}</legend>
          <div className="scope-grid">
            {scopeOptions.map(([scope, label]) => (
              <label key={scope} className="checkbox-row">
                <input
                  type="checkbox"
                  checked={scopes.includes(scope)}
                  onChange={() => toggle(scope)}
                />
                {label}
              </label>
            ))}
          </div>
        </fieldset>
        <div className="form-grid">
          <div>
            <label htmlFor="grant-label-key">标签键</label>
            <input
              id="grant-label-key"
              value={labelKey}
              maxLength={128}
              autoComplete="off"
              placeholder="environment"
              onChange={(event) => setLabelKey(event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="grant-label-value">标签值</label>
            <input
              id="grant-label-value"
              value={labelValue}
              maxLength={256}
              autoComplete="off"
              placeholder="prod"
              onChange={(event) => setLabelValue(event.target.value)}
            />
          </div>
        </div>
        <label htmlFor="grant-totp">TOTP 验证码</label>
        <input
          id="grant-totp"
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
            disabled={phase !== "idle" || scopes.length === 0}
          >
            {phase === "reverify"
              ? "正在验证…"
              : phase === "mutation"
                ? "正在保存…"
                : "保存授权"}
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
    </Modal>
  );
}

function operationCurrent(
  active: PrivilegedOperation | null,
  candidate: PrivilegedOperation,
) {
  return (
    active === candidate &&
    active.generation === candidate.generation &&
    !candidate.controller.signal.aborted
  );
}
