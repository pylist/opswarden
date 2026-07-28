import { useRef, useState, type FormEvent } from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import {
  credentialTypeLabels,
  credentialTypes,
  isCredentialMetadata,
  safeID,
  type CredentialDraft,
  type CredentialMetadata,
  type CredentialType,
  type WorkflowAPI,
} from "../workflow-api";

type Props = {
  api: WorkflowAPI;
  space: Space;
  initial?: {
    metadata: CredentialMetadata;
    draft: CredentialDraft;
  };
  prefillAssetId?: string;
  onSaved: (metadata?: CredentialMetadata) => void;
  onCancel: () => void;
};

export function CredentialForm({
  api,
  space,
  initial,
  prefillAssetId = "",
  onSaved,
  onCancel,
}: Props) {
  const [draft, setDraft] = useState<CredentialDraft>(
    initial?.draft ?? defaultDraft("login"),
  );
  const credentialType = draft.credentialType;
  const [displayName, setDisplayName] = useState(
    initial?.metadata.displayName ?? "",
  );
  const [tags, setTags] = useState(
    initial ? formatPairs(initial.metadata.tags) : "",
  );
  const [assetIds, setAssetIds] = useState(
    initial?.metadata.assetIds.join(", ") ?? prefillAssetId,
  );
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const submitting = useRef(false);

  function changeType(next: CredentialType) {
    if (initial) return;
    setDraft(defaultDraft(next));
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    const parsedAssets = parseIDs(assetIds);
    const parsedTags = parsePairs(tags);
    if (!displayName.trim() || !parsedAssets || !parsedTags || (initial && !reason.trim())) {
      setError("请填写必填项，并检查标签与资产标识格式。");
      return;
    }
    submitting.current = true;
    setSaving(true);
    setError("");
    try {
      const path = initial
        ? apiPath(["spaces", space.id, "credentials", initial.metadata.id])
        : apiPath(["spaces", space.id, "credentials"]);
      const body: Record<string, unknown> = initial
        ? {
            expectedVersion: initial.metadata.version,
            displayName: displayName.trim(),
            tags: parsedTags,
            assetIds: parsedAssets,
            payload: normalizedPayload(draft),
          }
        : {
            displayName: displayName.trim(),
            type: credentialType,
            tags: parsedTags,
            assetIds: parsedAssets,
            payload: normalizedPayload(draft),
          };
      const result = await api.request<unknown>(path, {
        method: initial ? "PATCH" : "POST",
        body,
        headers: initial
          ? { "X-OpsWarden-Reason": reason.trim() }
          : undefined,
      });
      if (!isMutation(result)) {
        throw new Error("invalid response");
      }
      const savedMetadata =
        initial
          ? {
              ...initial.metadata,
              displayName: displayName.trim(),
              tags: parsedTags,
              assetIds: parsedAssets,
              version: result.version,
            }
          : undefined;
      setDraft(defaultDraft(credentialType));
      onSaved(savedMetadata);
    } catch (caught) {
      if (errorCode(caught) === "VERSION_CONFLICT") {
        setError("版本冲突：该凭据已被其他人更新。你的修改仍保留，请刷新后对比再提交。");
      } else {
        setError(formatApiError(caught));
      }
    } finally {
      submitting.current = false;
      setSaving(false);
    }
  }

  return (
    <form className="workflow-form" onSubmit={submit}>
      <label htmlFor="credential-space">Space</label>
      <input id="credential-space" value={space.id} readOnly />
      <label htmlFor="credential-name">显示名称</label>
      <input
        id="credential-name"
        value={displayName}
        onChange={(event) => setDisplayName(event.target.value)}
        required
      />
      <label htmlFor="credential-type">凭据类型</label>
      <select
        id="credential-type"
        value={credentialType}
        disabled={Boolean(initial)}
        onChange={(event) => changeType(event.target.value as CredentialType)}
      >
        {credentialTypes.map((type) => (
          <option key={type} value={type}>{credentialTypeLabels[type]}</option>
        ))}
      </select>
      <PayloadFields
        credentialType={credentialType}
        payload={draft.payload}
        onChange={(next) =>
          setDraft({ ...draft, payload: next } as CredentialDraft)
        }
      />
      <label htmlFor="credential-tags">标签（每行 key=value）</label>
      <textarea
        id="credential-tags"
        value={tags}
        onChange={(event) => setTags(event.target.value)}
      />
      <label htmlFor="credential-assets">关联资产</label>
      <input
        id="credential-assets"
        value={assetIds}
        onChange={(event) => setAssetIds(event.target.value)}
        placeholder="多个资产标识用逗号分隔"
      />
      {initial && (
        <>
          <label htmlFor="credential-reason">变更原因</label>
          <input
            id="credential-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            required
          />
        </>
      )}
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="button-row">
        <button className="primary-button" type="submit" disabled={saving}>
          {saving ? "正在保存…" : "保存"}
        </button>
        <button className="secondary-button" type="button" onClick={onCancel}>
          取消
        </button>
      </div>
    </form>
  );
}

function PayloadFields({
  credentialType,
  payload,
  onChange,
}: {
  credentialType: CredentialType;
  payload: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
}) {
  const set = (key: string, value: string | number) =>
    onChange({ ...payload, [key]: value });
  const field = (
    key: string,
    label: string,
    options: { required?: boolean; sensitive?: boolean; type?: string } = {},
  ) => (
    <div className="field-group" key={key}>
      <label htmlFor={`payload-${key}`}>{label}</label>
      <input
        id={`payload-${key}`}
        type={options.sensitive ? "password" : options.type ?? "text"}
        value={String(payload[key] ?? "")}
        onChange={(event) =>
          set(
            key,
            options.type === "number"
              ? Number(event.target.value)
              : event.target.value,
          )
        }
        required={options.required}
        autoComplete="off"
      />
    </div>
  );
  switch (credentialType) {
    case "login":
      return <>{field("url", "网址", { required: true })}{field("username", "用户名", { required: true })}{field("password", "密码", { required: true, sensitive: true })}{field("totp_credential_id", "关联 TOTP 凭据")}</>;
    case "api_token":
      return <>{field("service", "服务", { required: true })}{field("token", "Token", { required: true, sensitive: true })}{field("header_name", "Header 名称")}{field("expires_at", "到期时间", { type: "datetime-local" })}</>;
    case "ssh_key":
      return <>{field("username", "用户名", { required: true })}<label htmlFor="payload-private_key">私钥</label><textarea id="payload-private_key" value={String(payload.private_key ?? "")} onChange={(event) => set("private_key", event.target.value)} required autoComplete="off" />{field("public_key", "公钥")}{field("fingerprint", "指纹")}{field("passphrase", "口令", { sensitive: true })}</>;
    case "database":
      return <>{field("engine", "数据库引擎", { required: true })}{field("host", "主机")}{field("port", "端口", { type: "number" })}{field("database", "数据库名")}{field("username", "用户名")}{field("password", "密码", { sensitive: true })}{field("connection_string", "完整连接串", { sensitive: true })}</>;
    case "totp":
      return <>{field("issuer", "签发方", { required: true })}{field("account", "账号", { required: true })}{field("seed", "Seed", { required: true, sensitive: true })}{field("algorithm", "算法", { required: true })}{field("digits", "位数", { required: true, type: "number" })}{field("period", "周期（秒）", { required: true, type: "number" })}</>;
  }
}

function defaultDraft(type: CredentialType): CredentialDraft {
  switch (type) {
    case "login":
      return {
        credentialType: "login",
        payload: { url: "", username: "", password: "" },
      };
    case "api_token":
      return {
        credentialType: "api_token",
        payload: { service: "", token: "" },
      };
    case "ssh_key":
      return {
        credentialType: "ssh_key",
        payload: { username: "", private_key: "" },
      };
    case "database":
      return {
        credentialType: "database",
        payload: { engine: "", host: "" },
      };
    case "totp":
      return {
        credentialType: "totp",
        payload: {
          issuer: "", account: "", seed: "", algorithm: "SHA1",
          digits: 6, period: 30,
        },
      };
  }
}

function normalizedPayload(draft: CredentialDraft): CredentialDraft["payload"] {
  if (draft.credentialType === "api_token" && draft.payload.expires_at) {
    return {
      ...draft.payload,
      expires_at: new Date(draft.payload.expires_at).toISOString(),
    };
  }
  return draft.payload;
}

function parsePairs(raw: string): Record<string, string> | null {
  const result: Record<string, string> = {};
  for (const line of raw.split("\n").map((item) => item.trim()).filter(Boolean)) {
    const split = line.indexOf("=");
    if (split < 1) return null;
    const key = line.slice(0, split).trim();
    if (!key || Object.prototype.hasOwnProperty.call(result, key)) return null;
    result[key] = line.slice(split + 1).trim();
  }
  return result;
}

function formatPairs(values: Record<string, string>) {
  return Object.entries(values).map(([key, value]) => `${key}=${value}`).join("\n");
}

function parseIDs(raw: string): string[] | null {
  const ids = raw.split(",").map((id) => id.trim()).filter(Boolean);
  return ids.every((id) => safeID.test(id)) ? [...new Set(ids)] : null;
}

function isMutation(value: unknown): value is { id: string; version: number } {
  return (
    Boolean(value) &&
    typeof value === "object" &&
    safeID.test(String((value as { id?: unknown }).id ?? "")) &&
    Number.isSafeInteger((value as { version?: unknown }).version) &&
    Number((value as { version?: unknown }).version) > 0
  );
}

function errorCode(error: unknown) {
  if (!error || typeof error !== "object") return "";
  return typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : "";
}
