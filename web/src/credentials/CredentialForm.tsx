import { useEffect, useRef, useState, type FormEvent } from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import {
  credentialTypeLabels,
  credentialTypes,
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

type ParameterRow = { id: number; key: string; value: string };

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
  const operationGeneration = useRef(0);
  const operation = useRef<{
    generation: number;
    controller: AbortController;
  } | null>(null);
  const nextParameterID = useRef(1);
  const [parameterRows, setParameterRows] = useState<ParameterRow[]>(() =>
    parameterRowsFromDraft(initial?.draft, nextParameterID),
  );

  useEffect(() => {
    return () => {
      operationGeneration.current += 1;
      operation.current?.controller.abort();
      operation.current = null;
      submitting.current = false;
    };
  }, [initial?.metadata.id, space.id]);

  function changeType(next: CredentialType) {
    if (initial) return;
    setDraft(defaultDraft(next));
    setParameterRows([]);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    const parsedAssets = parseIDs(assetIds);
    const parsedTags = parsePairs(tags);
    const parsedParameters =
      credentialType === "database"
        ? parseParameterRows(parameterRows)
        : undefined;
    if (!displayName.trim() || !parsedAssets || !parsedTags || (initial && !reason.trim())) {
      setError("请填写必填项，并检查标签与资产标识格式。");
      return;
    }
    if (parsedParameters === null) {
      setError("请检查数据库参数：键不能为空或重复，且不能使用危险键名。");
      return;
    }
    const current = {
      generation: ++operationGeneration.current,
      controller: new AbortController(),
    };
    operation.current?.controller.abort();
    operation.current = current;
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
            payload: normalizedPayload(draft, parsedParameters),
          }
        : {
            displayName: displayName.trim(),
            type: credentialType,
            tags: parsedTags,
            assetIds: parsedAssets,
            payload: normalizedPayload(draft, parsedParameters),
          };
      const result = await api.request<unknown>(path, {
        method: initial ? "PATCH" : "POST",
        body,
        headers: initial
          ? { "X-OpsWarden-Reason": reason.trim() }
          : undefined,
        signal: current.controller.signal,
      });
      if (!operationIsCurrent(operation.current, current)) return;
      if (
        !isMutation(result) ||
        (initial !== undefined && result.id !== initial.metadata.id)
      ) {
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
      if (!operationIsCurrent(operation.current, current)) return;
      if (errorCode(caught) === "VERSION_CONFLICT") {
        setError("版本冲突：该凭据已被其他人更新。你的修改仍保留，请刷新后对比再提交。");
      } else {
        setError(formatApiError(caught));
      }
    } finally {
      if (operationIsCurrent(operation.current, current)) {
        operation.current = null;
        submitting.current = false;
        setSaving(false);
      }
    }
  }

  function cancel() {
    operationGeneration.current += 1;
    operation.current?.controller.abort();
    operation.current = null;
    submitting.current = false;
    onCancel();
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
        parameterRows={parameterRows}
        onParameterRowsChange={setParameterRows}
        nextParameterID={nextParameterID}
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
        <button className="secondary-button" type="button" onClick={cancel}>
          取消
        </button>
      </div>
    </form>
  );
}

function PayloadFields({
  credentialType,
  payload,
  parameterRows,
  onParameterRowsChange,
  nextParameterID,
  onChange,
}: {
  credentialType: CredentialType;
  payload: Record<string, unknown>;
  parameterRows: ParameterRow[];
  onParameterRowsChange: (rows: ParameterRow[]) => void;
  nextParameterID: { current: number };
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
      return (
        <>
          {field("engine", "数据库引擎", { required: true })}
          {field("host", "主机")}
          {field("port", "端口", { type: "number" })}
          {field("database", "数据库名")}
          {field("username", "用户名")}
          {field("password", "密码", { sensitive: true })}
          {field("connection_string", "完整连接串", { sensitive: true })}
          <fieldset className="field-group">
            <legend>连接参数</legend>
            {parameterRows.map((row, index) => (
              <div className="form-grid" key={row.id}>
                <div>
                  <label htmlFor={`database-parameter-key-${row.id}`}>
                    参数键 {index + 1}
                  </label>
                  <input
                    id={`database-parameter-key-${row.id}`}
                    value={row.key}
                    autoComplete="off"
                    onChange={(event) =>
                      onParameterRowsChange(parameterRows.map((item) =>
                        item.id === row.id
                          ? { ...item, key: event.target.value }
                          : item
                      ))
                    }
                  />
                </div>
                <div>
                  <label htmlFor={`database-parameter-value-${row.id}`}>
                    参数值 {index + 1}
                  </label>
                  <input
                    id={`database-parameter-value-${row.id}`}
                    value={row.value}
                    autoComplete="off"
                    onChange={(event) =>
                      onParameterRowsChange(parameterRows.map((item) =>
                        item.id === row.id
                          ? { ...item, value: event.target.value }
                          : item
                      ))
                    }
                  />
                </div>
                <button
                  className="secondary-button"
                  type="button"
                  aria-label={`删除参数 ${index + 1}`}
                  onClick={() =>
                    onParameterRowsChange(
                      parameterRows.filter((item) => item.id !== row.id),
                    )
                  }
                >
                  删除
                </button>
              </div>
            ))}
            <button
              className="secondary-button"
              type="button"
              onClick={() => {
                const id = nextParameterID.current++;
                onParameterRowsChange([
                  ...parameterRows,
                  { id, key: "", value: "" },
                ]);
              }}
            >
              添加参数
            </button>
          </fieldset>
        </>
      );
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

function normalizedPayload(
  draft: CredentialDraft,
  parameters?: Record<string, string>,
): CredentialDraft["payload"] {
  if (draft.credentialType === "api_token" && draft.payload.expires_at) {
    return {
      ...draft.payload,
      expires_at: new Date(draft.payload.expires_at).toISOString(),
    };
  }
  if (draft.credentialType === "database") {
    const { parameters: _discarded, ...payload } = draft.payload;
    return parameters === undefined ? payload : { ...payload, parameters };
  }
  return draft.payload;
}

function parameterRowsFromDraft(
  draft: CredentialDraft | undefined,
  nextID: { current: number },
): ParameterRow[] {
  if (draft?.credentialType !== "database" || !draft.payload.parameters) {
    return [];
  }
  return Object.entries(draft.payload.parameters).map(([key, value]) => ({
    id: nextID.current++,
    key,
    value,
  }));
}

function parseParameterRows(
  rows: ParameterRow[],
): Record<string, string> | undefined | null {
  if (rows.length === 0) return undefined;
  const parameters: Record<string, string> = {};
  for (const row of rows) {
    const key = row.key.trim();
    if (
      !key ||
      key.length > 128 ||
      row.value.length > 4096 ||
      /[\u0000-\u001f\u007f]/.test(key) ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(row.value) ||
      key === "__proto__" ||
      key === "prototype" ||
      key === "constructor" ||
      Object.prototype.hasOwnProperty.call(parameters, key)
    ) {
      return null;
    }
    parameters[key] = row.value;
  }
  return parameters;
}

function operationIsCurrent(
  stored: { generation: number; controller: AbortController } | null,
  expected: { generation: number; controller: AbortController },
) {
  return (
    stored === expected &&
    stored.generation === expected.generation &&
    !expected.controller.signal.aborted
  );
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
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === 2 &&
    Object.prototype.hasOwnProperty.call(value, "id") &&
    Object.prototype.hasOwnProperty.call(value, "version") &&
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
