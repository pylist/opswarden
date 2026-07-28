import { useRef, useState, type FormEvent } from "react";

import { apiPath, formatApiError } from "../api/client";
import type { Space } from "../api/types";
import {
  isAsset,
  type Asset,
  type WorkflowAPI,
} from "../workflow-api";

type Props = {
  api: WorkflowAPI;
  space: Space;
  initial?: Asset;
  onSaved: (asset: Asset) => void;
  onCancel: () => void;
};

export function AssetForm({ api, space, initial, onSaved, onCancel }: Props) {
  const [name, setName] = useState(initial?.name ?? "");
  const [type, setType] = useState(initial?.type ?? "server");
  const [hostname, setHostname] = useState(initial?.hostname ?? "");
  const [os, setOS] = useState(initial?.os ?? "");
  const [environment, setEnvironment] = useState(initial?.environment ?? "");
  const [status, setStatus] = useState(initial?.status ?? "");
  const [ips, setIPs] = useState(initial?.ips.join(", ") ?? "");
  const [ports, setPorts] = useState(initial?.ports.join(", ") ?? "");
  const [tags, setTags] = useState(initial ? formatPairs(initial.tags) : "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const submitting = useRef(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    const parsedIPs = parseIPs(ips);
    const parsedPorts = parsePorts(ports);
    const parsedTags = parsePairs(tags);
    if (!name.trim() || !type.trim() || !parsedIPs || !parsedPorts || !parsedTags) {
      setError("请填写必填项，并检查 IP、端口与标签格式。");
      return;
    }
    submitting.current = true;
    setSaving(true);
    setError("");
    try {
      const body = {
        ...(initial ? { expectedVersion: initial.version } : {}),
        name: name.trim(),
        type: type.trim(),
        hostname: hostname.trim(),
        os: os.trim(),
        environment: environment.trim(),
        status: status.trim(),
        ips: parsedIPs,
        ports: parsedPorts,
        tags: parsedTags,
        notes: notes.trim(),
      };
      const value = await api.request<unknown>(
        initial
          ? apiPath(["spaces", space.id, "assets", initial.id])
          : apiPath(["spaces", space.id, "assets"]),
        { method: initial ? "PUT" : "POST", body },
      );
      if (!isAsset(value) || value.spaceId !== space.id) {
        throw new Error("invalid response");
      }
      onSaved(value);
    } catch (caught) {
      if (errorCode(caught) === "VERSION_CONFLICT") {
        setError("版本冲突：资产已被更新。你的修改仍保留，请刷新后对比。");
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
      <label htmlFor="asset-space">Space</label>
      <input id="asset-space" value={space.id} readOnly />
      <label htmlFor="asset-name">资产名称</label>
      <input id="asset-name" value={name} onChange={(event) => setName(event.target.value)} required />
      <label htmlFor="asset-type">资产类型</label>
      <input id="asset-type" value={type} onChange={(event) => setType(event.target.value)} required />
      <label htmlFor="asset-hostname">主机名 / 域名</label>
      <input id="asset-hostname" value={hostname} onChange={(event) => setHostname(event.target.value)} />
      <div className="form-grid">
        <div><label htmlFor="asset-os">操作系统</label><input id="asset-os" value={os} onChange={(event) => setOS(event.target.value)} /></div>
        <div><label htmlFor="asset-environment">环境</label><input id="asset-environment" value={environment} onChange={(event) => setEnvironment(event.target.value)} /></div>
        <div><label htmlFor="asset-status">状态</label><input id="asset-status" value={status} onChange={(event) => setStatus(event.target.value)} /></div>
      </div>
      <label htmlFor="asset-ips">IP 地址（逗号分隔）</label>
      <input id="asset-ips" value={ips} onChange={(event) => setIPs(event.target.value)} />
      <label htmlFor="asset-ports">端口（逗号分隔）</label>
      <input id="asset-ports" value={ports} onChange={(event) => setPorts(event.target.value)} />
      <label htmlFor="asset-tags">标签（每行 key=value）</label>
      <textarea id="asset-tags" value={tags} onChange={(event) => setTags(event.target.value)} />
      <label htmlFor="asset-notes">备注</label>
      <textarea id="asset-notes" value={notes} onChange={(event) => setNotes(event.target.value)} />
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="button-row">
        <button className="primary-button" type="submit" disabled={saving}>
          {saving ? "正在保存…" : "保存"}
        </button>
        <button className="secondary-button" type="button" onClick={onCancel}>取消</button>
      </div>
    </form>
  );
}

function parseIPs(raw: string) {
  const values = raw.split(",").map((value) => value.trim()).filter(Boolean);
  return values.every((value) =>
    /^(\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]+$/i.test(value),
  ) ? [...new Set(values)] : null;
}

function parsePorts(raw: string) {
  const values = raw.split(",").map((value) => value.trim()).filter(Boolean);
  const numbers = values.map(Number);
  return numbers.every((value) => Number.isInteger(value) && value > 0 && value <= 65535)
    ? [...new Set(numbers)]
    : null;
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

function errorCode(error: unknown) {
  return error && typeof error === "object" &&
    typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : "";
}
