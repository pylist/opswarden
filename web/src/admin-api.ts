import { ApiError } from "./api/client";
import type { SpaceRole } from "./api/types";
import { safeID } from "./workflow-api";

export type AgentUsage = {
  agentId: string;
  name: string;
  tokenCount: number;
  activeTokens: number;
  lastUsedAt?: string;
};

export type AgentRecord = {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
};

export type AuditRow = {
  id: string;
  requestId: string;
  createdAt: string;
  actorType: "user" | "agent" | "anonymous" | "system";
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  sourceIp: string;
  success: boolean;
  errorCode: string;
};

export type Member = {
  userId: string;
  email: string;
  role: SpaceRole;
  version: number;
  createdAt: string;
};

export class MemoryIdempotencyIntent {
  private signature = "";
  private key = "";

  keyFor(signature: string) {
    if (!signature || this.signature !== signature || !this.key) {
      this.signature = signature;
      this.key = newIdempotencyKey();
    }
    return this.key;
  }

  clear() {
    this.signature = "";
    this.key = "";
  }
}

export function retainIdempotencyOnError(error: unknown) {
  return !(error instanceof ApiError) ||
    error.status >= 500 ||
    error.status === 429;
}

export function parseAgentUsage(value: unknown): AgentUsage | null {
  if (
    !isRecord(value) ||
    !onlyKeys(value, [
      "agentId", "name", "tokenCount", "activeTokens", "lastUsedAt",
    ]) ||
    !validHexID(value.agentId, "agt_") ||
    !safeText(value.name, 256) ||
    !nonNegativeInteger(value.tokenCount) ||
    !nonNegativeInteger(value.activeTokens) ||
    Number(value.activeTokens) > Number(value.tokenCount) ||
    !optionalDate(value.lastUsedAt)
  ) {
    return null;
  }
  return {
    agentId: value.agentId,
    name: value.name,
    tokenCount: value.tokenCount,
    activeTokens: value.activeTokens,
    ...(typeof value.lastUsedAt === "string"
      ? { lastUsedAt: value.lastUsedAt }
      : {}),
  };
}

export function parseAgentRecord(value: unknown): AgentRecord | null {
  if (
    !isRecord(value) ||
    !onlyKeys(value, ["id", "name", "createdAt", "updatedAt"]) ||
    !validHexID(value.id, "agt_") ||
    !safeText(value.name, 256) ||
    !validDate(value.createdAt) ||
    !validDate(value.updatedAt)
  ) {
    return null;
  }
  return {
    id: value.id,
    name: value.name,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
  };
}

export function parseAuditRow(value: unknown): AuditRow | null {
  const errorCode =
    typeof (value as Record<string, unknown> | null)?.errorCode === "string"
      ? (value as Record<string, unknown>).errorCode as string
      : "";
  if (
    !isRecord(value) ||
    !onlyKeys(value, [
      "id", "requestId", "createdAt", "actorType", "actorId", "fingerprint",
      "action", "spaceId", "resourceType", "resourceId", "sourceIp",
      "userAgent", "success", "errorCode", "changeFields", "reason",
    ]) ||
    !validAuditIdentifier(value.id) ||
    !validAuditIdentifier(value.requestId) ||
    !canonicalRFC3339NanoUTC(value.createdAt) ||
    !["user", "agent", "anonymous", "system"].includes(String(value.actorType)) ||
    !validAuditIdentifier(value.actorId) ||
    typeof value.fingerprint !== "string" ||
    !/^[0-9a-f]{16}$/u.test(value.fingerprint) ||
    (value.actorType === "system" &&
      (value.actorId !== "maintenance" ||
        value.fingerprint !== "e4818b3eb3949901")) ||
    !validAuditAction(value.action) ||
    !optionalAuditIdentifier(value.spaceId) ||
    !validAuditResourceType(value.resourceType) ||
    !optionalAuditIdentifier(value.resourceId) ||
    !canonicalIP(value.sourceIp) ||
    !validAuditText(value.userAgent ?? "") ||
    typeof value.success !== "boolean" ||
    (value.success
      ? errorCode !== ""
      : !/^[A-Z0-9_]{1,128}$/u.test(errorCode)) ||
    !Array.isArray(value.changeFields) ||
    !validAuditChangeFields(value.changeFields) ||
    !validAuditText(value.reason ?? "")
  ) {
    return null;
  }
  return {
    id: value.id,
    requestId: value.requestId as string,
    createdAt: value.createdAt,
    actorType: value.actorType as AuditRow["actorType"],
    actorId: (value.actorId as string | undefined) ?? "",
    action: value.action as string,
    resourceType: value.resourceType as string,
    resourceId: (value.resourceId as string | undefined) ?? "",
    sourceIp: value.sourceIp as string,
    success: value.success,
    errorCode,
  };
}

export function parseMember(value: unknown): Member | null {
  if (
    !isRecord(value) ||
    !onlyKeys(value, ["userId", "email", "role", "version", "createdAt"]) ||
    !validID(value.userId) ||
    !safeText(value.email, 320) ||
    !["owner", "editor", "reader"].includes(String(value.role)) ||
    !positiveInteger(value.version) ||
    !validDate(value.createdAt)
  ) {
    return null;
  }
  return {
    userId: value.userId,
    email: value.email,
    role: value.role as SpaceRole,
    version: value.version,
    createdAt: value.createdAt,
  };
}

export function parseItems<T>(
  value: unknown,
  parser: (item: unknown) => T | null,
): T[] | null {
  if (
    !isRecord(value) ||
    !onlyKeys(value, ["items"]) ||
    !Array.isArray(value.items)
  ) {
    return null;
  }
  const result: T[] = [];
  for (const item of value.items) {
    const parsed = parser(item);
    if (!parsed) return null;
    result.push(parsed);
  }
  return result;
}

export function parseCursorItems<T>(
  value: unknown,
  parser: (item: unknown) => T | null,
): { items: T[]; nextCursor?: string } | null {
  if (
    !isRecord(value) ||
    !onlyKeys(value, ["items", "nextCursor"]) ||
    !Array.isArray(value.items) ||
    (value.nextCursor !== undefined &&
      (!validID(value.nextCursor) || value.nextCursor.length > 1024))
  ) {
    return null;
  }
  const items: T[] = [];
  for (const item of value.items) {
    const parsed = parser(item);
    if (!parsed) return null;
    items.push(parsed);
  }
  return {
    items,
    ...(typeof value.nextCursor === "string"
      ? { nextCursor: value.nextCursor }
      : {}),
  };
}

export function newIdempotencyKey() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new ApiError("INTERNAL_ERROR", "", 500);
  }
  const bytes = new Uint8Array(24);
  globalThis.crypto.getRandomValues(bytes);
  const encoded = Array.from(bytes, (value) =>
    value.toString(16).padStart(2, "0")
  ).join("");
  bytes.fill(0);
  return `web_${encoded}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: string[]) {
  const keys = new Set(allowed);
  return Object.keys(value).every((key) => keys.has(key));
}

function validID(value: unknown): value is string {
  return typeof value === "string" && safeID.test(value);
}

function validDate(value: unknown): value is string {
  return canonicalRFC3339NanoUTC(value);
}

function optionalDate(value: unknown) {
  return value === undefined || validDate(value);
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function safeText(value: unknown, max: number): value is string {
  return (
    typeof value === "string" &&
    value.trim() !== "" &&
    value === value.trim() &&
    value.length <= max &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
}

export function canonicalRFC3339NanoUTC(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/u.exec(
    value,
  );
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction] =
    match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return false;
  }
  return fraction === undefined || /[1-9]$/u.test(fraction);
}

function daysInMonth(year: number, month: number) {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function validHexID(value: unknown, prefix: string): value is string {
  return (
    typeof value === "string" &&
    value.startsWith(prefix) &&
    /^[0-9a-f]{32}$/u.test(value.slice(prefix.length))
  );
}

function validAuditIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 256 &&
    /^[A-Za-z0-9_.:@/-]+$/u.test(value)
  );
}

function optionalAuditIdentifier(value: unknown) {
  return value === undefined || validAuditIdentifier(value);
}

function validAuditAction(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[a-z0-9._]{1,128}$/u.test(value)
  );
}

function validAuditResourceType(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[a-z0-9_]{1,128}$/u.test(value)
  );
}

function canonicalIP(value: unknown): value is string {
  if (typeof value !== "string" || value.includes("%")) return false;
  if (!value.includes(":")) return canonicalIPv4(value);
  if (value.startsWith("::ffff:")) {
    return canonicalIPv4(value.slice("::ffff:".length));
  }
  try {
    const parsed = new URL(`http://[${value}]/`);
    return parsed.hostname === `[${value}]`;
  } catch {
    return false;
  }
}

function canonicalIPv4(value: string) {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) =>
      /^(?:0|[1-9]\d{0,2})$/u.test(part) &&
      Number(part) <= 255
    )
  );
}

const allowedAuditChangeFields = new Set([
  "display_name",
  "tags",
  "asset_links",
  "credential_type",
  "expires_at",
  "deleted_at",
  "name",
  "description",
  "role",
  "space_grants",
  "token_status",
  "system_role",
  "version",
]);

function validAuditChangeFields(value: unknown[]) {
  const seen = new Set<string>();
  for (const field of value) {
    if (
      typeof field !== "string" ||
      !allowedAuditChangeFields.has(field) ||
      seen.has(field)
    ) {
      return false;
    }
    seen.add(field);
  }
  return true;
}

function validAuditText(value: unknown): value is string {
  if (typeof value !== "string") return false;
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    if (first <= 0x1f || (first >= 0x7f && first <= 0x9f)) return false;
    if (first <= 0x7f) {
      bytes += 1;
    } else if (first <= 0x7ff) {
      bytes += 2;
    } else if (first >= 0xd800 && first <= 0xdbff) {
      const second = value.charCodeAt(index + 1);
      if (second < 0xdc00 || second > 0xdfff) return false;
      bytes += 4;
      index += 1;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      return false;
    } else {
      bytes += 3;
    }
    if (bytes > 512) return false;
  }
  return true;
}
