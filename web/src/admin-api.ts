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
  actorType: "user" | "agent" | "anonymous";
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

export function parseAgentUsage(value: unknown): AgentUsage | null {
  if (
    !isRecord(value) ||
    !onlyKeys(value, [
      "agentId", "name", "tokenCount", "activeTokens", "lastUsedAt",
    ]) ||
    !validID(value.agentId) ||
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
    !validID(value.id) ||
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
  if (
    !isRecord(value) ||
    !onlyKeys(value, [
      "id", "requestId", "createdAt", "actorType", "actorId", "fingerprint",
      "action", "spaceId", "resourceType", "resourceId", "sourceIp",
      "userAgent", "success", "errorCode", "changeFields", "reason",
    ]) ||
    !validID(value.id) ||
    !safeOpaque(value.requestId, 256) ||
    !validDate(value.createdAt) ||
    !["user", "agent", "anonymous"].includes(String(value.actorType)) ||
    !safeOpaque(value.actorId, 256, true) ||
    !safeOpaque(value.fingerprint, 256, true) ||
    !safeOpaque(value.action, 256) ||
    !optionalID(value.spaceId) ||
    !safeOpaque(value.resourceType, 128) ||
    !safeOpaque(value.resourceId, 256, true) ||
    !safeOpaque(value.sourceIp, 128) ||
    !safeOpaque(value.userAgent, 2048, true) ||
    typeof value.success !== "boolean" ||
    !safeOpaque(value.errorCode, 128, true) ||
    !Array.isArray(value.changeFields) ||
    !value.changeFields.every((field) => safeOpaque(field, 128)) ||
    !safeOpaque(value.reason, 1024, true)
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
    errorCode: (value.errorCode as string | undefined) ?? "",
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

function optionalID(value: unknown) {
  return value === undefined || validID(value);
}

function validDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
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

function safeOpaque(
  value: unknown,
  max: number,
  optional = false,
): value is string | undefined {
  if (optional && value === undefined) return true;
  return (
    typeof value === "string" &&
    (optional || value.length > 0) &&
    value.length <= max &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
}
