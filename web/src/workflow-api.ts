import type { ApiClient, RequestOptions } from "./api/client";

export type WorkflowAPI = Pick<ApiClient, "request" | "reverifyTOTP">;

export type CredentialType =
  | "login"
  | "api_token"
  | "ssh_key"
  | "database"
  | "totp";

export type CredentialMetadata = {
  id: string;
  spaceId: string;
  displayName: string;
  type: CredentialType;
  version: number;
  tags: Record<string, string>;
  assetIds: string[];
  deletedAt?: string;
};

export type Asset = {
  id: string;
  spaceId: string;
  name: string;
  type: string;
  hostname: string;
  os: string;
  environment: string;
  status: string;
  ips: string[];
  ports: number[];
  tags: Record<string, string>;
  notes: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string;
};

export type CredentialDraft =
  | {
      credentialType: "login";
      payload: {
        url: string;
        username: string;
        password: string;
        totp_credential_id?: string;
      };
    }
  | {
      credentialType: "api_token";
      payload: {
        service: string;
        token: string;
        header_name?: string;
        expires_at?: string;
      };
    }
  | {
      credentialType: "ssh_key";
      payload: {
        username: string;
        private_key: string;
        public_key?: string;
        fingerprint?: string;
        passphrase?: string;
      };
    }
  | {
      credentialType: "database";
      payload: {
        engine: string;
        host?: string;
        port?: number;
        database?: string;
        username?: string;
        password?: string;
        parameters?: Record<string, string>;
        connection_string?: string;
      };
    }
  | {
      credentialType: "totp";
      payload: {
        issuer: string;
        account: string;
        seed: string;
        algorithm: "SHA1" | "SHA256" | "SHA512";
        digits: 6 | 8;
        period: number;
      };
    };

export const safeID = /^[A-Za-z0-9_-]+$/;
export const credentialTypes: CredentialType[] = [
  "login",
  "api_token",
  "ssh_key",
  "database",
  "totp",
];

export const credentialTypeLabels: Record<CredentialType, string> = {
  login: "登录账号",
  api_token: "API Token",
  ssh_key: "SSH 密钥",
  database: "数据库连接",
  totp: "TOTP",
};

export function isCredentialMetadata(value: unknown): value is CredentialMetadata {
  if (!isRecord(value)) return false;
  return (
    typeof value.id === "string" &&
    safeID.test(value.id) &&
    typeof value.spaceId === "string" &&
    safeID.test(value.spaceId) &&
    typeof value.displayName === "string" &&
    credentialTypes.includes(value.type as CredentialType) &&
    isPositiveInteger(value.version) &&
    isStringRecord(value.tags) &&
    Array.isArray(value.assetIds) &&
    value.assetIds.every((id) => typeof id === "string" && safeID.test(id)) &&
    (value.deletedAt === undefined ||
      (typeof value.deletedAt === "string" &&
        Number.isFinite(Date.parse(value.deletedAt))))
  );
}

export function isAsset(value: unknown): value is Asset {
  if (!isRecord(value)) return false;
  return (
    typeof value.id === "string" &&
    safeID.test(value.id) &&
    typeof value.spaceId === "string" &&
    safeID.test(value.spaceId) &&
    ["name", "type", "hostname", "os", "environment", "status", "notes",
      "createdAt", "updatedAt"].every((key) => typeof value[key] === "string") &&
    Array.isArray(value.ips) &&
    value.ips.every((ip) => typeof ip === "string") &&
    Array.isArray(value.ports) &&
    value.ports.every(
      (port) => Number.isInteger(port) && Number(port) >= 0 && Number(port) <= 65535,
    ) &&
    isStringRecord(value.tags) &&
    isPositiveInteger(value.version)
  );
}

export function isCredentialDraft(
  credentialType: CredentialType,
  payload: unknown,
): payload is CredentialDraft["payload"] {
  if (!isRecord(payload)) return false;
  switch (credentialType) {
    case "login":
      return (
        exactKeys(payload, ["url", "username", "password", "totp_credential_id"]) &&
        requiredStrings(payload, "url", "username", "password") &&
        optionalString(payload.totp_credential_id) &&
        (payload.totp_credential_id === undefined ||
          safeID.test(payload.totp_credential_id))
      );
    case "api_token":
      return (
        exactKeys(payload, ["service", "token", "header_name", "expires_at"]) &&
        requiredStrings(payload, "service", "token") &&
        optionalString(payload.header_name) &&
        optionalString(payload.expires_at) &&
        (payload.expires_at === undefined ||
          payload.expires_at === "" ||
          Number.isFinite(Date.parse(payload.expires_at)))
      );
    case "ssh_key":
      return (
        exactKeys(payload, [
          "username", "private_key", "public_key", "fingerprint", "passphrase",
        ]) &&
        requiredStrings(payload, "username", "private_key") &&
        optionalString(payload.public_key) &&
        optionalString(payload.fingerprint) &&
        optionalString(payload.passphrase)
      );
    case "database":
      return (
        exactKeys(payload, [
          "engine", "host", "port", "database", "username", "password",
          "parameters", "connection_string",
        ]) &&
        typeof payload.engine === "string" &&
        payload.engine.trim() !== "" &&
        optionalString(payload.host) &&
        (payload.port === undefined ||
          (Number.isInteger(payload.port) &&
            Number(payload.port) >= 0 &&
            Number(payload.port) <= 65535)) &&
        optionalString(payload.database) &&
        optionalString(payload.username) &&
        optionalString(payload.password) &&
        (payload.parameters === undefined || isStringRecord(payload.parameters)) &&
        optionalString(payload.connection_string) &&
        ((typeof payload.host === "string" && payload.host.trim() !== "") ||
          (typeof payload.connection_string === "string" &&
            payload.connection_string !== ""))
      );
    case "totp":
      return (
        exactKeys(payload, [
          "issuer", "account", "seed", "algorithm", "digits", "period",
        ]) &&
        requiredStrings(payload, "issuer", "account", "seed", "algorithm") &&
        (payload.algorithm === "SHA1" ||
          payload.algorithm === "SHA256" ||
          payload.algorithm === "SHA512") &&
        (payload.digits === 6 || payload.digits === 8) &&
        Number.isInteger(payload.period) &&
        Number(payload.period) > 0 &&
        Number(payload.period) <= 300
      );
  }
}

export function parseList<T>(
  value: unknown,
  guard: (item: unknown) => item is T,
): { items: T[]; nextCursor?: string } | null {
  if (!isRecord(value) || !Array.isArray(value.items) || !value.items.every(guard)) {
    return null;
  }
  if (
    value.nextCursor !== undefined &&
    (typeof value.nextCursor !== "string" ||
      (value.nextCursor !== "" && !safeID.test(value.nextCursor)))
  ) {
    return null;
  }
  return {
    items: value.items,
    ...(typeof value.nextCursor === "string"
      ? { nextCursor: value.nextCursor }
      : {}),
  };
}

export function requestOptions(
  method: string,
  body?: Record<string, unknown>,
  signal?: AbortSignal,
  headers?: HeadersInit,
): RequestOptions {
  return { method, body, signal, headers };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return (
    isRecord(value) &&
    Object.entries(value).every(
      ([key, item]) => key.trim() !== "" && typeof item === "string",
    )
  );
}

function isPositiveInteger(value: unknown) {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function requiredStrings(
  value: Record<string, unknown>,
  ...keys: string[]
) {
  return keys.every(
    (key) => typeof value[key] === "string" && String(value[key]).trim() !== "",
  );
}

function optionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === "string";
}

function exactKeys(value: Record<string, unknown>, allowed: string[]) {
  const set = new Set(allowed);
  return Object.keys(value).every((key) => set.has(key));
}
