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

export function parseCredentialMetadata(value: unknown): CredentialMetadata | null {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      "id", "spaceId", "displayName", "type", "version", "tags", "assetIds",
      "deletedAt",
    ]) ||
    typeof value.id !== "string" ||
    !safeID.test(value.id) ||
    typeof value.spaceId !== "string" ||
    !safeID.test(value.spaceId) ||
    typeof value.displayName !== "string" ||
    !credentialTypes.includes(value.type as CredentialType) ||
    !isPositiveInteger(value.version) ||
    !Array.isArray(value.assetIds) ||
    !value.assetIds.every((id) => typeof id === "string" && safeID.test(id)) ||
    !optionalDate(value.deletedAt)
  ) {
    return null;
  }
  const tags = cloneStringRecord(value.tags);
  if (!tags) return null;
  return {
    id: value.id,
    spaceId: value.spaceId,
    displayName: value.displayName,
    type: value.type as CredentialType,
    version: value.version as number,
    tags,
    assetIds: [...value.assetIds],
    ...(typeof value.deletedAt === "string" ? { deletedAt: value.deletedAt } : {}),
  };
}

export function isCredentialMetadata(value: unknown): value is CredentialMetadata {
  return parseCredentialMetadata(value) !== null;
}

export function parseAsset(value: unknown): Asset | null {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      "id", "spaceId", "name", "type", "hostname", "os", "environment",
      "status", "ips", "ports", "tags", "notes", "version", "createdAt",
      "updatedAt", "deletedAt",
    ]) ||
    typeof value.id !== "string" ||
    !safeID.test(value.id) ||
    typeof value.spaceId !== "string" ||
    !safeID.test(value.spaceId) ||
    !["name", "type", "hostname", "os", "environment", "status", "notes"]
      .every((key) => typeof value[key] === "string") ||
    !Array.isArray(value.ips) ||
    !value.ips.every((ip) => typeof ip === "string") ||
    !Array.isArray(value.ports) ||
    !value.ports.every(
      (port) => Number.isInteger(port) && Number(port) >= 0 && Number(port) <= 65535,
    ) ||
    !isPositiveInteger(value.version) ||
    !validDate(value.createdAt) ||
    !validDate(value.updatedAt) ||
    !optionalDate(value.deletedAt)
  ) {
    return null;
  }
  const tags = cloneStringRecord(value.tags);
  if (!tags) return null;
  return {
    id: value.id,
    spaceId: value.spaceId,
    name: value.name as string,
    type: value.type as string,
    hostname: value.hostname as string,
    os: value.os as string,
    environment: value.environment as string,
    status: value.status as string,
    ips: [...value.ips],
    ports: [...value.ports],
    tags,
    notes: value.notes as string,
    version: value.version as number,
    createdAt: value.createdAt as string,
    updatedAt: value.updatedAt as string,
    ...(typeof value.deletedAt === "string" ? { deletedAt: value.deletedAt } : {}),
  };
}

export function isAsset(value: unknown): value is Asset {
  return parseAsset(value) !== null;
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

export function parseCredentialDraft(
  credentialType: CredentialType,
  payload: unknown,
): CredentialDraft | null {
  if (!isCredentialDraft(credentialType, payload)) return null;
  switch (credentialType) {
    case "login": {
      const source = payload as Extract<
        CredentialDraft,
        { credentialType: "login" }
      >["payload"];
      return {
        credentialType,
        payload: {
          url: source.url,
          username: source.username,
          password: source.password,
          ...(source.totp_credential_id !== undefined
            ? { totp_credential_id: source.totp_credential_id }
            : {}),
        },
      };
    }
    case "api_token": {
      const source = payload as Extract<
        CredentialDraft,
        { credentialType: "api_token" }
      >["payload"];
      return {
        credentialType,
        payload: {
          service: source.service,
          token: source.token,
          ...(source.header_name !== undefined ? { header_name: source.header_name } : {}),
          ...(source.expires_at !== undefined ? { expires_at: source.expires_at } : {}),
        },
      };
    }
    case "ssh_key": {
      const source = payload as Extract<
        CredentialDraft,
        { credentialType: "ssh_key" }
      >["payload"];
      return {
        credentialType,
        payload: {
          username: source.username,
          private_key: source.private_key,
          ...(source.public_key !== undefined ? { public_key: source.public_key } : {}),
          ...(source.fingerprint !== undefined ? { fingerprint: source.fingerprint } : {}),
          ...(source.passphrase !== undefined ? { passphrase: source.passphrase } : {}),
        },
      };
    }
    case "database": {
      const source = payload as Extract<
        CredentialDraft,
        { credentialType: "database" }
      >["payload"];
      let parameters: Record<string, string> | undefined;
      if (source.parameters !== undefined) {
        const cloned = cloneStringRecord(source.parameters);
        if (!cloned) return null;
        parameters = cloned;
      }
      return {
        credentialType,
        payload: {
          engine: source.engine,
          ...(source.host !== undefined ? { host: source.host } : {}),
          ...(source.port !== undefined ? { port: source.port } : {}),
          ...(source.database !== undefined ? { database: source.database } : {}),
          ...(source.username !== undefined ? { username: source.username } : {}),
          ...(source.password !== undefined ? { password: source.password } : {}),
          ...(parameters !== undefined ? { parameters } : {}),
          ...(source.connection_string !== undefined
            ? { connection_string: source.connection_string }
            : {}),
        },
      };
    }
    case "totp": {
      const source = payload as Extract<
        CredentialDraft,
        { credentialType: "totp" }
      >["payload"];
      return {
        credentialType,
        payload: {
          issuer: source.issuer,
          account: source.account,
          seed: source.seed,
          algorithm: source.algorithm,
          digits: source.digits,
          period: source.period,
        },
      };
    }
  }
}

export function parseList<T>(
  value: unknown,
  parser: (item: unknown) => T | null,
): { items: T[]; nextCursor?: string } | null {
  if (
    !isRecord(value) ||
    !exactKeys(value, ["items", "nextCursor"]) ||
    !Array.isArray(value.items)
  ) {
    return null;
  }
  const items: T[] = [];
  for (const item of value.items) {
    const parsed = parser(item);
    if (parsed === null) return null;
    items.push(parsed);
  }
  if (
    value.nextCursor !== undefined &&
    (typeof value.nextCursor !== "string" ||
      value.nextCursor === "" ||
      value.nextCursor.length > 1024 ||
      !safeID.test(value.nextCursor))
  ) {
    return null;
  }
  return {
    items,
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
  return cloneStringRecord(value) !== null;
}

function cloneStringRecord(value: unknown): Record<string, string> | null {
  if (!isRecord(value)) return null;
  const clone: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (
      key.trim() === "" ||
      key === "__proto__" ||
      key === "prototype" ||
      key === "constructor" ||
      typeof item !== "string"
    ) {
      return null;
    }
    clone[key] = item;
  }
  return clone;
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

function validDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function optionalDate(value: unknown): value is string | undefined {
  return value === undefined || validDate(value);
}

function exactKeys(value: Record<string, unknown>, allowed: string[]) {
  const set = new Set(allowed);
  return Object.keys(value).every((key) => set.has(key));
}
