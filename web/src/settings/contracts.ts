import { canonicalRFC3339NanoUTC } from "../admin-api";

export type HealthDetail = {
  status: "ok" | "degraded";
  version: string;
  uptimeSeconds: number;
  database: "ok" | "degraded";
  journalMode: "wal" | string;
  diskFreeBytes: number;
  migrationVersion: number;
  lastBackup?: {
    id: string;
    status: "succeeded";
    sizeBytes: number;
    completedAt: string;
    retained: boolean;
  };
  maintenance?: {
    running: boolean;
    lastStartedAt?: string;
    lastFinishedAt?: string;
    lastSuccessAt?: string;
    nextRunAt?: string;
    errorCodes: string[];
    auditRetentionEnabled: boolean;
  };
};

export type BackupRun = {
  id: string;
  status: "running" | "succeeded" | "failed";
  filename?: string;
  checksum?: string;
  sizeBytes?: number;
  startedAt: string;
  completedAt?: string;
  errorCode?: string;
  retained: boolean;
};

export function parseHealthDetail(value: unknown): HealthDetail | null {
  if (
    !record(value) ||
    !only(value, [
      "status", "version", "uptimeSeconds", "database", "journalMode",
      "diskFreeBytes", "migrationVersion", "lastBackup", "maintenance",
    ]) ||
    !["ok", "degraded"].includes(String(value.status)) ||
    !safeText(value.version, 64) ||
    !nonNegative(value.uptimeSeconds) ||
    !["ok", "degraded"].includes(String(value.database)) ||
    !safeText(value.journalMode, 32) ||
    !nonNegative(value.diskFreeBytes) ||
    !nonNegative(value.migrationVersion)
  ) {
    return null;
  }
  const lastBackup =
    value.lastBackup === undefined ? undefined : parseLastBackup(value.lastBackup);
  const maintenance =
    value.maintenance === undefined
      ? undefined
      : parseMaintenance(value.maintenance);
  if (
    (value.lastBackup !== undefined && !lastBackup) ||
    (value.maintenance !== undefined && !maintenance)
  ) {
    return null;
  }
  return {
    status: value.status as HealthDetail["status"],
    version: value.version,
    uptimeSeconds: value.uptimeSeconds,
    database: value.database as HealthDetail["database"],
    journalMode: value.journalMode,
    diskFreeBytes: value.diskFreeBytes,
    migrationVersion: value.migrationVersion,
    ...(lastBackup ? { lastBackup } : {}),
    ...(maintenance ? { maintenance } : {}),
  };
}

export function parseBackupRuns(
  value: unknown,
): { items: BackupRun[] } | null {
  if (!record(value) || !only(value, ["items"]) || !Array.isArray(value.items)) {
    return null;
  }
  const items: BackupRun[] = [];
  for (const candidate of value.items) {
    const parsed = parseBackupRun(candidate);
    if (!parsed) return null;
    items.push(parsed);
  }
  return { items };
}

function parseBackupRun(value: unknown): BackupRun | null {
  if (
    !record(value) ||
    !only(value, [
      "id", "status", "filename", "checksum", "sizeBytes", "startedAt",
      "completedAt", "errorCode", "retained",
    ]) ||
    !backupID(value.id) ||
    !["running", "succeeded", "failed"].includes(String(value.status)) ||
    (value.filename !== undefined && !canonicalFilename(value.filename)) ||
    (value.checksum !== undefined &&
      (typeof value.checksum !== "string" ||
        !/^[0-9a-f]{64}$/u.test(value.checksum))) ||
    (value.sizeBytes !== undefined && !nonNegative(value.sizeBytes)) ||
    !canonicalRFC3339NanoUTC(value.startedAt) ||
    (value.completedAt !== undefined &&
      !canonicalRFC3339NanoUTC(value.completedAt)) ||
    (value.errorCode !== undefined && !errorCode(value.errorCode)) ||
    typeof value.retained !== "boolean"
  ) {
    return null;
  }
  return {
    id: value.id,
    status: value.status as BackupRun["status"],
    ...(typeof value.filename === "string" ? { filename: value.filename } : {}),
    ...(typeof value.checksum === "string" ? { checksum: value.checksum } : {}),
    ...(typeof value.sizeBytes === "number" ? { sizeBytes: value.sizeBytes } : {}),
    startedAt: value.startedAt,
    ...(typeof value.completedAt === "string"
      ? { completedAt: value.completedAt }
      : {}),
    ...(typeof value.errorCode === "string" ? { errorCode: value.errorCode } : {}),
    retained: value.retained,
  };
}

function parseLastBackup(value: unknown): HealthDetail["lastBackup"] | null {
  if (
    !record(value) ||
    !only(value, ["id", "status", "sizeBytes", "completedAt", "retained"]) ||
    !backupID(value.id) ||
    value.status !== "succeeded" ||
    !nonNegative(value.sizeBytes) ||
    !canonicalRFC3339NanoUTC(value.completedAt) ||
    typeof value.retained !== "boolean"
  ) {
    return null;
  }
  return {
    id: value.id,
    status: "succeeded",
    sizeBytes: value.sizeBytes,
    completedAt: value.completedAt,
    retained: value.retained,
  };
}

function parseMaintenance(value: unknown): HealthDetail["maintenance"] | null {
  if (
    !record(value) ||
    !only(value, [
      "running", "lastStartedAt", "lastFinishedAt", "lastSuccessAt",
      "nextRunAt", "errorCodes", "auditRetentionEnabled",
    ]) ||
    typeof value.running !== "boolean" ||
    !optionalDate(value.lastStartedAt) ||
    !optionalDate(value.lastFinishedAt) ||
    !optionalDate(value.lastSuccessAt) ||
    !optionalDate(value.nextRunAt) ||
    !Array.isArray(value.errorCodes) ||
    !value.errorCodes.every(errorCode) ||
    typeof value.auditRetentionEnabled !== "boolean"
  ) {
    return null;
  }
  return {
    running: value.running,
    ...(typeof value.lastStartedAt === "string"
      ? { lastStartedAt: value.lastStartedAt }
      : {}),
    ...(typeof value.lastFinishedAt === "string"
      ? { lastFinishedAt: value.lastFinishedAt }
      : {}),
    ...(typeof value.lastSuccessAt === "string"
      ? { lastSuccessAt: value.lastSuccessAt }
      : {}),
    ...(typeof value.nextRunAt === "string" ? { nextRunAt: value.nextRunAt } : {}),
    errorCodes: [...value.errorCodes],
    auditRetentionEnabled: value.auditRetentionEnabled,
  };
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function only(value: Record<string, unknown>, keys: string[]) {
  const allowed = new Set(keys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function safeText(value: unknown, max: number): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= max &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
}

function nonNegative(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function backupID(value: unknown): value is string {
  return typeof value === "string" && /^bkp_[0-9a-f]{32}$/u.test(value);
}

function canonicalFilename(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^opswarden-\d{8}T\d{6}\.\d{9}Z-bkp_[0-9a-f]{32}\.sqlite3$/u.test(value)
  );
}

function errorCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9_]{1,64}$/u.test(value);
}

function optionalDate(value: unknown) {
  return value === undefined || canonicalRFC3339NanoUTC(value);
}
