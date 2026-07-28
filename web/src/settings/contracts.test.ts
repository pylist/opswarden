import { describe, expect, it } from "vitest";

import { parseBackupRuns, parseHealthDetail } from "./contracts";

const runId = "bkp_0123456789abcdef0123456789abcdef";

describe("settings contracts", () => {
  it("accepts the strict health and backup response shapes", () => {
    expect(parseHealthDetail({
      status: "ok",
      version: "dev",
      uptimeSeconds: 3600,
      database: "ok",
      journalMode: "wal",
      databaseDiskFreeBytes: 1024,
      backupDiskFreeBytes: 2048,
      migrationVersion: 11,
      lastBackup: {
        id: runId,
        status: "succeeded",
        sizeBytes: 4096,
        completedAt: "2026-07-29T01:02:03Z",
        retained: true,
        verificationStatus: "passed",
        verifiedAt: "2026-07-29T01:02:04Z",
      },
      maintenance: {
        running: false,
        nextRunAt: "2026-07-30T01:02:03Z",
        errorCodes: [],
        auditRetentionEnabled: false,
      },
    })).not.toBeNull();
    expect(parseBackupRuns({
      items: [{
        id: runId,
        status: "succeeded",
        filename:
          `opswarden-20260729T010203.000000000Z-${runId}.sqlite3`,
        checksum: "a".repeat(64),
        sizeBytes: 4096,
        startedAt: "2026-07-29T01:02:02Z",
        completedAt: "2026-07-29T01:02:03Z",
        retained: true,
        verificationStatus: "passed",
        verifiedAt: "2026-07-29T01:02:04Z",
      }],
    })?.items).toHaveLength(1);
  });

  it("rejects paths, unknown fields, malformed identifiers and unsafe codes", () => {
    expect(parseBackupRuns({
      items: [{
        id: runId,
        status: "succeeded",
        filename: "/var/lib/opswarden/backups/private.sqlite3",
        startedAt: "2026-07-29T01:02:02Z",
        retained: true,
      }],
    })).toBeNull();
    expect(parseHealthDetail({
      status: "ok",
      version: "dev",
      uptimeSeconds: 1,
      database: "ok",
      journalMode: "wal",
      databaseDiskFreeBytes: 1,
      backupDiskFreeBytes: 1,
      migrationVersion: 11,
      keyFingerprint: "forbidden",
    })).toBeNull();
  });
});
