import { describe, expect, it } from "vitest";

import {
  MemoryIdempotencyIntent,
  parseAgentRecord,
  parseAgentUsage,
  parseAuditRow,
  parseMember,
} from "./admin-api";

const agentID = "agt_0123456789abcdef0123456789abcdef";
const tokenID = "tok_0123456789abcdef0123456789abcdef";

describe("strict administration contracts", () => {
  it("retains one memory-only key per unchanged intent and rotates on intent reset", () => {
    const intent = new MemoryIdempotencyIntent();
    const first = intent.keyFor("agent:create:Hermes");
    expect(intent.keyFor("agent:create:Hermes")).toBe(first);
    const changed = intent.keyFor("agent:create:Other");
    expect(changed).not.toBe(first);
    intent.clear();
    expect(intent.keyFor("agent:create:Other")).not.toBe(changed);
  });

  it("accepts only canonical backend timestamps", () => {
    expect(parseAgentRecord({
      id: agentID,
      name: "Hermes",
      createdAt: "2026-07-28T12:00:00Z",
      updatedAt: "2026-07-28T12:00:00.123456789Z",
    })).not.toBeNull();
    for (const timestamp of [
      "2026-07-28 12:00:00Z",
      "2026-07-28T12:00:00+00:00",
      "2026-07-28T12:00:00.120Z",
      "2026-07-28T12:00:00.000Z",
      "2026-02-30T12:00:00Z",
    ]) {
      expect(parseAgentRecord({
        id: agentID,
        name: "Hermes",
        createdAt: timestamp,
        updatedAt: "2026-07-28T12:00:00Z",
      })).toBeNull();
      expect(parseAgentUsage({
        agentId: agentID,
        name: "Hermes",
        tokenCount: 1,
        activeTokens: 1,
        lastUsedAt: timestamp,
      })).toBeNull();
      expect(parseMember({
        userId: "usr_member",
        email: "member@example.test",
        role: "reader",
        version: 1,
        createdAt: timestamp,
      })).toBeNull();
    }
  });

  it("rejects noncanonical Agent and Token identifier shapes", () => {
    for (const id of [
      "agt_1",
      "agt_0123456789abcdef0123456789abcde",
      "agt_0123456789abcdef0123456789abcdef0",
      "agt_0123456789abcdef0123456789abcdeg",
      "agt_0123456789ABCDEF0123456789ABCDEF",
      tokenID,
    ]) {
      expect(parseAgentRecord({
        id,
        name: "Hermes",
        createdAt: "2026-07-28T12:00:00Z",
        updatedAt: "2026-07-28T12:00:00Z",
      })).toBeNull();
    }
  });

  it("matches audit.Validate before cloning safe evidence columns", () => {
    const valid = {
      id: "aud_1",
      requestId: "req_1",
      createdAt: "2026-07-28T12:00:00.123456789Z",
      actorType: "user",
      actorId: "usr_1",
      fingerprint: "0123456789abcdef",
      action: "credential.read",
      spaceId: "spc_prod",
      resourceType: "credential",
      resourceId: "crd_1",
      sourceIp: "2001:db8::1",
      userAgent: "fixture",
      success: true,
      changeFields: ["display_name", "tags"],
      reason: "",
    };
    expect(parseAuditRow(valid)).toEqual({
      id: "aud_1",
      requestId: "req_1",
      createdAt: "2026-07-28T12:00:00.123456789Z",
      actorType: "user",
      actorId: "usr_1",
      action: "credential.read",
      resourceType: "credential",
      resourceId: "crd_1",
      sourceIp: "2001:db8::1",
      success: true,
      errorCode: "",
    });
    for (const mutation of [
      { fingerprint: "F123456789abcdef" },
      { sourceIp: "2001:0db8::1" },
      { sourceIp: "127.00.0.1" },
      { actorId: "" },
      { action: "Credential.Read" },
      { resourceType: "credential-item" },
      { errorCode: "FAILURE" },
      { changeFields: ["display_name", "display_name"] },
      { changeFields: ["password"] },
      { userAgent: "x".repeat(513) },
      { reason: "bad\u0085text" },
      { createdAt: "2026-07-28T12:00:00.000Z" },
    ]) {
      expect(parseAuditRow({ ...valid, ...mutation })).toBeNull();
    }
    expect(parseAuditRow({
      ...valid,
      success: false,
      errorCode: "PERMISSION_DENIED",
    })).not.toBeNull();
    expect(parseAuditRow({
      ...valid,
      success: false,
      errorCode: "",
    })).toBeNull();
  });

  it("matches netip canonical IPv4-mapped IPv6 rendering", () => {
    const base = {
      id: "aud_1",
      requestId: "req_1",
      createdAt: "2026-07-28T12:00:00Z",
      actorType: "agent",
      actorId: agentID,
      fingerprint: "0123456789abcdef",
      action: "credential.read",
      resourceType: "credential",
      sourceIp: "::ffff:192.0.2.1",
      success: true,
      changeFields: [],
    };
    expect(parseAuditRow(base)).not.toBeNull();
    for (const sourceIp of [
      "::ffff:c000:201",
      "::FFFF:192.0.2.1",
      "::ffff:192.000.2.1",
      "::ffff:192.0.2.01",
    ]) {
      expect(parseAuditRow({ ...base, sourceIp })).toBeNull();
    }
  });
});
