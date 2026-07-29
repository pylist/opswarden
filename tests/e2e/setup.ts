import { createHmac, randomBytes } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { FullConfig } from "@playwright/test";

const root = resolve(import.meta.dirname, "../..");
const runtime = resolve(root, ".tmp/e2e");
const artifacts = resolve(root, ".artifacts/e2e");
const baseURL = "http://127.0.0.1:18081";

function unique(label: string) {
  return `OW_E2E_${label}_${randomBytes(18).toString("base64url")}`;
}

function base32(bytes: Buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function totp(seed: string, at = Date.now()) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const character of seed.replace(/=+$/u, "")) {
    value = (value << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, "0");
}

async function api(path: string, init: RequestInit = {}) {
  const response = await fetch(baseURL + path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`E2E setup request ${path} failed: ${response.status} ${body?.error?.code ?? ""}`);
  }
  return body;
}

export default async function setup(_config: FullConfig) {
  const password = unique("PASSWORD");
  const credentialPassword = unique("LOGIN_PASSWORD");
  const apiToken = unique("API_TOKEN");
  const privateKeyMarker = unique("PRIVATE_KEY");
  const privateKey = `-----BEGIN OPENSSH PRIVATE KEY-----\n${privateKeyMarker}\n-----END OPENSSH PRIVATE KEY-----`;
  const connectionString = `postgresql://opswarden:${unique("DB_PASSWORD")}@db.invalid/e2e?application_name=${unique("CONNECTION")}`;
  const credentialTOTPSeed = base32(randomBytes(20));
  const loginTOTPSeed = base32(randomBytes(20));
  const email = `e2e-${randomBytes(8).toString("hex")}@example.invalid`;

  const bootstrap = await api("/api/v1/bootstrap/initial-owner", {
    method: "POST",
    body: JSON.stringify({ email, password, totpSeed: loginTOTPSeed }),
  });
  const challenge = await api("/api/v1/auth/login/begin", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  const login = await api("/api/v1/auth/login/complete", {
    method: "POST",
    body: JSON.stringify({
      challengeId: challenge.challengeId,
      secondFactor: totp(loginTOTPSeed),
    }),
  });
  const authorization = { Authorization: `Bearer ${login.token}` };
  const create = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    api(path, { method: "POST", body: JSON.stringify(body), headers: { ...authorization, ...headers } });

  const primary = await create("/api/v1/spaces", { name: "E2E Primary" });
  const other = await create("/api/v1/spaces", { name: "E2E Other" });
  const createCredential = (spaceID: string, displayName: string, type: string, payload: unknown) =>
    create(`/api/v1/spaces/${spaceID}/credentials`, {
      displayName, type, tags: { suite: "e2e" }, assetIds: [], payload,
    });
  const otherCredential = await createCredential(other.id, "other-space-fixture", "api_token", {
    service: "e2e", token: apiToken,
  });
  await createCredential(primary.id, "private-key-fixture", "ssh_key", {
    username: "opswarden", private_key: privateKey,
  });
  await createCredential(primary.id, "database-fixture", "database", {
    engine: "postgresql", connection_string: connectionString,
  });
  await createCredential(primary.id, "totp-fixture", "totp", {
    issuer: "OpsWarden E2E", account: email, seed: credentialTOTPSeed,
    algorithm: "SHA1", digits: 6, period: 30,
  });

  const agent = await create("/api/v1/agents", { name: "Hermes E2E" }, {
    "Idempotency-Key": `agent-${randomBytes(12).toString("hex")}`,
  });
  await api(`/api/v1/agents/${agent.id}/grants`, {
    method: "PUT",
    body: JSON.stringify({
      spaceId: primary.id,
      scopes: [
        "credential:list", "credential:read", "credential:create",
        "credential:update", "credential:delete",
      ],
      requiredLabels: {},
    }),
    headers: {
      ...authorization,
      "Idempotency-Key": `grant-${randomBytes(12).toString("hex")}`,
    },
  });
  const issued = await create(`/api/v1/agents/${agent.id}/tokens`, {}, {
    "Idempotency-Key": `token-${randomBytes(12).toString("hex")}`,
  });
  const claims = JSON.parse(Buffer.from(login.token.split(".")[1], "base64url").toString("utf8"));
  const masterKey = (await readFile(resolve(runtime, "master.key"), "utf8")).trim();
  const control = {
    baseURL, email, password, loginTOTPSeed, credentialPassword,
    uiRecoveryCode: bootstrap.recoveryCodes[0],
    restoreRecoveryCode: bootstrap.recoveryCodes[1],
    jwt: login.token, sessionID: claims.sid, userID: bootstrap.userId,
    primarySpaceID: primary.id, otherSpaceID: other.id,
    otherCredentialID: otherCredential.id,
    agentID: agent.id, agentTokenID: issued.id, agentToken: issued.token,
    fixtureCredentialID: otherCredential.id,
  };
  const controlPath = resolve(runtime, "control.json");
  await writeFile(controlPath, JSON.stringify(control), { mode: 0o600 });
  await chmod(controlPath, 0o600);
  const secrets = [
    password, credentialPassword, apiToken, privateKeyMarker, connectionString,
    credentialTOTPSeed, loginTOTPSeed, bootstrap.recoveryCodes[0],
    bootstrap.recoveryCodes[1],
    claims.sid, issued.token, masterKey,
  ];
  const secretPath = resolve(artifacts, ".sensitive-values");
  await writeFile(secretPath, secrets.join("\n") + "\n", { mode: 0o600 });
  await chmod(secretPath, 0o600);
}
