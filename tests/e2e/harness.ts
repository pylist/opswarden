import { createHmac, randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { resolve } from "node:path";
import type { APIRequestContext, APIResponse, Locator, Page } from "@playwright/test";

const execFileAsync = promisify(execFile);
const root = resolve(import.meta.dirname, "../..");
const runtime = resolve(root, ".tmp/e2e");
const artifacts = resolve(root, ".artifacts/e2e");

type Control = {
  baseURL: string;
  email: string;
  password: string;
  loginTOTPSeed: string;
  uiRecoveryCode: string;
  restoreRecoveryCode: string;
  credentialPassword: string;
  jwt: string;
  sessionID: string;
  userID: string;
  primarySpaceID: string;
  otherSpaceID: string;
  otherCredentialID: string;
  agentID: string;
  agentTokenID: string;
  agentToken: string;
};

async function control(): Promise<Control> {
  return JSON.parse(await readFile(resolve(runtime, "control.json"), "utf8"));
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
  const offset = digest.at(-1)! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function login(request: APIRequestContext, state: Control, baseURL = state.baseURL) {
  const begin = await request.post(baseURL + "/api/v1/auth/login/begin", {
    data: { email: state.email, password: state.password },
  });
  if (!begin.ok()) throw new Error(`login begin failed: ${begin.status()}`);
  const challenge = await begin.json();
  const complete = await request.post(baseURL + "/api/v1/auth/login/complete", {
    data: {
      challengeId: challenge.challengeId,
      secondFactor: state.restoreRecoveryCode,
    },
  });
  if (!complete.ok()) throw new Error(`login complete failed: ${complete.status()}`);
  return (await complete.json()).token as string;
}

async function mcpCall(request: APIRequestContext, state: Control, name: string, args: object) {
  const response = await request.post(state.baseURL + "/mcp", {
    headers: {
      Authorization: `Bearer ${state.agentToken}`,
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    },
    data: {
      jsonrpc: "2.0",
      id: randomBytes(8).toString("hex"),
      method: "tools/call",
      params: { name, arguments: args },
    },
  });
  const body = await response.text();
  if (!response.ok()) throw new Error(`MCP HTTP ${response.status()}: ${body}`);
  const envelope = JSON.parse(body);
  if (envelope.error || envelope.result?.isError) {
    throw new Error(`MCP ${name} failed: ${body}`);
  }
  return envelope.result.structuredContent;
}

export class APIHarness {
  protected constructor(
    protected readonly request: APIRequestContext,
    protected readonly state: Control,
  ) {}

  static async start(request: APIRequestContext) {
    return new APIHarness(request, await control());
  }

  protected headers(token = this.state.jwt) {
    return { Authorization: `Bearer ${token}` };
  }

  getCredential(id: string): Promise<APIResponse> {
    return this.request.get(
      `${this.state.baseURL}/api/v1/spaces/${this.state.primarySpaceID}/credentials/${id}`,
      { headers: this.headers() },
    );
  }

  getOtherSpaceCredential() {
    return this.getCredential(this.state.otherCredentialID);
  }
}

export class E2EHarness extends APIHarness {
  private constructor(
    request: APIRequestContext,
    state: Control,
    private readonly page: Page,
  ) {
    super(request, state);
  }

  static async start(page: Page, request: APIRequestContext) {
    const state = await control();
    const harness = new E2EHarness(request, state, page);
    await page.goto("/");
    await page.getByLabel("邮箱").fill(state.email);
    await page.getByLabel("密码").fill(state.password);
    await page.getByRole("button", { name: "继续" }).click();
    await page.getByRole("radio", { name: "恢复码" }).check();
    await page.getByRole("textbox", { name: "恢复码" }).fill(state.uiRecoveryCode);
    await page.getByRole("button", { name: "登录", exact: true }).click();
    await page.getByLabel("当前空间").selectOption(state.primarySpaceID);
    await page.getByRole("link", { name: "凭据库" }).click();
    await page.getByRole("heading", { name: "凭据库" }).waitFor();
    return harness;
  }

  async createCredentialInUI() {
    await this.page.getByRole("button", { name: "新建凭据" }).click();
    await this.page.getByLabel("显示名称").fill("e2e-login");
    await this.page.getByLabel("网址").fill("https://e2e.invalid");
    await this.page.getByLabel("用户名").fill("hermes");
    await this.page.getByLabel("密码", { exact: true }).fill(this.state.credentialPassword);
    const response = this.page.waitForResponse((candidate) =>
      candidate.request().method() === "POST" &&
      candidate.url().endsWith(`/spaces/${this.state.primarySpaceID}/credentials`)
    );
    await this.page.getByRole("button", { name: "保存" }).click();
    const body = await (await response).json();
    await this.page.getByRole("button", { name: "e2e-login" }).waitFor();
    return body.id as string;
  }

  async mcpCredentialGet(id: string) {
    const result = await mcpCall(this.request, this.state, "credential_get", {
      space_id: this.state.primarySpaceID,
      credential_id: id,
    });
    return result.metadata;
  }

  async mcpCredentialUpdate(id: string, displayName: string) {
    const current = await this.mcpCredentialGet(id);
    const result = await mcpCall(this.request, this.state, "credential_update", {
      space_id: this.state.primarySpaceID,
      credential_id: id,
      expected_version: current.version,
      display_name: displayName,
      reason: "E2E Hermes lifecycle",
      idempotency_key: `update-${randomBytes(12).toString("hex")}`,
    });
    return result.version as number;
  }

  async mcpCredentialDelete(id: string, version: number) {
    await mcpCall(this.request, this.state, "credential_delete", {
      space_id: this.state.primarySpaceID,
      credential_id: id,
      expected_version: version,
      reason: "E2E Hermes lifecycle",
      idempotency_key: `delete-${randomBytes(12).toString("hex")}`,
    });
    await this.page.getByRole("link", { name: "概览" }).click();
    await this.page.getByRole("link", { name: "凭据库" }).click();
    await this.page.getByRole("button", { name: "回收站" }).click();
  }

  recycleBinRow(_id: string): Locator {
    return this.page.getByRole("row").filter({ hasText: "e2e-login-updated" });
  }

  async auditActionsFor(id: string) {
    const response = await this.request.get(
      `${this.state.baseURL}/api/v1/audit-events?spaceId=${this.state.primarySpaceID}&resourceId=${id}&limit=100`,
      { headers: this.headers() },
    );
    const body = await response.json();
    await writeFile(resolve(artifacts, "audit-export.json"), JSON.stringify(body), { mode: 0o600 });
    const browserStorage = await this.page.evaluate(async () => ({
      localStorage: Object.fromEntries(Object.entries(localStorage)),
      sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
      indexedDB: typeof indexedDB.databases === "function"
        ? (await indexedDB.databases()).map((database) => database.name ?? "")
        : [],
    }));
    const cookies = await this.page.context().cookies();
    await writeFile(
      resolve(artifacts, "browser-storage.json"),
      JSON.stringify({ ...browserStorage, cookies }),
      { mode: 0o600 },
    );
    const actions = body.items.map((item: { action: string }) => item.action);
    return ["credential.create", "credential.read", "credential.update", "credential.delete"]
      .filter((action) => actions.includes(action));
  }
}

export class RestoreHarness extends APIHarness {
  static async start(request: APIRequestContext) {
    return new RestoreHarness(request, await control());
  }

  async backupRestoreAndRevoke() {
    const db = resolve(runtime, "data/opswarden.db");
    const backup = resolve(artifacts, "online-backup.sqlite3");
    const python = [
      "import sqlite3,sys",
      "source=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)",
      "target=sqlite3.connect(sys.argv[2])",
      "source.backup(target)",
      "target.execute('PRAGMA integrity_check').fetchone()==('ok',) or sys.exit(2)",
      "target.close(); source.close()",
    ].join(";");
    await execFileAsync("/usr/bin/python3", ["-I", "-c", python, db, backup]);
    await chmod(backup, 0o600);

    const restore = resolve(runtime, "restore");
    const restoreState = resolve(restore, "state-root");
    const restoreData = resolve(restoreState, "data");
    const restoreKey = resolve(restore, "master.key");
    await mkdir(restoreData, { recursive: true, mode: 0o700 });
    await mkdir(resolve(restoreState, "backups"), { recursive: true, mode: 0o700 });
    await copyFile(backup, resolve(restoreData, "opswarden.db"));
    await copyFile(resolve(runtime, "master.key"), restoreKey);
    await chmod(restoreKey, 0o600);
    const envPath = resolve(restore, "restore.env");
    const overridePath = resolve(restore, "restore.override.yaml");
    await writeFile(envPath, [
      "OPSWARDEN_VERSION=e2e",
      "OPSWARDEN_REVISION=e2e",
      "SOURCE_DATE_EPOCH=0",
      `OPSWARDEN_STATE_PATH=${restoreState}`,
      `OPSWARDEN_MASTER_KEY_PATH=${restoreKey}`,
      `CADDY_DATA_PATH=${restore}/caddy-data`,
      `CADDY_CONFIG_PATH=${restore}/caddy-config`,
      "OPSWARDEN_HOSTNAME=e2e.invalid",
      "OPSWARDEN_TLS_EMAIL=e2e@example.invalid",
      "OPSWARDEN_BACKEND_SUBNET=172.31.251.0/29",
      "OPSWARDEN_APP_IP=172.31.251.2",
      "OPSWARDEN_CADDY_IP=172.31.251.3",
    ].join("\n") + "\n", { mode: 0o600 });
    await writeFile(overridePath, [
      "services:",
      "  opswarden:",
      "    ports:",
      '      - "127.0.0.1:18082:8080"',
      "    networks:",
      "      backend:",
      "        ipv4_address: 172.31.251.2",
      "      edge: {}",
    ].join("\n") + "\n", { mode: 0o600 });
    await mkdir(resolve(restore, "caddy-data"), { recursive: true, mode: 0o700 });
    await mkdir(resolve(restore, "caddy-config"), { recursive: true, mode: 0o700 });
    const compose = [
      "compose", "-p", "opswarden-e2e-restore",
      "--env-file", envPath,
      "-f", resolve(root, "deploy/compose.yaml"),
      "-f", overridePath,
    ];
    const runDocker = (args: string[]) => execFileAsync("docker", [...compose, ...args], {
      cwd: root,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
    });
    try {
      await runDocker(["up", "-d", "--no-build", "opswarden"]);
      await waitHealthy("http://127.0.0.1:18082/health/live");
      const restoredJWT = await login(this.request, this.state, "http://127.0.0.1:18082");
      const decrypted = await this.request.get(
        `http://127.0.0.1:18082/api/v1/spaces/${this.state.otherSpaceID}/credentials/${this.state.otherCredentialID}`,
        { headers: this.headers(restoredJWT) },
      );
      if (!decrypted.ok()) throw new Error(`restored decryption failed: ${decrypted.status()}`);

      await runDocker(["stop", "opswarden"]);
      const revoke = [
        "import datetime,sqlite3,sys",
        "db=sqlite3.connect(sys.argv[1])",
        "now=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')",
        "db.execute('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',(now,sys.argv[2]))",
        "db.execute('UPDATE agent_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL',(now,sys.argv[3]))",
        "db.commit(); db.close()",
      ].join(";");
      await execFileAsync("/usr/bin/python3", [
        "-I", "-c", revoke, resolve(restoreData, "opswarden.db"),
        this.state.userID, this.state.agentTokenID,
      ]);
      await runDocker(["start", "opswarden"]);
      await waitHealthy("http://127.0.0.1:18082/health/live");
      const revokedSession = await this.request.get(
        `http://127.0.0.1:18082/api/v1/me`,
        { headers: this.headers(restoredJWT) },
      );
      if (revokedSession.status() !== 401) throw new Error("restored browser session was not revoked");
      const revokedAgent = await this.request.post("http://127.0.0.1:18082/mcp", {
        headers: {
          Authorization: `Bearer ${this.state.agentToken}`,
          Accept: "application/json, text/event-stream",
          "Content-Type": "application/json",
        },
        data: { jsonrpc: "2.0", id: "revoked", method: "tools/list", params: {} },
      });
      if (revokedAgent.status() !== 401) throw new Error("restored Agent Token was not revoked");
      await writeFile(resolve(artifacts, "captured-errors.json"), JSON.stringify({
        session: await revokedSession.json(),
        agent: await revokedAgent.json(),
      }), { mode: 0o600 });
    } finally {
      const logs = await runDocker(["logs", "--no-color"]).catch((error: unknown) => ({
        stdout: "",
        stderr: error instanceof Error ? error.message : "compose log capture failed",
      }));
      await writeFile(
        resolve(artifacts, "restore-compose.log"),
        `${logs.stdout ?? ""}${logs.stderr ?? ""}`,
        { mode: 0o600 },
      );
      await runDocker(["down", "--volumes", "--remove-orphans"]).catch(() => undefined);
    }
  }
}

async function waitHealthy(url: string) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Container startup is expected to refuse connections briefly.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`health timeout: ${url}`);
}
