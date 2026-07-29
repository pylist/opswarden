import { createHmac, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { APIRequestContext, APIResponse, Locator, Page } from "@playwright/test";

const root = resolve(import.meta.dirname, "../..");
const runtime = resolve(process.env.OPSWARDEN_E2E_RUNTIME_DIR ?? "");
const artifacts = resolve(process.env.OPSWARDEN_E2E_ARTIFACT_DIR ?? "");
const secretFile = resolve(process.env.OPSWARDEN_E2E_SECRET_FILE ?? "");
const restorePort = Number(process.env.OPSWARDEN_E2E_RESTORE_PORT);
const composeProject = process.env.OPSWARDEN_E2E_PROJECT ?? "";
const backendSubnet = process.env.OPSWARDEN_E2E_BACKEND_SUBNET ?? "";
const appIP = process.env.OPSWARDEN_E2E_APP_IP ?? "";
const caddyIP = process.env.OPSWARDEN_E2E_CADDY_IP ?? "";
const imageVersion = process.env.OPSWARDEN_E2E_IMAGE_VERSION ?? "";
if (
  !runtime.startsWith(resolve(root, ".tmp") + "/") ||
  !artifacts.startsWith(resolve(root, ".artifacts") + "/") ||
  secretFile !== resolve(runtime, "sensitive-patterns") ||
  !Number.isInteger(restorePort) ||
  restorePort < 1024 ||
  restorePort > 65535 ||
  !/^opswarden-e2e-[a-z0-9]{8}$/u.test(composeProject) ||
  !/^172\.2[0-7]\.\d{1,3}\.0\/29$/u.test(backendSubnet) ||
  !/^172\.2[0-7]\.\d{1,3}\.[23]$/u.test(appIP) ||
  !/^172\.2[0-7]\.\d{1,3}\.[23]$/u.test(caddyIP) ||
  appIP.replace(/\.2$/u, ".0/29") !== backendSubnet ||
  caddyIP.replace(/\.3$/u, ".0/29") !== backendSubnet ||
  !/^e2e-[0-9a-f]{40}$/u.test(imageVersion)
) {
  throw new Error("validated E2E harness environment is required");
}

type Control = {
  baseURL: string;
  email: string;
  password: string;
  loginTOTPSeed: string;
  uiRecoveryCode: string;
  restoreRecoveryCode: string;
  wrongKeyRecoveryCode: string;
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
  apiToken: string;
};

type CommandResult = { stdout: string; stderr: string };

async function runCommand(
  command: string,
  args: string[],
  options: { cwd?: string; timeoutMs?: number } = {},
): Promise<CommandResult> {
  return new Promise((resolveCommand, rejectCommand) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? root,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks = { stdout: [] as Buffer[], stderr: [] as Buffer[], size: 0 };
    const collect = (key: "stdout" | "stderr", chunk: Buffer) => {
      chunks.size += chunk.length;
      if (chunks.size > (4 << 20)) {
        child.kill("SIGTERM");
        return;
      }
      chunks[key].push(chunk);
    };
    child.stdout.on("data", (chunk: Buffer) => collect("stdout", chunk));
    child.stderr.on("data", (chunk: Buffer) => collect("stderr", chunk));
    let killedForTimeout = false;
    const timeout = setTimeout(() => {
      killedForTimeout = true;
      child.kill("SIGTERM");
      setTimeout(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
      }, 5000).unref();
    }, options.timeoutMs ?? 60_000);
    child.on("error", (error) => {
      clearTimeout(timeout);
      rejectCommand(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timeout);
      const result = {
        stdout: Buffer.concat(chunks.stdout).toString("utf8"),
        stderr: Buffer.concat(chunks.stderr).toString("utf8"),
      };
      if (code === 0 && !killedForTimeout && chunks.size <= (4 << 20)) {
        resolveCommand(result);
      } else {
        rejectCommand(new Error(
          `bounded subprocess failed: code=${code} signal=${signal ?? ""}` +
          ` timeout=${killedForTimeout}`,
        ));
      }
    });
  });
}

async function appendPatterns(...patterns: string[]) {
  if (patterns.some((pattern) => pattern.length < 12 || pattern.includes("\n"))) {
    throw new Error("invalid dynamic sensitive pattern");
  }
  await writeFile(secretFile, patterns.map((pattern) => `${pattern}\n`).join(""), {
    flag: "a",
    mode: 0o600,
  });
  await chmod(secretFile, 0o600);
}

async function appendJWTPatterns(token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid E2E JWT");
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (typeof claims.sid !== "string") throw new Error("E2E JWT has no session pattern");
  await appendPatterns(token, claims.sid);
}

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

async function login(
  request: APIRequestContext,
  state: Control,
  baseURL = state.baseURL,
  secondFactor = state.restoreRecoveryCode,
) {
  const begin = await request.post(baseURL + "/api/v1/auth/login/begin", {
    data: { email: state.email, password: state.password },
  });
  if (!begin.ok()) throw new Error(`login begin failed: ${begin.status()}`);
  const challenge = await begin.json();
  const complete = await request.post(baseURL + "/api/v1/auth/login/complete", {
    data: {
      challengeId: challenge.challengeId,
      secondFactor,
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
  if (!response.ok()) {
    await recordMCPFailure(name, response.status(), body);
    throw new Error(`MCP ${name} HTTP failure: status=${response.status()}`);
  }
  let envelope: any;
  try {
    envelope = JSON.parse(body);
  } catch {
    await recordMCPFailure(name, response.status(), body);
    throw new Error(`MCP ${name} returned an invalid protected response`);
  }
  if (envelope.error || envelope.result?.isError) {
    await recordMCPFailure(name, response.status(), body);
    throw new Error(`MCP ${name} reported a protected tool failure`);
  }
  return envelope.result.structuredContent;
}

async function recordMCPFailure(name: string, status: number, body: string) {
  const raw = Buffer.from(body, "utf8");
  await writeProtectedArtifact(raw);
  void name;
  void status;
}

async function writeProtectedArtifact(body: Buffer) {
  await new Promise<void>((resolveWrite, rejectWrite) => {
    const child = spawn(
      "/usr/bin/python3",
      [
        "-I",
        resolve(root, "scripts/write_e2e_artifact.py"),
        artifacts,
        "errors/mcp-failures.bin",
      ],
      {
        cwd: root,
        env: { HOME: "/nonexistent", PATH: "/usr/bin:/bin", LC_ALL: "C" },
        stdio: ["pipe", "ignore", "ignore"],
      },
    );
    const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
    child.on("error", () => {
      clearTimeout(timeout);
      rejectWrite(new Error("protected MCP failure artifact writer could not start"));
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (code === 0) resolveWrite();
      else rejectWrite(new Error("protected MCP failure artifact writer refused output"));
    });
    child.stdin.end(body);
  });
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

  static async startWithPage(page: Page, request: APIRequestContext) {
    const state = await control();
    const harness = new E2EHarness(request, state, page);
    await page.goto("/");
    await page.getByLabel("邮箱").fill(state.email);
    await page.getByLabel("密码").fill(state.password);
    await page.getByRole("button", { name: "继续" }).click();
    await page.getByRole("radio", { name: "恢复码" }).check();
    await page.getByRole("textbox", { name: "恢复码" }).fill(state.uiRecoveryCode);
    const loginResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/v1/auth/login/complete") &&
      response.request().method() === "POST"
    );
    await page.getByRole("button", { name: "登录", exact: true }).click();
    const loginBody = await (await loginResponse).json();
    await appendJWTPatterns(loginBody.token);
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
    await writeFile(resolve(artifacts, "audit/audit-export.json"), JSON.stringify(body), { mode: 0o600 });
    const browserStorage = await this.page.evaluate(async () => ({
      localStorage: Object.fromEntries(Object.entries(localStorage)),
      sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
      indexedDB: typeof indexedDB.databases === "function"
        ? (await indexedDB.databases()).map((database) => database.name ?? "")
        : [],
    }));
    const cookies = await this.page.context().cookies();
    await writeFile(
      resolve(artifacts, "browser/browser-storage.json"),
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
    const backup = resolve(artifacts, "backups/online-backup.sqlite3");
    const python = [
      "import sqlite3,sys",
      "source=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)",
      "target=sqlite3.connect(sys.argv[2])",
      "source.backup(target)",
      "target.execute('PRAGMA integrity_check').fetchone()==('ok',) or sys.exit(2)",
      "target.close(); source.close()",
    ].join(";");
    await runCommand("/usr/bin/python3", ["-I", "-c", python, db, backup]);
    await chmod(backup, 0o600);
    const correct = await prepareRestoreLayout(
      "restore",
      backup,
      await readFile(resolve(runtime, "master.key"), "utf8"),
      composeProject,
    );
    const wrongKey = randomBytes(32).toString("base64");
    await appendPatterns(wrongKey);
    const wrong = await prepareRestoreLayout(
      "restore-wrong",
      backup,
      wrongKey + "\n",
      `${composeProject}-wrong`,
    );
    const capturedErrors: Record<string, unknown> = {};
    try {
      await runCommand("docker", ["image", "inspect", `opswarden:${imageVersion}`]);

      await wrong.run(["up", "-d", "--no-build", "opswarden"]);
      await waitHealthy(wrong.baseURL + "/health/live");
      const wrongJWT = await login(
        this.request,
        this.state,
        wrong.baseURL,
        this.state.wrongKeyRecoveryCode,
      );
      await appendJWTPatterns(wrongJWT);
      const wrongDecryption = await this.request.get(
        `${wrong.baseURL}/api/v1/spaces/${this.state.otherSpaceID}/credentials/${this.state.otherCredentialID}`,
        { headers: this.headers(wrongJWT) },
      );
      const wrongDecryptionBody = await wrongDecryption.json();
      if (
        wrongDecryption.status() !== 500 ||
        wrongDecryptionBody?.error?.code !== "INTERNAL_ERROR" ||
        "payload" in wrongDecryptionBody
      ) {
        throw new Error("wrong master key did not fail closed during decryption");
      }
      capturedErrors.wrongKey = wrongDecryptionBody;
      await captureComposeLogs(wrong, "restore-wrong-compose.log");
      await wrong.run(["down", "--volumes", "--remove-orphans"]);

      await correct.run(["up", "-d", "--no-build", "opswarden"]);
      await waitHealthy(correct.baseURL + "/health/live");
      const restoredJWT = await login(
        this.request,
        this.state,
        correct.baseURL,
        totp(this.state.loginTOTPSeed, Date.now() + 30_000),
      );
      await appendJWTPatterns(restoredJWT);
      const decrypted = await this.request.get(
        `${correct.baseURL}/api/v1/spaces/${this.state.otherSpaceID}/credentials/${this.state.otherCredentialID}`,
        { headers: this.headers(restoredJWT) },
      );
      if (!decrypted.ok()) throw new Error(`restored decryption failed: ${decrypted.status()}`);
      const decryptedBody = await decrypted.json();
      if (
        decryptedBody?.metadata?.id !== this.state.otherCredentialID ||
        decryptedBody?.payload?.token !== this.state.apiToken
      ) {
        throw new Error("restored credential plaintext did not match the known fixture");
      }

      const restoredAgent = await this.request.post(`${correct.baseURL}/api/v1/agents`, {
        headers: {
          ...this.headers(restoredJWT),
          "Idempotency-Key": `restored-agent-${randomBytes(12).toString("hex")}`,
        },
        data: { name: "Restored emergency-revocation Agent" },
      });
      if (restoredAgent.status() !== 201) {
        throw new Error(`restored Agent create failed: ${restoredAgent.status()}`);
      }
      const restoredAgentBody = await restoredAgent.json();
      const restoredToken = await this.request.post(
        `${correct.baseURL}/api/v1/agents/${restoredAgentBody.id}/tokens`,
        {
          headers: {
            ...this.headers(restoredJWT),
            "Idempotency-Key": `restored-token-${randomBytes(12).toString("hex")}`,
          },
          data: {},
        },
      );
      if (restoredToken.status() !== 201) {
        throw new Error(`restored Agent Token issue failed: ${restoredToken.status()}`);
      }
      const restoredTokenBody = await restoredToken.json();
      await appendPatterns(restoredTokenBody.token);
      const activeAgent = await mcpTransport(
        this.request,
        correct.baseURL,
        restoredTokenBody.token,
      );
      if (!activeAgent.ok()) throw new Error("new restored Agent Token was never active");

      await correct.run(["stop", "opswarden"]);
      const revoke = [
        "import datetime,sqlite3,sys",
        "db=sqlite3.connect(sys.argv[1])",
        "now=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')",
        "db.execute('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',(now,sys.argv[2]))",
        "db.execute('UPDATE agent_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL',(now,sys.argv[3]))",
        "db.commit(); db.close()",
      ].join(";");
      await runCommand("/usr/bin/python3", [
        "-I", "-c", revoke, resolve(correct.dataDir, "opswarden.db"),
        this.state.userID, restoredTokenBody.id,
      ]);
      await correct.run(["start", "opswarden"]);
      await waitHealthy(correct.baseURL + "/health/live");
      const revokedSession = await this.request.get(
        `${correct.baseURL}/api/v1/me`,
        { headers: this.headers(restoredJWT) },
      );
      if (revokedSession.status() !== 401) throw new Error("restored browser session was not revoked");
      const revokedAgent = await mcpTransport(
        this.request,
        correct.baseURL,
        restoredTokenBody.token,
      );
      if (revokedAgent.status() !== 401) throw new Error("restored Agent Token was not revoked");
      capturedErrors.session = await revokedSession.json();
      capturedErrors.agent = await revokedAgent.json();
    } finally {
      await captureComposeLogs(correct, "restore-compose.log");
      await captureComposeLogs(wrong, "restore-wrong-compose.log");
      await correct.run(["down", "--volumes", "--remove-orphans"]).catch(() => undefined);
      await wrong.run(["down", "--volumes", "--remove-orphans"]).catch(() => undefined);
      await writeFile(
        resolve(artifacts, "errors/captured-errors.json"),
        JSON.stringify(capturedErrors),
        { mode: 0o600 },
      );
    }
  }
}

type RestoreLayout = {
  baseURL: string;
  dataDir: string;
  run(args: string[]): Promise<CommandResult>;
};

async function prepareRestoreLayout(
  name: "restore" | "restore-wrong",
  backup: string,
  key: string,
  project: string,
): Promise<RestoreLayout> {
  if (!/^opswarden-e2e-[a-z0-9]{8}(?:-wrong)?$/u.test(project)) {
    throw new Error("invalid isolated Compose project name");
  }
  const directory = resolve(runtime, name);
  const state = resolve(directory, "state-root");
  const dataDir = resolve(state, "data");
  const keyPath = resolve(directory, "master.key");
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await mkdir(resolve(state, "backups"), { recursive: true, mode: 0o700 });
  await mkdir(resolve(directory, "caddy-data"), { recursive: true, mode: 0o700 });
  await mkdir(resolve(directory, "caddy-config"), { recursive: true, mode: 0o700 });
  await copyFile(backup, resolve(dataDir, "opswarden.db"));
  await writeFile(keyPath, key, { mode: 0o600 });
  await chmod(keyPath, 0o600);
  const envPath = resolve(directory, "restore.env");
  const overridePath = resolve(directory, "restore.override.yaml");
  await writeFile(envPath, [
    `OPSWARDEN_VERSION=${imageVersion}`,
    `OPSWARDEN_REVISION=${imageVersion.slice(4)}`,
    "SOURCE_DATE_EPOCH=0",
    `OPSWARDEN_STATE_PATH=${state}`,
    `OPSWARDEN_MASTER_KEY_PATH=${keyPath}`,
    `CADDY_DATA_PATH=${directory}/caddy-data`,
    `CADDY_CONFIG_PATH=${directory}/caddy-config`,
    "OPSWARDEN_HOSTNAME=e2e.invalid",
    "OPSWARDEN_TLS_EMAIL=e2e@example.invalid",
    `OPSWARDEN_BACKEND_SUBNET=${backendSubnet}`,
    `OPSWARDEN_APP_IP=${appIP}`,
    `OPSWARDEN_CADDY_IP=${caddyIP}`,
  ].join("\n") + "\n", { mode: 0o600 });
  await writeFile(overridePath, [
    "services:",
    "  opswarden:",
    "    ports:",
    `      - "127.0.0.1:${restorePort}:8080"`,
    "    networks:",
    "      backend:",
    `        ipv4_address: ${appIP}`,
    "      edge: {}",
  ].join("\n") + "\n", { mode: 0o600 });
  const compose = [
    "compose", "-p", project,
    "--env-file", envPath,
    "-f", resolve(root, "deploy/compose.yaml"),
    "-f", overridePath,
  ];
  return {
    baseURL: `http://127.0.0.1:${restorePort}`,
    dataDir,
    run: (args: string[]) => runCommand("docker", [...compose, ...args], {
      timeoutMs: 60_000,
    }),
  };
}

async function captureComposeLogs(layout: RestoreLayout, filename: string) {
  const result = await layout.run(["logs", "--no-color"]).catch(() => ({
    stdout: "",
    stderr: "bounded Compose log capture failed\n",
  }));
  await writeFile(
    resolve(artifacts, "logs", filename),
    `${result.stdout}${result.stderr}`,
    { mode: 0o600 },
  );
}

function mcpTransport(
  request: APIRequestContext,
  baseURL: string,
  token: string,
) {
  return request.post(baseURL + "/mcp", {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    },
    data: { jsonrpc: "2.0", id: "revocation-check", method: "tools/list", params: {} },
  });
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
