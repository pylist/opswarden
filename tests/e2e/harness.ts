import { createHmac, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  expect,
  type APIRequestContext,
  type APIResponse,
  type Locator,
  type Page,
} from "@playwright/test";
import { HumanRequestBudget } from "./request-budget.mjs";

const root = resolve(import.meta.dirname, "../..");
const runtime = resolve(process.env.OPSWARDEN_E2E_RUNTIME_DIR ?? "");
const artifacts = resolve(process.env.OPSWARDEN_E2E_ARTIFACT_DIR ?? "");
const secretFile = resolve(process.env.OPSWARDEN_E2E_SECRET_FILE ?? "");
const restorePort = Number(process.env.OPSWARDEN_E2E_RESTORE_PORT);
const composeProject = process.env.OPSWARDEN_E2E_PROJECT ?? "";
const backendSubnet = process.env.OPSWARDEN_E2E_BACKEND_SUBNET ?? "";
const appIP = process.env.OPSWARDEN_E2E_APP_IP ?? "";
const caddyIP = process.env.OPSWARDEN_E2E_CADDY_IP ?? "";
const restoreBackendSubnet = process.env.OPSWARDEN_E2E_RESTORE_BACKEND_SUBNET ?? "";
const restoreAppIP = process.env.OPSWARDEN_E2E_RESTORE_APP_IP ?? "";
const restoreCaddyIP = process.env.OPSWARDEN_E2E_RESTORE_CADDY_IP ?? "";
const imageVersion = process.env.OPSWARDEN_E2E_IMAGE_VERSION ?? "";
const caddySourceImage =
  "caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d";
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
  !/^172\.2[0-7]\.\d{1,3}\.0\/29$/u.test(restoreBackendSubnet) ||
  restoreAppIP.replace(/\.2$/u, ".0/29") !== restoreBackendSubnet ||
  restoreCaddyIP.replace(/\.3$/u, ".0/29") !== restoreBackendSubnet ||
  restoreBackendSubnet === backendSubnet ||
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
    let closedCode: number | null | undefined;
    let pipeComplete = false;
    let settled = false;
    const succeedIfComplete = () => {
      if (!settled && closedCode === 0 && pipeComplete) {
        settled = true;
        resolveWrite();
      }
    };
    const refuse = () => {
      if (!settled) {
        settled = true;
        rejectWrite(new Error("protected MCP failure artifact writer refused output"));
      }
    };
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      refuse();
    }, 10_000);
    child.on("error", () => {
      clearTimeout(timeout);
      refuse();
    });
    child.stdin.on("error", () => {
      clearTimeout(timeout);
      refuse();
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      closedCode = code;
      if (code !== 0) refuse();
      else succeedIfComplete();
    });
    child.stdin.end(body, (error?: Error | null) => {
      if (error) {
        refuse();
        return;
      }
      pipeComplete = true;
      succeedIfComplete();
    });
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

  async assertConcealedFailureAuditRows() {
    const database = resolve(runtime, "state-root/data/opswarden.db");
    const script = [
      "import json,sqlite3,sys",
      "db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)",
      "rows=db.execute(\"SELECT COALESCE(space_id,''),COALESCE(entity_id,''),CAST(metadata_json AS TEXT) FROM audit_events WHERE action='credential.read' AND json_extract(metadata_json,'$.success')=0 AND json_extract(metadata_json,'$.error_code')='NOT_FOUND' ORDER BY rowid\").fetchall()",
      "db.close()",
      "print(json.dumps(rows,separators=(',',':')))",
    ].join(";");
    const output = await runCommand("/usr/bin/python3", [
      "-I", "-c", script, database,
    ]);
    const rows = JSON.parse(output.stdout) as [string, string, string][];
    if (
      rows.length < 2 ||
      rows.slice(-2).some(([spaceID, resourceID, metadata]) =>
        spaceID !== "" ||
        resourceID !== "" ||
        !metadata.includes('"success":false') ||
        metadata.includes(this.state.otherCredentialID)
      )
    ) {
      throw new Error("concealed credential failures lack normalized database audit rows");
    }
    await writeFile(
      resolve(artifacts, "audit/failure-audit-evidence.json"),
      JSON.stringify(rows.slice(-2)),
      { mode: 0o600 },
    );
  }
}

export class E2EHarness extends APIHarness {
  private readonly requestBudget = new HumanRequestBudget();
  private uiSession = "ui-session-1";

  private constructor(
    request: APIRequestContext,
    state: Control,
    private readonly page: Page,
  ) {
    super(request, state);
    page.on("response", (response) => {
      this.requestBudget.record(
        this.uiSession,
        response.request().method(),
        response.url(),
        response.status(),
        response.headers()["retry-after"] ?? null,
      );
    });
  }

  static async startWithPage(page: Page, request: APIRequestContext) {
    const state = await control();
    const harness = new E2EHarness(request, state, page);
    await harness.guarded(harness.loginWithRecoveryCode(), "initial UI login");
    return harness;
  }

  private async loginWithRecoveryCode() {
    const state = this.state;
    const page = this.page;
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
  }

  private async loginWithTOTPAsNewSession() {
    await this.page.getByRole("button", { name: "退出", exact: true }).click();
    await this.page.getByLabel("邮箱").fill(this.state.email);
    await this.page.getByLabel("密码").fill(this.state.password);
    await this.page.getByRole("button", { name: "继续" }).click();
    // Setup verified a TOTP moments earlier. Cross a counter boundary so the
    // production replay guard sees a fresh code for this real second login.
    const nextCounterDelay = 30_000 - (Date.now() % 30_000) + 500;
    await new Promise((resolveWait) => setTimeout(resolveWait, nextCounterDelay));
    await this.page.getByRole("textbox", { name: "动态验证码" }).fill(
      totp(this.state.loginTOTPSeed),
    );
    const loginResponse = this.page.waitForResponse((response) =>
      response.url().endsWith("/api/v1/auth/login/complete") &&
      response.request().method() === "POST"
    );
    await this.page.getByRole("button", { name: "登录", exact: true }).click();
    const completed = await loginResponse;
    if (!completed.ok()) {
      throw new Error(`second UI login failed: status=${completed.status()}`);
    }
    const loginBody = await completed.json();
    await appendJWTPatterns(loginBody.token);
    this.uiSession = "ui-session-2";
    await this.page.getByLabel("当前空间").selectOption(this.state.primarySpaceID);
    await this.page.getByRole("link", { name: "凭据库" }).click();
    await this.page.getByRole("heading", { name: "凭据库" }).waitFor();
  }

  private async guarded<T>(action: Promise<T>, label: string): Promise<T> {
    let active = true;
    const rateLimit = this.requestBudget.failure.then((failure) => {
      if (!active) return new Promise<T>(() => {});
      throw new Error(`${label} aborted: ${failure.message}`);
    });
    try {
      return await Promise.race([action, rateLimit]);
    } finally {
      active = false;
    }
  }

  async createCredentialInUI() {
    return this.guarded(this.createCredentialInUIUnsafe(), "Hermes handoff credential creation");
  }

  private async createCredentialInUIUnsafe() {
    await this.page.getByRole("link", { name: "凭据库" }).click();
    await this.page.getByRole("heading", { name: "凭据库" }).waitFor();
    await this.page.getByText("正在加载凭据元数据…").waitFor({ state: "detached" });
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

  async exerciseReactCredentialAndAssetCRUD() {
    return this.guarded(
      this.exerciseReactCredentialAndAssetCRUDUnsafe(),
      "five-type React credential and asset CRUD",
    );
  }

  private async exerciseReactCredentialAndAssetCRUDUnsafe() {
    const asset = await this.createAssetInUI();
    const fixtures: Array<{
      type: string;
      name: string;
      fields: Record<string, string>;
    }> = [
      {
        type: "login",
        name: "ui-login",
        fields: {
          "网址": "https://ui-login.invalid",
          "用户名": "ui-login-user",
          "密码": this.state.credentialPassword,
        },
      },
      {
        type: "api_token",
        name: "ui-api-token",
        fields: { "服务": "ui-service", "Token": this.state.apiToken },
      },
      {
        type: "ssh_key",
        name: "ui-ssh-key",
        fields: {
          "用户名": "ui-ssh-user",
          "私钥": "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            this.state.credentialPassword +
            "\n-----END OPENSSH PRIVATE KEY-----",
        },
      },
      {
        type: "database",
        name: "ui-database",
        fields: {
          "数据库引擎": "postgresql",
          "主机": "db-ui.invalid",
          "用户名": "ui-db-user",
          "密码": this.state.credentialPassword,
        },
      },
      {
        type: "totp",
        name: "ui-totp",
        fields: {
          "签发方": "OpsWarden UI",
          "账号": this.state.email,
          "Seed": this.state.loginTOTPSeed,
        },
      },
    ];
    const first = fixtures[0];
    await this.credentialCRUDInUI(first.type, first.name, first.fields, asset.id);
    await this.assertRecycleBinRows([`${first.name}-updated`]);
    await this.updateAndDeleteAssetInUI(asset.id, asset.name);

    await this.loginWithTOTPAsNewSession();
    const secondSessionDeleted: string[] = [];
    for (const fixture of fixtures.slice(1)) {
      await this.credentialCRUDInUI(fixture.type, fixture.name, fixture.fields, "");
      secondSessionDeleted.push(`${fixture.name}-updated`);
    }
    await this.assertRecycleBinRows(secondSessionDeleted);
  }

  private async createAssetInUI() {
    await this.page.getByRole("link", { name: "资产", exact: true }).click();
    await this.page.getByRole("heading", { name: "资产", level: 1 }).waitFor();
    await this.page.getByText("正在加载资产…").waitFor({ state: "detached" });
    await this.page.getByRole("button", { name: "新建资产" }).click();
    const dialog = this.page.getByRole("dialog", { name: "新建资产" });
    const name = "ui-asset";
    await dialog.getByLabel("资产名称").fill(name);
    await dialog.getByLabel("主机名 / 域名").fill("ui-asset.invalid");
    await dialog.getByLabel("环境").fill("e2e");
    const response = this.page.waitForResponse((candidate) =>
      candidate.request().method() === "POST" &&
      candidate.url().endsWith(`/spaces/${this.state.primarySpaceID}/assets`)
    );
    await dialog.getByRole("button", { name: "保存" }).click();
    const assetResponse = await response;
    const rawBody = await assetResponse.text();
    const body = JSON.parse(rawBody);
    if (!assetResponse.ok()) {
      await writeFile(
        resolve(artifacts, "errors/ui-asset-failure.json"),
        rawBody,
        { mode: 0o600 },
      );
      throw new Error(
        `asset create failed: status=${assetResponse.status()} code=${body?.error?.code ?? ""}`,
      );
    }
    await dialog.waitFor({ state: "detached" });
    await this.page.getByRole("button", { name }).waitFor();
    return { id: body.id as string, name };
  }

  private async credentialCRUDInUI(
    type: string,
    name: string,
    fields: Record<string, string>,
    assetID: string,
  ) {
    await this.page.getByRole("link", { name: "凭据库" }).click();
    await this.page.getByRole("heading", { name: "凭据库" }).waitFor();
    await this.page.getByText("正在加载凭据元数据…").waitFor({ state: "detached" });
    await this.page.getByRole("button", { name: "新建凭据" }).click();
    const createDialog = this.page.getByRole("dialog", { name: "新建凭据" });
    await createDialog.getByLabel("显示名称").fill(name);
    await createDialog.getByLabel("凭据类型").selectOption(type);
    for (const [label, value] of Object.entries(fields)) {
      await createDialog.getByLabel(label, { exact: true }).fill(value);
    }
    if (assetID) await createDialog.getByLabel("关联资产").fill(assetID);
    await createDialog.getByRole("button", { name: "保存" }).click();
    await this.page.getByRole("button", { name, exact: true }).waitFor();

    await this.page.getByRole("button", { name, exact: true }).click();
    await this.page.getByRole("button", { name: "显示", exact: true }).click();
    const editCredential = this.page.getByRole("button", { name: "编辑凭据" });
    await expect(editCredential).toBeEnabled({ timeout: 10_000 });
    await editCredential.click();
    const updatedName = `${name}-updated`;
    await this.page.getByLabel("显示名称").fill(updatedName);
    await this.page.getByLabel("变更原因").fill("React E2E full CRUD");
    await this.page.getByRole("button", { name: "保存", exact: true }).click();
    await this.page.getByRole("button", { name: updatedName, exact: true }).waitFor();

    if (assetID) {
      await this.page.getByRole("button", { name: updatedName, exact: true }).click();
      await this.page.getByRole("button", { name: assetID, exact: true }).click();
      await this.page.getByRole("heading", { name: "ui-asset", exact: true }).waitFor();
      await this.page.getByRole("button", { name: new RegExp(updatedName) }).click();
      await this.page.getByRole("heading", { name: updatedName, exact: true }).waitFor();
      await this.page.getByRole("button", { name: "显示", exact: true }).click();
      const editLinkedCredential = this.page.getByRole("button", { name: "编辑凭据" });
      await expect(editLinkedCredential).toBeEnabled({ timeout: 10_000 });
      await editLinkedCredential.click();
      await this.page.getByLabel("关联资产").fill("");
      await this.page.getByLabel("变更原因").fill("React E2E unlink");
      await this.page.getByRole("button", { name: "保存", exact: true }).click();
      await this.page.getByRole("button", { name: updatedName, exact: true }).waitFor();
      await this.page.getByRole("link", { name: "资产", exact: true }).click();
      await this.page.getByRole("button", { name: "ui-asset", exact: true }).click();
      await this.page.getByRole("heading", { name: "ui-asset", exact: true }).waitFor();
      await this.page.getByText("尚未关联凭据。").waitFor();
      await this.page.getByRole("link", { name: "凭据库" }).click();
    }

    await this.page.getByRole("button", { name: updatedName, exact: true }).click();
    await this.page.getByRole("button", { name: "移至回收站" }).click();
    await this.page.getByLabel("输入凭据名称以确认").fill(updatedName);
    await this.page.getByRole("button", { name: "确认删除" }).click();
    await this.page.getByRole("button", { name: updatedName, exact: true }).waitFor({
      state: "detached",
    });
  }

  private async assertRecycleBinRows(updatedNames: string[]) {
    await this.page.getByRole("button", { name: "回收站" }).click();
    for (const updatedName of updatedNames) {
      await this.page.getByRole("row").filter({ hasText: updatedName }).waitFor();
    }
    await this.page.getByRole("button", { name: "返回凭据列表" }).click();
  }

  private async updateAndDeleteAssetInUI(assetID: string, originalName: string) {
    await this.page.getByRole("link", { name: "资产", exact: true }).click();
    await this.page.getByRole("button", { name: originalName, exact: true }).click();
    await this.page.getByRole("button", { name: "编辑资产" }).click();
    const updatedName = `${originalName}-updated`;
    await this.page.getByLabel("资产名称").fill(updatedName);
    await this.page.getByLabel("备注").fill(`React E2E asset ${assetID}`);
    await this.page.getByRole("button", { name: "保存", exact: true }).click();
    await this.page.getByRole("heading", { name: updatedName, exact: true }).waitFor();
    await this.page.getByRole("button", { name: "删除资产" }).click();
    await this.page.getByLabel("输入资产名称以确认").fill(updatedName);
    await this.page.getByRole("button", { name: "确认删除" }).click();
    await this.page.getByRole("button", { name: updatedName, exact: true }).waitFor({
      state: "detached",
    });
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
    await this.guarded((async () => {
      await this.page.getByRole("link", { name: "概览" }).click();
      await this.page.getByRole("link", { name: "凭据库" }).click();
      await this.page.getByRole("button", { name: "回收站" }).click();
    })(), "Hermes deletion recycle-bin refresh");
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
    this.requestBudget.assertWithinLimits();
    await writeFile(
      resolve(artifacts, "audit/ui-request-budget.json"),
      JSON.stringify(this.requestBudget.snapshot()),
      { mode: 0o600 },
    );
    return ["credential.create", "credential.read", "credential.update", "credential.delete"]
      .filter((action) => actions.includes(action));
  }
}

export class RestoreHarness extends APIHarness {
  static async start(request: APIRequestContext) {
    return new RestoreHarness(request, await control());
  }

  async backupRestoreAndRevoke() {
    const db = resolve(runtime, "state-root/data/opswarden.db");
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

async function setRestoreIdentity(directory: string, delegated: boolean) {
  const uid = delegated ? 10001 : process.getuid();
  const gid = delegated ? 10001 : process.getgid();
  const keyMode = delegated ? "0400" : "0600";
  await runCommand("docker", [
    "run", "--rm", "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
    "--security-opt", "no-new-privileges:true",
    "--mount", `type=bind,src=${directory},dst=/work`,
    "--entrypoint", "/bin/sh",
    caddySourceImage,
    "-c",
    'chown "$1:$2" /work/master.key && chmod "$3" /work/master.key && chown -R "$1:$2" /work/state-root && chmod 0700 /work/state-root /work/state-root/data /work/state-root/backups',
    "opswarden-e2e-restore",
    String(uid), String(gid), keyMode,
  ]);
}

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
    `OPSWARDEN_BACKEND_SUBNET=${restoreBackendSubnet}`,
    `OPSWARDEN_APP_IP=${restoreAppIP}`,
    `OPSWARDEN_CADDY_IP=${restoreCaddyIP}`,
  ].join("\n") + "\n", { mode: 0o600 });
  await writeFile(overridePath, [
    "services:",
    "  opswarden:",
    "    ports:",
    `      - "127.0.0.1:${restorePort}:8080"`,
    "    networks:",
    "      backend:",
    `        ipv4_address: ${restoreAppIP}`,
    "      edge: {}",
  ].join("\n") + "\n", { mode: 0o600 });
  const compose = [
    "compose", "-p", project,
    "--env-file", envPath,
    "-f", resolve(root, "deploy/compose.yaml"),
    "-f", overridePath,
  ];
  let delegated = false;
  return {
    baseURL: `http://127.0.0.1:${restorePort}`,
    dataDir,
    run: async (args: string[]) => {
      if (args[0] === "up" && !delegated) {
        await setRestoreIdentity(directory, true);
        delegated = true;
      }
      try {
        return await runCommand("docker", [...compose, ...args], {
          timeoutMs: 60_000,
        });
      } finally {
        if (args[0] === "down" && delegated) {
          await setRestoreIdentity(directory, false);
          delegated = false;
        }
      }
    },
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
