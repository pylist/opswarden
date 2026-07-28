import { useRef, useState, type FormEvent } from "react";

import { ApiClient, ApiError, formatApiError } from "../api/client";
import type { BootstrapResponse } from "../api/types";

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateTOTPSeed() {
  const bytes = new Uint8Array(20);
  globalThis.crypto.getRandomValues(bytes);
  let bits = 0;
  let value = 0;
  let result = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += base32Alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    result += base32Alphabet[(value << (5 - bits)) & 31];
  }
  bytes.fill(0);
  return result;
}

export function SetupPage({
  onLogin,
}: {
  onLogin: (completed: boolean, unavailable?: boolean) => void;
}) {
  const client = useRef(new ApiClient()).current;
  const submitting = useRef(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpSeed, setTotpSeed] = useState(generateTOTPSeed);
  const [seedVisible, setSeedVisible] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function clearEnrollment() {
    setPassword("");
    setTotpSeed("");
    setSeedVisible(false);
  }

  function leaveSetup() {
    const completed = recoveryCodes.length > 0;
    setRecoveryCodes([]);
    clearEnrollment();
    onLogin(completed);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    submitting.current = true;
    setBusy(true);
    setError("");
    const submittedSeed = totpSeed;
    try {
      const result = await client.publicRequest<BootstrapResponse>(
        "/api/v1/bootstrap/initial-owner",
        {
          method: "POST",
          body: { email, password, totpSeed: submittedSeed },
        },
      );
      if (
        typeof result.userId !== "string" ||
        !Array.isArray(result.recoveryCodes) ||
        !result.recoveryCodes.every(
          (code) => typeof code === "string" && code.length > 0,
        )
      ) {
        throw new ApiError("INVALID_RESPONSE", "", 502);
      }
      clearEnrollment();
      setRecoveryCodes(result.recoveryCodes);
    } catch (reason) {
      setPassword("");
      if (reason instanceof ApiError && reason.code === "VERSION_CONFLICT") {
        clearEnrollment();
        onLogin(false, true);
        return;
      }
      setTotpSeed(generateTOTPSeed());
      setSeedVisible(false);
      setError(
        reason instanceof ApiError && reason.code === "PERMISSION_DENIED"
          ? supportMessage(
              "初始化只允许从服务器本机或已配置的内部网络访问。",
              reason.requestId,
            )
          : formatApiError(reason),
      );
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }

  async function copySeed() {
    try {
      await navigator.clipboard.writeText(totpSeed);
    } catch {
      setError("无法访问剪贴板，请显示后手动录入。");
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-card setup-card" aria-labelledby="setup-title">
        <p className="eyebrow">仅限本机初始化</p>
        <h1 id="setup-title">设置初始管理员</h1>
        {!recoveryCodes.length ? (
          <>
            <p className="muted">
              OpsWarden 已使用 Web Crypto 生成 160 位随机 TOTP 种子。将它手动录入
              验证器并离线保存；种子不会进入地址栏或浏览器存储。
            </p>
            <form onSubmit={submit}>
              <label htmlFor="setup-email">管理员邮箱</label>
              <input
                id="setup-email"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
              <label htmlFor="setup-password">管理员密码</label>
              <input
                id="setup-password"
                type="password"
                autoComplete="new-password"
                minLength={12}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
              <label htmlFor="totp-seed">TOTP 种子</label>
              <div className="seed-field">
                <input
                  id="totp-seed"
                  type={seedVisible ? "text" : "password"}
                  autoComplete="off"
                  spellCheck={false}
                  value={totpSeed}
                  readOnly
                />
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => setSeedVisible((visible) => !visible)}
                >
                  {seedVisible ? "隐藏种子" : "显示种子"}
                </button>
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => void copySeed()}
                >
                  复制种子
                </button>
              </div>
              <button className="primary-button" disabled={busy} type="submit">
                {busy ? "正在创建…" : "创建初始管理员"}
              </button>
              <button className="text-button" type="button" onClick={leaveSetup}>
                返回登录
              </button>
            </form>
          </>
        ) : (
          <div aria-live="polite">
            <h2>保存恢复码</h2>
            <p className="warning-copy">
              恢复码只在此显示一次。请立即离线保存，不要复制到聊天或工单。
              登录后，系统会引导你创建初始空间。
            </p>
            <ul className="recovery-codes" aria-label="一次性恢复码">
              {recoveryCodes.map((code) => <li key={code}>{code}</li>)}
            </ul>
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
              />
              我已离线保存全部恢复码
            </label>
            <button
              className="primary-button"
              disabled={!confirmed}
              type="button"
              onClick={leaveSetup}
            >
              前往登录
            </button>
          </div>
        )}
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
    </main>
  );
}

function supportMessage(message: string, requestId: string) {
  return requestId ? `${message}（请求编号：${requestId}）` : message;
}
