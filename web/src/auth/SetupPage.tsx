import { useState, type FormEvent } from "react";

import { ApiClient } from "../api/client";
import type { BootstrapResponse } from "../api/types";

export function SetupPage({
  onLogin,
}: {
  onLogin: (completed: boolean) => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpSeed, setTotpSeed] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function leaveSetup() {
    const completed = recoveryCodes.length > 0;
    setRecoveryCodes([]);
    setPassword("");
    setTotpSeed("");
    onLogin(completed);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await new ApiClient().publicRequest<BootstrapResponse>(
        "/api/v1/bootstrap/initial-owner",
        {
          method: "POST",
          body: { email, password, totpSeed },
        },
      );
      setPassword("");
      setTotpSeed("");
      setRecoveryCodes(result.recoveryCodes);
    } catch (reason) {
      setPassword("");
      const message = String(reason);
      setError(
        message.includes("PERMISSION_DENIED") || message.includes("权限")
          ? "初始化只允许从服务器本机或已配置的内部网络访问。"
          : message,
      );
    } finally {
      setBusy(false);
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
              使用验证器生成一个 Base32 TOTP 种子并离线保存。服务端会安全验证
              初始化是否仍被允许；已经完成初始化时不会覆盖现有管理员。
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
              <input
                id="totp-seed"
                autoComplete="off"
                spellCheck={false}
                value={totpSeed}
                onChange={(event) => setTotpSeed(event.target.value)}
                required
              />
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
