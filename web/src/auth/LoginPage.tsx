import { useState, type FormEvent } from "react";

import { formatApiError, SessionSupersededError } from "../api/client";
import { useAuth } from "./AuthProvider";

export function LoginPage({
  onSetup,
  canSetup,
  setupNotice,
}: {
  onSetup: () => void;
  canSetup: boolean;
  setupNotice?: string;
}) {
  const { beginLogin, completeLogin, status } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [secondFactor, setSecondFactor] = useState("");
  const [factorMode, setFactorMode] = useState<"totp" | "recovery">("totp");
  const [error, setError] = useState("");
  const busy = status === "authenticating";

  async function submitPassword(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const challenge = await beginLogin(email, password);
      setPassword("");
      setChallengeId(challenge.challengeId);
    } catch (reason) {
      setPassword("");
      if (!(reason instanceof SessionSupersededError)) {
        setError(formatApiError(reason));
      }
    }
  }

  async function submitSecondFactor(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await completeLogin(challengeId, secondFactor);
      setSecondFactor("");
      setChallengeId("");
    } catch (reason) {
      setSecondFactor("");
      if (!(reason instanceof SessionSupersededError)) {
        setError(formatApiError(reason));
      }
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-card" aria-labelledby="login-title">
        <div className="brand-mark" aria-hidden="true">O</div>
        <p className="eyebrow">内部凭据管理</p>
        <h1 id="login-title">登录 OpsWarden</h1>
        <p className="muted">
          JWT 只保存在当前页面内存中。刷新或关闭页面后需要重新登录。
        </p>

        {challengeId ? (
          <form onSubmit={submitSecondFactor}>
            <fieldset className="factor-modes">
              <legend>验证方式</legend>
              <label>
                <input
                  type="radio"
                  name="factor-mode"
                  checked={factorMode === "totp"}
                  onChange={() => {
                    setFactorMode("totp");
                    setSecondFactor("");
                  }}
                />
                动态验证码
              </label>
              <label>
                <input
                  type="radio"
                  name="factor-mode"
                  checked={factorMode === "recovery"}
                  onChange={() => {
                    setFactorMode("recovery");
                    setSecondFactor("");
                  }}
                />
                恢复码
              </label>
            </fieldset>
            <label htmlFor="second-factor">
              {factorMode === "totp" ? "动态验证码" : "恢复码"}
            </label>
            <input
              id="second-factor"
              autoComplete="one-time-code"
              inputMode={factorMode === "totp" ? "numeric" : "text"}
              autoCapitalize={factorMode === "recovery" ? "characters" : "off"}
              value={secondFactor}
              onChange={(event) => setSecondFactor(event.target.value)}
              required
              autoFocus
            />
            <button className="primary-button" disabled={busy} type="submit">
              {busy ? "正在验证…" : "登录"}
            </button>
            <button
              className="text-button"
              type="button"
              onClick={() => {
                setChallengeId("");
                setSecondFactor("");
                setError("");
              }}
            >
              返回密码登录
            </button>
          </form>
        ) : (
          <form onSubmit={submitPassword}>
            <label htmlFor="email">邮箱</label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
              autoFocus
            />
            <label htmlFor="password">密码</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
            <button className="primary-button" disabled={busy} type="submit">
              {busy ? "正在验证…" : "继续"}
            </button>
          </form>
        )}

        {error && <p className="form-error" role="alert">{error}</p>}
        {!challengeId && canSetup && (
          <div className="auth-footer">
            <span>首次在本机运行？</span>
            <button className="text-button" type="button" onClick={onSetup}>
              初始化管理员
            </button>
          </div>
        )}
        {!challengeId && setupNotice && (
          <p className="setup-notice">{setupNotice}</p>
        )}
      </section>
    </main>
  );
}
