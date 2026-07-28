import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { ApiClient } from "../api/client";
import type { LoginChallenge, Me, TokenResponse } from "../api/types";

type AuthStatus = "anonymous" | "authenticating" | "authenticated";

type AuthContextValue = {
  status: AuthStatus;
  principal: Me | null;
  api: ApiClient;
  beginLogin: (email: string, password: string) => Promise<LoginChallenge>;
  completeLogin: (
    challengeId: string,
    secondFactor: string,
  ) => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const sessionRef = useRef<{ token: string; expiresAt: number } | null>(null);
  const [status, setStatus] = useState<AuthStatus>("anonymous");
  const [principal, setPrincipal] = useState<Me | null>(null);

  const clearSession = useCallback(() => {
    sessionRef.current = null;
    setPrincipal(null);
    setStatus("anonymous");
  }, []);

  const apiRef = useRef<ApiClient | null>(null);
  if (!apiRef.current) {
    apiRef.current = new ApiClient({
      readSession: () => sessionRef.current,
      replaceSession: (token, expiresAt) => {
        sessionRef.current = { token, expiresAt };
      },
      clearSession,
    });
  }
  const api = apiRef.current;

  const beginLogin = useCallback(
    async (email: string, password: string) => {
      setStatus("authenticating");
      try {
        const challenge = await api.publicRequest<LoginChallenge>(
          "/api/v1/auth/login/begin",
          { method: "POST", body: { email, password } },
        );
        setStatus("anonymous");
        return challenge;
      } catch (error) {
        setStatus("anonymous");
        throw error;
      }
    },
    [api],
  );

  const completeLogin = useCallback(
    async (challengeId: string, secondFactor: string) => {
      setStatus("authenticating");
      try {
        const token = await api.publicRequest<TokenResponse>(
          "/api/v1/auth/login/complete",
          { method: "POST", body: { challengeId, secondFactor } },
        );
        sessionRef.current = {
          token: token.token,
          expiresAt: Date.parse(token.expiresAt),
        };
        const current = await api.request<Me>("/api/v1/me");
        setPrincipal(current);
        setStatus("authenticated");
      } catch (error) {
        clearSession();
        throw error;
      }
    },
    [api, clearSession],
  );

  const logout = useCallback(async () => {
    try {
      await api.request("/api/v1/auth/logout", { method: "POST" });
    } finally {
      clearSession();
    }
  }, [api, clearSession]);

  const value = useMemo(
    () => ({
      status,
      principal,
      api,
      beginLogin,
      completeLogin,
      logout,
    }),
    [api, beginLogin, completeLogin, logout, principal, status],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth 必须在 AuthProvider 内使用");
  }
  return value;
}
