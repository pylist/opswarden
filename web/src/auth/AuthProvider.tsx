import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import {
  ApiClient,
  ApiError,
  MemorySessionController,
  SessionSupersededError,
  parseTokenExpiry,
  type SessionSnapshot,
} from "../api/client";
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

type AuthOperation = {
  generation: number;
  controller: AbortController;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const sessionsRef = useRef<MemorySessionController | null>(null);
  if (!sessionsRef.current) {
    sessionsRef.current = new MemorySessionController();
  }
  const sessions = sessionsRef.current;
  const apiRef = useRef<ApiClient | null>(null);
  if (!apiRef.current) {
    apiRef.current = new ApiClient(sessions);
  }
  const api = apiRef.current;

  const [status, setStatus] = useState<AuthStatus>("anonymous");
  const [principal, setPrincipal] = useState<Me | null>(null);
  const expiryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const operationCounter = useRef(0);
  const operation = useRef<AuthOperation | null>(null);

  const cancelOperation = useCallback(() => {
    operation.current?.controller.abort();
    operation.current = null;
    operationCounter.current += 1;
  }, []);

  const beginOperation = useCallback(() => {
    cancelOperation();
    const next = {
      generation: operationCounter.current,
      controller: new AbortController(),
    };
    operation.current = next;
    return next;
  }, [cancelOperation]);

  const operationIsCurrent = useCallback((candidate: AuthOperation) => {
    return (
      operation.current === candidate &&
      operation.current.generation === candidate.generation &&
      !candidate.controller.signal.aborted
    );
  }, []);

  useEffect(() => {
    const clearTimer = () => {
      if (expiryTimer.current !== null) {
        clearTimeout(expiryTimer.current);
        expiryTimer.current = null;
      }
    };
    const unsubscribe = sessions.subscribe((snapshot) => {
      clearTimer();
      if (!snapshot) {
        setPrincipal(null);
        setStatus("anonymous");
        return;
      }
      expiryTimer.current = setTimeout(() => {
        sessions.clearIfCurrent(snapshot);
      }, Math.max(0, snapshot.expiresAt - Date.now()));
    });
    return () => {
      unsubscribe();
      clearTimer();
      cancelOperation();
      sessions.clearIfCurrent();
    };
  }, [cancelOperation, sessions]);

  const beginLogin = useCallback(
    async (email: string, password: string) => {
      const auth = beginOperation();
      sessions.clearIfCurrent();
      setPrincipal(null);
      setStatus("authenticating");
      try {
        const challenge = await api.publicRequest<LoginChallenge>(
          "/api/v1/auth/login/begin",
          {
            method: "POST",
            body: { email, password },
            signal: auth.controller.signal,
          },
        );
        if (
          typeof challenge.challengeId !== "string" ||
          challenge.challengeId.length === 0 ||
          !Number.isFinite(Date.parse(challenge.expiresAt))
        ) {
          throw new ApiError("INVALID_RESPONSE", "", 502);
        }
        if (!operationIsCurrent(auth)) {
          throw new SessionSupersededError();
        }
        setStatus("anonymous");
        return challenge;
      } catch (error) {
        if (operationIsCurrent(auth)) {
          setStatus("anonymous");
        }
        throw error;
      }
    },
    [api, beginOperation, operationIsCurrent, sessions],
  );

  const completeLogin = useCallback(
    async (challengeId: string, secondFactor: string) => {
      const auth = beginOperation();
      sessions.clearIfCurrent();
      setPrincipal(null);
      setStatus("authenticating");
      let allocated: SessionSnapshot | null = null;
      try {
        const response = await api.publicRequest<TokenResponse>(
          "/api/v1/auth/login/complete",
          {
            method: "POST",
            body: { challengeId, secondFactor },
            signal: auth.controller.signal,
          },
        );
        if (
          !operationIsCurrent(auth) ||
          typeof response.token !== "string" ||
          response.token.length === 0
        ) {
          throw new SessionSupersededError();
        }
        allocated = sessions.allocate(
          response.token,
          parseTokenExpiry(response.expiresAt),
        );
        const current = await api.request<Me>("/api/v1/me", {
          signal: auth.controller.signal,
        });
        if (
          typeof current.userId !== "string" ||
          current.userId.length === 0 ||
          typeof current.systemRole !== "string" ||
          !Number.isFinite(Date.parse(current.issuedAt))
        ) {
          throw new ApiError("INVALID_RESPONSE", "", 502);
        }
        if (
          !operationIsCurrent(auth) ||
          !sessions.isCurrentLineage(allocated)
        ) {
          throw new SessionSupersededError();
        }
        setPrincipal(current);
        setStatus("authenticated");
      } catch (error) {
        if (operationIsCurrent(auth)) {
          if (allocated) sessions.clearLineageIfCurrent(allocated);
          setPrincipal(null);
          setStatus("anonymous");
        }
        throw error;
      }
    },
    [api, beginOperation, operationIsCurrent, sessions],
  );

  const logout = useCallback(async () => {
    cancelOperation();
    setPrincipal(null);
    setStatus("anonymous");
    await api.closeSession();
  }, [api, cancelOperation]);

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
