import { useEffect, useState } from "react";

import { ApiClient, ApiError } from "./api/client";
import { AuthProvider, useAuth } from "./auth/AuthProvider";
import { LoginPage } from "./auth/LoginPage";
import { SetupPage } from "./auth/SetupPage";
import { AppShell } from "./layout/AppShell";
import "./styles.css";

function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function AppContent() {
  const { status } = useAuth();
  const [path, setPath] = useState(window.location.pathname);
  const [setupAvailability, setSetupAvailability] = useState<
    "loading" | "available" | "unavailable" | "forbidden"
  >("loading");

  useEffect(() => {
    const sync = () => setPath(window.location.pathname);
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, []);

  useEffect(() => {
    let active = true;
    new ApiClient()
      .publicRequest<{ needsInitialOwner: boolean }>("/api/v1/bootstrap/status")
      .then((result) => {
        if (active) {
          setSetupAvailability(
            result.needsInitialOwner ? "available" : "unavailable",
          );
        }
      })
      .catch((error) => {
        if (active) {
          setSetupAvailability(
            error instanceof ApiError && error.status === 403
              ? "forbidden"
              : "unavailable",
          );
        }
      });
    return () => {
      active = false;
    };
  }, []);

  if (status === "authenticated") {
    return <AppShell />;
  }
  if (setupAvailability === "loading") {
    return (
      <main className="auth-page">
        <section className="loading-panel" aria-labelledby="loading-title">
          <h1 id="loading-title">OpsWarden</h1>
          <p role="status">正在检查初始化状态…</p>
        </section>
      </main>
    );
  }
  if (path === "/setup" && setupAvailability === "available") {
    return (
      <SetupPage
        onLogin={(completed) => {
          if (completed) {
            setSetupAvailability("unavailable");
          }
          navigate("/");
        }}
      />
    );
  }
  return (
    <LoginPage
      canSetup={setupAvailability === "available"}
      onSetup={() => navigate("/setup")}
      setupNotice={
        setupAvailability === "forbidden"
          ? "如需初始化或重置服务，请联系管理员在服务器本机操作。"
          : undefined
      }
    />
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
