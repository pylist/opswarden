import { defineConfig } from "@playwright/test";

const appPort = Number(process.env.OPSWARDEN_E2E_APP_PORT);
const artifactDir = process.env.OPSWARDEN_E2E_ARTIFACT_DIR;
if (
  !Number.isInteger(appPort) ||
  appPort < 1024 ||
  appPort > 65535 ||
  !artifactDir
) {
  throw new Error("validated E2E run environment is required");
}

export default defineConfig({
  testDir: ".",
  testMatch: ["*.spec.ts"],
  globalSetup: "./setup.ts",
  fullyParallel: false,
  workers: 1,
  reporter: [["line"]],
  outputDir: `${artifactDir}/playwright/test-results`,
  timeout: 120_000,
  use: {
    baseURL: `http://127.0.0.1:${appPort}`,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  webServer: {
    command: "node server.mjs",
    url: `http://127.0.0.1:${appPort}/health/live`,
    cwd: ".",
    timeout: 120_000,
    reuseExistingServer: false,
    stdout: "ignore",
    stderr: "pipe",
  },
});
