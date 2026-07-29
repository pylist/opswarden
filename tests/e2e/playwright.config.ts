import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: ["*.spec.ts"],
  globalSetup: "./setup.ts",
  fullyParallel: false,
  workers: 1,
  reporter: [["line"]],
  timeout: 120_000,
  use: {
    baseURL: "http://127.0.0.1:18081",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "node server.mjs",
    url: "http://127.0.0.1:18081/health/live",
    cwd: ".",
    timeout: 120_000,
    reuseExistingServer: false,
    stdout: "ignore",
    stderr: "pipe",
  },
});
