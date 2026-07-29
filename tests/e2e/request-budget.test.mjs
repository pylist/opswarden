import assert from "node:assert/strict";
import test from "node:test";
import {
  HumanRequestBudget,
  REQUEST_BUDGETS,
  classifyHumanRequest,
} from "./request-budget.mjs";

test("request classification mirrors the production human limiter operations", () => {
  const base = "https://opswarden.invalid/api/v1/spaces/space-sensitive";
  assert.equal(classifyHumanRequest("GET", `${base}/credentials`), "human_credential_list");
  assert.equal(classifyHumanRequest("GET", `${base}/credentials/credential-sensitive`), "human_credential_read");
  assert.equal(classifyHumanRequest("PATCH", `${base}/credentials/credential-sensitive`), "human_credential_write");
  assert.equal(classifyHumanRequest("GET", `${base}/assets`), "human_generic_read");
  assert.equal(classifyHumanRequest("POST", `${base}/assets`), "human_generic_write");
  assert.equal(classifyHumanRequest("POST", "https://opswarden.invalid/api/v1/auth/login/complete"), null);
  assert.ok(REQUEST_BUDGETS.human_credential_write < 20);
});

test("429 resolves the fail-fast signal with sanitized bucket diagnostics", async () => {
  const budget = new HumanRequestBudget();
  const sensitiveURL =
    "https://opswarden.invalid/api/v1/spaces/space-sensitive/credentials/credential-sensitive";
  budget.record("ui-session-2", "PATCH", sensitiveURL, 429, "7");
  const failure = await budget.failure;
  assert.match(failure.message, /status|429/u);
  assert.match(failure.message, /human_credential_write/u);
  assert.match(failure.message, /retry_after_seconds=7/u);
  assert.doesNotMatch(failure.message, /space-sensitive|credential-sensitive|opswarden\.invalid/u);
});

test("per-session budget keeps the five-type flow below production capacity", () => {
  const budget = new HumanRequestBudget();
  const collection = "https://opswarden.invalid/api/v1/spaces/space/credentials";
  for (let index = 0; index < 4; index += 1) {
    budget.record("ui-session-1", "PATCH", `${collection}/credential`, 200, null);
  }
  for (let index = 0; index < 13; index += 1) {
    budget.record("ui-session-2", "PATCH", `${collection}/credential`, 200, null);
  }
  budget.assertWithinLimits();
  budget.record("ui-session-2", "PATCH", `${collection}/credential`, 200, null);
  budget.record("ui-session-2", "PATCH", `${collection}/credential`, 200, null);
  budget.record("ui-session-2", "PATCH", `${collection}/credential`, 200, null);
  assert.throws(() => budget.assertWithinLimits(), /request budget exceeded/u);
});
