import { expect, test } from "@playwright/test";
import { APIHarness } from "./harness";

test("cross-Space existing and missing IDs are indistinguishable", async ({ request }) => {
  const harness = await APIHarness.start(request);
  const missing = await harness.getCredential(
    "00000000-0000-0000-0000-000000000000",
  );
  const forbidden = await harness.getOtherSpaceCredential();
  expect(forbidden.status()).toBe(missing.status());
  const forbiddenBody = await forbidden.json();
  const missingBody = await missing.json();
  expect(forbiddenBody.error).toMatchObject({
    code: missingBody.error.code,
    message: missingBody.error.message,
    retryable: missingBody.error.retryable,
  });
  expect(forbiddenBody.error.requestId).toMatch(/^req_[0-9a-f]{32}$/);
  expect(missingBody.error.requestId).toMatch(/^req_[0-9a-f]{32}$/);
});
