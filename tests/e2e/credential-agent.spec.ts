import { expect, test } from "@playwright/test";
import { E2EHarness } from "./harness";

test("member and Hermes-style Agent share one credential lifecycle", async ({ page, request }) => {
  const harness = await E2EHarness.start(page, request);
  const id = await harness.createCredentialInUI();
  expect((await harness.mcpCredentialGet(id)).display_name).toBe("e2e-login");
  const version = await harness.mcpCredentialUpdate(id, "e2e-login-updated");
  await harness.mcpCredentialDelete(id, version);
  await expect(harness.recycleBinRow(id)).toBeVisible();
  expect(await harness.auditActionsFor(id)).toEqual([
    "credential.create",
    "credential.read",
    "credential.update",
    "credential.delete",
  ]);
});
