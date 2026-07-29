import { test } from "@playwright/test";
import { RestoreHarness } from "./harness";

test("online backup restores with separate key and supports emergency revocation", async ({ request }) => {
  const harness = await RestoreHarness.start(request);
  await harness.backupRestoreAndRevoke();
});
