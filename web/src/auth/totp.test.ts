import { describe, expect, it } from "vitest";

import { generateTOTPCode, verifyTOTPCode } from "./totp";

const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("RFC 6238 TOTP", () => {
  it("matches the SHA-1 reference vector at 59 seconds", async () => {
    await expect(generateTOTPCode(rfcSecret, 59_000, 8)).resolves.toBe(
      "94287082",
    );
  });

  it("accepts only the current code and a narrow one-step clock window", async () => {
    const now = 59_000;
    const previous = await generateTOTPCode(rfcSecret, 29_000);
    const current = await generateTOTPCode(rfcSecret, now);
    const next = await generateTOTPCode(rfcSecret, 89_000);
    const tooFar = await generateTOTPCode(rfcSecret, 119_000);

    await expect(verifyTOTPCode(rfcSecret, previous, now)).resolves.toBe(true);
    await expect(verifyTOTPCode(rfcSecret, current, now)).resolves.toBe(true);
    await expect(verifyTOTPCode(rfcSecret, next, now)).resolves.toBe(true);
    await expect(verifyTOTPCode(rfcSecret, tooFar, now)).resolves.toBe(false);
    await expect(verifyTOTPCode(rfcSecret, "not-a-code", now)).resolves.toBe(false);
  });
});
