import { expect, test } from "@playwright/test";
import { APIHarness } from "./harness";

test("cross-Space existing and missing IDs are indistinguishable", async ({ request }) => {
  const harness = await APIHarness.start(request);
  const missing = await harness.getCredential(
    "00000000-0000-0000-0000-000000000000",
  );
  const forbidden = await harness.getOtherSpaceCredential();
  expect(missing.status()).toBe(404);
  expect(forbidden.status()).toBe(404);
  const forbiddenBody = await forbidden.json();
  const missingBody = await missing.json();
  for (const body of [missingBody, forbiddenBody]) {
    expect(Object.keys(body)).toEqual(["error"]);
    expect(Object.keys(body.error).sort()).toEqual(
      ["code", "message", "requestId", "retryable"].sort(),
    );
    expect(body.error.requestId).toMatch(/^req_[0-9a-f]{32}$/);
  }
  const normalize = (body: typeof missingBody) => ({
    ...body,
    error: { ...body.error, requestId: "<normalized-request-id>" },
  });
  expect(normalize(forbiddenBody)).toEqual(normalize(missingBody));

  const securityHeaders = (response: typeof missing) => {
    const headers = response.headers();
    return {
      cacheControl: headers["cache-control"],
      contentSecurityPolicy: headers["content-security-policy"],
      contentType: headers["content-type"],
      referrerPolicy: headers["referrer-policy"],
      xContentTypeOptions: headers["x-content-type-options"],
      xFrameOptions: headers["x-frame-options"],
      requestId: "<normalized-request-id>",
    };
  };
  const expectedHeaders = {
    cacheControl: "no-store",
    contentSecurityPolicy:
      "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
    contentType: "application/json",
    referrerPolicy: "no-referrer",
    xContentTypeOptions: "nosniff",
    xFrameOptions: "DENY",
    requestId: "<normalized-request-id>",
  };
  expect(securityHeaders(missing)).toEqual(expectedHeaders);
  expect(securityHeaders(forbidden)).toEqual(expectedHeaders);
  if (process.env.OPSWARDEN_E2E_VERIFY_FAILURE_PATH === "1") {
    throw new Error("intentional E2E runner failure-path verification");
  }
});
