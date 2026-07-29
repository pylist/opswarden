import { readFile } from "node:fs/promises";
import { connect } from "node:tls";
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";

const artifacts = resolve(process.env.OPSWARDEN_E2E_ARTIFACT_DIR ?? "");
const imageVersion = process.env.OPSWARDEN_E2E_IMAGE_VERSION ?? "";
const appPort = Number(process.env.OPSWARDEN_E2E_APP_PORT);

test("release UI, REST, and MCP are reached through the exact TLS Compose deployment", async ({
  request,
}) => {
  const metadata = JSON.parse(
    await readFile(resolve(artifacts, "deployment.json"), "utf8"),
  );
  expect(metadata.baseURL).toBe(`https://localhost:${appPort}`);
  expect(metadata.image).toBe(`opswarden:${imageVersion}`);
  expect(metadata.revision).toBe(imageVersion.slice(4));
  expect(metadata.publishedPorts.opswarden["8080/tcp"]).toBeNull();
  expect(Object.keys(metadata.publishedPorts.caddy)).toEqual(["443/tcp"]);
  expect(metadata.publishedPorts.caddy["443/tcp"]).toEqual([
    { HostIp: "127.0.0.1", HostPort: String(appPort) },
  ]);

  const tls = await new Promise<{
    encrypted: boolean;
    protocol: string | null;
    subjectAltName: string | undefined;
  }>((resolveTLS, rejectTLS) => {
    const socket = connect({
      host: "127.0.0.1",
      port: appPort,
      servername: "localhost",
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
      ALPNProtocols: ["h2", "http/1.1"],
    });
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      resolveTLS({
        encrypted: socket.encrypted,
        protocol: socket.getProtocol(),
        subjectAltName: certificate.subjectaltname,
      });
      socket.end();
    });
    socket.once("error", rejectTLS);
  });
  expect(tls.encrypted).toBe(true);
  expect(["TLSv1.2", "TLSv1.3"]).toContain(tls.protocol);
  expect(tls.subjectAltName).toContain("DNS:localhost");

  const health = await request.get("/health/live");
  expect(health.status()).toBe(200);
  expect(await health.text()).toBe('{"status":"ok"}\n');
  const headers = health.headers();
  expect(headers["strict-transport-security"]).toBe(
    "max-age=31536000; includeSubDomains",
  );
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers.server).toBeUndefined();
  expect(headers.via).toBeUndefined();
});
