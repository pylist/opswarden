import { chromium } from "@playwright/test";
import { lstatSync, readFileSync } from "node:fs";

const installed = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
if (installed.devDependencies?.["@playwright/test"] !== "1.62.0") {
  throw new Error("unexpected Playwright package version");
}
const executable = chromium.executablePath();
const metadata = lstatSync(executable);
if (!metadata.isFile() || metadata.isSymbolicLink()) {
  throw new Error("the pinned Chromium executable is not installed safely");
}
