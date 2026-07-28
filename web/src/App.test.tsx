import { render, screen } from "@testing-library/react";
import { it, expect } from "vitest";

import App from "./App";

it("renders the product name", () => {
  render(<App />);
  expect(screen.getByRole("heading", { name: "OpsWarden" })).toBeVisible();
});
