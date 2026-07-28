import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import type { Me, Space } from "../api/types";
import type { WorkflowAPI } from "../workflow-api";
import { SettingsPage } from "./SettingsPage";

const principal: Me = {
  userId: "usr_owner",
  systemRole: "system_owner",
  issuedAt: "2026-07-28T12:00:00Z",
};
const space: Space = {
  id: "spc_prod",
  name: "生产环境",
  role: "owner",
};

describe("settings", () => {
  it("shows precise unavailable states for Task 15 endpoints without fake metrics", async () => {
    const api = {
      request: vi.fn(async () => {
        throw new ApiError("NOT_FOUND", "req_settings", 404);
      }),
      reverifyTOTP: vi.fn(),
    } as unknown as WorkflowAPI;
    render(
      <SettingsPage
        api={api}
        space={space}
        principal={principal}
        sessionActive
      />,
    );
    expect(await screen.findByText("健康检查尚未配置")).toBeVisible();
    expect(screen.getByText("备份管理尚未配置")).toBeVisible();
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/health",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/backups",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(document.body).not.toHaveTextContent("99.9%");
  });

  it("does not probe administrative endpoints for a regular member", () => {
    const api = {
      request: vi.fn(async () => ({})),
      reverifyTOTP: vi.fn(),
    } as unknown as WorkflowAPI;
    render(
      <SettingsPage
        api={api}
        space={{ ...space, role: "reader" }}
        principal={{ ...principal, systemRole: "member" }}
        sessionActive
      />,
    );
    expect(screen.getByText("当前账号没有查看系统设置的权限。")).toBeVisible();
    expect(api.request).not.toHaveBeenCalled();
  });
});
