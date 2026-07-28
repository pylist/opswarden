import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Space } from "../api/types";
import type { WorkflowAPI } from "../workflow-api";
import { AuditPage } from "./AuditPage";

const space: Space = {
  id: "spc_prod",
  name: "生产环境",
  role: "owner",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function apiFor(
  implementation: (path: string, options?: { signal?: AbortSignal }) =>
    Promise<unknown>,
) {
  return {
    request: vi.fn(implementation),
    reverifyTOTP: vi.fn(),
  } as unknown as WorkflowAPI;
}

const event = {
  id: "aud_1",
  requestId: "req_1",
  createdAt: "2026-07-28T12:00:00Z",
  actorType: "user",
  actorId: "usr_1",
  fingerprint: "fingerprint",
  action: "credential.read",
  spaceId: "spc_prod",
  resourceType: "credential",
  resourceId: "crd_1",
  sourceIp: "10.0.0.8",
  userAgent: "fixture",
  success: true,
  changeFields: ["password"],
  reason: "unsafe reason fixture",
};

describe("audit page", () => {
  it("sends supported actor/action/resource filters and renders only safe columns", async () => {
    const api = apiFor(async () => ({ items: [event] }));
    render(
      <AuditPage
        api={api}
        space={space}
        systemRole="member"
        sessionActive
      />,
    );
    await screen.findByText("req_1");
    fireEvent.change(screen.getByLabelText("动作"), {
      target: { value: "credential.read" },
    });
    fireEvent.change(screen.getByLabelText("主体 ID"), {
      target: { value: "usr_1" },
    });
    fireEvent.change(screen.getByLabelText("资源类型"), {
      target: { value: "credential" },
    });
    await waitFor(() => {
      expect(api.request).toHaveBeenLastCalledWith(
        "/api/v1/audit-events?spaceId=spc_prod&actorId=usr_1&action=credential.read&resourceType=credential&limit=100",
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      );
    });
    expect(screen.getByRole("columnheader", { name: "请求 ID" })).toBeVisible();
    expect(screen.getByRole("columnheader", { name: "结果" })).toBeVisible();
    expect(document.body).not.toHaveTextContent("unsafe reason fixture");
    expect(document.body).not.toHaveTextContent("password");
    expect(document.body).not.toHaveTextContent("fixture");
  });

  it("uses hardened cursor flow and ignores a stale continuation after filters change", async () => {
    const stale = deferred<unknown>();
    const api = apiFor(async (path) => {
      if (path.includes("after=cursor_1")) return stale.promise;
      if (path.includes("action=credential.read")) {
        return {
          items: [{
            ...event,
            id: "aud_filtered",
            requestId: "req_filtered",
          }],
        };
      }
      return { items: [event], nextCursor: "cursor_1" };
    });
    render(
      <AuditPage
        api={api}
        space={space}
        systemRole="member"
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "加载更多审计事件" }));
    fireEvent.change(screen.getByLabelText("动作"), {
      target: { value: "credential.read" },
    });
    expect(await screen.findByText("req_filtered")).toBeVisible();
    await act(async () => {
      stale.resolve({
        items: [{ ...event, id: "aud_stale", requestId: "req_stale" }],
      });
      await stale.promise;
    });
    expect(screen.queryByText("req_stale")).toBeNull();
  });

  it("does not fetch audit for an Editor", () => {
    const api = apiFor(async () => ({ items: [] }));
    render(
      <AuditPage
        api={api}
        space={{ ...space, role: "editor" }}
        systemRole="member"
        sessionActive
      />,
    );
    expect(screen.getByText("当前账号没有查看审计日志的权限。")).toBeVisible();
    expect(api.request).not.toHaveBeenCalled();
  });

  it("rejects arbitrary audit payload fields instead of rendering them", async () => {
    const api = apiFor(async () => ({
      items: [{
        ...event,
        payload: { token: "owat_audit_hostile_plaintext" },
      }],
    }));
    render(
      <AuditPage
        api={api}
        space={space}
        systemRole="member"
        sessionActive
      />,
    );
    expect(await screen.findByRole("alert")).toBeVisible();
    expect(document.body).not.toHaveTextContent("owat_audit_hostile_plaintext");
    expect(screen.queryByText("req_1")).toBeNull();
  });
});
