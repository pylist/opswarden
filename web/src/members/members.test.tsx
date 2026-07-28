import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Me, Space } from "../api/types";
import type { WorkflowAPI } from "../workflow-api";
import { MembersPage } from "./MembersPage";

const ownerSpace: Space = {
  id: "spc_prod",
  name: "生产环境",
  role: "owner",
};
const principal: Me = {
  userId: "usr_self",
  systemRole: "member",
  issuedAt: "2026-07-28T12:00:00Z",
};
const members = [
  {
    userId: "usr_self",
    email: "self@example.test",
    role: "owner",
    version: 3,
    createdAt: "2026-07-20T12:00:00Z",
  },
  {
    userId: "usr_member",
    email: "member@example.test",
    role: "reader",
    version: 2,
    createdAt: "2026-07-21T12:00:00Z",
  },
];

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function apiFor(
  implementation: (path: string, options?: {
    method?: string;
    body?: Record<string, unknown>;
    signal?: AbortSignal;
  }) => Promise<unknown>,
) {
  const request = vi.fn(implementation);
  return {
    request,
    reverifyTOTP: vi.fn(async () => undefined),
  } as unknown as WorkflowAPI & { request: typeof request };
}

describe("membership administration", () => {
  it("requires recent TOTP before removing a member and uses the member version", async () => {
    const removal = deferred<unknown>();
    const api = apiFor(async (path, options) => {
      if (!options?.method) return { items: members };
      if (options.method === "DELETE") return removal.promise;
      throw new Error(`unexpected ${path}`);
    });
    render(
      <MembersPage
        api={api}
        space={ownerSpace}
        principal={principal}
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", {
      name: "移除 member@example.test",
    }));
    expect(screen.getByRole("dialog", { name: "重新验证 TOTP" })).toBeVisible();
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "验证并移除" }));
    await waitFor(() => expect(api.reverifyTOTP).toHaveBeenCalledTimes(1));
    expect(api.request).toHaveBeenCalledWith(
      "/api/v1/spaces/spc_prod/members/usr_member",
      expect.objectContaining({
        method: "DELETE",
        body: { expectedVersion: 2 },
      }),
    );
    await act(async () => {
      removal.resolve(undefined);
      await removal.promise;
    });
  });

  it("prevents duplicate two-stage membership submissions", async () => {
    const change = deferred<unknown>();
    const api = apiFor(async (_path, options) => {
      if (!options?.method) return { items: members };
      if (options.method === "PATCH") return change.promise;
      throw new Error("unexpected");
    });
    render(
      <MembersPage
        api={api}
        space={ownerSpace}
        principal={principal}
        sessionActive
      />,
    );
    fireEvent.click(await screen.findByRole("button", {
      name: "修改 member@example.test 的角色",
    }));
    fireEvent.change(screen.getByLabelText("角色"), {
      target: { value: "editor" },
    });
    fireEvent.change(screen.getByLabelText("TOTP 验证码"), {
      target: { value: "123456" },
    });
    const submit = screen.getByRole("button", { name: "验证并保存" });
    fireEvent.click(submit);
    fireEvent.click(submit);
    await waitFor(() => expect(api.reverifyTOTP).toHaveBeenCalledTimes(1));
    expect(
      api.request.mock.calls.filter(([, options]) => options?.method === "PATCH"),
    ).toHaveLength(1);
    await act(async () => {
      change.resolve({ ...members[1], role: "editor", version: 3 });
      await change.promise;
    });
  });

  it("prevents an Editor from seeing membership controls", async () => {
    const api = apiFor(async () => ({ items: members }));
    render(
      <MembersPage
        api={api}
        space={{ ...ownerSpace, role: "editor" }}
        principal={principal}
        sessionActive
      />,
    );
    expect(await screen.findByText("member@example.test")).toBeVisible();
    expect(screen.queryByRole("button", { name: "添加成员" })).toBeNull();
    expect(screen.queryByRole("button", { name: /移除/ })).toBeNull();
  });

  it("does not offer self-removal or changing the only owner", async () => {
    const api = apiFor(async () => ({ items: members.slice(0, 1) }));
    render(
      <MembersPage
        api={api}
        space={ownerSpace}
        principal={principal}
        sessionActive
      />,
    );
    expect(await screen.findByText("self@example.test")).toBeVisible();
    expect(screen.queryByRole("button", { name: /移除 self/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /修改 self/ })).toBeNull();
    expect(screen.getByText("当前账号 · 唯一所有者")).toBeVisible();
  });
});
