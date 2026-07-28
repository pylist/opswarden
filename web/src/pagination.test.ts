import { describe, expect, it } from "vitest";

import { CursorFlow, mergeUniqueByID } from "./pagination";

describe("cursor pagination state", () => {
  it("allows a failed cursor retry and consumes it only after success", () => {
    const flow = new CursorFlow();
    const first = flow.begin("");
    expect(first).not.toBeNull();
    expect(flow.complete(first!, "cursor_1")).toBe(true);

    const failed = flow.begin("cursor_1");
    expect(failed).not.toBeNull();
    flow.fail(failed!);
    const retry = flow.begin("cursor_1");
    expect(retry).not.toBeNull();
    expect(flow.complete(retry!, "cursor_2")).toBe(true);
    expect(flow.begin("cursor_1")).toBeNull();
  });

  it("rejects repeated and cyclic cursors without consuming the failed attempt", () => {
    const flow = new CursorFlow();
    const first = flow.begin("");
    expect(flow.complete(first!, "cursor_1")).toBe(true);
    const repeated = flow.begin("cursor_1");
    expect(flow.complete(repeated!, "cursor_1")).toBe(false);
    flow.fail(repeated!);

    const retry = flow.begin("cursor_1");
    expect(flow.complete(retry!, "cursor_2")).toBe(true);
    const cyclic = flow.begin("cursor_2");
    expect(flow.complete(cyclic!, "cursor_1")).toBe(false);
    flow.fail(cyclic!);
    expect(flow.begin("cursor_2")).not.toBeNull();
  });

  it("does not let a stale failure release a newer attempt after reset", () => {
    const flow = new CursorFlow();
    const stale = flow.begin("");
    flow.reset();
    const current = flow.begin("");
    flow.fail(stale!);
    expect(flow.isCurrent(current!)).toBe(true);
  });

  it("deduplicates existing and incoming IDs in encounter order", () => {
    expect(
      mergeUniqueByID(
        [{ id: "a", value: 1 }, { id: "a", value: 2 }],
        [
          { id: "a", value: 3 },
          { id: "b", value: 4 },
          { id: "b", value: 5 },
        ],
      ),
    ).toEqual([
      { id: "a", value: 1 },
      { id: "b", value: 4 },
    ]);
  });
});
