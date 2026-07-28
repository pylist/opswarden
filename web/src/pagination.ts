export type CursorAttempt = Readonly<{
  cursor: string;
  token: symbol;
}>;

export class CursorFlow {
  private consumed = new Set<string>();
  private inFlight = new Map<string, symbol>();

  reset() {
    this.consumed.clear();
    this.inFlight.clear();
  }

  begin(cursor: string): CursorAttempt | null {
    if (this.consumed.has(cursor) || this.inFlight.has(cursor)) return null;
    const attempt = { cursor, token: Symbol("cursor-attempt") };
    this.inFlight.set(cursor, attempt.token);
    return attempt;
  }

  isCurrent(attempt: CursorAttempt) {
    return this.inFlight.get(attempt.cursor) === attempt.token;
  }

  complete(attempt: CursorAttempt, nextCursor?: string) {
    if (!this.isCurrent(attempt)) return false;
    if (
      nextCursor !== undefined &&
      (nextCursor === attempt.cursor ||
        this.consumed.has(nextCursor) ||
        this.inFlight.has(nextCursor))
    ) {
      return false;
    }
    this.inFlight.delete(attempt.cursor);
    this.consumed.add(attempt.cursor);
    return true;
  }

  fail(attempt: CursorAttempt) {
    if (this.isCurrent(attempt)) this.inFlight.delete(attempt.cursor);
  }
}

export function mergeUniqueByID<T extends { id: string }>(
  existing: readonly T[],
  incoming: readonly T[],
) {
  const merged: T[] = [];
  const ids = new Set<string>();
  for (const item of [...existing, ...incoming]) {
    if (ids.has(item.id)) continue;
    ids.add(item.id);
    merged.push(item);
  }
  return merged;
}
