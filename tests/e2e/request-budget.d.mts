export const REQUEST_BUDGETS: Readonly<Record<string, number>>;
export function classifyHumanRequest(method: string, rawURL: string): string | null;
export class HumanRequestBudget {
  readonly failure: Promise<Error>;
  record(
    session: string,
    method: string,
    rawURL: string,
    status: number,
    retryAfter: string | null,
  ): void;
  assertWithinLimits(): void;
  snapshot(): {
    budgets: Readonly<Record<string, number>>;
    sessions: Record<string, Record<string, number>>;
  };
}
