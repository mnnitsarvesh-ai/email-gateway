export const SNAPSHOT_PATH: string;
export const SCHEMA_OUT: string;
export const OPERATIONS_OUT: string;
export interface ExtractedOperation {
  operationId: string;
  method: string;
  path: string;
  tag: string | null;
  permissions: { mode: 'all' | 'any'; permissions: string[] }[] | null;
  public: boolean;
  idempotency: string | null;
  cursor: string | null;
  rateClass: string | null;
  returnsSecret: boolean;
  secretReplay: string | null;
  listKey: 'data' | 'items' | null;
  sort: string[] | null;
  bffOnly: boolean;
}
export function extractOperations(spec: unknown): ExtractedOperation[];
export function buildMatchers(
  operations: ExtractedOperation[],
): { method: string; segments: (string | { param: string })[]; operationId: string }[];
export function generate(specText?: string): Promise<Record<string, string>>;
export function check(specText?: string): Promise<{ path: string; summary: string }[]>;
