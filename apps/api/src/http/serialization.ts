/**
 * Helpers for response mappers (D2): Prisma rows are never returned as-is, external ids are
 * public ids, log rows expose their numeric id as a decimal string (`formatId`), and `bigint`
 * never reaches `JSON.stringify`.
 */
export { formatId } from '@email-gateway/database';

export function toIso(date: Date): string {
  return date.toISOString();
}

export function toIsoOrNull(date: Date | null | undefined): string | null {
  return date ? date.toISOString() : null;
}
