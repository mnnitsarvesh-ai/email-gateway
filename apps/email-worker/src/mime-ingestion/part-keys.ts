import type { PartInfo } from '@email-gateway/mime-parser';

/** Extension of a part object by the parser's part kind (M11). */
export const PART_EXTENSIONS = { text: 'text', html: 'html', attachment: 'att' } as const;

export interface PartKeyTarget {
  organizationId: bigint;
  messageId: bigint;
  /** `email_messages.received_at`: the key's date, so a retry on another day writes the same key. */
  receivedAt: Date;
}

const pad = (value: number, width: number): string => String(value).padStart(width, '0');

/** `org/{organizationId}/` — the only prefix any object of the organization may use (invariant 5). */
export const organizationPrefix = (organizationId: bigint): string =>
  `org/${organizationId.toString()}/`;

/**
 * Deterministic part key (design M11):
 * `org/{organizationId}/part/{yyyy}/{mm}/{dd}/{messageId}/{partIndex}.{text|html|att}`, with the
 * UTC date of the message's `received_at`. Ids come from the writer row, never from the event or
 * from message content; filenames are never part of a key.
 */
export function partKey(target: PartKeyTarget, part: Pick<PartInfo, 'partIndex' | 'kind'>): string {
  if (target.organizationId <= 0n || target.messageId <= 0n) {
    throw new Error('part keys need positive organization and message ids');
  }
  if (!Number.isSafeInteger(part.partIndex) || part.partIndex < 0) {
    throw new Error('part index must be a non-negative integer');
  }
  const at = target.receivedAt;
  if (Number.isNaN(at.getTime())) throw new Error('part keys need a valid received_at');
  const date = `${pad(at.getUTCFullYear(), 4)}/${pad(at.getUTCMonth() + 1, 2)}/${pad(at.getUTCDate(), 2)}`;
  const key =
    `${organizationPrefix(target.organizationId)}part/${date}/` +
    `${target.messageId.toString()}/${part.partIndex}.${PART_EXTENSIONS[part.kind]}`;
  assertOrganizationKey(key, target.organizationId);
  return key;
}

/** True when `key` lies under the organization's prefix (and has something after it). */
export function isOrganizationKey(key: string, organizationId: bigint): boolean {
  const prefix = organizationPrefix(organizationId);
  return key.startsWith(prefix) && key.length > prefix.length && !key.includes('..');
}

export function assertOrganizationKey(key: string, organizationId: bigint): void {
  if (!isOrganizationKey(key, organizationId)) {
    throw new Error('object key is not under the organization prefix');
  }
}
