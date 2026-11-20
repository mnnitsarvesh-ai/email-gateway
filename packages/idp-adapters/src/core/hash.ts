/**
 * Hashes used by the adapters (design note D4, D8, §3). Every hash is lower-case hex SHA-256 over
 * `|`-joined parts, so the same input always yields the same value across processes.
 */
import { createHash } from 'node:crypto';
import type { MailboxItemKind } from '../port/state-ports';

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** `binding_key`-style directory hash: SHA-256(provider|tenant id), tenant id lower-cased. */
export function directoryRefHash(provider: string, externalTenantId: string): string {
  return sha256Hex(`${provider}|${externalTenantId.trim().toLowerCase()}`);
}

/** OAuth application hash: SHA-256 of the service principal object id (Entra) or client id (Google). */
export function appIdHash(appOrClientId: string): string {
  return sha256Hex(appOrClientId.trim().toLowerCase());
}

/** `identity_external_id_hash` of mailbox items: SHA-256(provider|externalId). */
export function identityHash(provider: string, externalId: string): string {
  return sha256Hex(`${provider}|${externalId}`);
}

/** Mailbox item identity (D8.3): SHA-256(provider|externalUserId|kind|providerItemId or canonical). */
export function mailboxItemHash(
  provider: string,
  externalUserId: string,
  kind: MailboxItemKind,
  providerItemIdOrCanonical: string,
): string {
  return sha256Hex(`${provider}|${externalUserId}|${kind}|${providerItemIdOrCanonical}`);
}

/** Device hash (§3.1): first 16 hex of SHA-256(provider device id). */
export function deviceIdHash(deviceId: string): string {
  return sha256Hex(deviceId).slice(0, 16);
}

/** Lower-cased domain of an address, or `null` when it is not an address. */
export function domainOf(address: string | null | undefined): string | null {
  if (!address) return null;
  const cleaned = address
    .trim()
    .replace(/^smtp:/i, '')
    .replace(/^<|>$/g, '');
  const at = cleaned.lastIndexOf('@');
  if (at <= 0 || at === cleaned.length - 1) return null;
  const domain = cleaned
    .slice(at + 1)
    .toLowerCase()
    .replace(/[>\]]+$/, '');
  return /^[a-z0-9.-]{1,253}$/.test(domain) && domain.includes('.') ? domain : null;
}
