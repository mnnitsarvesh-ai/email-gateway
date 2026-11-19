import { createHash } from 'node:crypto';
import { z } from 'zod';

/**
 * Shared account takeover (ATO) vocabulary (step 8.4, docs/plan/steps/24-account-takeover-core.md
 * D1, D23, §3.3; ADR-0070, ADR-0073). One definition imported by `@email-gateway/policy-dsl`
 * (the four `ato.*` fields), `@email-gateway/ato-detection`, the smtp-adapter and the
 * policy-engine, so every component computes identical account keys and level names without
 * depending on each other. Pure (Node `crypto` only); no I/O.
 */

/**
 * Account risk levels in ascending order (brief defaults: low 0–29, medium 30–49, high 50–74,
 * critical 75–100; the bands themselves are per-tenant settings). Equal to the Prisma enum
 * `AtoRiskLevel` (`ato_accounts.risk_level`, `ato_risk_scores.level`). Append-only.
 */
export const ATO_RISK_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
export type AtoRiskLevel = (typeof ATO_RISK_LEVELS)[number];
export const atoRiskLevelSchema = z.enum(ATO_RISK_LEVELS);

/** Rank of a risk level (0 = `low`); ordered comparisons (`gte`, `lte`) use it. */
export const atoRiskLevelRank = (level: AtoRiskLevel): number => ATO_RISK_LEVELS.indexOf(level);

/**
 * Monitored-subject kinds of `ato_accounts.kind` (D1): a tenant mailbox (seen through the mail it
 * sends), a portal user (`users.id`) and an SMTP connector (`smtp_connectors.id`). Equal to the
 * Prisma enum `AtoAccountKind`.
 */
export const ATO_ACCOUNT_KINDS = ['mailbox', 'gateway_user', 'smtp_connector'] as const;
export type AtoAccountKind = (typeof ATO_ACCOUNT_KINDS)[number];

/** Prefixes of the subject key `<prefix>:<subject>` hashed into `ato_accounts.subject_hash`. */
export const ATO_SUBJECT_KINDS = ['mailbox', 'user', 'connector'] as const;
export type AtoSubjectKind = (typeof ATO_SUBJECT_KINDS)[number];

/** The subject-key prefix of each account kind (D1 table). */
export const ATO_ACCOUNT_SUBJECT_KIND: Readonly<Record<AtoAccountKind, AtoSubjectKind>> =
  Object.freeze({ mailbox: 'mailbox', gateway_user: 'user', smtp_connector: 'connector' });

/** Version of the optional `ato` block of `policy-input/1` and of `policy_execution_logs.ato_facts`. */
export const ATO_POLICY_FACTS_VERSION = 'ato-policy-facts/1';

/** Longest mailbox address accepted (RFC 5321 path limit, as `ato_accounts.address`). */
export const ATO_MAILBOX_ADDRESS_MAX_LENGTH = 320;

const DECIMAL_ID = /^[1-9][0-9]{0,19}$/;

const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/**
 * The normalized mailbox address of D1: the full address lower-cased (local part and domain), no
 * sub-address stripping (`a+x@` and `a@` are different accounts; recorded limitation). Throws on
 * an empty address, one without a single `@` between non-empty parts, one with whitespace or
 * control characters, or one longer than 320 characters.
 */
export function normalizeAtoMailboxAddress(address: string): string {
  const value = address.toLowerCase();
  const at = value.indexOf('@');
  if (
    value.length === 0 ||
    value.length > ATO_MAILBOX_ADDRESS_MAX_LENGTH ||
    at <= 0 ||
    at !== value.lastIndexOf('@') ||
    at === value.length - 1 ||
    // eslint-disable-next-line no-control-regex
    /[\s\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error('Invalid mailbox address');
  }
  return value;
}

/**
 * `ato_accounts.subject_hash` (D1): lower-case hex SHA-256 of `<kind>:<subject>`, where the
 * subject is the normalized address for `mailbox` and the decimal id (`users.id`,
 * `smtp_connectors.id`) for `user` and `connector`. Throws on an unknown kind, a malformed
 * address or a non-canonical decimal id, so a caller can never key an account inconsistently.
 */
export function atoSubjectHash(kind: AtoSubjectKind, subject: string | bigint): string {
  switch (kind) {
    case 'mailbox':
      if (typeof subject !== 'string') throw new Error('A mailbox subject is an address');
      return sha256Hex(`mailbox:${normalizeAtoMailboxAddress(subject)}`);
    case 'user':
    case 'connector': {
      const id = typeof subject === 'bigint' ? subject.toString() : subject;
      if (!DECIMAL_ID.test(id)) throw new Error('A user or connector subject is a decimal id');
      return sha256Hex(`${kind}:${id}`);
    }
    default:
      throw new Error('Unknown ATO subject kind');
  }
}

/**
 * `ato_smtp_restrictions.mailbox_sha256` and `ato.restriction.changed.v1` `mailboxSha256` (D14):
 * lower-case hex SHA-256 of the normalized (lower-cased) address. The smtp-adapter compares it
 * with the hash of the envelope sender, so restrictions never carry the address on the SMTP path.
 */
export function atoMailboxSha256(address: string): string {
  return sha256Hex(normalizeAtoMailboxAddress(address));
}
