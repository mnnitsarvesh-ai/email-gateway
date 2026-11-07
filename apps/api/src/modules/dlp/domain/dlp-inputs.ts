import { BadRequestException } from '@nestjs/common';
import {
  type DlpDirection,
  type DlpExceptionScope,
  type DlpRuleConditions,
  dlpRuleConditionsSchema,
} from '@email-gateway/security-contracts';
import { normalizeDomainInput } from '@email-gateway/url-security';
import { formatZodIssues } from '../../../validation/zod-validation.pipe';
import { normalizeAddress } from '../../bec/domain/bec-inputs';

/**
 * Pure normalization and validation of the DLP tenant inputs (step 4.5 D11, D12, D17):
 * addresses lower-cased with an IDNA domain (the bec addr-spec parser), domains through
 * `@email-gateway/url-security` `normalizeDomainInput` (ASCII A-labels; public suffixes, IP
 * literals and single labels refused), rule conditions through `dlpRuleConditionsSchema` after
 * that normalization, and the bounded expiry / review dates. Invalid input is a `400` naming the
 * field (`<field>.<index>: …`), never echoing the value.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

const DOMAIN_MESSAGES: Record<string, string> = {
  invalid: 'Not a valid domain or host name',
  ip_literal: 'An IP address is not a domain',
  single_label: 'A single label is not a registrable domain',
  public_suffix: 'A public suffix (e.g. co.uk, github.io) is not allowed',
};

/** A domain normalized to ASCII (exact host kept, D12); `400` naming the field otherwise. */
export function normalizeDlpDomain(field: string, raw: string): string {
  const result = normalizeDomainInput(raw);
  if (!result.ok) {
    throw new BadRequestException([
      `${field}: ${DOMAIN_MESSAGES[result.code] ?? 'Invalid domain'}`,
    ]);
  }
  return result.domain;
}

/** An address normalized for comparison (`local@a-label-domain`); `400` naming the field. */
export function normalizeDlpAddress(field: string, raw: string): string {
  const address = normalizeAddress(raw);
  if (address === null) throw new BadRequestException([`${field}: Not a valid e-mail address`]);
  return address;
}

/** An exception value for its scope (D12). */
export function normalizeExceptionValue(scope: DlpExceptionScope, raw: string): string {
  return scope === 'sender_address' || scope === 'recipient_address'
    ? normalizeDlpAddress('value', raw)
    : normalizeDlpDomain('value', raw);
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/** Normalizes one `{ addresses?, domains? }` scope of the conditions in a copy. */
function normalizeScope(path: string, scope: unknown): unknown {
  if (!isRecord(scope)) return scope;
  const copy: Record<string, unknown> = { ...scope };
  if (Array.isArray(copy.addresses)) {
    const out: unknown[] = [];
    copy.addresses.forEach((entry: unknown, index) => {
      const value =
        typeof entry === 'string'
          ? normalizeDlpAddress(`${path}.addresses.${index}`, entry)
          : entry;
      if (!out.includes(value)) out.push(value);
    });
    copy.addresses = out;
  }
  if (Array.isArray(copy.domains)) {
    const out: unknown[] = [];
    copy.domains.forEach((entry: unknown, index) => {
      const value =
        typeof entry === 'string' ? normalizeDlpDomain(`${path}.domains.${index}`, entry) : entry;
      if (!out.includes(value)) out.push(value);
    });
    copy.domains = out;
  }
  return copy;
}

/**
 * Rule conditions (D11): sender and recipient addresses and domains normalized (duplicates after
 * normalization removed), then parsed with the strict `dlpRuleConditionsSchema`; `400` with
 * `conditions.<path>: <issue>` messages otherwise.
 */
export function parseRuleConditions(raw: unknown): DlpRuleConditions {
  const input = isRecord(raw)
    ? {
        ...raw,
        ...('sender' in raw && { sender: normalizeScope('conditions.sender', raw.sender) }),
        ...('recipients' in raw && {
          recipients: normalizeScope('conditions.recipients', raw.recipients),
        }),
      }
    : raw;
  const parsed = dlpRuleConditionsSchema.safeParse(input);
  if (!parsed.success) {
    throw new BadRequestException(
      formatZodIssues(parsed.error).map((issue) =>
        issue.startsWith('(root)') ? `conditions${issue.slice(6)}` : `conditions.${issue}`,
      ),
    );
  }
  return parsed.data;
}

/** The pattern and dictionary public ids a rule selects (D11 `selectors`). */
export function referencedIds(conditions: DlpRuleConditions): {
  patterns: string[];
  dictionaries: string[];
} {
  return {
    patterns: [...(conditions.selectors.customPatternIds ?? [])],
    dictionaries: [...(conditions.selectors.dictionaryIds ?? [])],
  };
}

/** Rule directions are a subset of the policy's (D11); default = the policy's. */
export function directionsWithin(
  conditions: DlpRuleConditions,
  policyDirections: readonly DlpDirection[],
): boolean {
  return (conditions.directions ?? []).every((d) => policyDirections.includes(d));
}

/** A required exception expiry: future and at most `maxDays` ahead (D12); `400` otherwise. */
export function checkExceptionExpiry(value: string, now: Date, maxDays: number): Date {
  const at = new Date(value);
  if (at.getTime() <= now.getTime()) {
    throw new BadRequestException(['expiresAt: must be in the future']);
  }
  if (at.getTime() - now.getTime() > maxDays * DAY_MS) {
    throw new BadRequestException([`expiresAt: must be at most ${maxDays} days ahead`]);
  }
  return at;
}

/** The Aadhaar review date: future and at most 365 days after the recording (D17). */
export function checkAadhaarReview(value: string, now: Date): Date {
  const at = new Date(value);
  if (at.getTime() <= now.getTime()) {
    throw new BadRequestException(['reviewDueAt: must be in the future']);
  }
  if (at.getTime() - now.getTime() > 365 * DAY_MS) {
    throw new BadRequestException(['reviewDueAt: must be at most 365 days ahead']);
  }
  return at;
}

/** `dlp_exceptions.target_key` (no NULLs in the unique key): `all`, `policy:<id>`, `rule:<id>`. */
export function exceptionTargetKey(target: {
  policyId: bigint | null;
  ruleId: bigint | null;
}): string {
  if (target.ruleId !== null) return `rule:${target.ruleId.toString()}`;
  if (target.policyId !== null) return `policy:${target.policyId.toString()}`;
  return 'all';
}

/** Whether the stored Aadhaar compliance row lets NI2 run (the worker's rule, D17). */
export function aadhaarActive(
  row: {
    aadhaarEnabled: boolean;
    aadhaarBasis: string | null;
    aadhaarReference: string | null;
    aadhaarAttested: boolean;
    aadhaarReviewDueAt: Date | null;
  } | null,
  now: Date,
): boolean {
  return (
    row !== null &&
    row.aadhaarEnabled &&
    row.aadhaarBasis !== null &&
    row.aadhaarReference !== null &&
    row.aadhaarReference.length > 0 &&
    row.aadhaarAttested &&
    row.aadhaarReviewDueAt !== null &&
    row.aadhaarReviewDueAt.getTime() > now.getTime()
  );
}

/** Rounds to two decimals (DECIMAL(3,2) columns read as Prisma decimals). */
export const twoDecimals = (value: { toNumber(): number } | number): number =>
  Math.round((typeof value === 'number' ? value : value.toNumber()) * 100) / 100;
