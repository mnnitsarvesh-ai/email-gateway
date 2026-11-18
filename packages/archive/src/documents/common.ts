import { z } from 'zod';
import { DECIMAL_ID_PATTERN, UUID_PATTERN } from '../ids';
import {
  ARCHIVE_CATEGORIES,
  ARCHIVE_SOURCES,
  MESSAGE_ACTIONS,
  MESSAGE_DIRECTIONS,
  MESSAGE_STATUSES,
  MESSAGE_VERDICTS,
  RECIPIENT_STATUSES,
} from '../vocabulary';

/** Shared zod pieces of the archive documents (§4.2). */

export const uuidSchema = z.string().regex(UUID_PATTERN, 'must be a lower-case UUID');
export const decimalIdSchema = z.string().regex(DECIMAL_ID_PATTERN, 'must be a decimal id');
export const sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/, 'must be a SHA-256 (hex)');
export const isoDateTimeSchema = z.iso.datetime({ offset: true });
/** A date (`YYYY-MM-DD`, whole UTC day) or a date-time with offset. */
export const dateOrDateTimeSchema = z.union([z.iso.date(), z.iso.datetime({ offset: true })]);
/** An address as stored (envelope addresses may be empty for the null sender). */
export const storedAddressSchema = z.string().max(320);
export const addressSchema = z
  .string()
  .min(3)
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+$/, 'address');
export const domainSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/, 'domain');

export const directionSchema = z.enum(MESSAGE_DIRECTIONS);
export const categorySchema = z.enum(ARCHIVE_CATEGORIES);
export const sourceSchema = z.enum(ARCHIVE_SOURCES);
export const messageStatusSchema = z.enum(MESSAGE_STATUSES);
export const recipientStatusSchema = z.enum(RECIPIENT_STATUSES);
export const verdictSchema = z.enum(MESSAGE_VERDICTS);
export const actionSchema = z.enum(MESSAGE_ACTIONS);

/** A non-empty list without duplicates, at most `max` entries. */
export function setOf<T extends z.ZodType>(item: T, max: number) {
  return z
    .array(item)
    .min(1)
    .max(max)
    .refine((list) => new Set(list.map((v) => JSON.stringify(v))).size === list.length, {
      message: 'must not contain duplicates',
    });
}

/** A stored document did not match its schema. Names the document, never its content. */
export class ArchiveDocumentError extends Error {
  constructor(readonly document: string) {
    super(`Invalid ${document} document`);
    this.name = 'ArchiveDocumentError';
  }
}

/** A list without duplicates (may be empty), at most `max` entries. */
export function uniqueListOf<T extends z.ZodType>(item: T, max: number) {
  return z
    .array(item)
    .max(max)
    .refine((list) => new Set(list.map((v) => JSON.stringify(v))).size === list.length, {
      message: 'must not contain duplicates',
    });
}
