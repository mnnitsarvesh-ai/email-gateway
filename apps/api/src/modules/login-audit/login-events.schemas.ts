import { z } from 'zod';
import { PageQuerySchema } from '../../http/pagination';

/** `GET /audit/login-events` (§4.2). */

export const LOGIN_OUTCOMES = [
  'success',
  'failure',
  'locked',
  'mfa_required',
  'mfa_failure',
  'rate_limited',
] as const;

export const LoginEventsQuerySchema = PageQuerySchema.extend({
  from: z.iso.datetime({ offset: true }).optional().describe('Inclusive; default `to` − 7 days'),
  to: z.iso.datetime({ offset: true }).optional().describe('Exclusive; default now'),
  outcome: z.enum(LOGIN_OUTCOMES).optional(),
  userId: z.uuid().optional().describe('Public id of a user of the organization'),
});

export const LoginEventResponseSchema = z.object({
  id: z.string().describe('Decimal row id'),
  occurredAt: z.iso.datetime(),
  email: z.string().describe('Email address attempted (lower-cased)'),
  outcome: z.enum(LOGIN_OUTCOMES),
  failureReason: z.string().nullable(),
  ipAddress: z.string().nullable(),
  userAgent: z.string().nullable(),
  userId: z.uuid().nullable(),
});

export const LoginEventListResponseSchema = z.object({
  data: z.array(LoginEventResponseSchema),
  nextCursor: z.string().nullable(),
});

export type LoginEventsQuery = z.output<typeof LoginEventsQuerySchema>;
export type LoginEventView = z.output<typeof LoginEventResponseSchema>;
