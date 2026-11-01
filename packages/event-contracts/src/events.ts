import { z } from 'zod';

const direction = z.enum(['inbound', 'outbound', 'internal']);
const s3Key = z.string().regex(/^org\/[0-9a-f-]{36}\//, 'S3 keys are tenant-prefixed');

/** Published by ingestion after the EML is in S3 and the message row is committed. */
export const messageReceivedV1 = z.object({
  messageId: z.uuid(),
  receivedAt: z.iso.datetime(),
  direction,
  emlS3Key: s3Key,
  sizeBytes: z.number().int().nonnegative(),
  envelopeFrom: z.string().max(320),
  recipientCount: z.number().int().positive(),
});
export type MessageReceivedV1 = z.infer<typeof messageReceivedV1>;

/** Published by the email worker once all required security stages report or time out. */
export const messageScannedV1 = z.object({
  messageId: z.uuid(),
  receivedAt: z.iso.datetime(),
  verdictIds: z.array(z.uuid()),
  timedOutStages: z.array(z.string()),
});
export type MessageScannedV1 = z.infer<typeof messageScannedV1>;

/** Published by the policy engine with the final action for the message. */
export const policyDecidedV1 = z.object({
  messageId: z.uuid(),
  receivedAt: z.iso.datetime(),
  action: z.enum(['deliver', 'tag', 'quarantine', 'discard']),
  matchedRuleIds: z.array(z.string()),
  archive: z.boolean(),
});
export type PolicyDecidedV1 = z.infer<typeof policyDecidedV1>;

export const EventTypes = {
  MessageReceived: 'mail.message.received.v1',
  MessageScanned: 'mail.message.scanned.v1',
  PolicyDecided: 'mail.policy.decided.v1',
} as const;
