import {
  messageParsedV1,
  messageReceivedV1,
  type MessageParsedV1,
  messageParseFailedV1,
  type MessageParseFailedV1,
} from '@email-gateway/event-contracts';
import type { BodyResult } from '@email-gateway/mime-parser';
import type { FinalOutcome, MessageRecord } from './mime-store';

interface PayloadInput {
  message: MessageRecord;
  attempts: number;
  parserVersion: string;
  outcome: FinalOutcome;
}

const storedBody = (body: BodyResult | null): MessageParsedV1['textBody'] =>
  body === null ? null : { s3Key: body.key, sha256: body.sha256, sizeBytes: body.sizeBytes };

/** `mail.message.parsed.v1` (M14), validated by the schema (throws on a contract violation). */
export function buildParsedPayload(input: PayloadInput): MessageParsedV1 {
  const { message, outcome } = input;
  if (outcome.status === 'parse_failed')
    throw new Error('parse_failed uses buildParseFailedPayload');
  const result = outcome.result;
  const attachments = result?.attachments ?? [];
  const flags = new Set<string>();
  let flagged = 0;
  for (const attachment of attachments) {
    if (attachment.flags.length > 0) flagged += 1;
    for (const flag of attachment.flags) flags.add(flag);
  }
  return messageParsedV1.parse({
    messageId: message.id.toString(),
    receivedAt: message.receivedAt.toISOString(),
    direction: message.direction,
    emlS3Key: message.emlObjectKey,
    parseStatus: outcome.status,
    parserVersion: input.parserVersion,
    limitsExceeded: outcome.limitsExceeded,
    defects: outcome.defects,
    textBody: storedBody(result?.textBody ?? null),
    htmlBody: storedBody(result?.htmlBody ?? null),
    attachmentCount: attachments.length,
    flaggedAttachmentCount: flagged,
    attachmentFlags: [...flags],
    partCount: outcome.stats?.partCount ?? 0,
    maxDepth: outcome.stats?.maxDepth ?? 0,
    headerCount: outcome.stats?.headerCount ?? 0,
  });
}

/** `mail.message.parse_failed.v1` (M14), validated by the schema. */
export function buildParseFailedPayload(input: PayloadInput): MessageParseFailedV1 {
  const { message, outcome } = input;
  if (outcome.status !== 'parse_failed' || outcome.failureReason === null) {
    throw new Error('buildParseFailedPayload needs a parse_failed outcome with a reason');
  }
  return messageParseFailedV1.parse({
    messageId: message.id.toString(),
    receivedAt: message.receivedAt.toISOString(),
    direction: message.direction,
    // A key without any org/<id>/ prefix cannot be carried (the schema refuses it): null, so the
    // eml_key_mismatch verdict still commits instead of failing every attempt.
    emlS3Key: carriableKey(message.emlObjectKey),
    reason: outcome.failureReason,
    attempts: input.attempts,
    parserVersion: input.parserVersion,
  });
}

/** The key if the event contracts accept it (organization-prefixed), else null. */
function carriableKey(key: string): string | null {
  return messageReceivedV1.shape.emlS3Key.safeParse(key).success ? key : null;
}
