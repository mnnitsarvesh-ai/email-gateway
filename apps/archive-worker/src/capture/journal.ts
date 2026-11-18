import {
  type ArchiveCategory,
  ArchiveDocumentError,
  type ArchiveJournal,
  archiveJournalSchema,
  isKeyOfOrganization,
} from '@email-gateway/archive';
import type { Prisma } from '@email-gateway/database';
import type { ArchiveStorage } from '../storage/archive-storage';
import { isMissing } from '../storage/archive-storage';
import type { MessageFacts } from './facts';

type JsonValue = Prisma.JsonValue;

export interface JournalInputs {
  parse: {
    status: string;
    failureReason: string | null;
    limitsExceeded: JsonValue | null;
    defects: JsonValue | null;
    textBodyObjectKey: string | null;
    htmlBodyObjectKey: string | null;
  } | null;
  headers: Array<{ seq: number; name: string; value: string }>;
  attachments: Array<{
    partIndex: number;
    filename: string | null;
    declaredContentType: string | null;
    detectedContentType: string | null;
    sizeBytes: number;
    sha256: string;
  }>;
  deliveries: Array<{
    recipientId: bigint;
    status: string;
    deliveredAt: Date | null;
    statusChangedAt: Date | null;
  }>;
}

export interface JournalBodies {
  text: string | null;
  html: string | null;
  truncated: boolean;
  unavailableReason: string | null;
}

const CODE = /^[a-z0-9][a-z0-9_.:-]{0,63}$/i;

/** Parse outcome codes (failure reason, exceeded limits, defect codes), bounded tokens only. */
export function parseCodes(parse: JournalInputs['parse']): string[] {
  if (parse === null) return [];
  const out = new Set<string>();
  const add = (value: unknown): void => {
    if (typeof value === 'string' && CODE.test(value)) out.add(value);
  };
  add(parse.failureReason);
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const v of value) {
        if (typeof v === 'string') add(v);
        else if (v && typeof v === 'object') add((v as { code?: unknown }).code);
      }
    } else if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) if (v) add(k);
    }
  };
  visit(parse.limitsExceeded);
  visit(parse.defects);
  return [...out].slice(0, 256);
}

/**
 * The decoded `.text` / `.html` parts for the sanitized preview (A5 step 4, A19): bounded Range
 * GETs (≤ `ARCHIVE_PREVIEW_PART_MAX_BYTES` each) of keys under `org/<organizationId>/part/` only.
 * A missing part is recorded as `unavailableReason`, never guessed.
 */
export async function readBodies(
  storage: ArchiveStorage,
  organizationId: bigint,
  parse: JournalInputs['parse'],
  maxBytes: number,
): Promise<JournalBodies> {
  if (parse === null)
    return { text: null, html: null, truncated: false, unavailableReason: 'not_parsed' };
  if (parse.textBodyObjectKey === null && parse.htmlBodyObjectKey === null) {
    return {
      text: null,
      html: null,
      truncated: false,
      unavailableReason: parse.status === 'parse_failed' ? 'parse_failed' : null,
    };
  }
  let truncated = false;
  let unavailable: string | null = null;
  const read = async (key: string | null): Promise<string | null> => {
    if (key === null) return null;
    if (!isKeyOfOrganization(key, organizationId, 'part')) {
      unavailable = 'foreign_key';
      return null;
    }
    try {
      const out = await storage.readRange(storage.buckets.mail, key, maxBytes);
      truncated ||= out.truncated;
      return out.bytes.toString('utf8');
    } catch (error) {
      if (isMissing(error)) {
        unavailable = 'part_missing';
        return null;
      }
      throw error;
    }
  };
  const text = await read(parse.textBodyObjectKey);
  const html = await read(parse.htmlBodyObjectKey);
  return { text, html, truncated, unavailableReason: unavailable };
}

const clip = (value: string | null, max: number): string | null =>
  value === null ? null : value.slice(0, max);

/** The `archive-journal/1` document (A5 step 4, §4.2); validated before it is encrypted. */
export function buildJournal(input: {
  facts: MessageFacts;
  inputs: JournalInputs;
  bodies: JournalBodies;
  captureId: string;
  capturedAt: Date;
  category: ArchiveCategory;
  sources: { journal: boolean; policy: boolean };
  policyRuleRef: string | null;
  settingsGeneration: bigint;
}): ArchiveJournal {
  const m = input.facts.message;
  const seqOf = new Map(input.facts.recipients.map((r) => [r.id.toString(), r.seq]));
  const journal: ArchiveJournal = {
    version: 'archive-journal/1',
    organizationId: m.organizationId.toString(),
    messageId: m.publicId,
    receivedAt: m.receivedAt.toISOString(),
    capturedAt: input.capturedAt.toISOString(),
    captureId: input.captureId,
    direction: m.direction,
    category: input.category,
    sources: {
      journal: input.sources.journal,
      policy: input.sources.policy,
      policyRuleRef: clip(input.policyRuleRef, 128),
    },
    settingsGeneration: Number(input.settingsGeneration),
    message: {
      internetMessageId: clip(m.internetMessageId, 998),
      envelopeFrom: m.envelopeFrom.slice(0, 320),
      headerFrom: clip(m.headerFrom, 320),
      subject: clip(m.subject, 998),
      sizeBytes: m.sizeBytes,
      emlSha256: m.emlSha256.toLowerCase(),
      clientIp: clip(m.clientIp, 45),
      clientHelo: clip(m.clientHelo, 255),
      clientName: clip(m.clientName, 255),
    },
    envelope: {
      recipients: input.facts.recipients.map((r) => ({
        seq: r.seq,
        address: r.address.slice(0, 320),
        direction: r.direction,
        status: r.status,
      })),
    },
    headers: input.inputs.headers.map((h) => ({
      name: h.name.slice(0, 128),
      value: h.value.slice(0, 65_536),
    })),
    parse: { status: input.inputs.parse?.status ?? null, codes: parseCodes(input.inputs.parse) },
    body: input.bodies,
    attachments: input.inputs.attachments.map((a) => ({
      partIndex: a.partIndex,
      fileName: clip(a.filename, 1024),
      contentType: clip(a.declaredContentType, 255),
      detectedType: clip(a.detectedContentType, 255),
      sizeBytes: a.sizeBytes,
      sha256: /^[0-9a-fA-F]{64}$/.test(a.sha256) ? a.sha256.toLowerCase() : null,
    })),
    deliveries: input.inputs.deliveries.flatMap((d) => {
      const seq = seqOf.get(d.recipientId.toString());
      if (seq === undefined) return [];
      return [
        {
          seq,
          status: d.status,
          finalAt: (d.deliveredAt ?? d.statusChangedAt)?.toISOString() ?? null,
        },
      ];
    }),
  };
  const parsed = archiveJournalSchema.safeParse(journal);
  if (!parsed.success) throw new ArchiveDocumentError('archive-journal/1');
  return parsed.data;
}
