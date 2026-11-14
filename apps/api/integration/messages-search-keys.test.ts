/**
 * Parity of the step 7.2 search keys (docs/plan/steps/21-email-explorer-details.md §2 E1, §3.1):
 * a corpus of subjects, Message-IDs, envelope senders and recipient addresses is inserted on the
 * writer, and for every row the TypeScript normalizer of `domain/search-keys.ts` must equal the
 * VIRTUAL generated column MySQL computes (`subject_key`, `message_id_key`, `sender_domain`,
 * `address_domain`), character for character. The corpus covers reply markers in several
 * languages and forms, every White_Space code point, JavaScript-only whitespace (U+FEFF),
 * non-ASCII and right-to-left text, supplementary characters, 200-character subjects, the
 * subjects that made the design's pattern time out (§13 WP1), Message-IDs with and without
 * brackets, the null sender and addresses without or with several `@`.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  domainOf,
  normalizeMessageIdKey,
  normalizeSubjectKey,
} from '../src/modules/messages/domain/search-keys';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { deleteMessagesData } from './support/messages-data';

const WHITE_SPACE = [
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
  0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
].map((cp) => String.fromCodePoint(cp));

const SUBJECTS: string[] = [
  'Re: Hello',
  'RE:Hello',
  're : Hello',
  'Fwd: Re: AW: WG: Hello',
  'FW: fwd: Hello',
  'Re[3]: Hello',
  'RE [12] : Hello',
  'Re[]: Hello',
  'RE [ 2]: x',
  'Sv: Vs: Antw: TR: RIF: Enc: Odp: Hello',
  'ſv: long s folds to s',
  'Hello: Re: world',
  'trace: not a marker',
  'Re',
  'Re:',
  'Re: Re:  ',
  '',
  '   ',
  'Hello   world',
  '\tRe:\tTabbed\t\tsubject\t',
  `${WHITE_SPACE.join('')}Re:${WHITE_SPACE.join('')}every${WHITE_SPACE.join('')}space${WHITE_SPACE.join('')}`,
  'zero​width and BOM﻿ kept',
  'NEL\u0085collapsed',
  'Re: Überweisung für Müller',
  'Re: Ödeme talimatı',
  'Re: 请查收发票',
  'Re: מסמך חשוב לחתימה',
  'Re: فاتورة مستحقة',
  'Re: ‮evil‬ override',
  'Re: 😀 emoji 🔥 subject',
  `Re: ${'x'.repeat(196)}`,
  `Fwd: ${'é'.repeat(200)}`,
  `${'😀'.repeat(140)}`,
  `re${' '.repeat(990)}x`,
  `re${' '.repeat(480)}[12]${' '.repeat(500)}x`,
  're: '.repeat(249),
  `${'re '.repeat(330)}x`,
  `${'re[1]'.repeat(190)}x`,
  `re[${'1'.repeat(990)}x`,
  ' '.repeat(998),
  'Invoice 100% off_now!',
];

const MESSAGE_IDS: Array<string | null> = [
  '<abc@mx.example>',
  'abc@mx.example',
  '  <abc@mx.example>  ',
  '<<<abc@mx.example>>>',
  '< abc@mx.example >',
  '\t<abc>\t',
  '<>',
  '',
  'a>b<c',
  `<${'m'.repeat(300)}@x.example>`,
  `<${'ü'.repeat(300)}>`,
  null,
];

const SENDERS = [
  'alice@example.com',
  'Alice@Mail.Example.COM',
  '',
  'postmaster',
  'a@b@c.example',
  'x@',
  'a＠b.example',
  `a@${'d'.repeat(300)}`,
  'bücher@xn--bcher-kva.example',
];

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
const receivedAt = new Date(Date.now() - 60_000);
let nextId = BigInt(Date.now()) * 1000n;

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  fx.registerCleanup(() => deleteMessagesData(ctx, [org.id]));
}, 120_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 120_000);

async function insertMessage(over: {
  subject?: string | null;
  internetMessageId?: string | null;
  envelopeFrom?: string;
}): Promise<bigint> {
  nextId += 1n;
  await ctx.prisma.emailMessage.create({
    data: {
      id: nextId,
      receivedAt,
      organizationId: org.id,
      direction: 'inbound',
      statusChangedAt: receivedAt,
      envelopeFrom: over.envelopeFrom ?? 'sender@vendor.example',
      subject: over.subject === undefined ? null : over.subject,
      internetMessageId: over.internetMessageId === undefined ? null : over.internetMessageId,
      sizeBytes: 10,
      recipientCount: 1,
      emlObjectKey: `it/${randomUUID()}.eml`,
      emlSha256: 'a'.repeat(64),
    },
  });
  return nextId;
}

const keysOf = (id: bigint) =>
  ctx.prisma.emailMessage.findFirstOrThrow({
    where: { id, receivedAt, organizationId: org.id },
    select: { subject: true, subjectKey: true, messageIdKey: true, senderDomain: true },
  });

describe('search key parity: TypeScript normalizers === MySQL generated columns', () => {
  it.each(SUBJECTS.map((s, i) => [i, s]))('subject #%i', async (_i, subject) => {
    const id = await insertMessage({ subject });
    const row = await keysOf(id);
    expect(row.subject).toBe(subject);
    expect(row.subjectKey).toBe(normalizeSubjectKey(subject));
  });

  it('a NULL subject has a NULL key', async () => {
    expect((await keysOf(await insertMessage({ subject: null }))).subjectKey).toBeNull();
  });

  it.each(MESSAGE_IDS.map((m, i) => [i, m]))('Message-ID #%i', async (_i, internetMessageId) => {
    const row = await keysOf(await insertMessage({ internetMessageId }));
    expect(row.messageIdKey).toBe(
      internetMessageId === null ? null : normalizeMessageIdKey(internetMessageId),
    );
  });

  it.each(SENDERS.map((s, i) => [i, s]))('envelope sender #%i', async (_i, envelopeFrom) => {
    const row = await keysOf(await insertMessage({ envelopeFrom }));
    expect(row.senderDomain).toBe(domainOf(envelopeFrom));
  });

  it('recipient address domains', async () => {
    const id = await insertMessage({});
    const addresses = [
      'bob@Partner.Example',
      'noat',
      'a@b@c.example',
      'x@',
      'a＠b.example',
      `r@${'p'.repeat(300)}`,
    ];
    await ctx.prisma.emailRecipient.createMany({
      data: addresses.map((address, rcptSeq) => ({
        receivedAt,
        messageId: id,
        organizationId: org.id,
        rcptSeq,
        address,
      })),
    });
    const rows = await ctx.prisma.emailRecipient.findMany({
      where: { messageId: id, receivedAt },
      select: { address: true, addressDomain: true },
      orderBy: { rcptSeq: 'asc' },
    });
    expect(rows.map((r) => r.addressDomain)).toEqual(addresses.map(domainOf));
  });

  it('the generated key is case-insensitive under its collation (the search compares there)', async () => {
    const id = await insertMessage({ subject: 'Re: Quarterly REPORT Ö' });
    const found = await ctx.prisma.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM email_messages
      WHERE organization_id = ${org.id} AND subject_key = ${'quarterly report o'}
        AND received_at = ${receivedAt}`;
    expect(found.map((r) => BigInt(r.id))).toContain(id);
  });
});
