import { CLICK_DECISIONS } from '@email-gateway/security-contracts';
import { z } from 'zod';
import { defineListQuery } from '../../http/listing/list-query';
import {
  tenantUrlShape,
  UrlClickDecisionSchema,
  UrlRewriteViewSchema,
} from '../messages/dto/message-scans.schemas';

/**
 * Request and response shapes of the step 6.1 URL protection routes (WP2, §3.3):
 * `GET /messages/{messageId}/urls` and `GET /url-protection/clicks`. The tenant URL shape of the
 * scans view (never the cross-tenant cache outcomes); clicks never carry token material or the
 * token key id.
 */

export const MESSAGE_URLS_RESOURCE = 'message_urls';
export const URL_CLICKS_RESOURCE = 'url_clicks';

/** `GET /url-protection/clicks`: default 24 h, at most 31 days (§3.3). */
export const CLICKS_MAX_RANGE_DAYS = 31;

export const URL_VERDICTS = ['clean', 'suspicious', 'malicious', 'unknown'] as const;

export const MessageUrlsQuerySchema = defineListQuery({
  filters: {},
  sorts: ['urlSeq'],
  defaultSort: 'urlSeq',
});
export type MessageUrlsQuery = z.output<typeof MessageUrlsQuerySchema>;

export const UrlClicksQuerySchema = defineListQuery({
  filters: {
    decision: { type: 'enum', values: CLICK_DECISIONS, maxValues: 6 },
    verdict: { type: 'enum', values: URL_VERDICTS, maxValues: 4 },
    messageId: { type: 'publicId' },
  },
  sorts: ['-clickedAt'],
  defaultSort: '-clickedAt',
  range: true,
});
export type UrlClicksQuery = z.output<typeof UrlClicksQuerySchema>;

export const URL_CLICKS_PARAMETERS: Record<string, string> = {
  from: 'Start of the range (ISO 8601 with offset, inclusive); default `to` − 24 h',
  to: 'End of the range (exclusive); default now. At most 31 days',
  decision:
    'Click decision(s): `allowed`, `warned`, `blocked`, `continued`, `expired`, `not_found`',
  verdict: 'Verdict(s) at click time: `clean`, `suspicious`, `malicious`, `unknown`',
  messageId: 'Public id of one of your messages (`404 message_not_found` otherwise)',
  limit: 'Page size, 1-100 (default 25). A page may hold fewer rows (see the scan budget).',
  cursor: '`nextCursor` of the previous page',
  sort: '`-clickedAt` (the only order: newest first)',
};

const IsoDate = z.iso.datetime();

/** The `message_urls` part of the tenant URL view (step 4.3 U16). */
const UrlFieldsSchema = z.object(tenantUrlShape).pick({
  urlSeq: true,
  url: true,
  host: true,
  unicodeHost: true,
  registrableDomain: true,
  hostKind: true,
  sources: true,
  flags: true,
});

export const MessageUrlItemSchema = UrlFieldsSchema.extend({
  latest: z
    .object({
      round: z.number().int().min(0),
      verdict: tenantUrlShape.verdict,
      reasonCodes: z.array(z.string()),
      rewritten: z.boolean(),
    })
    .nullable()
    .describe(
      'Result of the newest scan round that checked the URL; null before the url engine ran',
    ),
  rewrite: UrlRewriteViewSchema.pick({ status: true, skipReason: true })
    .extend({ round: z.number().int().min(0) })
    .nullable()
    .describe('Rewrite of the message’s latest rewritten round (the same for every URL)'),
  clicks: z.object({
    total: z.number().int().min(0),
    byDecision: z.partialRecord(UrlClickDecisionSchema, z.number().int().min(1)),
  }),
});
export type MessageUrlItem = z.output<typeof MessageUrlItemSchema>;

export const MessageUrlsPageSchema = z.object({
  data: z.array(MessageUrlItemSchema),
  nextCursor: z.string().nullable(),
});
export type MessageUrlsPage = z.output<typeof MessageUrlsPageSchema>;

export const UrlClickItemSchema = z.object({
  id: z.uuid().describe('Click public id (the reference id shown on the click pages)'),
  clickedAt: IsoDate,
  decision: UrlClickDecisionSchema,
  verdict: z.enum(URL_VERDICTS).nullable(),
  reasonCodes: z.array(z.string()),
  messageId: z.uuid().nullable().describe('Message public id (null once the message is purged)'),
  urlSeq: z.number().int().min(0),
  host: z.string().nullable(),
  registrableDomain: z.string().nullable(),
  clientNetwork: z.string().nullable().describe('/24 IPv4 or /48 IPv6 network, when stored'),
});
export type UrlClickItem = z.output<typeof UrlClickItemSchema>;

export const UrlClicksPageSchema = z.object({
  data: z.array(UrlClickItemSchema),
  nextCursor: z.string().nullable(),
});
export type UrlClicksPage = z.output<typeof UrlClicksPageSchema>;

export const URL_EXAMPLES = {
  messagePage: {
    data: [
      {
        urlSeq: 0,
        url: 'https://login.example-bank.test/verify?id=42',
        host: 'login.example-bank.test',
        unicodeHost: null,
        registrableDomain: 'example-bank.test',
        hostKind: 'domain',
        sources: { html_href: 1 },
        flags: [],
        latest: {
          round: 0,
          verdict: 'malicious',
          reasonCodes: ['url.feed_malicious'],
          rewritten: true,
        },
        rewrite: { round: 0, status: 'rewritten', skipReason: null },
        clicks: { total: 3, byDecision: { blocked: 2, continued: 1 } },
      },
    ],
    nextCursor: null,
  },
  clicksPage: {
    data: [
      {
        id: '0193a1c4-11aa-7bcd-8e0f-112233445566',
        clickedAt: '2026-11-12T09:01:12.500Z',
        decision: 'blocked',
        verdict: 'malicious',
        reasonCodes: ['url.feed_malicious'],
        messageId: '0193a1b2-7c3d-7e4f-8a5b-6c7d8e9f0a1b',
        urlSeq: 0,
        host: 'login.example-bank.test',
        registrableDomain: 'example-bank.test',
        clientNetwork: '203.0.113.0/24',
      },
    ],
    nextCursor: null,
  },
} as const;
