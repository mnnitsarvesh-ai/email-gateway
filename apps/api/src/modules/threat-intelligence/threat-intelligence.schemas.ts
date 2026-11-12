import { z } from 'zod';
import { LOOKUP_TYPES } from './domain/lookup-value';

/** `GET /threat-intelligence/lookup` (step 6.1 §3.3). */
export const ThreatLookupQuerySchema = z.strictObject({
  type: z.enum(LOOKUP_TYPES).describe('What `value` is'),
  value: z
    .string()
    .min(1)
    .max(2048)
    .describe(
      'sha256: 64 hex characters; url: absolute http(s) URL (≤ 2048); domain: DNS name ' +
        '(≤ 253, not a public suffix); ip: IPv4 or IPv6 literal',
    ),
});
export type ThreatLookupQuery = z.output<typeof ThreatLookupQuerySchema>;

export const MATCH_SOURCES = ['platform_indicator', 'hash_catalog'] as const;

export const ThreatLookupResponseSchema = z.object({
  type: z.enum(LOOKUP_TYPES),
  valueSha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .describe('SHA-256 of the normalized value (the indicator key; never the value itself)'),
  known: z.boolean().describe('True when at least one platform source lists the value'),
  matches: z.array(
    z.object({
      source: z.enum(MATCH_SOURCES),
      severity: z.enum(['low', 'medium', 'high', 'critical']),
      category: z.enum(['phishing', 'malware', 'spam', 'scam', 'c2', 'other']).nullable(),
      firstSeenAt: z.iso.datetime(),
      lastSeenAt: z.iso.datetime(),
      expiresAt: z.iso.datetime().nullable(),
    }),
  ),
});
export type ThreatLookupResponse = z.output<typeof ThreatLookupResponseSchema>;

export const THREAT_LOOKUP_EXAMPLE: ThreatLookupResponse = {
  type: 'domain',
  valueSha256: 'a3c9d0f1e2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e',
  known: true,
  matches: [
    {
      source: 'platform_indicator',
      severity: 'high',
      category: 'phishing',
      firstSeenAt: '2026-11-02T08:15:00.000Z',
      lastSeenAt: '2026-11-11T17:40:00.000Z',
      expiresAt: '2026-12-02T08:15:00.000Z',
    },
  ],
};
