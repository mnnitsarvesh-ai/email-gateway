/**
 * Entra risk detections → normalized events (design note §3.2): token risk types go to stream
 * `session_events`, others to `risk_events`; dismissed detections are dropped; `hidden` levels
 * (no Entra ID P2) are omitted.
 */
import {
  boundedText,
  canonicalIp,
  code64,
  eventIdPart,
  isoUtc,
  normalizedAddress,
  providerLocation,
  riskLevel,
} from '../../core/normalize';
import type { ProviderEvent } from '../../port/ato-port';
import { MICROSOFT_PROVIDER, TOKEN_RISK_TYPES } from '../constants';
import { riskDetectionSchema } from '../schemas';

export type RiskMapResult =
  { kind: 'event'; event: ProviderEvent } | { kind: 'dropped' } | { kind: 'invalid' };

export function mapRiskDetection(raw: unknown): RiskMapResult {
  const parsed = riskDetectionSchema.safeParse(raw);
  if (!parsed.success) return { kind: 'invalid' };
  const record = parsed.data;
  if (record.riskState === 'dismissed') return { kind: 'dropped' };
  const occurredAt = isoUtc(
    record.activityDateTime ?? record.detectedDateTime ?? record.lastUpdatedDateTime,
  );
  if (!occurredAt) return { kind: 'invalid' };
  const upn = boundedText(record.userPrincipalName, 256);
  const email = normalizedAddress(upn);
  const stream = TOKEN_RISK_TYPES.has(record.riskEventType) ? 'session_events' : 'risk_events';
  const event: ProviderEvent = {
    provider: MICROSOFT_PROVIDER,
    eventId: `entra:risk:${eventIdPart(record.id)}`.slice(0, 128),
    stream,
    occurredAt,
    identity: {
      provider: MICROSOFT_PROVIDER,
      externalId: record.userId,
      ...(upn ? { userPrincipalName: upn } : {}),
      ...(email ? { primaryEmail: email } : {}),
    },
    // 8.4 codes are lower-case; token risk types are 8.4's `token_anomaly` (rule Q2, WP3-2).
    riskDetail:
      stream === 'session_events' ? 'token_anomaly' : code64(record.riskEventType) || 'entra_risk',
  };
  const level = riskLevel(record.riskLevel);
  if (level) event.riskLevel = level;
  const ip = canonicalIp(record.ipAddress);
  if (ip) event.ip = ip;
  const location = providerLocation(record.location);
  if (location) event.providerLocation = location;
  return { kind: 'event', event };
}
