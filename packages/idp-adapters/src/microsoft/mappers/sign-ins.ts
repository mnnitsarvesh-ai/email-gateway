/**
 * Entra sign-ins → normalized events (design note §3.2): error code 0 → success; MFA or
 * Conditional Access interruption codes → interrupted; others → failure `entra_<code>`.
 */
import { deviceIdHash } from '../../core/hash';
import {
  boundedText,
  canonicalIp,
  eventIdPart,
  isoUtc,
  normalizedAddress,
  providerLocation,
  riskLevel,
} from '../../core/normalize';
import type { ProviderEvent } from '../../port/ato-port';
import { ENTRA_INTERRUPT_CODES, MICROSOFT_PROVIDER } from '../constants';
import { signInSchema } from '../schemas';

export function deviceLabel(
  browser: string | null | undefined,
  os: string | null | undefined,
): string | undefined {
  const parts = [boundedText(browser, 46), boundedText(os, 46)].filter((p): p is string => !!p);
  if (parts.length === 0) return undefined;
  return parts.join(' · ').slice(0, 96);
}

export function mapSignIn(raw: unknown): ProviderEvent | null {
  const parsed = signInSchema.safeParse(raw);
  if (!parsed.success) return null;
  const record = parsed.data;
  const occurredAt = isoUtc(record.createdDateTime);
  if (!occurredAt) return null;
  const upn = boundedText(record.userPrincipalName, 256);
  const event: ProviderEvent = {
    provider: MICROSOFT_PROVIDER,
    eventId: `entra:${eventIdPart(record.id)}`.slice(0, 128),
    stream: 'sign_ins',
    occurredAt,
    identity: {
      provider: MICROSOFT_PROVIDER,
      externalId: record.userId,
      ...(upn ? { userPrincipalName: upn } : {}),
      ...(normalizedAddress(upn) ? { primaryEmail: normalizedAddress(upn) } : {}),
    },
  };
  const errorCode = record.status.errorCode;
  if (errorCode === 0) event.outcome = 'success';
  else if (ENTRA_INTERRUPT_CODES.has(errorCode)) event.outcome = 'interrupted';
  else {
    event.outcome = 'failure';
    event.failureCode = `entra_${errorCode}`;
  }
  const ip = canonicalIp(record.ipAddress);
  if (ip) event.ip = ip;
  const deviceId = record.deviceDetail?.deviceId?.trim();
  if (deviceId) event.deviceIdHash = deviceIdHash(deviceId);
  const label = deviceLabel(record.deviceDetail?.browser, record.deviceDetail?.operatingSystem);
  if (label) event.deviceLabel = label;
  const location = providerLocation(record.location);
  if (location) event.providerLocation = location;
  const level = riskLevel(record.riskLevelDuringSignIn);
  if (level) event.riskLevel = level;
  return event;
}
