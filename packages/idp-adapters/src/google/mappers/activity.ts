/**
 * Shared parts of the Reports activity mappers (design note §3.1): event ids, identities, IPs and
 * provider locations of one activity, and parameter access. An activity may carry several events;
 * each mapped event gets `gws:<application>:<time ms>:<uniqueQualifier>:<event index>` (the Reports
 * `uniqueQualifier` is unique only together with the time).
 */
import { canonicalIp, eventIdPart, isoUtc, normalizedAddress } from '../../core/normalize';
import type { ProviderEvent, ProviderStream } from '../../port/ato-port';
import { GOOGLE_PROVIDER, type ReportsApplication } from '../constants';
import type { GoogleActivity, GoogleActivityEvent } from '../schemas';

/** One mapping outcome per activity event. */
export type ActivityEventResult =
  | { kind: 'event'; event: ProviderEvent }
  | { kind: 'dropped'; stream: ProviderStream }
  | { kind: 'invalid'; stream: ProviderStream };

export function parameter(event: GoogleActivityEvent, name: string): string | undefined {
  const found = event.parameters?.find((p) => p.name === name);
  if (!found) return undefined;
  if (typeof found.value === 'string') return found.value;
  if (typeof found.intValue === 'string' || typeof found.intValue === 'number') {
    return String(found.intValue);
  }
  if (typeof found.boolValue === 'boolean') return String(found.boolValue);
  return undefined;
}

export function multiParameter(event: GoogleActivityEvent, name: string): string[] {
  const found = event.parameters?.find((p) => p.name === name);
  if (!found) return [];
  if (Array.isArray(found.multiValue)) return found.multiValue;
  if (typeof found.value === 'string') return found.value.split(/\s+/).filter(Boolean);
  return [];
}

/**
 * The event skeleton of an activity's event; `null` when the activity carries no usable identity
 * or time (the event is then counted `invalid`).
 */
export function activityEvent(
  activity: GoogleActivity,
  application: ReportsApplication,
  index: number,
  stream: ProviderStream,
): ProviderEvent | null {
  const occurredAt = isoUtc(activity.id.time);
  const profileId = activity.actor?.profileId?.trim();
  if (!occurredAt || !profileId || !/^[A-Za-z0-9_-]{1,128}$/.test(profileId)) return null;
  const email = normalizedAddress(activity.actor?.email);
  const eventId = `gws:${application}:${Date.parse(occurredAt)}:${eventIdPart(String(activity.id.uniqueQualifier))}:${index}`;
  if (eventId.length > 128) return null;
  const event: ProviderEvent = {
    provider: GOOGLE_PROVIDER,
    eventId,
    stream,
    occurredAt,
    identity: {
      provider: GOOGLE_PROVIDER,
      externalId: profileId,
      ...(email ? { primaryEmail: email } : {}),
    },
  };
  const ip = canonicalIp(activity.ipAddress);
  if (ip) event.ip = ip;
  const region = activity.networkInfo?.regionCode?.trim().toUpperCase();
  if (region && /^[A-Z]{2}$/.test(region)) event.providerLocation = { countryCode: region };
  return event;
}
