import { z } from 'zod';
import type { RequestBody } from '@/lib/api/types';

export const LOOKUP_TYPES = ['sha256', 'url', 'domain', 'ip'] as const;
export const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export const CATEGORIES = ['phishing', 'malware', 'spam', 'scam', 'c2', 'other'] as const;
export const INDICATOR_TYPES = ['url', 'domain', 'ip'] as const;

const SHA256 = /^[0-9a-f]{64}$/;
const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+\.?$/i;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:.]+$/i;

/** Client checks matching the api's rules (the api normalizes and decides). */
export function indicatorValueError(
  type: (typeof LOOKUP_TYPES)[number],
  value: string,
): string | null {
  if (type === 'sha256')
    return SHA256.test(value) ? null : 'Enter 64 lower-case hexadecimal characters';
  if (type === 'url') {
    if (value.length > 2048) return 'At most 2048 characters';
    try {
      const url = new URL(value);
      return url.protocol === 'http:' || url.protocol === 'https:'
        ? null
        : 'Use an http or https URL';
    } catch {
      return 'Enter an absolute URL such as https://example.com/path';
    }
  }
  if (type === 'domain')
    return DOMAIN.test(value) ? null : 'Enter a domain name such as login.example.com';
  return IPV4.test(value) || (value.includes(':') && IPV6.test(value))
    ? null
    : 'Enter an IPv4 or IPv6 address';
}

export const lookupSchema = z
  .object({
    type: z.enum(LOOKUP_TYPES),
    value: z.string().trim().min(1, 'Enter a value').max(2048),
  })
  .strict()
  .superRefine((v, ctx) => {
    const error = v.value
      ? indicatorValueError(v.type, v.type === 'sha256' ? v.value.toLowerCase() : v.value)
      : null;
    if (error) ctx.addIssue({ code: 'custom', path: ['value'], message: error });
  })
  .transform((v) => ({
    type: v.type,
    value: v.type === 'sha256' ? v.value.toLowerCase() : v.value,
  }));

/** `YYYY-MM-DD` (end of that UTC day) → ISO, empty → undefined. */
export function expiryIso(day: string): string | undefined {
  return day ? new Date(`${day}T23:59:59.000Z`).toISOString() : undefined;
}

const futureDay = z
  .string()
  .refine(
    (d) => d === '' || (/^\d{4}-\d{2}-\d{2}$/.test(d) && Date.parse(`${d}T23:59:59Z`) > Date.now()),
    {
      message: 'Choose a future date or leave it empty',
    },
  );

export const addHashSchema = z
  .object({
    sha256: z
      .string()
      .trim()
      .toLowerCase()
      .regex(SHA256, 'Enter 64 lower-case hexadecimal characters'),
    md5: z
      .string()
      .trim()
      .toLowerCase()
      .refine((v) => v === '' || /^[0-9a-f]{32}$/.test(v), {
        message: '32 hexadecimal characters or empty',
      }),
    severity: z.enum(SEVERITIES),
    family: z.string().trim().max(128),
    reason: z.string().trim().min(1, 'Enter a reason').max(512),
    expiresOn: futureDay,
  })
  .strict();

export function addHashBody(
  values: z.output<typeof addHashSchema>,
): RequestBody<'ThreatHashesController_add_v1'> {
  const expiresAt = expiryIso(values.expiresOn);
  return {
    sha256: values.sha256,
    ...(values.md5 ? { md5: values.md5 } : {}),
    severity: values.severity,
    ...(values.family ? { family: values.family } : {}),
    reason: values.reason,
    ...(expiresAt ? { expiresAt } : {}),
  };
}

export const addIndicatorSchema = z
  .object({
    type: z.enum(INDICATOR_TYPES),
    value: z.string().trim().min(1, 'Enter a value').max(4096),
    severity: z.enum(SEVERITIES),
    category: z.enum(CATEGORIES),
    reason: z.string().trim().min(1, 'Enter a reason').max(512),
    expiresOn: futureDay,
  })
  .strict()
  .superRefine((v, ctx) => {
    const error = v.value ? indicatorValueError(v.type, v.value) : null;
    if (error) ctx.addIssue({ code: 'custom', path: ['value'], message: error });
  });

export function addIndicatorBody(
  values: z.output<typeof addIndicatorSchema>,
): RequestBody<'ThreatIndicatorsController_add_v1'> {
  const expiresAt = expiryIso(values.expiresOn);
  return {
    type: values.type,
    value: values.value,
    severity: values.severity,
    category: values.category,
    reason: values.reason,
    ...(expiresAt ? { expiresAt } : {}),
  };
}
