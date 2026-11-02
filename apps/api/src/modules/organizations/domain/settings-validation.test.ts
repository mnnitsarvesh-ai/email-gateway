import { describe, expect, it } from 'vitest';
import type { z } from 'zod';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import {
  CreateOrganizationSchema,
  SettingsUpdateSchema,
  StatusChangeSchema,
  UpdateOrganizationSchema,
} from '../dto/organizations.schemas';
import {
  isValidCron,
  isValidLocale,
  isValidTimeZone,
  maxQuarantineRetentionDays,
  MAX_PREFERENCES_BYTES,
} from './settings-validation';

describe('isValidTimeZone', () => {
  it.each(['UTC', 'Europe/Berlin', 'Asia/Kolkata', 'Asia/Calcutta', 'America/Argentina/Salta'])(
    'accepts %s',
    (zone) => expect(isValidTimeZone(zone)).toBe(true),
  );
  it.each(['', 'Mars/Olympus', 'Europe', '+05:30', 'utc offset', 'Etc/GMT+99', 'x'.repeat(65)])(
    'rejects %j',
    (zone) => expect(isValidTimeZone(zone)).toBe(false),
  );
});

describe('isValidLocale', () => {
  it.each(['en', 'en-IN', 'pt-BR', 'zh-Hant-TW'])('accepts %s', (tag) =>
    expect(isValidLocale(tag)).toBe(true),
  );
  it.each(['e', 'en_US_', '12', 'not a locale', 'en-' + 'x'.repeat(20)])('rejects %j', (tag) =>
    expect(isValidLocale(tag)).toBe(false),
  );
});

describe('isValidCron', () => {
  it.each([
    '0 8 * * *',
    '*/15 * * * *',
    '0 8 * * MON-FRI',
    '0 0 1,15 * *',
    '30 6 * JAN-MAR 0',
    '0-30/5 9-17 * * 1-5',
    '0 0 * * 7',
  ])('accepts %j', (expr) => expect(isValidCron(expr)).toBe(true));

  it.each([
    '',
    '* * * *',
    '* * * * * *',
    '60 * * * *',
    '0 24 * * *',
    '0 0 0 * *',
    '0 0 * 13 *',
    '0 0 * * 8',
    '5-1 * * * *',
    '*/0 * * * *',
    '5/10 * * * *',
    '@daily',
    '0 0 ? * *',
    '0 0 L * *',
    'a b c d e',
  ])('rejects %j', (expr) => expect(isValidCron(expr)).toBe(false));
});

describe('maxQuarantineRetentionDays', () => {
  it('takes the lower of the organization limit and the platform maximum', () => {
    expect(maxQuarantineRetentionDays(30n, 90)).toBe(30);
    expect(maxQuarantineRetentionDays(120n, 90)).toBe(90);
  });
  it('ignores a missing bound and is null without any', () => {
    expect(maxQuarantineRetentionDays(null, 90)).toBe(90);
    expect(maxQuarantineRetentionDays(14n, null)).toBe(14);
    expect(maxQuarantineRetentionDays(null, null)).toBeNull();
  });
  it('never drops below one day', () => {
    expect(maxQuarantineRetentionDays(0n, 90)).toBe(1);
  });
});

function parse(
  schema: z.ZodType,
  value: unknown,
): { ok: true; value: unknown } | { ok: false; messages: string[] } {
  try {
    return { ok: true, value: new ZodValidationPipe(schema).transform(value) };
  } catch (err) {
    return { ok: false, messages: (err as { response: { message: string[] } }).response.message };
  }
}

describe('SettingsUpdateSchema', () => {
  it('accepts a partial update', () => {
    expect(parse(SettingsUpdateSchema, { timezone: 'Asia/Kolkata', digestEnabled: false }).ok).toBe(
      true,
    );
  });

  it('rejects an empty body, unknown fields and invalid values with path messages', () => {
    expect(parse(SettingsUpdateSchema, {})).toMatchObject({ ok: false });
    const result = parse(SettingsUpdateSchema, {
      timezone: 'Mars/Base',
      locale: 'x',
      digestSchedule: '* *',
      quarantineRetentionDays: 0,
      notificationEmail: 'nope',
      color: 'red',
    });
    expect(result.ok).toBe(false);
    const messages = result.ok ? [] : result.messages.join('\n');
    for (const path of [
      'timezone:',
      'locale:',
      'digestSchedule:',
      'quarantineRetentionDays:',
      'notificationEmail:',
    ]) {
      expect(messages).toContain(path);
    }
    expect(messages).toMatch(/color/);
  });

  it('bounds preferences to 16 KiB', () => {
    const big = { blob: 'x'.repeat(MAX_PREFERENCES_BYTES) };
    expect(parse(SettingsUpdateSchema, { preferences: big })).toMatchObject({ ok: false });
    expect(parse(SettingsUpdateSchema, { preferences: { theme: 'dark' } }).ok).toBe(true);
    expect(parse(SettingsUpdateSchema, { preferences: ['not', 'an', 'object'] }).ok).toBe(false);
  });

  it('never echoes input values in messages', () => {
    const result = parse(SettingsUpdateSchema, { timezone: 'SECRET-VALUE-123' });
    expect(result.ok ? '' : result.messages.join()).not.toContain('SECRET-VALUE-123');
  });
});

describe('CreateOrganizationSchema', () => {
  const base = {
    name: 'Acme',
    slug: 'acme-corp',
    planCode: 'standard',
    deploymentMode: 'saas',
    dataRegion: 'ap-south-1',
  };

  it('accepts a SaaS organization', () => {
    expect(parse(CreateOrganizationSchema, base).ok).toBe(true);
  });

  it.each(['platform', 'admin', 'api', 'www', 'system'])('rejects the reserved slug %s', (slug) => {
    expect(parse(CreateOrganizationSchema, { ...base, slug })).toMatchObject({
      ok: false,
      messages: ['slug: is reserved'],
    });
  });

  it.each(['ab', '-acme', 'acme-', 'Acme', 'ac_me', 'a'.repeat(64)])(
    'rejects the slug %j',
    (slug) => {
      expect(parse(CreateOrganizationSchema, { ...base, slug }).ok).toBe(false);
    },
  );

  it.each(['ap-south', 'AP-SOUTH-1', 'apsouth1', 'ap-south-12'])(
    'rejects the region %j',
    (dataRegion) => {
      expect(parse(CreateOrganizationSchema, { ...base, dataRegion }).ok).toBe(false);
    },
  );

  it('requires deployment details exactly for dedicated deployments', () => {
    expect(parse(CreateOrganizationSchema, { ...base, deploymentMode: 'dedicated' })).toMatchObject(
      {
        ok: false,
        messages: ['deployment: is required for a dedicated deployment'],
      },
    );
    const deployment = { region: 'eu-west-1', environment: 'prod-eu' };
    expect(
      parse(CreateOrganizationSchema, { ...base, deploymentMode: 'dedicated', deployment }).ok,
    ).toBe(true);
    expect(parse(CreateOrganizationSchema, { ...base, deployment }).ok).toBe(false);
  });

  it('validates the initial administrator and nested settings', () => {
    expect(
      parse(CreateOrganizationSchema, {
        ...base,
        initialAdmin: { email: 'Admin@Acme.Test', displayName: 'Admin' },
        settings: { timezone: 'Europe/Berlin' },
      }),
    ).toMatchObject({ ok: true, value: { initialAdmin: { email: 'admin@acme.test' } } });
    expect(parse(CreateOrganizationSchema, { ...base, initialAdmin: { email: 'x' } }).ok).toBe(
      false,
    );
    expect(parse(CreateOrganizationSchema, { ...base, settings: { timezone: 'Nowhere' } }).ok).toBe(
      false,
    );
  });
});

describe('UpdateOrganizationSchema', () => {
  it('passes name and planCode through', () => {
    expect(parse(UpdateOrganizationSchema, { name: 'New', planCode: 'enterprise' })).toEqual({
      ok: true,
      value: { name: 'New', planCode: 'enterprise' },
    });
  });

  it('rejects immutable fields with a 400 message per field', () => {
    const result = parse(UpdateOrganizationSchema, {
      name: 'New',
      slug: 'other',
      kind: 'platform',
      deploymentMode: 'dedicated',
      dataRegion: 'eu-west-1',
    });
    expect(result).toEqual({
      ok: false,
      messages: [
        'slug: is immutable',
        'kind: is immutable',
        'deploymentMode: is immutable',
        'dataRegion: is immutable',
      ],
    });
  });
});

describe('StatusChangeSchema', () => {
  it('requires a reason to suspend, not to reactivate', () => {
    expect(parse(StatusChangeSchema, { status: 'suspended' })).toMatchObject({
      ok: false,
      messages: ['reason: is required when suspending'],
    });
    expect(parse(StatusChangeSchema, { status: 'suspended', reason: 'Unpaid invoices' }).ok).toBe(
      true,
    );
    expect(parse(StatusChangeSchema, { status: 'active' }).ok).toBe(true);
    expect(parse(StatusChangeSchema, { status: 'deleted', reason: 'xyz' }).ok).toBe(false);
  });
});
