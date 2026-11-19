import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  AUTH_CHANNELS,
  AUTH_OUTCOMES,
  AUTH_SOURCES,
  GEO_STATUSES,
  GROUP_CAPS,
  RESPONSE_AUTHORIZATIONS,
  RESPONSE_IMPACTS,
  RESPONSE_PROVIDER_STATUSES,
  RESPONSE_STATUSES,
  SCORE_TRIGGERS,
  SIGNAL_CATEGORIES,
  SIGNAL_SOURCE_KINDS,
  SIGNAL_STATUSES,
  SIGNAL_STRENGTHS,
} from './taxonomy';

const schema = readFileSync(resolve(__dirname, '../../database/prisma/schema.prisma'), 'utf8');

function prismaEnum(name: string): string[] {
  const match = new RegExp(`enum ${name} \\{([^}]*)\\}`).exec(schema);
  if (!match) throw new Error(`enum ${name} not found`);
  return match[1]!
    .split('\n')
    .map((l) => l.replace(/\/\/.*$/, '').trim())
    .filter((l) => l.length > 0);
}

describe('taxonomy equals the Prisma enums', () => {
  it.each([
    ['AtoSignalCategory', SIGNAL_CATEGORIES],
    ['AtoSignalStrength', SIGNAL_STRENGTHS],
    ['AtoSignalStatus', SIGNAL_STATUSES],
    ['AtoSignalSourceKind', SIGNAL_SOURCE_KINDS],
    ['AtoScoreTrigger', SCORE_TRIGGERS],
    ['AtoResponseStatus', RESPONSE_STATUSES],
    ['AtoResponseImpact', RESPONSE_IMPACTS],
    ['AtoResponseAuthorization', RESPONSE_AUTHORIZATIONS],
    ['AtoProviderStatus', RESPONSE_PROVIDER_STATUSES],
    ['AtoAuthSource', AUTH_SOURCES],
    ['AtoAuthChannel', AUTH_CHANNELS],
    ['AtoAuthOutcome', AUTH_OUTCOMES],
    ['AtoGeoStatus', GEO_STATUSES],
  ] as const)('%s', (name, list) => {
    expect(prismaEnum(name)).toEqual([...list]);
  });

  it('group caps of ato-score/1 (D11)', () => {
    expect(GROUP_CAPS).toEqual({
      authentication: 50,
      access_context: 30,
      geography: 40,
      threat_intel: 60,
      account_change: 50,
      outbound_behaviour: 50,
      outbound_content: 70,
      mailbox_configuration: 60,
      oauth_activity: 50,
      provider_risk: 60,
      correlation: 60,
    });
  });
});
