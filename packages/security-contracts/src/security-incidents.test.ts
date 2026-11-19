import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  ATO_ACCOUNT_KINDS,
  ATO_RISK_LEVELS,
  isActiveSecurityIncidentStatus,
  SECURITY_INCIDENT_ACTIVE_STATUSES,
  SECURITY_INCIDENT_CATEGORIES,
  SECURITY_INCIDENT_LINK_TYPES,
  SECURITY_INCIDENT_ORIGINS,
  SECURITY_INCIDENT_RESOLUTION_CODES,
  SECURITY_INCIDENT_SEVERITIES,
  SECURITY_INCIDENT_STATUSES,
  SECURITY_INCIDENT_SUBJECT_TYPES,
  securityIncidentResolutionCodeSchema,
  securityIncidentSeverityRank,
  securityIncidentStatusSchema,
} from './index';

describe('security incident vocabulary (step 8.4 D24, §3.1)', () => {
  it('starts with the ATO category, subject, links and origins (append-only lists)', () => {
    expect([...SECURITY_INCIDENT_CATEGORIES]).toEqual(['account_takeover']);
    expect([...SECURITY_INCIDENT_SUBJECT_TYPES]).toEqual(['ato_account']);
    expect([...SECURITY_INCIDENT_LINK_TYPES]).toEqual(['message', 'ato_signal', 'ato_auth_event']);
    expect([...SECURITY_INCIDENT_ORIGINS]).toEqual(['detection', 'manual']);
  });

  it('has six states, four of them active', () => {
    expect([...SECURITY_INCIDENT_STATUSES]).toEqual([
      'open',
      'investigating',
      'confirmed',
      'false_positive',
      'mitigated',
      'resolved',
    ]);
    expect([...SECURITY_INCIDENT_ACTIVE_STATUSES]).toEqual([
      'open',
      'investigating',
      'confirmed',
      'mitigated',
    ]);
    const terminal = SECURITY_INCIDENT_STATUSES.filter((s) => !isActiveSecurityIncidentStatus(s));
    expect(terminal).toEqual(['false_positive', 'resolved']);
    expect(isActiveSecurityIncidentStatus('closed')).toBe(false);
    expect(securityIncidentStatusSchema.safeParse('closed').success).toBe(false);
  });

  it('orders severities and lists the resolution codes', () => {
    expect([...SECURITY_INCIDENT_SEVERITIES]).toEqual(['low', 'medium', 'high', 'critical']);
    expect(SECURITY_INCIDENT_SEVERITIES.map(securityIncidentSeverityRank)).toEqual([0, 1, 2, 3]);
    expect([...SECURITY_INCIDENT_RESOLUTION_CODES]).toEqual([
      'remediated',
      'false_positive',
      'benign_activity',
      'duplicate',
      'other',
    ]);
    expect(securityIncidentResolutionCodeSchema.safeParse('fixed').success).toBe(false);
  });
});

/**
 * The Prisma enums mirror these lists (§3.3). The database package does not depend on this one,
 * so the comparison reads `schema.prisma` itself: a value added on one side only fails here.
 */
describe('Prisma enums equal the shared vocabulary', () => {
  const schema = readFileSync(resolve(__dirname, '../../database/prisma/schema.prisma'), 'utf8');
  const prismaEnum = (name: string): string[] => {
    const match = new RegExp(`^enum ${name} \\{\\n([\\s\\S]*?)^\\}`, 'm').exec(schema);
    if (!match?.[1]) throw new Error(`enum ${name} not found`);
    return match[1]
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '' && !line.startsWith('//'));
  };

  it.each([
    ['SecurityIncidentCategory', SECURITY_INCIDENT_CATEGORIES],
    ['SecurityIncidentSubjectType', SECURITY_INCIDENT_SUBJECT_TYPES],
    ['SecurityIncidentLinkType', SECURITY_INCIDENT_LINK_TYPES],
    ['SecurityIncidentOrigin', SECURITY_INCIDENT_ORIGINS],
    ['SecurityIncidentStatus', SECURITY_INCIDENT_STATUSES],
    ['SecurityIncidentSeverity', SECURITY_INCIDENT_SEVERITIES],
    ['SecurityIncidentResolutionCode', SECURITY_INCIDENT_RESOLUTION_CODES],
    ['AtoRiskLevel', ATO_RISK_LEVELS],
    ['AtoAccountKind', ATO_ACCOUNT_KINDS],
  ] as const)('%s', (name, values) => {
    expect(prismaEnum(name)).toEqual([...values]);
  });

  it('generates the active marker of exactly the active statuses (migration SQL)', () => {
    const migration = readFileSync(
      resolve(
        __dirname,
        '../../database/prisma/migrations/20261118060000_security_incidents/migration.sql',
      ),
      'utf8',
    );
    const quoted = SECURITY_INCIDENT_ACTIVE_STATUSES.map((s) => `'${s}'`).join(', ');
    expect(migration).toContain(
      `GENERATED ALWAYS AS (IF(\`status\` IN (${quoted}), 1, NULL)) STORED NULL`,
    );
  });
});
