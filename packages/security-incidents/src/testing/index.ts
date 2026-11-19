/**
 * Test kit of `@email-gateway/security-incidents` (never imported by runtime code; a unit test
 * asserts it): incident and timeline row builders and a configurable fake category handler (to
 * prove category isolation with a second category).
 */
import type {
  SecurityIncidentCategory,
  SecurityIncidentSubjectType,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import type { IncidentCategoryHandler } from '../registry';
import type { IncidentEventRow, IncidentRow } from '../rows';

let nextId = 1000n;

/** A `security_incidents` row with defaults (open, high, account_takeover). */
export function buildIncidentRow(overrides: Partial<IncidentRow> = {}): IncidentRow {
  const id = overrides.id ?? nextId++;
  const at = new Date('2026-11-18T10:00:00.000Z');
  return {
    id,
    publicId: '01900000-0000-7000-8000-000000000001',
    organizationId: 1n,
    category: 'account_takeover',
    subjectType: 'ato_account',
    subjectRefId: 1n,
    subjectRefTime: null,
    subjectPublicId: '01900000-0000-7000-8000-0000000000aa',
    origin: 'detection',
    status: 'open',
    severity: 'high',
    titleCode: 'ato.auth.bruteforce',
    reasonCodes: ['ato.auth.bruteforce'],
    detectorVersion: 'ato-rules/1',
    detectedAt: at,
    firstEvidenceAt: null,
    lastEvidenceAt: null,
    evidenceCount: 0,
    assignedUserId: null,
    assignedAt: null,
    escalatedAt: null,
    confirmedAt: null,
    mitigatedAt: null,
    resolvedAt: null,
    resolvedByUserId: null,
    resolutionCode: null,
    resolutionNote: null,
    lastUpdateEventAt: null,
    createdByType: 'system',
    createdById: null,
    activeMarker: 1,
    rowVersion: 1,
    createdAt: at,
    updatedAt: at,
    ...overrides,
  };
}

/** A `security_incident_events` row with defaults. */
export function buildIncidentEventRow(overrides: Partial<IncidentEventRow> = {}): IncidentEventRow {
  return {
    id: overrides.id ?? nextId++,
    organizationId: 1n,
    incidentId: 1n,
    eventType: 'created',
    actorType: 'system',
    actorId: null,
    fromStatus: null,
    toStatus: 'open',
    fromSeverity: null,
    toSeverity: 'high',
    note: null,
    details: null,
    createdAt: new Date('2026-11-18T10:00:00.000Z'),
    ...overrides,
  };
}

export interface FakeCategoryCalls {
  transitions: Array<{ from: string; to: string; feedback: unknown }>;
}

/**
 * A fake category handler for tests (e.g. `fake_category` with `fake:read`/`fake:manage`). Its
 * category is not a database enum value: it exists only in the registry, which is exactly what
 * the isolation tests need (a principal holding only its permissions reads no ATO incident).
 */
export function fakeCategoryHandler(
  options: {
    category?: string;
    subjectTypes?: readonly string[];
    read?: string;
    manage?: string;
    feedbackSchema?: z.ZodType | null;
  } = {},
): IncidentCategoryHandler & { calls: FakeCategoryCalls } {
  const calls: FakeCategoryCalls = { transitions: [] };
  return {
    category: (options.category ?? 'fake_category') as SecurityIncidentCategory,
    subjectTypes: (options.subjectTypes ?? ['ato_account']) as SecurityIncidentSubjectType[],
    permissions: { read: options.read ?? 'fake:read', manage: options.manage ?? 'fake:manage' },
    feedbackSchema:
      options.feedbackSchema === undefined
        ? z.strictObject({ flag: z.boolean() })
        : options.feedbackSchema,
    calls,
    resolveSubject: () => Promise.resolve(null),
    loadDetail: (_tx, incident) => Promise.resolve({ fake: true, id: incident.publicId }),
    onTransition: (_tx, _incident, from, to, _actor, feedback) => {
      calls.transitions.push({ from, to, feedback });
      return Promise.resolve();
    },
    reportSections: () =>
      Promise.resolve([{ id: 'fake', title: 'Fake section', data: { ok: true } }]),
  };
}
