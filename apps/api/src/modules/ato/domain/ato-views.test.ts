import { AtoStoreError } from '@email-gateway/ato-detection';
import { IncidentActiveConflictError, IncidentError } from '@email-gateway/security-incidents';
import { describe, expect, it } from 'vitest';
import { CodedHttpException } from '../../../http/coded-exception';
import { mapIncidentError } from '../../incidents/incidents.errors';
import { mapAtoStoreError } from '../ato.errors';
import { referencesAtoField } from '../repositories/ato-read.repository';
import { trendBuckets } from '../services/ato-overview.service';
import { evidenceRange } from '../services/ato-evidence.service';
import type { ResponseRow } from '../repositories/ato-read.repository';
import { explanationText, opaqueRef, parseCapabilities, responseView } from './ato-views';

const NOW = new Date('2026-11-18T12:00:00.000Z');

const coded = (fn: () => unknown): CodedHttpException => {
  try {
    fn();
  } catch (error) {
    if (error instanceof CodedHttpException) return error;
    throw error;
  }
  throw new Error('expected a coded exception');
};

describe('capabilities (D17)', () => {
  it('missing, malformed or stale reports are unknown', () => {
    expect(parseCapabilities(null, NOW).view.status).toBe('unknown');
    expect(parseCapabilities({ value: 'x', updatedAt: NOW }, NOW).view.status).toBe('unknown');
    const stale = parseCapabilities(
      { value: { updatedAt: '2026-11-18T11:40:00.000Z' }, updatedAt: NOW },
      NOW,
    );
    expect(stale.known).toBe(false);
    expect(stale.set.has('geoip_city')).toBe(false);
  });

  it('a fresh report maps databases, zones, indicators and providers', () => {
    const c = parseCapabilities(
      {
        value: {
          geoipCity: { loaded: true, stale: false },
          geoipAsn: { loaded: true, stale: true },
          geoipAnonymous: { loaded: false },
          dnsblZones: 2,
          breachIndicators: 0,
          becObservations: true,
          providers: ['fake', 'Bad Name'],
          updatedAt: '2026-11-18T11:55:00.000Z',
        },
        updatedAt: NOW,
      },
      NOW,
    );
    expect(c.view).toMatchObject({
      status: 'known',
      geoipCity: 'available',
      geoipAsn: 'stale',
      geoipAnonymous: 'unavailable',
      dnsbl: 'available',
      breachIntel: 'unavailable',
      becObservations: 'available',
      providers: ['fake'],
    });
    expect(c.set.has('geoip_city')).toBe(true);
    expect(c.set.has('geoip_asn')).toBe(false);
    expect(c.set.has('provider:fake')).toBe(true);
  });
});

describe('views and helpers', () => {
  it('renders the score explanation line from rule titles', () => {
    expect(
      explanationText(
        { top: [{ code: 'ato.geo.impossible_travel', contribution: 35 }] },
        40,
        'medium',
      ),
    ).toMatch(/^Risk 40 \(medium\): .+ \+35$/);
    expect(explanationText(null, 0, 'low')).toBeNull();
    expect(explanationText({ top: [] }, 0, 'low')).toBe('Risk 0 (low): no active signals');
  });

  it('opaque references are stable, short and never the id', () => {
    const a = opaqueRef('signal', 42n, NOW);
    expect(a).toMatch(/^[0-9a-f]{20}$/);
    expect(opaqueRef('signal', 42n, NOW)).toBe(a);
    expect(opaqueRef('auth_event', 42n, NOW)).not.toBe(a);
  });

  it('detects ato.* fields anywhere in a policy definition', () => {
    expect(
      referencesAtoField({
        rules: [{ when: { all: [{ field: 'ato.risk_level', op: 'gte', value: 'high' }] } }],
      }),
    ).toBe(true);
    expect(referencesAtoField({ rules: [{ when: { field: 'sender.domain' } }] })).toBe(false);
    expect(referencesAtoField(null)).toBe(false);
  });

  it('trend buckets cover the range and count by severity', () => {
    const from = new Date('2026-11-17T12:30:00.000Z');
    const buckets = trendBuckets(from, NOW, 3_600_000, [
      { detectedAt: new Date('2026-11-17T12:45:00.000Z'), severity: 'high' },
      { detectedAt: new Date('2026-11-18T11:59:00.000Z'), severity: 'critical' },
    ]);
    expect(buckets).toHaveLength(24);
    expect(buckets[0]).toMatchObject({ bucketStart: '2026-11-17T12:00:00.000Z', high: 1 });
    expect(buckets.at(-1)).toMatchObject({ critical: 1 });
  });

  it('evidence ranges start a day before the first evidence, bounded to 400 days', () => {
    const r = evidenceRange(
      { detectedAt: NOW, firstEvidenceAt: new Date('2026-11-10T00:00:00.000Z') },
      NOW,
    );
    expect(r.from.toISOString()).toBe('2026-11-09T00:00:00.000Z');
    const old = evidenceRange(
      { detectedAt: new Date('2020-01-01T00:00:00Z'), firstEvidenceAt: null },
      NOW,
    );
    expect(NOW.getTime() - old.from.getTime()).toBe(400 * 86_400_000);
  });
});

describe('error mapping', () => {
  it.each([
    ['ato_account_not_found', 404, 'ato_account_not_found'],
    ['ato_response_active', 409, 'ato_response_active'],
    ['ato_response_state', 409, 'ato_response_state'],
    ['ato_response_expired', 409, 'ato_response_expired'],
    ['ato_self_approval', 403, 'ato_approval_self'],
    ['ato_approver_invalid', 403, 'ato_approver_invalid'],
    ['ato_rollback_unsupported', 422, 'ato_rollback_unsupported'],
    ['ato_response_invalid', 422, 'ato_response_invalid'],
    ['ato_trusted_context_invalid', 422, 'ato_trusted_context_invalid'],
    ['ato_settings_conflict', 409, 'ato_settings_conflict'],
    ['ato_inconsistent_read', 503, 'inconsistent_read'],
  ] as const)('%s → %d %s', (code, status, mapped) => {
    const e = coded(() => mapAtoStoreError(new AtoStoreError(code, 'x', { actual: 3 })));
    expect(e.getStatus()).toBe(status);
    expect(e.code).toBe(mapped);
  });

  it('settings issues carry paths and messages only', () => {
    const e = coded(() =>
      mapAtoStoreError(
        new AtoStoreError('ato_settings_invalid', 'x', {
          issues: [{ path: 'mode', message: 'Invalid option' }],
        }),
      ),
    );
    expect(e.getStatus()).toBe(400);
    expect(e.details).toEqual({ issues: [{ path: 'mode', message: 'Invalid option' }] });
  });

  it('other errors pass through unchanged', () => {
    const boom = new Error('boom');
    expect(() => mapAtoStoreError(boom)).toThrow(boom);
  });

  it('maps incident errors (conflicts, transitions, active incidents with the public id)', async () => {
    const run = async (error: unknown) => {
      try {
        await mapIncidentError(error, () =>
          Promise.resolve('0193b0a0-2222-7a00-8000-000000000001'),
        );
      } catch (e) {
        return e as CodedHttpException;
      }
      throw new Error('expected');
    };
    expect(
      (
        await run(
          new IncidentError('incident_note_required', 'x', { from: 'open', to: 'confirmed' }),
        )
      ).details,
    ).toEqual({
      reason: 'note_required',
      from: 'open',
      to: 'confirmed',
    });
    const active = await run(new IncidentActiveConflictError(5n));
    expect(active.code).toBe('incident_active');
    expect(active.details).toEqual({ incidentId: '0193b0a0-2222-7a00-8000-000000000001' });
    expect((await run(new IncidentError('incident_category_unknown', 'x'))).code).toBe(
      'incident_category_unsupported',
    );
    expect((await run(new IncidentError('incident_closed', 'x'))).getStatus()).toBe(409);
  });
});

describe('responseView canDecide (four eyes, ADR-0072)', () => {
  const USER = '019a0000-0000-7000-8000-000000000001';
  const OTHER = '019a0000-0000-7000-8000-000000000002';
  const KEY = '019a0000-0000-7000-8000-0000000000aa';
  const row = (over: Partial<ResponseRow>): ResponseRow =>
    ({
      publicId: '019a0000-0000-7000-8000-0000000000ff',
      actionType: 'restrict_smtp_sending',
      provider: 'gateway',
      impact: 'high',
      status: 'pending_approval',
      requiresApproval: true,
      authorization: 'manual',
      target: { scope: 'connector', connectorId: '7' },
      params: { durationMinutes: 60, mode: 'reject' },
      requestedByType: 'user',
      requestedById: USER,
      requestReason: null,
      approvedByUserId: null,
      decidedAt: null,
      decisionReason: null,
      approvalExpiresAt: null,
      executedAt: null,
      completedAt: null,
      effectiveUntil: null,
      providerReference: null,
      providerStatus: null,
      resultCode: null,
      attempts: 0,
      rollbackReason: null,
      createdAt: NOW,
      updatedAt: NOW,
      accountPublicId: '019a0000-0000-7000-8000-0000000000bb',
      accountKind: 'smtp_connector',
      incidentPublicId: null,
      approvedByPublicId: null,
      requestedByPublicId: USER,
      requestedByKeyCreatorPublicId: null,
      ...over,
    }) as ResponseRow;
  const can = (r: ResponseRow, caller: string) =>
    responseView(r, new Map(), { userWithMfaAndRespond: true, callerPublicId: caller }).canDecide;

  it('the requesting user cannot decide; another user can', () => {
    expect(can(row({}), USER)).toBe(false);
    expect(can(row({}), OTHER)).toBe(true);
  });

  it('a request made with an API key cannot be decided by the key creator', () => {
    const byKey = row({
      requestedByType: 'api_key',
      requestedById: KEY,
      requestedByPublicId: KEY,
      requestedByKeyCreatorPublicId: USER,
    });
    expect(can(byKey, USER)).toBe(false);
    expect(can(byKey, OTHER)).toBe(true);
    expect(can({ ...byKey, requestedByKeyCreatorPublicId: null }, USER)).toBe(true);
  });
});
