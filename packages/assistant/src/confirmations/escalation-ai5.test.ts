import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { AI5_WRITES_TESTED_BY } from '../registry/manifest';
import { ALL_TOOLS } from '../registry/registry';
import type { OperationTool } from '../registry/types';
import {
  effectiveRisk,
  escalationField,
  escalationMatches,
  escalationNote,
  escalationPath,
  readRelativeOf,
  type EscalationCondition,
} from './escalation';
import {
  AI5_ESCALATION_WARNINGS,
  CONFIRMATION_SPECS,
  SNAPSHOT_STRING_MAX_CHARS,
  buildSnapshot,
  confirmationSpecOf,
  type ConfirmationSnapshot,
  type SinglePrecondition,
} from './specs';
import type { ConfirmationRisk } from './types';

const ORDER: Record<ConfirmationRisk, number> = { low: 0, medium: 1, high: 2 };
const W = AI5_ESCALATION_WARNINGS;

const tool = (operationId: string): OperationTool =>
  ALL_TOOLS.find((t) => t.operationId === operationId)!;

describe('read-relative escalation kinds (design 33 D3)', () => {
  const below: EscalationCondition = { below: { path: 'body.days', field: 'days' } };
  const belowDefault: EscalationCondition = {
    below: { path: 'body.days', field: 'days', absentAs: 30 },
  };
  const becomes: EscalationCondition = {
    becomes: { path: 'body.mode', field: 'mode', value: 'delete' },
  };
  const becomesDefault: EscalationCondition = {
    becomes: { path: 'body.mode', field: 'mode', value: 'delete', absentAs: 'delete' },
  };
  const differs: EscalationCondition = { differs: { path: 'body.criteria', field: 'criteria' } };
  const differsDefault: EscalationCondition = {
    differs: { path: 'body.criteria', field: 'criteria', absentAs: {} },
  };
  const m = (
    c: EscalationCondition,
    body: Record<string, unknown>,
    snap: ConfirmationSnapshot | null,
  ) => escalationMatches(c, { body }, snap);

  it('below: a lower number matches; equal or higher does not; absentAs stands in for an absent argument', () => {
    expect(m(below, { days: 29 }, { days: 30 })).toBe(true);
    expect(m(below, { days: 30 }, { days: 30 })).toBe(false);
    expect(m(below, { days: 31 }, { days: 30 })).toBe(false);
    // Absent without absentAs never matches, even without a snapshot.
    expect(m(below, {}, { days: 30 })).toBe(false);
    expect(m(below, {}, null)).toBe(false);
    expect(m(belowDefault, {}, { days: 60 })).toBe(true);
    expect(m(belowDefault, {}, { days: 30 })).toBe(false);
  });

  it('below fails closed: missing, null or non-number read values, a non-number argument, no snapshot', () => {
    expect(m(below, { days: 1000 }, {})).toBe(true);
    expect(m(below, { days: 1000 }, { days: null })).toBe(true);
    expect(m(below, { days: 1000 }, { days: '365' })).toBe(true);
    expect(m(below, { days: 1000 }, { days: true })).toBe(true);
    expect(m(below, { days: '1000' }, { days: 30 })).toBe(true);
    expect(m(below, { days: 1000 }, null)).toBe(true);
    expect(escalationMatches(below, { body: { days: 1000 } })).toBe(true);
  });

  it('becomes: a switch to the value matches; staying or another value does not', () => {
    expect(m(becomes, { mode: 'delete' }, { mode: 'review' })).toBe(true);
    expect(m(becomes, { mode: 'delete' }, { mode: 'delete' })).toBe(false);
    expect(m(becomes, { mode: 'review' }, { mode: 'review' })).toBe(false);
    expect(m(becomes, { mode: 'review' }, null)).toBe(false); // the argument is not the value
    expect(m(becomes, {}, { mode: 'review' })).toBe(false);
    expect(m(becomesDefault, {}, { mode: 'review' })).toBe(true);
    expect(m(becomesDefault, {}, { mode: 'delete' })).toBe(false);
    // Fail closed on the read side.
    expect(m(becomes, { mode: 'delete' }, {})).toBe(true);
    expect(m(becomes, { mode: 'delete' }, { mode: null })).toBe(true);
    expect(m(becomes, { mode: 'delete' }, null)).toBe(true);
    // A null value with a null argument: the read null fails closed.
    const toNull: EscalationCondition = { becomes: { path: 'body.x', field: 'x', value: null } };
    expect(m(toNull, { x: null }, { x: 'a' })).toBe(true);
    expect(m(toNull, { x: 'a' }, { x: 'a' })).toBe(false);
  });

  it('differs: canonical JSON (sorted object keys); arrays keep their order (a reorder escalates)', () => {
    const snap = (value: unknown): ConfirmationSnapshot => ({ criteria: JSON.stringify(value) });
    const read = { directions: ['inbound', 'outbound'], sources: ['journal'] };
    expect(
      m(
        differs,
        { criteria: { sources: ['journal'], directions: ['inbound', 'outbound'] } },
        snap(read),
      ),
    ).toBe(false);
    expect(
      m(
        differs,
        { criteria: { directions: ['outbound', 'inbound'], sources: ['journal'] } },
        snap(read),
      ),
    ).toBe(true);
    expect(m(differs, { criteria: { directions: ['inbound'] } }, snap(read))).toBe(true);
    expect(m(differs, {}, snap(read))).toBe(false);
    expect(m(differsDefault, {}, snap({}))).toBe(false);
    expect(m(differsDefault, {}, snap(read))).toBe(true);
    // Scalars: numbers and strings compare as JSON values.
    const priority: EscalationCondition = {
      differs: { path: 'body.priority', field: 'priority', absentAs: 100 },
    };
    expect(m(priority, { priority: 100 }, { priority: 100 })).toBe(false);
    expect(m(priority, {}, { priority: 100 })).toBe(false);
    expect(m(priority, { priority: 99 }, { priority: 100 })).toBe(true);
    expect(m(priority, { priority: '100' }, { priority: 100 })).toBe(true);
    const id: EscalationCondition = { differs: { path: 'body.id', field: 'id' } };
    expect(m(id, { id: 'a' }, { id: 'a' })).toBe(false);
    expect(m(id, { id: 'b' }, { id: 'a' })).toBe(true);
    expect(m(id, { id: null }, { id: 'a' })).toBe(true);
  });

  it('differs fails closed: missing or null read values and lists or objects cut by the snapshot caps', () => {
    expect(m(differs, { criteria: {} }, {})).toBe(true);
    expect(m(differs, { criteria: {} }, { criteria: null })).toBe(true);
    expect(m(differs, { criteria: {} }, null)).toBe(true);
    // A snapshot object longer than the cap is cut (sanitizeText adds `…`) and no longer parses.
    const pre: SinglePrecondition = {
      kind: 'single',
      tool: 't',
      params: {},
      stateFields: ['criteria'],
    };
    const big = {
      domainIds: Array.from(
        { length: 40 },
        (_, i) => `0193aaaa-0000-7000-8000-${String(i).padStart(12, '0')}`,
      ),
    };
    const snapshot = buildSnapshot({ criteria: big }, pre);
    expect(String(snapshot.criteria).length).toBeLessThanOrEqual(SNAPSHOT_STRING_MAX_CHARS);
    expect(m(differs, { criteria: big }, snapshot)).toBe(true);
    // The same small object is kept whole and compares equal.
    const small = buildSnapshot({ criteria: { directions: ['inbound'] } }, pre);
    expect(m(differs, { criteria: { directions: ['inbound'] } }, small)).toBe(false);
    // A string that is not JSON text is compared as a string.
    expect(m(differs, { criteria: '[x' }, { criteria: '[x' })).toBe(true);
    expect(m(differs, { criteria: 'plain' }, { criteria: 'plain' })).toBe(false);
  });

  it('paths, fields and matrix notes of the three kinds', () => {
    expect(escalationPath(below)).toBe('body.days');
    expect(escalationField(below)).toBe('days');
    expect(escalationField({ present: 'body.x' })).toBeNull();
    expect(escalationField({ equals: { path: 'body.x', value: 1 } })).toBeNull();
    expect(readRelativeOf(becomes)).toEqual({
      kind: 'becomes',
      path: 'body.mode',
      field: 'mode',
      value: 'delete',
    });
    const spec = confirmationSpecOf('ArchiveRetentionController_update_v1')!;
    expect(spec.escalate!.map(escalationNote)).toEqual([
      '↑ high when body.retentionDays < retentionDays',
      '↑ high when body.onExpiry → delete',
      '↑ high when body.criteria ≠ criteria',
      '↑ high when body.priority ≠ priority',
    ]);
  });
});

describe('the D3 escalation table (AI-5 specs)', () => {
  it('has exactly the escalations of the design table', () => {
    const table = CONFIRMATION_SPECS.filter(
      (s) => s.escalate && s.operationId in AI5_WRITES_TESTED_BY,
    ).flatMap((s) => s.escalate!.map((e) => [s.operationId, escalationNote(e), e.warning]));
    expect(table).toEqual([
      [
        'ArchiveRetentionController_update_v1',
        '↑ high when body.retentionDays < retentionDays',
        W.retentionShortened,
      ],
      [
        'ArchiveRetentionController_update_v1',
        '↑ high when body.onExpiry → delete',
        W.expiryDelete,
      ],
      [
        'ArchiveRetentionController_update_v1',
        '↑ high when body.criteria ≠ criteria',
        W.retentionScope,
      ],
      [
        'ArchiveRetentionController_update_v1',
        '↑ high when body.priority ≠ priority',
        W.retentionScope,
      ],
      ['ArchiveAdminController_update_v1', '↑ high when body.enabled = false', W.archiveOff],
      ['ArchiveAdminController_update_v1', '↑ high when body.settings', W.archiveSettings],
      [
        'ArchiveAdminController_update_v1',
        '↑ high when body.immutability ≠ immutability',
        W.archiveImmutability,
      ],
      [
        'ArchiveAdminController_update_v1',
        '↑ high when body.defaultRetentionPolicyId ≠ defaultRetentionPolicyId',
        W.archiveDefaultPolicy,
      ],
      ['JournalingController_update_v1', '↑ high when body.enabled = false', W.journalingOff],
      ['JournalingController_update_v1', '↑ high when body.settings', W.journalingSettings],
      ['IntakeSourcesController_update_v1', '↑ high when body.status = paused', W.intakePaused],
      ['IntakeSourcesController_update_v1', '↑ high when body.networks', W.intakeNetworks],
      ['IntakeSourcesController_update_v1', '↑ high when body.requireTls = false', W.intakeTls],
      [
        'IntakeSourcesController_update_v1',
        '↑ high when body.clientCertFingerprints',
        W.intakeCertificates,
      ],
      [
        'IntakeSourcesController_update_v1',
        '↑ high when body.maxMessageBytes < maxMessageBytes',
        W.intakeSize,
      ],
      [
        'IntakeSourcesController_update_v1',
        '↑ high when body.silenceAlertMinutes = null',
        W.intakeSilenceOff,
      ],
      ['EdiscoveryCasesController_update_v1', '↑ medium when body.custodians', W.caseCustodians],
      [
        'EdiscoveryExportsController_create_v1',
        '↑ high when body.acknowledgeMalicious = true',
        W.exportMalicious,
      ],
    ]);
    // The design's fixed English texts.
    expect(W).toEqual({
      retentionShortened:
        'Shortens retention: mail captured from now on that this policy matches is kept for fewer days (records already archived keep their stored dates).',
      expiryDelete: 'Expired records are deleted without a review step.',
      retentionScope:
        'Changes which new captures this policy applies to; mail that no longer matches falls to another policy, possibly with a shorter retention.',
      archiveOff: 'Archiving stops: mail received from now on is not captured.',
      archiveSettings:
        'Replaces the whole archive settings document (directions, included outcomes, scope, policy archiving, access, intake scanning); keys you leave out return to their defaults.',
      archiveImmutability:
        'Changes the S3 Object Lock mode of new captures; compliance mode can never be weakened afterwards.',
      archiveDefaultPolicy:
        'Changes the retention of every new capture that no other policy matches.',
      journalingOff: 'Journaling stops: mail received from now on is not captured.',
      journalingSettings:
        'Replaces the given journaling sections (directions, included outcomes, scope, policy archiving, intake scanning); keys left out inside a given section return to their defaults.',
      intakePaused:
        'Journal intake stops: senders get a temporary failure and retry; nothing is captured from this source while it is paused.',
      intakeNetworks: 'Changes which networks may deliver journal mail to this source.',
      intakeTls: 'Journal mail may then arrive without TLS.',
      intakeCertificates: 'Changes which client certificates this source accepts.',
      intakeSize:
        'Lowers the largest journal message this source accepts: larger messages are refused permanently and are not captured.',
      intakeSilenceOff:
        'Turns the silence alert off: a source that stops delivering journal mail is no longer reported.',
      caseCustodians:
        'Replaces the case custodians; later searches and holds that use the case custodians change (existing holds keep theirs).',
      exportMalicious: 'The export includes messages flagged as malicious.',
    });
  });

  const retention = tool('ArchiveRetentionController_update_v1');
  const retentionSpec = confirmationSpecOf('ArchiveRetentionController_update_v1')!;
  const READ: ConfirmationSnapshot = {
    rowVersion: 4,
    retentionDays: 365,
    onExpiry: 'review',
    priority: 50,
    criteria: '{"directions":["inbound"]}',
    isDefault: false,
  };
  const policyBody = (patch: Record<string, unknown> = {}) => ({
    body: {
      expectedRowVersion: 4,
      name: 'P',
      retentionDays: 365,
      onExpiry: 'review',
      priority: 50,
      criteria: { directions: ['inbound'] },
      ...patch,
    },
  });

  it('retention update: none, one, several (deduplicated) escalations', () => {
    expect(effectiveRisk(retention, retentionSpec, policyBody(), READ)).toEqual({
      risk: 'medium',
      warnings: [],
      escalatedFrom: null,
    });
    expect(
      effectiveRisk(
        retention,
        retentionSpec,
        policyBody({ name: 'Renamed', retentionDays: 400 }),
        READ,
      ).risk,
    ).toBe('medium');
    expect(
      effectiveRisk(retention, retentionSpec, policyBody({ retentionDays: 30 }), READ),
    ).toEqual({
      risk: 'high',
      warnings: [W.retentionShortened],
      escalatedFrom: 'medium',
    });
    expect(
      effectiveRisk(
        retention,
        retentionSpec,
        policyBody({ retentionDays: 30, onExpiry: 'delete', priority: 1, criteria: {} }),
        READ,
      ).warnings,
    ).toEqual([W.retentionShortened, W.expiryDelete, W.retentionScope]);
    // Omitted PUT fields return to their defaults (delete, 100, {}): escalated against the read.
    const { onExpiry: _o, priority: _p, criteria: _c, ...bare } = policyBody().body;
    expect(effectiveRisk(retention, retentionSpec, { body: bare }, READ).warnings).toEqual([
      W.expiryDelete,
      W.retentionScope,
    ]);
    // No snapshot (or the earlier call shape without it): every read-relative condition with a
    // present argument matches (fail closed).
    expect(effectiveRisk(retention, retentionSpec, policyBody()).risk).toBe('high');
    expect(effectiveRisk(retention, retentionSpec, policyBody(), null).warnings).toEqual([
      W.retentionShortened,
      W.retentionScope,
    ]);
  });

  it('intake update: a lower size limit or turning the silence alert off is high (I22)', () => {
    const intake = tool('IntakeSourcesController_update_v1');
    const intakeSpec = confirmationSpecOf('IntakeSourcesController_update_v1')!;
    const read: ConfirmationSnapshot = {
      rowVersion: 2,
      status: 'active',
      maxMessageBytes: 10_485_760,
    };
    const update = (patch: Record<string, unknown>) => ({
      sourceId: 'src',
      body: { expectedRowVersion: 2, ...patch },
    });
    const risk = (patch: Record<string, unknown>, snap: ConfirmationSnapshot | null = read) =>
      effectiveRisk(intake, intakeSpec, update(patch), snap);
    // Renaming, raising or keeping the size, and changing the alert interval stay low.
    expect(risk({ displayName: 'Journal' })).toEqual({
      risk: 'low',
      warnings: [],
      escalatedFrom: null,
    });
    expect(risk({ maxMessageBytes: 20_971_520 }).risk).toBe('low');
    expect(risk({ maxMessageBytes: 10_485_760 }).risk).toBe('low');
    expect(risk({ silenceAlertMinutes: 60 }).risk).toBe('low');
    expect(risk({ silenceAlertMinutes: 10_080 }).risk).toBe('low');
    // A lower limit refuses larger journal messages permanently.
    expect(risk({ maxMessageBytes: 1024 })).toEqual({
      risk: 'high',
      warnings: [W.intakeSize],
      escalatedFrom: 'low',
    });
    // Fail closed: no source limit read (the platform limit applies), no snapshot, or a null
    // argument.
    expect(risk({ maxMessageBytes: 157_286_400 }, { ...read, maxMessageBytes: null }).risk).toBe(
      'high',
    );
    expect(risk({ maxMessageBytes: 20_971_520 }, null).risk).toBe('high');
    expect(risk({ maxMessageBytes: null }).risk).toBe('high');
    // Turning the silence alert off.
    expect(risk({ silenceAlertMinutes: null })).toEqual({
      risk: 'high',
      warnings: [W.intakeSilenceOff],
      escalatedFrom: 'low',
    });
    expect(risk({ maxMessageBytes: 2048, silenceAlertMinutes: null }).warnings).toEqual([
      W.intakeSize,
      W.intakeSilenceOff,
    ]);
  });

  it('every read-relative field is a state field of the single precondition', () => {
    for (const spec of CONFIRMATION_SPECS)
      for (const escalation of spec.escalate ?? []) {
        const field = escalationField(escalation.when);
        if (field === null) continue;
        expect(spec.precondition?.kind, spec.operationId).toBe('single');
        expect((spec.precondition as SinglePrecondition).stateFields, spec.operationId).toContain(
          field,
        );
      }
  });
});

describe('property: the effective risk is never below the registry risk (with snapshots)', () => {
  const specs = CONFIRMATION_SPECS.filter((s) => !s.native);
  const arbValue = fc.oneof(
    fc.boolean(),
    fc.constant(null),
    fc.constantFrom('delete', 'review', 'paused', 'active', 'compliance', 'governance', 'none'),
    fc.string({ maxLength: 6 }),
    fc.integer({ min: -5, max: 40000 }),
    fc.constant({}),
    fc.array(fc.constantFrom('inbound', 'outbound', 'internal'), { maxLength: 3 }),
    fc.record({ directions: fc.array(fc.constantFrom('inbound', 'outbound'), { maxLength: 2 }) }),
  );
  const keys = [
    ...new Set(
      specs.flatMap((s) =>
        (s.escalate ?? []).map((e) => escalationPath(e.when).replace(/^body\./, '')),
      ),
    ),
    'name',
  ];
  const snapshotKeys = [
    ...new Set(
      specs.flatMap((s) =>
        s.precondition?.kind === 'single'
          ? [...s.precondition.stateFields, ...(s.precondition.displayFields ?? [])]
          : [],
      ),
    ),
  ];
  const arbSnapshotValue = fc.oneof(
    fc.constant(null),
    fc.boolean(),
    fc.integer({ min: 0, max: 40000 }),
    fc.constantFrom(
      'delete',
      'review',
      'governance',
      '{"directions":["inbound"]}',
      '{}',
      '[1',
      '{"a…',
    ),
  );

  it('holds for every enabled write, with and without a snapshot', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...specs),
        fc.dictionary(fc.constantFrom(...keys), arbValue),
        fc.option(fc.dictionary(fc.constantFrom(...snapshotKeys), arbSnapshotValue), {
          nil: null,
        }),
        (spec, body, snapshot) => {
          const write = tool(spec.operationId);
          const result = effectiveRisk(write, spec, { body }, snapshot);
          const base = write.risk as ConfirmationRisk;
          expect(ORDER[result.risk]).toBeGreaterThanOrEqual(ORDER[base]);
          if (result.escalatedFrom !== null) expect(result.escalatedFrom).toBe(base);
          // Losing the snapshot never lowers the risk (fail closed).
          expect(ORDER[effectiveRisk(write, spec, { body }, null).risk]).toBeGreaterThanOrEqual(
            ORDER[result.risk],
          );
        },
      ),
      { numRuns: 2000 },
    );
  });
});
