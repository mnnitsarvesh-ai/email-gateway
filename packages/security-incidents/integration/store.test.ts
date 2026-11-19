import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PrismaClient } from '@email-gateway/database';
import {
  IncidentActiveConflictError,
  IncidentCategoryRegistry,
  IncidentError,
  IncidentStore,
  assembleIncidentReport,
  type IncidentActor,
  type IncidentRow,
} from '../src';
import { fakeCategoryHandler } from '../src/testing';
import { Fixtures } from './support/fixtures';

const fx = new Fixtures();
let prisma: PrismaClient;
let clock = new Date('2026-11-18T10:00:00.000Z');
const ato = fakeCategoryHandler({
  category: 'account_takeover',
  read: 'ato:read',
  manage: 'ato:manage',
});
const fake = fakeCategoryHandler();
const registry = new IncidentCategoryRegistry([ato, fake]);
const store = new IncidentStore({ registry, now: () => clock });
const system: IncidentActor = { type: 'system', id: null };
let orgA: bigint;
let orgB: bigint;
let analyst: { id: bigint; publicId: string };
let analystActor: IncidentActor;

const tx = <T>(
  fn: (tx: Parameters<Parameters<PrismaClient['$transaction']>[0]>[0]) => Promise<T>,
) => prisma.$transaction(fn, { timeout: 120_000, maxWait: 30_000 });

async function openFor(organizationId: bigint, label: string): Promise<IncidentRow> {
  const account = await fx.account(organizationId, label);
  return tx((t) =>
    store.open(t, {
      organizationId,
      category: 'account_takeover',
      subject: {
        type: 'ato_account',
        refId: account.id,
        refTime: null,
        publicId: account.publicId,
      },
      origin: 'detection',
      severity: 'high',
      titleCode: 'ato.auth.bruteforce',
      reasonCodes: ['ato.auth.bruteforce', 'ato.access.new_ip_prefix'],
      detectorVersion: 'ato-rules/1',
      detectedAt: clock,
      actor: system,
    }),
  );
}

const outboxOf = (incident: IncidentRow) =>
  prisma.messageOutbox.findMany({
    where: {
      organizationId: incident.organizationId,
      aggregateType: 'security_incident',
      aggregateId: incident.id.toString(),
    },
    orderBy: { id: 'asc' },
  });

beforeAll(async () => {
  prisma = fx.prisma;
  orgA = await fx.organization('a');
  orgB = await fx.organization('b');
  analyst = await fx.user(orgA, 'analyst');
  analystActor = { type: 'user', id: analyst.publicId, userId: analyst.id };
});

afterAll(async () => {
  await fx.cleanup();
});

describe('IncidentStore.open', () => {
  it('writes the row, the created entry, the created event and the audit row', async () => {
    const incident = await openFor(orgA, 'open1');
    expect(incident.status).toBe('open');
    expect(incident.activeMarker).toBe(1);
    const events = await store.timeline(prisma, orgA, incident.id);
    expect(events.map((e) => e.eventType)).toEqual(['created']);
    const outbox = await outboxOf(incident);
    expect(outbox.map((o) => o.eventType)).toEqual(['security.incident.created.v1']);
    expect(outbox[0]?.payload).toMatchObject({
      incidentPublicId: incident.publicId,
      category: 'account_takeover',
      status: 'open',
      reasonCodes: ['ato.auth.bruteforce', 'ato.access.new_ip_prefix'],
    });
    const audit = await prisma.auditLog.findMany({
      where: {
        organizationId: orgA,
        resourceType: 'security_incident',
        resourceId: incident.publicId,
      },
    });
    expect(audit.map((a) => a.action)).toEqual(['security_incident.created']);
  });

  it('allows one active incident per subject and category', async () => {
    const account = await fx.account(orgA, 'dup');
    const input = {
      organizationId: orgA,
      category: 'account_takeover' as const,
      subject: {
        type: 'ato_account' as const,
        refId: account.id,
        refTime: null,
        publicId: account.publicId,
      },
      origin: 'manual' as const,
      severity: 'medium' as const,
      titleCode: null,
      reasonCodes: [],
      detectorVersion: null,
      detectedAt: clock,
      actor: analystActor,
      note: 'User reported a strange login.',
    };
    const first = await tx((t) => store.open(t, input));
    const error = await tx((t) => store.open(t, input)).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IncidentActiveConflictError);
    expect((error as IncidentActiveConflictError).activeIncidentId).toBe(first.id);
    // After closing, a new incident may open for the same subject.
    await tx((t) =>
      store.transition(t, {
        organizationId: orgA,
        incidentId: first.id,
        to: 'resolved',
        resolutionCode: 'duplicate',
        note: 'Duplicate of an earlier report.',
        actor: analystActor,
      }),
    );
    const second = await tx((t) => store.open(t, input));
    expect(second.id).not.toBe(first.id);
  });

  it('refuses unregistered categories, wrong subject types and malformed codes', async () => {
    const unregistered = new IncidentStore({ registry: new IncidentCategoryRegistry() });
    const account = await fx.account(orgA, 'bad');
    const base = {
      organizationId: orgA,
      category: 'account_takeover' as const,
      subject: {
        type: 'ato_account' as const,
        refId: account.id,
        refTime: null,
        publicId: account.publicId,
      },
      origin: 'detection' as const,
      severity: 'high' as const,
      titleCode: null,
      reasonCodes: [] as string[],
      detectorVersion: null,
      detectedAt: clock,
      actor: system,
    };
    await expect(tx((t) => unregistered.open(t, base))).rejects.toMatchObject({
      code: 'incident_category_unknown',
    });
    await expect(
      tx((t) => store.open(t, { ...base, reasonCodes: ['NOT A CODE'] })),
    ).rejects.toMatchObject({
      code: 'incident_input_invalid',
    });
    await expect(
      tx((t) =>
        store.open(t, {
          ...base,
          reasonCodes: Array.from({ length: 17 }, (_, i) => `ato.c.r${i}`),
        }),
      ),
    ).rejects.toMatchObject({ code: 'incident_input_invalid' });
  });
});

describe('IncidentStore.transition', () => {
  it('walks open -> investigating -> confirmed -> mitigated -> resolved with events and audit', async () => {
    const incident = await openFor(orgA, 'walk');
    let row = await tx((t) =>
      store.transition(t, {
        organizationId: orgA,
        incidentId: incident.id,
        to: 'investigating',
        actor: analystActor,
      }),
    );
    expect(row.status).toBe('investigating');
    await expect(
      tx((t) =>
        store.transition(t, {
          organizationId: orgA,
          incidentId: incident.id,
          to: 'confirmed',
          actor: analystActor,
        }),
      ),
    ).rejects.toMatchObject({ code: 'incident_note_required' });
    row = await tx((t) =>
      store.transition(t, {
        organizationId: orgA,
        incidentId: incident.id,
        to: 'confirmed',
        note: 'Confirmed with the mailbox owner.',
        actor: analystActor,
      }),
    );
    expect(row.confirmedAt).not.toBeNull();
    row = await tx((t) =>
      store.transition(t, {
        organizationId: orgA,
        incidentId: incident.id,
        to: 'mitigated',
        actor: analystActor,
      }),
    );
    expect(row.mitigatedAt).not.toBeNull();
    row = await tx((t) =>
      store.transition(t, {
        organizationId: orgA,
        incidentId: incident.id,
        to: 'resolved',
        resolutionCode: 'remediated',
        note: 'Sessions revoked and password reset.',
        actor: analystActor,
      }),
    );
    expect(row.status).toBe('resolved');
    expect(row.activeMarker).toBeNull();
    expect(row.resolvedByUserId).toBe(analyst.id);
    expect(row.resolutionCode).toBe('remediated');
    const types = (await store.timeline(prisma, orgA, incident.id)).map((e) => e.eventType);
    expect(types).toEqual([
      'created',
      'status_changed',
      'status_changed',
      'status_changed',
      'status_changed',
    ]);
    const outbox = await outboxOf(incident);
    expect(outbox).toHaveLength(5);
    expect(outbox.at(-1)?.payload).toMatchObject({
      status: 'resolved',
      previousStatus: 'mitigated',
      changedFields: ['status', 'resolution'],
      actorType: 'user',
    });
    const audits = await prisma.auditLog.count({
      where: {
        organizationId: orgA,
        action: 'security_incident.status_changed',
        resourceId: incident.publicId,
      },
    });
    expect(audits).toBe(4);
    // Terminal: no further transition.
    await expect(
      tx((t) =>
        store.transition(t, {
          organizationId: orgA,
          incidentId: incident.id,
          to: 'confirmed',
          note: 'Reopen attempt here.',
          actor: analystActor,
        }),
      ),
    ).rejects.toMatchObject({ code: 'incident_transition_not_allowed' });
    expect(ato.calls.transitions.map((c) => c.to)).toEqual(
      expect.arrayContaining(['investigating', 'confirmed', 'mitigated', 'resolved']),
    );
  });

  it('enforces the row-version compare-and-set and the tenant', async () => {
    const incident = await openFor(orgA, 'cas');
    await expect(
      tx((t) =>
        store.transition(t, {
          organizationId: orgA,
          incidentId: incident.id,
          to: 'investigating',
          actor: analystActor,
          expectedRowVersion: 99,
        }),
      ),
    ).rejects.toMatchObject({ code: 'incident_version_conflict' });
    await expect(
      tx((t) =>
        store.transition(t, {
          organizationId: orgB,
          incidentId: incident.id,
          to: 'investigating',
          actor: analystActor,
        }),
      ),
    ).rejects.toMatchObject({ code: 'incident_not_found' });
    const row = await tx((t) =>
      store.transition(t, {
        organizationId: orgA,
        incidentId: incident.id,
        to: 'investigating',
        actor: analystActor,
        expectedRowVersion: incident.rowVersion,
      }),
    );
    expect(row.rowVersion).toBe(incident.rowVersion + 1);
  });

  it('validates category feedback with the handler schema and passes it to the hook', async () => {
    const incident = await openFor(orgA, 'fb');
    await expect(
      tx((t) =>
        store.transition(t, {
          organizationId: orgA,
          incidentId: incident.id,
          to: 'false_positive',
          resolutionCode: 'benign_activity',
          note: 'Travelling user on a hotel network.',
          feedback: { flag: 'yes' },
          actor: analystActor,
        }),
      ),
    ).rejects.toMatchObject({ code: 'incident_feedback_invalid' });
    await tx((t) =>
      store.transition(t, {
        organizationId: orgA,
        incidentId: incident.id,
        to: 'false_positive',
        resolutionCode: 'benign_activity',
        note: 'Travelling user on a hotel network.',
        feedback: { flag: true },
        actor: analystActor,
      }),
    );
    expect(ato.calls.transitions.at(-1)).toEqual({
      from: 'open',
      to: 'false_positive',
      feedback: { flag: true },
    });
  });
});

describe('assignment, severity, escalation, notes', () => {
  it('assigns users of the organization only and emits assignee changes', async () => {
    const incident = await openFor(orgA, 'assign');
    const other = await fx.user(orgB, 'foreign');
    const disabled = await fx.user(orgA, 'disabled', 'disabled');
    for (const userId of [other.id, disabled.id]) {
      await expect(
        tx((t) =>
          store.assign(t, {
            organizationId: orgA,
            incidentId: incident.id,
            assigneeUserId: userId,
            actor: analystActor,
          }),
        ),
      ).rejects.toMatchObject({ code: 'incident_assignee_invalid' });
    }
    const row = await tx((t) =>
      store.assign(t, {
        organizationId: orgA,
        incidentId: incident.id,
        assigneeUserId: analyst.id,
        actor: analystActor,
      }),
    );
    expect(row.assignedUserId).toBe(analyst.id);
    const outbox = await outboxOf(incident);
    expect(outbox.at(-1)?.payload).toMatchObject({ assigned: true, changedFields: ['assignee'] });
    const cleared = await tx((t) =>
      store.assign(t, {
        organizationId: orgA,
        incidentId: incident.id,
        assigneeUserId: null,
        actor: analystActor,
      }),
    );
    expect(cleared.assignedUserId).toBeNull();
  });

  it('system severity changes only raise; users may lower; escalate raises to at least high', async () => {
    const incident = await openFor(orgA, 'sev');
    let row = await tx((t) =>
      store.setSeverity(t, {
        organizationId: orgA,
        incidentId: incident.id,
        severity: 'medium',
        actor: system,
      }),
    );
    expect(row.severity).toBe('high');
    row = await tx((t) =>
      store.setSeverity(t, {
        organizationId: orgA,
        incidentId: incident.id,
        severity: 'critical',
        actor: system,
      }),
    );
    expect(row.severity).toBe('critical');
    row = await tx((t) =>
      store.setSeverity(t, {
        organizationId: orgA,
        incidentId: incident.id,
        severity: 'low',
        actor: analystActor,
        reason: 'Overstated.',
      }),
    );
    expect(row.severity).toBe('low');
    row = await tx((t) =>
      store.escalate(t, { organizationId: orgA, incidentId: incident.id, actor: analystActor }),
    );
    expect(row.severity).toBe('high');
    expect(row.escalatedAt).not.toBeNull();
    const types = (await store.timeline(prisma, orgA, incident.id)).map((e) => e.eventType);
    expect(types).toEqual(['created', 'severity_changed', 'severity_changed', 'escalated']);
  });

  it('adds notes (1-4000) and audits their length only', async () => {
    const incident = await openFor(orgA, 'note');
    await expect(
      tx((t) =>
        store.addNote(t, {
          organizationId: orgA,
          incidentId: incident.id,
          actor: analystActor,
          note: '   ',
        }),
      ),
    ).rejects.toBeInstanceOf(IncidentError);
    await tx((t) =>
      store.addNote(t, {
        organizationId: orgA,
        incidentId: incident.id,
        actor: analystActor,
        note: 'Called the user.',
      }),
    );
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: orgA,
        action: 'security_incident.note_added',
        resourceId: incident.publicId,
      },
    });
    expect(audit.metadata).toMatchObject({ noteLength: 16, category: 'account_takeover' });
    expect(JSON.stringify(audit.metadata)).not.toContain('Called the user');
  });
});

describe('links and evidence events', () => {
  it('caps links per type, ignores duplicates and throttles evidence updates to 15 minutes', async () => {
    const incident = await openFor(orgA, 'links');
    const base = new Date('2026-11-18T09:00:00.000Z');
    const messages = Array.from({ length: 505 }, (_, i) => ({
      type: 'message' as const,
      refId: BigInt(i + 1),
      refTime: new Date(base.getTime() + i * 1000),
    }));
    const first = await tx((t) =>
      store.link(t, { organizationId: orgA, incidentId: incident.id, links: messages }),
    );
    expect(first.linked.message).toBe(500);
    expect(first.overflow.message).toBe(5);
    const again = await tx((t) =>
      store.link(t, {
        organizationId: orgA,
        incidentId: incident.id,
        links: [
          { type: 'ato_signal', refId: 7n, refTime: base },
          { type: 'ato_signal', refId: 7n, refTime: base },
        ],
      }),
    );
    expect(again.linked.ato_signal).toBe(1);
    const row = await prisma.securityIncident.findUniqueOrThrow({ where: { id: incident.id } });
    expect(row.evidenceCount).toBe(501);
    expect(row.firstEvidenceAt?.toISOString()).toBe(base.toISOString());

    clock = new Date('2026-11-18T10:01:00.000Z');
    let current = await tx((t) =>
      store.recordEvidence(t, row, { codes: ['ato.auth.bruteforce'], counts: { signals: 1 } }),
    );
    clock = new Date('2026-11-18T10:10:00.000Z');
    current = await tx((t) =>
      store.recordEvidence(t, current, { codes: ['ato.auth.bruteforce'], counts: { signals: 2 } }),
    );
    clock = new Date('2026-11-18T10:17:00.000Z');
    await tx((t) =>
      store.recordEvidence(t, current, { codes: ['ato.auth.bruteforce'], counts: { signals: 3 } }),
    );
    clock = new Date('2026-11-18T10:00:00.000Z');
    const updates = (await outboxOf(incident)).filter(
      (o) => o.eventType === 'security.incident.updated.v1',
    );
    expect(updates).toHaveLength(2);
    const timeline = await store.timeline(prisma, orgA, incident.id);
    expect(timeline.filter((e) => e.eventType === 'evidence_linked')).toHaveLength(3);
  });

  it('assembles the report with masked related messages and category sections', async () => {
    const incident = await openFor(orgA, 'report');
    const report = await tx((t) =>
      assembleIncidentReport(t, registry, incident, { maxItems: 50, now: clock }),
    );
    expect(report.incident.id).toBe(incident.publicId);
    expect(report.sections).toEqual([{ id: 'fake', title: 'Fake section', data: { ok: true } }]);
    await tx((t) => store.recordReportExport(t, incident, analystActor));
    expect(
      await prisma.auditLog.count({
        where: { action: 'security_incident.report_exported', resourceId: incident.publicId },
      }),
    ).toBe(1);
  });
});

describe('category isolation (a second, fake category)', () => {
  it('a principal with only the fake category permission reads no ATO incident', async () => {
    const incident = await openFor(orgA, 'iso');
    const fakeOnly = registry.categoriesReadableBy(['fake:read']);
    const atoOnly = registry.categoriesReadableBy(['ato:read']);
    expect(fakeOnly).toEqual(['fake_category']);
    expect(await store.findByPublicId(prisma, orgA, incident.publicId, fakeOnly)).toBeNull();
    expect(await store.findByPublicId(prisma, orgA, incident.publicId, [])).toBeNull();
    expect((await store.findByPublicId(prisma, orgA, incident.publicId, atoOnly))?.id).toBe(
      incident.id,
    );
    expect(await store.list(prisma, orgA, { categories: fakeOnly })).toEqual([]);
    const listed = await store.list(prisma, orgA, { categories: atoOnly, limit: 100 });
    expect(listed.some((r) => r.id === incident.id)).toBe(true);
    // Another tenant's id looks missing, whatever the permissions.
    expect(await store.findByPublicId(prisma, orgB, incident.publicId, atoOnly)).toBeNull();
    expect(await store.list(prisma, orgB, { categories: atoOnly })).toEqual([]);
  });
});

describe('lock order (subject → incident)', () => {
  it('lockForUpdate locks the category subject first through lockSubject', async () => {
    const order: string[] = [];
    const ordered = new IncidentStore({
      registry: new IncidentCategoryRegistry([
        {
          ...ato,
          lockSubject(_tx, incident) {
            order.push(`subject:${incident.subjectRefId}`);
            return Promise.resolve();
          },
        },
      ]),
      now: () => clock,
    });
    const incident = await openFor(orgA, 'lockorder');
    const locked = await tx((t) => ordered.lockForUpdate(t, orgA, incident.id));
    expect(locked?.id).toBe(incident.id);
    expect(order).toEqual([`subject:${incident.subjectRefId}`]);
    // Another tenant's incident: null, and its subject is never locked.
    expect(await tx((t) => ordered.lockForUpdate(t, orgB, incident.id))).toBeNull();
    expect(order).toHaveLength(1);
    // Every mutation goes through it (setSeverity → requireLocked → lockForUpdate).
    await tx((t) =>
      ordered.setSeverity(t, {
        organizationId: orgA,
        incidentId: incident.id,
        severity: 'critical',
        actor: system,
      }),
    );
    expect(order).toHaveLength(2);
  });
});
