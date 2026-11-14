import { describe, expect, it } from 'vitest';
import { expectRequestMatchesContract, permissionsOf, SYSTEM_ROLE_KEYS } from '@/test';
import { detailSectionHref } from '../links';
import { AUDIT_WINDOW_DAYS, auditWindow } from './audit-section';
import { RESCAN_REASON_MAX, rescanBody, rescanSchema } from './rescan-dialog';
import {
  DETAIL_URL_SHAPE,
  SECTIONS,
  SECTION_IDS,
  sectionAllowed,
  sectionById,
  sectionRequirement,
} from './sections';

describe('details sections (§1.4)', () => {
  it('lists the 14 sections in §1.4 order, 4–10 round-scoped', () => {
    expect(SECTIONS.map((s) => s.id)).toEqual([...SECTION_IDS]);
    expect(SECTIONS).toHaveLength(14);
    expect(SECTIONS.filter((s) => s.roundScoped).map((s) => s.id)).toEqual([
      'authentication',
      'spam',
      'phishing',
      'urls',
      'attachments',
      'dlp',
      'risk',
    ]);
  });

  it('gates every section for every system role like the §1.4 table', () => {
    const visible = Object.fromEntries(
      SYSTEM_ROLE_KEYS.map((role) => [
        role,
        SECTIONS.filter((s) => sectionAllowed(s, new Set(permissionsOf(role)))).map((s) => s.id),
      ]),
    );
    const all = [...SECTION_IDS];
    const noDlpAudit = all.filter((id) => id !== 'dlp' && id !== 'audit');
    expect(visible).toEqual({
      super_admin: all,
      platform_admin: all.filter((id) => id !== 'dlp'),
      organization_admin: all,
      domain_admin: noDlpAudit,
      security_analyst: all,
      quarantine_reviewer: noDlpAudit,
      compliance_auditor: all,
      read_only_user: noDlpAudit,
      mailbox_user: [],
    });
  });

  it('names the permissions of the forbidden state', () => {
    expect(sectionRequirement(sectionById('dlp'))).toEqual(['message:read', 'dlp:read']);
    expect(sectionRequirement(sectionById('delivery'))).toEqual(['delivery:read']);
    expect(sectionRequirement(sectionById('audit'))).toEqual(['audit:read']);
  });

  it('parses the URL state with silent fall-backs', () => {
    expect(DETAIL_URL_SHAPE.section.parse(undefined)).toBe('summary');
    expect(DETAIL_URL_SHAPE.section.parse('nope')).toBe('summary');
    expect(DETAIL_URL_SHAPE.section.parse('dlp')).toBe('dlp');
    expect(DETAIL_URL_SHAPE.round.parse('2')).toBe(2);
    expect(DETAIL_URL_SHAPE.round.parse('-1')).toBeUndefined();
    expect(DETAIL_URL_SHAPE.round.parse('x')).toBeUndefined();
    expect(DETAIL_URL_SHAPE.round.parse(undefined)).toBeUndefined();
  });

  it('builds deep links to sections and rounds', () => {
    expect(detailSectionHref('m-1', 'summary')).toBe('/messages/m-1');
    expect(detailSectionHref('m-1', 'risk', 2)).toBe('/messages/m-1?section=risk&round=2');
  });
});

describe('audit window (§2 E3)', () => {
  const received = '2026-01-01T00:00:00.000Z';
  it('covers 90 days from one minute before the message, capped at now', () => {
    const now = Date.parse('2026-01-10T00:00:00.000Z');
    expect(auditWindow(received, now, 0)).toEqual({
      from: '2025-12-31T23:59:00.000Z',
      to: '2026-01-10T00:00:00.000Z',
      hasLater: false,
    });
  });
  it('offers later windows for old messages and none beyond now', () => {
    const now = Date.parse('2026-06-01T00:00:00.000Z');
    const first = auditWindow(received, now, 0);
    expect(first?.hasLater).toBe(true);
    expect(Date.parse(first?.to ?? '') - Date.parse(first?.from ?? '')).toBe(
      AUDIT_WINDOW_DAYS * 86_400_000,
    );
    const second = auditWindow(received, now, 1);
    expect(second?.from).toBe(first?.to);
    expect(auditWindow(received, now, 3)).toBeNull();
  });
});

describe('rescan form', () => {
  it('validates the reason like the api and builds a contract body', () => {
    expect(rescanSchema.safeParse({ reason: 'too short' }).success).toBe(false);
    expect(rescanSchema.safeParse({ reason: 'x'.repeat(RESCAN_REASON_MAX + 1) }).success).toBe(
      false,
    );
    expect(rescanSchema.safeParse({ reason: 'New threat feed data', extra: 1 }).success).toBe(
      false,
    );
    const parsed = rescanSchema.parse({ reason: '  New threat feed data  ' });
    expect(parsed.reason).toBe('New threat feed data');
    expectRequestMatchesContract(
      'MessageLifecycleController_rescan_v1',
      rescanBody(parsed.reason, 6),
    );
  });
});
