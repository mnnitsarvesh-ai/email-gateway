import { describe, expect, it } from 'vitest';
import type { ArchiveParties } from '@email-gateway/archive';
import { variantEntryPath } from '../ediscovery/exports';
import {
  disposalObjectsWithMerged,
  mergedCopiesOf,
  recordVersionsWithMerged,
} from '../storage/record-versions';
import { headerBlockOf, refreshMergedParties } from './dedupe';
import { alertWindowOf, computeIntakeHealth, type IntakeHealthFacts } from './intake-health';

const NOW = new Date('2026-11-20T12:00:00.000Z');
const ago = (minutes: number) => new Date(NOW.getTime() - minutes * 60_000);

const base: IntakeHealthFacts = {
  status: 'active',
  kind: 'smtp_bcc',
  verifiedAt: ago(10_000),
  lastAcceptedAt: ago(5),
  lastRefusedAt: null,
  silenceAlertMinutes: 240,
  connection: null,
  unwrapFailuresLastHour: 0,
};

describe('computeIntakeHealth (step 8.6 D9)', () => {
  it.each<[string, Partial<IntakeHealthFacts>, string, string]>([
    ['active and recent', {}, 'healthy', 'healthy'],
    ['paused wins over everything', { status: 'paused', lastAcceptedAt: null }, 'paused', 'paused'],
    [
      'provider kind without a connection',
      { kind: 'microsoft_365_journal', connection: null },
      'failing',
      'connection_unusable',
    ],
    [
      'provider kind with a disabled connection',
      { kind: 'google_workspace_copy', connection: { status: 'disabled', bound: true } },
      'failing',
      'connection_unusable',
    ],
    [
      'provider kind with an unbound connection',
      { kind: 'microsoft_365_journal', connection: { status: 'active', bound: false } },
      'failing',
      'connection_unusable',
    ],
    [
      'provider kind with a bound connection',
      { kind: 'microsoft_365_journal', connection: { status: 'active', bound: true } },
      'healthy',
      'healthy',
    ],
    [
      'refused in the last hour without acceptance',
      { lastRefusedAt: ago(10), lastAcceptedAt: ago(120) },
      'failing',
      'refused_without_acceptance',
    ],
    [
      'refused in the last hour with an acceptance in it',
      { lastRefusedAt: ago(10), lastAcceptedAt: ago(20) },
      'healthy',
      'healthy',
    ],
    ['an old refusal', { lastRefusedAt: ago(90), lastAcceptedAt: ago(120) }, 'healthy', 'healthy'],
    [
      'unwrap failures in the last hour',
      { unwrapFailuresLastHour: 2 },
      'failing',
      'unwrap_failures',
    ],
    ['never verified', { verifiedAt: null, lastAcceptedAt: null }, 'unknown', 'not_verified'],
    ['silent past the threshold', { lastAcceptedAt: ago(241) }, 'silent', 'silent'],
    ['verified, nothing accepted yet', { lastAcceptedAt: null }, 'silent', 'silent'],
    [
      'silence alerts off (NULL)',
      { silenceAlertMinutes: null, lastAcceptedAt: ago(10_000) },
      'healthy',
      'healthy',
    ],
  ])('%s', (_label, over, health, reason) => {
    expect(computeIntakeHealth({ ...base, ...over }, NOW)).toEqual({ health, reason });
  });
});

describe('alertWindowOf', () => {
  it('floors to a multiple of the window size since the epoch', () => {
    expect(alertWindowOf(new Date('2026-11-20T13:45:00.000Z'), 24 * 60)).toEqual({
      from: new Date('2026-11-20T00:00:00.000Z'),
      to: new Date('2026-11-21T00:00:00.000Z'),
    });
  });
});

describe('headerBlockOf (dedupe header block)', () => {
  it('ends at the first CRLF CRLF or LF LF; null without a separator', () => {
    expect(headerBlockOf(Buffer.from('A: 1\r\nB: 2\r\n\r\nbody'))?.toString()).toBe('A: 1\r\nB: 2');
    expect(headerBlockOf(Buffer.from('A: 1\nB: 2\n\nbody\r\n\r\n'))?.toString()).toBe('A: 1\nB: 2');
    expect(headerBlockOf(Buffer.from('A: 1\r\nB: 2'))).toBeNull();
  });
});

describe('refreshMergedParties (step 8.6 D7)', () => {
  const stored: ArchiveParties = {
    v: 1,
    from: 'a@corp.example',
    headerFrom: null,
    recipients: [
      {
        seq: 0,
        address: 'b@corp.example',
        direction: 'internal',
        status: 'journaled',
        finalAction: null,
        field: 'to',
        sources: ['journal_intake'],
      },
      {
        seq: 1,
        address: 'hidden@corp.example',
        direction: 'internal',
        status: 'journaled',
        finalAction: null,
        field: 'bcc',
        sources: ['journal_intake'],
      },
    ],
  };

  it('a gateway copy is authoritative for its recipients and keeps the intake-only BCC', () => {
    const fresh: ArchiveParties = {
      v: 1,
      from: 'a@corp.example',
      headerFrom: null,
      recipients: [
        {
          seq: 0,
          address: 'B@corp.example',
          direction: 'internal',
          status: 'delivered',
          finalAction: 'deliver',
        },
      ],
    };
    const out = refreshMergedParties(stored, fresh, 'gateway');
    expect(out.recipients).toEqual([
      {
        seq: 0,
        address: 'b@corp.example',
        direction: 'internal',
        status: 'delivered',
        finalAction: 'deliver',
        field: 'to',
        sources: ['gateway', 'journal_intake'],
      },
      stored.recipients[1],
    ]);
  });

  it('an intake copy never overwrites a recipient status; new recipients are appended', () => {
    const fresh: ArchiveParties = {
      v: 1,
      from: 'a@corp.example',
      headerFrom: null,
      recipients: [
        {
          seq: 0,
          address: 'b@corp.example',
          direction: null,
          status: 'journaled',
          finalAction: null,
        },
        {
          seq: 1,
          address: 'new@ext.example',
          direction: null,
          status: 'journaled',
          finalAction: null,
          field: 'cc',
        },
      ],
    };
    const gatewayFirst: ArchiveParties = {
      ...stored,
      recipients: [{ ...stored.recipients[0]!, status: 'delivered', sources: ['gateway'] }],
    };
    const out = refreshMergedParties(gatewayFirst, fresh, 'journal_intake');
    expect(out.recipients[0]).toMatchObject({ status: 'delivered', direction: 'internal' });
    expect(out.recipients[1]).toMatchObject({
      seq: 1,
      address: 'new@ext.example',
      field: 'cc',
      sources: ['journal_intake'],
    });
  });
});

describe('record versions with merged copies', () => {
  const ORG = 42n;
  const ref = (key: string) => ({ key, versionId: 'v1', sha256: 'a'.repeat(64), bytes: 10 });
  const objects = {
    captureId: '0190a5d0-0000-7000-8000-0000000000c1',
    eml: ref('org/42/archive/2026/11/20/0190a5d0-0000-7000-8000-0000000000a1/c/eml.bin'),
    journal: ref('org/42/archive/2026/11/20/0190a5d0-0000-7000-8000-0000000000a1/c/journal.bin'),
    scans: [],
    merged: [
      {
        messageId: '0190a5d0-0000-7000-8000-0000000000a2',
        receivedAt: '2026-11-20T10:00:00.000Z',
        source: 'journal_intake',
        journal: ref(
          'org/42/archive/2026/11/20/0190a5d0-0000-7000-8000-0000000000a2/d/journal.bin',
        ),
        eml: ref('org/42/archive/2026/11/20/0190a5d0-0000-7000-8000-0000000000a2/d/eml.bin'),
      },
      {
        messageId: '0190a5d0-0000-7000-8000-0000000000a3',
        receivedAt: '2026-11-20T10:01:00.000Z',
        source: 'journal_intake',
        journal: ref(
          'org/43/archive/2026/11/20/0190a5d0-0000-7000-8000-0000000000a3/e/journal.bin',
        ),
        eml: null,
      },
    ],
  };

  it('adds merged journals and variants of the own organization only', () => {
    const versions = recordVersionsWithMerged({ objects, organizationId: ORG }).map((v) => v.key);
    expect(versions).toHaveLength(4);
    expect(versions.some((k) => k.startsWith('org/43/'))).toBe(false);
    expect(mergedCopiesOf(objects)).toHaveLength(2);
    expect(mergedCopiesOf('not json')).toEqual([]);
  });

  it('disposal objects keep the record prefix and list the merged versions', () => {
    const d = disposalObjectsWithMerged({
      organizationId: ORG,
      receivedAt: new Date('2026-11-20T09:00:00.000Z'),
      messagePublicId: '0190a5d0-0000-7000-8000-0000000000a1',
      objects,
    });
    expect(d.prefix).toBe('org/42/archive/2026/11/20/0190a5d0-0000-7000-8000-0000000000a1/');
    expect(d.versions).toHaveLength(4);
  });
});

describe('exports and configuration (step 8.6)', () => {
  it('names variants after the item', () => {
    expect(variantEntryPath('messages/20261120T100000.000Z_abc.eml', 2)).toBe(
      'messages/20261120T100000.000Z_abc.variant-2.eml',
    );
  });
});
