/* eslint-disable @typescript-eslint/require-await -- the fakes implement async ports */
import { describe, expect, it, vi } from 'vitest';
import type { Prisma } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { remediationActionKey } from '@email-gateway/mailbox-api';
import { hardBlockIds, RemediationDecider, type DecisionCopy } from './decide';
import { RemediationPolicyLoader } from './policy-loader';

const logger = createLogger({ service: 'mailbox-worker-test', level: 'silent' });
const NOW = new Date('2026-11-26T12:00:00.000Z');
const ORG = 41n;
const COPY_PUBLIC_ID = '0193a000-0000-7000-8000-000000000001';

interface World {
  policies: Array<{
    publicId: string;
    domainId: bigint | null;
    mode: string;
    document: unknown;
    rowVersion: number;
  }>;
  grant: 'active' | 'revoked' | null;
  paused: boolean;
  domainMode: 'inline' | 'api' | 'hybrid' | null;
  mailboxStatus: 'active' | 'discovered' | 'disabled' | 'deleted';
  risk: { level: string; hard_blocks: unknown } | null;
  insertResult: number;
  /** Step API-3: `api_mode_org_settings.internal_mail_enabled` (null = no row, defaults). */
  internalMailEnabled: boolean | null;
  reportMailbox: boolean;
}

/** A fake writer transaction answering the decision's reads; records the writes. */
function fakeTx(world: World) {
  const writes: { sql: string; values: unknown[] }[] = [];
  const sql = (strings: TemplateStringsArray) => strings.join('?').replace(/\s+/g, ' ');
  const tx = {
    apiMailbox: {
      findUnique: vi.fn(async () => ({
        organizationId: ORG,
        apiConnectionId: 7n,
        status: world.mailboxStatus,
        domainId: 3n,
        reportMailbox: world.reportMailbox,
      })),
    },
    apiModeOrgSetting: {
      findUnique: vi.fn(async () =>
        world.internalMailEnabled === null
          ? null
          : {
              organizationId: ORG,
              internalMailEnabled: world.internalMailEnabled,
              autoClawback: 'enforce',
              autoMaxMailboxes: 500,
              purgeApprovalMailboxes: 50,
              clawbackLookbackDays: 14,
              tiMinConfidence: 80,
              reportAckEnabled: true,
              reportFeedbackEnabled: true,
              rowVersion: 1,
            },
      ),
    },
    providerConnectionGrant: {
      findUnique: vi.fn(async () =>
        world.grant === null ? null : { organizationId: ORG, status: world.grant },
      ),
    },
    domain: {
      findUnique: vi.fn(async () =>
        world.domainMode === null
          ? null
          : {
              organizationId: ORG,
              protectionMode: world.domainMode,
              deletedAt: null,
              organization: { id: ORG, protectionMode: 'inline' },
            },
      ),
    },
    apiRemediationPolicy: {
      findMany: vi.fn(async () => world.policies.map((p) => ({ ...p, organizationId: ORG }))),
    },
    $queryRaw: vi.fn(async (strings: TemplateStringsArray) => {
      const text = sql(strings);
      if (text.includes('FROM api_mode_connections')) {
        return [
          {
            organization_id: ORG,
            provider: 'microsoft_365',
            remediation_paused: world.paused ? 1 : 0,
            provider_connection_id: 9n,
          },
        ];
      }
      if (text.includes('FROM message_risk_scores')) {
        return world.risk ? [{ organization_id: ORG, ...world.risk }] : [];
      }
      if (text.includes('FROM api_remediation_actions'))
        return [{ id: 555n, organization_id: ORG }];
      throw new Error(`unexpected query ${text}`);
    }),
    $executeRaw: vi.fn(async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const text = sql(strings);
      writes.push({ sql: text, values });
      return text.startsWith(' INSERT IGNORE') ? world.insertResult : 1;
    }),
  };
  return { tx: tx as unknown as Prisma.TransactionClient, writes, raw: tx };
}

const world = (over: Partial<World> = {}): World => ({
  policies: [],
  grant: 'active',
  paused: false,
  domainMode: 'api',
  mailboxStatus: 'active',
  risk: {
    level: 'critical',
    hard_blocks: [{ id: 'hb.malware_attachment', verdict: 'malware', action: 'block' }],
  },
  insertResult: 1,
  internalMailEnabled: null,
  reportMailbox: false,
  ...over,
});

const copy = (over: Partial<DecisionCopy> = {}): DecisionCopy => ({
  id: 100n,
  receivedAt: new Date('2026-11-26T11:00:00.000Z'),
  publicId: COPY_PUBLIC_ID,
  organizationId: ORG,
  apiConnectionId: 7n,
  mailboxId: 8n,
  messageId: 200n,
  status: 'scanned',
  verdict: 'malware',
  riskScore: 980,
  verdictAuthority: 'copy',
  verdictAt: new Date('2026-11-26T11:00:30.000Z'),
  remediationState: 'none',
  remediationGeneration: 0,
  direction: 'inbound',
  ...over,
});

const decider = (now = () => NOW) =>
  new RemediationDecider({
    policies: new RemediationPolicyLoader({ now, logger }),
    hardDeleteEnabled: false,
  });

const insertOf = (writes: { sql: string; values: unknown[] }[]) =>
  writes.find((w) => w.sql.startsWith(' INSERT IGNORE INTO api_remediation_actions'));

describe('RemediationDecider (R4) with step API-3 context (C8.5, C9.2)', () => {
  it('an internal copy with internal mail disabled → skipped internal_mail_disabled', async () => {
    const { tx, writes } = fakeTx(world({ internalMailEnabled: false }));
    const result = await decider().decide(tx, copy({ direction: 'internal' }), '12', NOW);
    expect(result).toMatchObject({ kind: 'skipped', inserted: true });
    expect(insertOf(writes)!.values).toContain('internal_mail_disabled');
  });

  it('an internal copy with the default settings is decided like an inbound one', async () => {
    const { tx } = fakeTx(world());
    const result = await decider().decide(tx, copy({ direction: 'internal' }), '12', NOW);
    expect(result).toMatchObject({ kind: 'pending', action: 'move_quarantine' });
  });

  it('a report-mailbox copy gets no decision (C-I5)', async () => {
    const { tx, writes } = fakeTx(world({ reportMailbox: true }));
    expect(await decider().decide(tx, copy(), '12', NOW)).toEqual({ kind: 'none' });
    expect(writes).toHaveLength(0);
  });
});

describe('RemediationDecider (R4)', () => {
  it('P1: a hard-blocked malware copy gets a pending move_quarantine due now', async () => {
    const { tx, writes } = fakeTx(world());
    const result = await decider().decide(tx, copy(), '12', NOW);
    expect(result).toMatchObject({ kind: 'pending', action: 'move_quarantine', inserted: true });
    const insert = insertOf(writes)!;
    expect(insert.values).toContain(remediationActionKey(COPY_PUBLIC_ID, 'move_quarantine', 0));
    expect(insert.values).toContain('pending');
    const decision = JSON.parse(
      insert.values.find((v) => typeof v === 'string' && v.startsWith('{"v"')) as string,
    );
    expect(decision).toMatchObject({
      v: 1,
      policy: { scope: 'platform_default', publicId: null },
      mode: 'enforce',
      ruleId: 'p1-high-confidence-malware-phishing-hb',
      inputs: { verdict: 'malware', level: 'critical', hardBlocks: ['hb.malware_attachment'] },
      policyOutcome: null,
    });
    const update = writes.find((w) => w.sql.includes('UPDATE api_message_copies'))!;
    expect(update.values.slice(0, 3)).toEqual(['pending', 'move_quarantine', 555n]);
    expect(result.kind === 'pending' && result.counters).toEqual({});
  });

  it('P1: suspicious → tag; spam and clean → none (no write)', async () => {
    const tagged = fakeTx(world({ risk: null }));
    expect(
      await decider().decide(tagged.tx, copy({ verdict: 'suspicious', riskScore: 400 }), '12', NOW),
    ).toMatchObject({ kind: 'pending', action: 'tag' });
    for (const verdict of ['spam', 'clean', 'unknown'] as const) {
      const f = fakeTx(world());
      expect(await decider().decide(f.tx, copy({ verdict }), '12', NOW)).toEqual({ kind: 'none' });
      expect(f.writes).toHaveLength(0);
    }
    const failed = fakeTx(world());
    expect(await decider().decide(failed.tx, copy({ status: 'scan_failed' }), null, NOW)).toEqual({
      kind: 'none',
    });
  });

  it('detect-only → simulated; inline authority, no grant, paused → skipped with the reason', async () => {
    const detect = fakeTx(
      world({
        policies: [
          {
            publicId: '0193a000-0000-7000-8000-0000000000aa',
            domainId: null,
            mode: 'detect_only',
            document: {
              v: 1,
              rules: [
                { id: 'all-malware', when: { verdicts: ['malware'] }, action: 'move_quarantine' },
              ],
            },
            rowVersion: 3,
          },
        ],
      }),
    );
    expect(await decider().decide(detect.tx, copy(), '12', NOW)).toMatchObject({
      kind: 'simulated',
      counters: { remediation_simulated: 1 },
    });
    expect(insertOf(detect.writes)!.values).toContain('simulated');

    const cases: Array<[Partial<World>, Partial<DecisionCopy>, string]> = [
      [{}, { verdictAuthority: 'inline' }, 'inline_authority'],
      [{ grant: 'revoked' }, {}, 'no_mailbox_access'],
      [{ grant: null }, {}, 'no_mailbox_access'],
      [{ paused: true }, {}, 'remediation_paused'],
      [{ domainMode: 'inline' }, {}, 'out_of_scope'],
      [{ mailboxStatus: 'disabled' }, {}, 'out_of_scope'],
    ];
    for (const [w, c, reason] of cases) {
      const f = fakeTx(world(w));
      expect(await decider().decide(f.tx, copy(c), '12', NOW)).toMatchObject({
        kind: 'skipped',
        counters: { remediation_skipped: 1 },
      });
      expect(insertOf(f.writes)!.values).toContain(reason);
    }
  });

  it('leaves a copy alone whose remediation is pending, done or reversed, and a duplicate key', async () => {
    for (const remediationState of ['pending', 'remediated', 'restored'] as const) {
      const f = fakeTx(world());
      expect(await decider().decide(f.tx, copy({ remediationState }), '12', NOW)).toEqual({
        kind: 'unchanged',
      });
      expect(f.writes).toHaveLength(0);
    }
    const dup = fakeTx(world({ insertResult: 0 }));
    expect(await decider().decide(dup.tx, copy(), '12', NOW)).toMatchObject({
      kind: 'pending',
      inserted: false,
      counters: {},
    });
    expect(dup.writes.some((w) => w.sql.includes('UPDATE api_message_copies'))).toBe(false);
  });

  it('uses the domain override, caches the rows 30 s and treats an invalid document as no rules', async () => {
    let now = NOW;
    const d = decider(() => now);
    const w = world({
      policies: [
        {
          publicId: '0193a000-0000-7000-8000-0000000000bb',
          domainId: 3n,
          mode: 'enforce',
          document: {
            v: 1,
            rules: [{ id: 'junk-all', when: { verdicts: ['malware'] }, action: 'move_junk' }],
          },
          rowVersion: 1,
        },
      ],
    });
    const f = fakeTx(w);
    expect(await d.decide(f.tx, copy(), '12', now)).toMatchObject({ action: 'move_junk' });
    w.policies[0]!.document = { v: 1, rules: [{ id: 'bad rule id!' }] };
    w.policies[0]!.rowVersion = 2;
    const cached = fakeTx(w);
    expect(await d.decide(cached.tx, copy(), '12', now)).toMatchObject({ action: 'move_junk' });
    expect(cached.raw.apiRemediationPolicy.findMany).not.toHaveBeenCalled();
    now = new Date(NOW.getTime() + 31_000);
    const reloaded = fakeTx(w);
    expect(await d.decide(reloaded.tx, copy(), '12', now)).toEqual({ kind: 'none' });
  });
});

describe('hardBlockIds', () => {
  it('reads stored hard-block objects and tolerates strings and junk', () => {
    expect(
      hardBlockIds([
        { id: 'hb.malware_url', verdict: 'malware', action: 'block' },
        'hb.known_phishing',
        { id: 42 },
        null,
        'hb.malware_url',
        'Not An Id',
      ]),
    ).toEqual(['hb.malware_url', 'hb.known_phishing']);
    expect(hardBlockIds('x')).toEqual([]);
  });
});
