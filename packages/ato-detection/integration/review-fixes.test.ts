import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AtoAccount, PrismaClient } from '@email-gateway/database';
import { atoMailboxSha256 } from '@email-gateway/security-contracts';
import {
  IncidentCategoryRegistry,
  IncidentStore,
  type IncidentActor,
} from '@email-gateway/security-incidents';
import { atoIncidentHandler } from '../src/incident-handler';
import {
  ATO_TRANSACTION_ISOLATION,
  AtoStore,
  isAtoStoreError,
  type AtoStoreConfig,
  type IncidentPolicyResult,
} from '../src/store';
import { candidate, Fixtures, type Tx } from './support/fixtures';

/**
 * Step 8.4 closer review fixes against the real MySQL writer: four eyes for API-key requests,
 * restrictions shared or past expiry, the per-organization automation cap under concurrency, stale
 * provider actions, and the account → incident lock order of api incident mutations.
 */
const fx = new Fixtures();
let prisma: PrismaClient;
const MIN = 60_000;
const config: AtoStoreConfig = {
  approvalTtlHours: 24,
  automatedResponsesEnabled: true,
  maxAutomatedPerOrgPerHour: 10,
  maxActiveRestrictionsPerOrg: 500,
};
let clock = new Date();
const at = () => clock;
// eslint-disable-next-line prefer-const -- assigned after the registry that needs it lazily
let store: AtoStore;
const incidents = new IncidentStore({
  registry: new IncidentCategoryRegistry([atoIncidentHandler({ store: () => store })]),
  now: at,
});
store = new AtoStore({ now: at, incidents, config });
const system: IncidentActor = { type: 'system', id: null };

const rc = <T>(fn: (tx: Tx) => Promise<T>): Promise<T> =>
  fx.prisma.$transaction(fn, {
    timeout: 120_000,
    maxWait: 30_000,
    isolationLevel: ATO_TRANSACTION_ISOLATION,
  });

async function codeOf(promise: Promise<unknown>): Promise<string | null> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  if (error === null) return null;
  return isAtoStoreError(error) ? error.code : String((error as { code?: string }).code);
}

async function mailbox(organizationId: bigint, label: string): Promise<AtoAccount> {
  return rc((t) =>
    store.ensureAccount(t, {
      organizationId,
      subject: { kind: 'mailbox', address: fx.address(label) },
      at: clock,
    }),
  );
}

const sendBlock = (account: AtoAccount) => ({
  scope: 'mailbox' as const,
  accountPublicId: account.publicId,
  mailboxSha256: atoMailboxSha256(account.address!),
});

let org: bigint;
let owner: IncidentActor;
let colleague: IncidentActor;

beforeAll(async () => {
  prisma = fx.prisma;
  org = await fx.organization('review');
  const u1 = await fx.user(org, 'owner');
  const u2 = await fx.user(org, 'colleague');
  owner = { type: 'user', id: u1.publicId, userId: u1.id };
  colleague = { type: 'user', id: u2.publicId, userId: u2.id };
});

afterAll(async () => {
  await fx.cleanup();
});

describe('four eyes for requests made with an API key (ADR-0072)', () => {
  it('the key creator may neither approve nor reject; another user may', async () => {
    clock = new Date();
    const key = await fx.apiKey(org, owner.userId!, 'respond');
    const account = await mailbox(org, 'keyed');
    const pending = await rc((t) =>
      store.requestResponse(t, {
        organizationId: org,
        accountId: account.id,
        incidentId: null,
        actionType: 'restrict_smtp_sending',
        target: sendBlock(account),
        actor: { type: 'api_key', id: key.publicId },
        authorization: 'manual',
      }),
    );
    expect(pending).toMatchObject({
      status: 'pending_approval',
      requestedByType: 'api_key',
      requestedById: key.publicId,
    });
    for (const decision of ['approve', 'reject'] as const) {
      expect(
        await codeOf(
          rc((t) =>
            store.decideResponse(t, {
              organizationId: org,
              actionId: pending.id,
              decision,
              actor: owner,
            }),
          ),
        ),
      ).toBe('ato_self_approval');
    }
    // Matched by internal id as well as by public id.
    expect(
      await codeOf(
        rc((t) =>
          store.decideResponse(t, {
            organizationId: org,
            actionId: pending.id,
            decision: 'approve',
            actor: { type: 'user', id: owner.id },
          }),
        ),
      ),
    ).toBe('ato_self_approval');
    const done = await rc((t) =>
      store.decideResponse(t, {
        organizationId: org,
        actionId: pending.id,
        decision: 'approve',
        actor: colleague,
      }),
    );
    expect(done).toMatchObject({ status: 'succeeded', approvedByUserId: colleague.userId });
  });
});

describe('SMTP restrictions of one subject (D14)', () => {
  const restrict = (account: AtoAccount, minutes: number) =>
    rc((t) =>
      store.requestResponse(t, {
        organizationId: org,
        accountId: account.id,
        incidentId: null,
        actionType: 'restrict_smtp_sending',
        target: sendBlock(account),
        params: { durationMinutes: minutes, mode: 'reject' },
        actor: system,
        authorization: 'automation_policy',
      }),
    );

  it('a second action shares the running restriction, extends it, and only the last rollback lifts it', async () => {
    clock = new Date();
    const account = await mailbox(org, 'shared');
    const first = await restrict(account, 60);
    expect(first).toMatchObject({ status: 'succeeded', resultCode: 'restriction_applied' });
    // The first action is completed (`succeeded`, no active marker), so a second one is accepted.
    const second = await restrict(account, 240);
    expect(second).toMatchObject({
      status: 'succeeded',
      resultCode: 'restriction_already_active',
      restrictionId: first.restrictionId,
    });
    const extended = clock.getTime() + 240 * MIN;
    expect(second.effectiveUntil!.getTime()).toBe(extended);
    const row = await prisma.atoSmtpRestriction.findUniqueOrThrow({
      where: { id: first.restrictionId! },
    });
    expect(row).toMatchObject({ status: 'active', responseActionId: first.id });
    expect(row.expiresAt.getTime()).toBe(extended);
    const owning = await prisma.atoResponseAction.findUniqueOrThrow({ where: { id: first.id } });
    expect(owning.effectiveUntil!.getTime()).toBe(extended);

    const back1 = await rc((t) =>
      store.requestRollback(t, {
        organizationId: org,
        actionId: first.id,
        actor: owner,
        reason: 'owner verified',
      }),
    );
    expect(back1).toMatchObject({ status: 'rolled_back', resultCode: 'restriction_kept_shared' });
    expect(
      (await prisma.atoSmtpRestriction.findUniqueOrThrow({ where: { id: row.id } })).status,
    ).toBe('active');
    const back2 = await rc((t) =>
      store.requestRollback(t, {
        organizationId: org,
        actionId: second.id,
        actor: owner,
        reason: 'owner verified',
      }),
    );
    expect(back2.status).toBe('rolled_back');
    expect(
      (await prisma.atoSmtpRestriction.findUniqueOrThrow({ where: { id: row.id } })).status,
    ).toBe('lifted');
  });

  it('a restriction past expires_at but not yet swept is expired and replaced', async () => {
    clock = new Date();
    const account = await mailbox(org, 'stale-restriction');
    const first = await restrict(account, 15);
    clock = new Date(clock.getTime() + 16 * MIN); // the sweep has not run yet
    const second = await restrict(account, 60);
    expect(second).toMatchObject({ status: 'succeeded', resultCode: 'restriction_applied' });
    expect(second.restrictionId).not.toBe(first.restrictionId);
    expect(second.effectiveUntil!.getTime()).toBe(clock.getTime() + 60 * MIN);
    const old = await prisma.atoSmtpRestriction.findUniqueOrThrow({
      where: { id: first.restrictionId! },
    });
    expect(old).toMatchObject({ status: 'expired', activeMarker: null });
    const fresh = await prisma.atoSmtpRestriction.findUniqueOrThrow({
      where: { id: second.restrictionId! },
    });
    expect(fresh).toMatchObject({ status: 'active', activeMarker: 1, responseActionId: second.id });
  });
});

describe('automation hourly cap under concurrency (D13)', () => {
  it('two concurrent detections of one organization never exceed the tenant cap', async () => {
    clock = new Date();
    const orgC = await fx.organization('cap');
    await rc(async (t) => {
      await store.ensureSettings(t, orgC);
      await store.saveSettings(t, {
        organizationId: orgC,
        settings: {
          mode: 'enforce',
          automation: {
            maxAutomaticPerHour: 1,
            restrict_smtp_sending: { mode: 'automatic', minLevel: 'high', durationMinutes: 60 },
          },
        },
        expectedRowVersion: 1,
        actor: system,
      });
    });
    const prepared: Array<{ account: AtoAccount; policy: IncidentPolicyResult }> = [];
    for (const label of ['cap-a', 'cap-b']) {
      const account = await mailbox(orgC, label);
      const policy = await rc(async (t) => {
        const settings = await store.ensureSettings(t, orgC);
        const [locked] = await store.lockAccounts(t, orgC, [account.id]);
        const recorded = await store.recordSignals(t, {
          organizationId: orgC,
          account: locked!,
          candidates: [
            candidate('ato.content.phishing_sent', { subject: `${label}-1` }),
            candidate('ato.access.new_ip_prefix', { subject: `${label}-2` }),
          ],
          settingsVersion: settings.version,
          at: clock,
        });
        const rescore = await store.rescore(t, {
          organizationId: orgC,
          accountId: account.id,
          trigger: 'signal',
          settings,
        });
        expect(store.automationMayExecute(settings, rescore.result.level)).toBe(true);
        return store.applyIncidentPolicy(t, {
          organizationId: orgC,
          accountId: account.id,
          rescore,
          settings,
          evidence: {
            signals: recorded.created.map((s) => ({ id: s.id, detectedAt: s.detectedAt })),
            authEvents: [],
            messages: [],
            codes: recorded.created.map((s) => s.ruleCode),
          },
          newStrongSignal: true,
          context: { hasAtoPolicyRule: false, providerActions: new Set<string>() },
        });
      });
      prepared.push({ account, policy });
    }
    const automate = (i: number, hold?: Promise<void>) =>
      rc(async (t) => {
        const settings = await store.ensureSettings(t, orgC);
        const out = await store.runAutomation(t, {
          organizationId: orgC,
          accountId: prepared[i]!.account.id,
          incident: prepared[i]!.policy.incident!,
          recommendations: prepared[i]!.policy.recommendations,
          contributors: prepared[i]!.policy.contributors,
          settings,
          platformOrganization: false,
        });
        if (hold) await hold;
        return out.find((o) => o.actionType === 'restrict_smtp_sending')!;
      });
    let release!: () => void;
    const hold = new Promise<void>((resolve) => (release = resolve));
    const first = automate(0, hold);
    // Let the first transaction create its automatic action and keep it uncommitted.
    await new Promise((r) => setTimeout(r, 1_000));
    const second = automate(1);
    await new Promise((r) => setTimeout(r, 500));
    release();
    const [a, b] = await Promise.all([first, second]);
    expect(a.guard).toBeNull();
    expect(a.action).toMatchObject({ authorization: 'automation_policy', status: 'succeeded' });
    expect(b.guard).toBe('tenant_hourly_cap');
    expect(b.action).toMatchObject({ status: 'pending_approval', authorization: 'manual' });
    expect(
      await prisma.atoResponseAction.count({
        where: { organizationId: orgC, authorization: 'automation_policy' },
      }),
    ).toBe(1);
  });
});

describe('stale provider actions (D15)', () => {
  it('an approved provider action without progress past the retry horizon ends failed', async () => {
    clock = new Date();
    const account = await mailbox(org, 'provider');
    const target = { scope: 'account' as const, accountPublicId: account.publicId };
    const approved = await rc((t) =>
      store.requestResponse(t, {
        organizationId: org,
        accountId: account.id,
        incidentId: null,
        actionType: 'require_mfa',
        target,
        actor: system,
        authorization: 'automation_policy',
        providerKind: 'fake',
      }),
    );
    expect(approved.status).toBe('approved');
    // A new request for the same target is refused while it is active.
    expect(
      await codeOf(
        rc((t) =>
          store.requestResponse(t, {
            organizationId: org,
            accountId: account.id,
            incidentId: null,
            actionType: 'require_mfa',
            target,
            actor: system,
            authorization: 'automation_policy',
            providerKind: 'fake',
          }),
        ),
      ),
    ).toBe('ato_response_active');
    // Not yet stale: untouched.
    expect(
      await rc((t) =>
        store.failStaleProviderActions(t, {
          before: new Date(clock.getTime() - 60 * MIN),
          limit: 50,
          organizationIds: [org],
        }),
      ),
    ).toBe(0);
    const swept = await rc((t) =>
      store.failStaleProviderActions(t, {
        before: new Date(Date.now() + 60 * MIN),
        limit: 50,
        organizationIds: [org],
      }),
    );
    expect(swept).toBe(1);
    const failed = await prisma.atoResponseAction.findUniqueOrThrow({ where: { id: approved.id } });
    expect(failed).toMatchObject({
      status: 'failed',
      providerStatus: 'failed',
      resultCode: 'provider_retry_exhausted',
      activeMarker: null,
    });
    // The marker is free: the same response can be requested again.
    const again = await rc((t) =>
      store.requestResponse(t, {
        organizationId: org,
        accountId: account.id,
        incidentId: null,
        actionType: 'require_mfa',
        target,
        actor: system,
        authorization: 'automation_policy',
        providerKind: 'fake',
      }),
    );
    expect(again.status).toBe('approved');
    // Another organization's filter never touches it.
    expect(
      await rc((t) =>
        store.failStaleProviderActions(t, {
          before: new Date(Date.now() + 60 * MIN),
          limit: 50,
          organizationIds: [],
        }),
      ),
    ).toBe(0);
  });
});

describe('lock order account → incident (api incident mutation vs detection)', () => {
  it('an incident mutation waits for the account lock of a detection instead of deadlocking', async () => {
    clock = new Date();
    const account = await mailbox(org, 'lock-order');
    const incident = await rc((t) =>
      store.createManualIncident(t, {
        organizationId: org,
        accountPublicId: account.publicId,
        severity: 'high',
        actor: system,
      }),
    );
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let held!: () => void;
    const accountHeld = new Promise<void>((resolve) => (held = resolve));
    // The detect role: account, then (after the api started) the account's incident.
    const detection = rc(async (t) => {
      await store.lockAccounts(t, org, [account.id]);
      held();
      await gate;
      await incidents.lockForUpdate(t, org, incident.id);
    });
    await accountHeld;
    // The api's PATCH /incidents/{id} → resolved: lockForUpdate (subject first), the transition,
    // whose ATO hook updates and rescores the account.
    const mutation = rc(async (t) => {
      const locked = await incidents.lockForUpdate(t, org, incident.id);
      return incidents.transition(t, {
        organizationId: org,
        incidentId: locked!.id,
        to: 'resolved',
        resolutionCode: 'remediated',
        note: 'password reset with the user',
        actor: owner,
      });
    });
    await new Promise((r) => setTimeout(r, 500));
    release();
    const [d, m] = await Promise.allSettled([detection, mutation]);
    expect(d.status).toBe('fulfilled');
    expect(m.status, m.status === 'rejected' ? String(m.reason) : '').toBe('fulfilled');
    const row = await prisma.securityIncident.findUniqueOrThrow({ where: { id: incident.id } });
    expect(row.status).toBe('resolved');
    const after = await prisma.atoAccount.findUniqueOrThrow({ where: { id: account.id } });
    expect(after.activeIncidentId).toBeNull();
  });
});
