import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  messageLocation,
  microsoftDirectory,
  MS_DOMAIN,
  MS_TENANT_ID,
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { DEFAULT_REMEDIATION_POLICY, remediationActionKey } from '@email-gateway/mailbox-api';
import { M365_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
import { loadOrgApiModeState } from '../src/domain/api-mode-state';
import { loadConnectionContext } from '../src/domain/connections';
import { MAILBOX_SELECT } from '../src/feeds/feed-runner';
import { claimDueActions } from '../src/remediation/claims';
import { executeGraph, GraphFolderIds } from '../src/remediation/provider-exec';
import { RedisThrottleGate } from '../src/runtime/redis-stores';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';
import {
  actionsOfCopy,
  cancelOpenActions,
  copiesOf,
  drain,
  policy,
  queueAdminAction,
  remediationConfig,
  riskRow,
} from './support/remediation';

/**
 * Design note 36 §9.3 (mailbox-worker, Microsoft 365): the remediation decision in the copies
 * transaction (P1 rows, detect-only, hybrid inline, no grant, paused, redelivery) and the
 * `remediate` role against the in-process Graph simulator with the real MySQL writer, Redis and
 * MinIO: a feed copy moved to the hidden quarantine folder (created once, new id stored, entry
 * held, counters, audit), journal copies located by Message-ID (Sent Items ignored), already in
 * target, not found → back-off → `message_not_found`, tag and remove_tag, a 429 `Retry-After`
 * pause shared with feeds (no attempt counted), 503 back-off to the maximum attempts, a grant
 * revoked mid-queue, and a lease expiry re-claimed without a second provider effect.
 * Synthetic `it-apirem-*` organizations only.
 */
const fx = new Fixtures('it-apirem');
const clock = new Clock();
const S = fx.suffix;
let sims: RunningSimulators;
let tokens: SimAccessTokens;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const FOLDER = 'Email Gateway Quarantine';
const TAG = 'Email Gateway: Suspicious';
const ALEX = `alex@${MS_DOMAIN}`;
const BLAKE = `blake@${MS_DOMAIN}`;
const CASEY = `casey@${MS_DOMAIN}`;
const DREW = `drew@${MS_DOMAIN}`;
const ERIN = `erin@${MS_DOMAIN}`;
let scan = 1000n;

const mailboxOf = (address: string) =>
  fx.prisma.apiMailbox.findFirstOrThrow({
    where: { organizationId: org.id, primaryAddress: address },
    select: MAILBOX_SELECT,
  });

const moveCalls = () =>
  sims.script.calls({ simulator: 'graph', method: 'POST', path: /\/messages\/[^/]+\/move$/ });

/** A journal copy for `to` with a risk row of its scan round, handled by the copies role. */
async function journal(
  to: string,
  input: {
    verdict: 'malware' | 'phishing' | 'suspicious' | 'spam' | 'clean';
    hardBlocks?: string[];
    level?: 'low' | 'medium' | 'high' | 'critical';
    messageId?: string;
    deliver?: false | 'inbox' | 'inbox+sent';
    organization?: TestOrg;
    source?: bigint;
  },
) {
  const o = input.organization ?? org;
  const messageId = input.messageId ?? `${crypto.randomUUID()}@sender.example`;
  const eml = syntheticEml({ messageId, to: [to] });
  let delivered: string | null = null;
  let sent: string | null = null;
  if (input.deliver !== false) {
    delivered = (await sims.deliver({ user: to, eml })).messageId;
    if (input.deliver === 'inbox+sent') {
      sent = (await sims.deliver({ user: to, eml, folder: 'sentitems' })).messageId;
    }
  }
  const message = await fx.journalCopy(o, input.source ?? sourceId, {
    eml,
    recipients: [to],
    messageId,
    from: 'sender@sender.example',
    receivedAt: clock.now(),
  });
  scan += 1n;
  await riskRow(fx, o.id, message, {
    scanId: scan,
    level: input.level ?? (input.hardBlocks ? 'critical' : 'medium'),
    verdict: input.verdict === 'clean' ? 'clean' : input.verdict,
    score: input.hardBlocks ? 990 : 500,
    hardBlocks: input.hardBlocks ?? [],
  });
  const event = fx.copyScanned(o.id, message, {
    completedAt: clock.now(),
    verdict: input.verdict,
    riskScore: input.hardBlocks ? 990 : 500,
    scanId: scan.toString(),
  });
  const handled = await comps.copies.handle(event);
  const [copy] = await copiesOf(fx, message.id);
  return { message, copy: copy!, event, delivered, sent, messageId, handled };
}

beforeAll(async () => {
  sims = await startSimulators({
    dataset: { microsoft: { directories: [microsoftDirectory(clock.now())] } },
    now: clock.ms,
  });
  sims.tokens.setGrant(
    MS_TENANT_ID,
    M365_MAILBOX_REMEDIATION_PROFILE.key,
    M365_MAILBOX_REMEDIATION_PROFILE.permissions,
  );
  tokens = new SimAccessTokens(() => sims, clock);
  comps = fx.components(
    remediationConfig(fx, sims, {
      API_MODE_REMEDIATION_LOCATE_ATTEMPTS: '2',
      API_MODE_REMEDIATION_MAX_ATTEMPTS: '3',
    }),
    { clock, tokens },
  );
  org = await fx.organization('graph');
  await fx.domain(org, MS_DOMAIN, 'api');
  conn = await fx.connection(org, 'microsoft_365', {
    tenantId: MS_TENANT_ID,
    domains: [MS_DOMAIN],
    feeds: { enabled: true, mode: 'poll' },
  });
  tokens.directories.set(conn.providerConnectionPublicId, MS_TENANT_ID);
  sourceId = await fx.journalSource(org, conn);
  expect(await comps.inventory!.run(conn.apiConnectionId)).toMatchObject({ result: 'ok' });
});

beforeEach(async () => {
  await cancelOpenActions(fx, fx.organizationIds);
  comps.policies.invalidate();
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('decision in the copies transaction (R4)', () => {
  it('P1: hard-blocked malware → pending move_quarantine, suspicious → tag, spam → none; redelivery adds nothing', async () => {
    const malware = await journal(ALEX, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
    });
    expect(malware.copy).toMatchObject({
      remediationState: 'pending',
      remediationAction: 'move_quarantine',
    });
    const [action] = await actionsOfCopy(fx, malware.copy.id);
    expect(action).toMatchObject({
      action: 'move_quarantine',
      trigger: 'policy',
      status: 'pending',
      generation: 0,
      attempts: 0,
      requestedByType: 'system',
      actionKey: remediationActionKey(malware.copy.publicId, 'move_quarantine', 0),
    });
    expect(action!.nextAttemptAt?.getTime()).toBe(clock.ms());
    expect(malware.copy.lastActionId).toBe(action!.id);
    expect(action!.decision).toMatchObject({
      v: 1,
      policy: { scope: 'platform_default' },
      mode: 'enforce',
      ruleId: 'p1-high-confidence-malware-phishing-hb',
      inputs: {
        verdict: 'malware',
        hardBlocks: ['hb.malware_attachment'],
        verdictAuthority: 'copy',
      },
    });

    const suspicious = await journal(BLAKE, { verdict: 'suspicious', deliver: false });
    expect((await actionsOfCopy(fx, suspicious.copy.id))[0]).toMatchObject({
      action: 'tag',
      status: 'pending',
    });
    const spam = await journal(BLAKE, { verdict: 'spam', deliver: false });
    expect(spam.copy.remediationState).toBe('none');
    expect(await actionsOfCopy(fx, spam.copy.id)).toHaveLength(0);

    // A redelivered event is a ledger duplicate: no second row.
    expect(await comps.copies.handle(malware.event)).toBe('duplicate');
    expect(await actionsOfCopy(fx, malware.copy.id)).toHaveLength(1);
  });

  it('detect-only → simulated (no provider call); paused → skipped; default policy restored', async () => {
    await policy(fx, org.id, 'detect_only', DEFAULT_REMEDIATION_POLICY.document);
    const writes = sims.script.writes('graph').length;
    const simulated = await journal(CASEY, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_url'],
      deliver: false,
    });
    expect(simulated.copy.remediationState).toBe('simulated');
    const [row] = await actionsOfCopy(fx, simulated.copy.id);
    expect(row).toMatchObject({ status: 'simulated', action: 'move_quarantine' });
    expect(row!.completedAt).not.toBeNull();
    expect(row!.decision).toMatchObject({ mode: 'detect_only', policy: { scope: 'organization' } });
    await drain(comps);
    expect(sims.script.writes('graph').length).toBe(writes);
    await fx.prisma.apiRemediationPolicy.deleteMany({ where: { organizationId: org.id } });
    comps.policies.invalidate();

    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { remediationPaused: true },
    });
    const paused = await journal(CASEY, {
      verdict: 'phishing',
      hardBlocks: ['hb.known_phishing'],
      deliver: false,
    });
    expect(paused.copy.remediationState).toBe('skipped');
    expect((await actionsOfCopy(fx, paused.copy.id))[0]).toMatchObject({
      status: 'skipped',
      reasonCode: 'remediation_paused',
    });
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { remediationPaused: false },
    });
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.remediationSimulated, 0)).toBeGreaterThanOrEqual(1);
    expect(counters.reduce((n, c) => n + c.remediationSkipped, 0)).toBeGreaterThanOrEqual(1);
  });

  it('hybrid inline copies → inline_authority; a connection without a grant → no_mailbox_access', async () => {
    const hybrid = await fx.organization('hybrid');
    const domain = `hy-${S}.it-apirem.example`;
    await fx.domain(hybrid, domain, 'hybrid');
    const hconn = await fx.connection(hybrid, 'microsoft_365', {
      tenantId: `tenant-hybrid-${S}`,
      domains: [domain],
    });
    const hsource = await fx.journalSource(hybrid, hconn);
    const to = `jo@${domain}`;
    const messageId = `${crypto.randomUUID()}@sender.example`;
    await fx.gatewayMessage(hybrid, {
      messageId,
      recipient: to,
      receivedAt: clock.now(),
      finalVerdict: 'spam',
    });
    const inline = await journal(to, {
      verdict: 'phishing',
      hardBlocks: ['hb.known_phishing'],
      messageId,
      deliver: false,
      organization: hybrid,
      source: hsource,
    });
    expect(inline.copy.verdictAuthority).toBe('inline');
    // The inline verdict (spam) matches no P1 rule: no action at all.
    expect(await actionsOfCopy(fx, inline.copy.id)).toHaveLength(0);
    await policy(fx, hybrid.id, 'enforce', {
      v: 1,
      rules: [{ id: 'junk-spam', when: { verdicts: ['spam'] }, action: 'move_junk' }],
    });
    comps.policies.invalidate();
    const again = await journal(`kai@${domain}`, {
      verdict: 'malware',
      messageId: `${crypto.randomUUID()}@sender.example`,
      deliver: false,
      organization: hybrid,
      source: hsource,
    });
    expect(again.copy.verdictAuthority).toBe('copy');
    expect(await actionsOfCopy(fx, again.copy.id)).toHaveLength(0);
    // A hybrid copy linked to its inline message is never remediated automatically (R8).
    const id2 = `${crypto.randomUUID()}@sender.example`;
    await fx.gatewayMessage(hybrid, {
      messageId: id2,
      recipient: to,
      receivedAt: clock.now(),
      finalVerdict: 'spam',
    });
    const linked = await journal(to, {
      verdict: 'spam',
      messageId: id2,
      deliver: false,
      organization: hybrid,
      source: hsource,
    });
    expect((await actionsOfCopy(fx, linked.copy.id))[0]).toMatchObject({
      status: 'skipped',
      reasonCode: 'inline_authority',
    });

    const nogrant = await fx.organization('nogrant');
    const ngDomain = `ng-${S}.it-apirem.example`;
    await fx.domain(nogrant, ngDomain, 'api');
    const ngConn = await fx.connection(nogrant, 'microsoft_365', {
      tenantId: `tenant-ng-${S}`,
      domains: [ngDomain],
      grantStatus: 'revoked',
    });
    const ngSource = await fx.journalSource(nogrant, ngConn);
    const skipped = await journal(`max@${ngDomain}`, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
      deliver: false,
      organization: nogrant,
      source: ngSource,
    });
    expect((await actionsOfCopy(fx, skipped.copy.id))[0]).toMatchObject({
      status: 'skipped',
      reasonCode: 'no_mailbox_access',
      action: 'move_quarantine',
    });
  });
});

describe('remediate role on Microsoft Graph (R3, R5)', () => {
  it('moves a feed copy to the hidden quarantine folder: folder created once, new id stored, entry held', async () => {
    const mailbox = await mailboxOf(ALEX);
    const ctx = await loadConnectionContext(fx.prisma, mailbox.apiConnectionId);
    const state = await loadOrgApiModeState(fx.prisma, org.id);
    expect(await comps.feeds!.syncMailbox(mailbox, ctx, state)).toBe('initialized');
    const messageId = `${crypto.randomUUID()}@sender.example`;
    const delivered = await sims.deliver({
      user: ALEX,
      eml: syntheticEml({ messageId, to: [ALEX] }),
    });
    clock.advance(1_000);
    expect(await comps.feeds!.syncMailbox(await mailboxOf(ALEX), ctx, state)).toBe('ok');
    const copy = await fx.prisma.apiMessageCopy.findFirstOrThrow({
      where: { mailboxId: mailbox.id, providerMessageId: delivered.messageId },
    });
    const message = { id: copy.messageId, receivedAt: copy.receivedAt };
    const identity = await fx.prisma.messageIdentity.findUniqueOrThrow({
      where: { id: copy.messageId },
    });
    scan += 1n;
    await riskRow(fx, org.id, message, {
      scanId: scan,
      level: 'critical',
      verdict: 'malware',
      score: 1000,
      hardBlocks: ['hb.malware_attachment'],
    });
    const verdictAt = clock.now();
    await comps.copies.handle(
      fx.copyScanned(
        org.id,
        { ...message, publicId: identity.publicId },
        {
          completedAt: verdictAt,
          ingestSource: 'mailbox_api',
          verdict: 'malware',
          riskScore: 1000,
          scanId: scan.toString(),
        },
      ),
    );
    clock.advance(5_000);
    const folderPosts = () =>
      sims.script.calls({ simulator: 'graph', method: 'POST', path: /\/childFolders$/ }).length;
    expect(await comps.remediation!.tick()).toBe(false);

    const [action] = await actionsOfCopy(fx, copy.id);
    expect(action).toMatchObject({ status: 'succeeded', attempts: 1, reasonCode: null });
    const refs = action!.providerRefs as { before: string[]; after: string[]; container: string };
    expect(refs.before).toEqual([delivered.messageId]);
    expect(refs.after).toHaveLength(1);
    expect(refs.after[0]).not.toBe(delivered.messageId);
    expect(refs.container).toBe('quarantine_folder');
    const remediated = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: copy.id } });
    expect(remediated).toMatchObject({
      remediationState: 'remediated',
      remediationAction: 'move_quarantine',
      providerMessageId: refs.after[0],
      lastActionId: action!.id,
    });
    const location = messageLocation(sims.script, ALEX, delivered.messageId)!;
    expect(location).toMatchObject({ currentId: refs.after[0], state: 'present' });
    expect(location.folder).toMatchObject({ displayName: FOLDER, isHidden: true });
    const box = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: mailbox.id } });
    expect(box.quarantineContainerId).toBe(location.folder!.id);
    expect(box.containersCheckedAt).not.toBeNull();

    // R9.1: the mailbox-located entry.
    const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: copy.id },
      include: { actions: true },
    });
    expect(entry).toMatchObject({
      organizationId: org.id,
      location: 'mailbox',
      mailboxContainer: 'quarantine_folder',
      origin: 'api_remediation',
      kind: 'quarantine',
      status: 'held',
      reason: 'malware',
      lifecycleRound: 0,
      recipientAddress: ALEX,
      hasHardBlock: true,
      primaryEngine: 'attachment',
      riskLevel: 'critical',
      riskVerdict: 'malware',
      scanId: scan,
      apiMailboxId: mailbox.id,
      apiRemediationActionId: action!.id,
      decisionSource: null,
      subject: null,
    });
    expect(entry.hardBlocks).toEqual(['hb.malware_attachment']);
    expect(entry.explanationText).toBe(
      'Removed from the mailbox by the API-mode remediation policy (rule p1-high-confidence-malware-phishing-hb)',
    );
    expect(entry.expiresAt.getTime()).toBeGreaterThan(entry.quarantinedAt.getTime());
    expect(entry.actions.map((a) => [a.action, a.actorType])).toEqual([
      ['mailbox_remediated', 'system'],
    ]);
    expect(action!.quarantineEntryId).toBe(entry.id);

    const audit = await fx.prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: org.id,
        action: 'api_mode.remediation_executed',
        resourceId: action!.publicId,
      },
    });
    expect(audit).toMatchObject({ actorType: 'system', resourceType: 'api_remediation_action' });
    expect(audit.metadata).toEqual({
      actionId: action!.publicId,
      action: 'move_quarantine',
      trigger: 'policy',
      result: 'succeeded',
      reasonCode: null,
      copyId: copy.publicId,
      mailboxId: mailbox.publicId,
      connectionId: conn.apiConnectionPublicId,
    });
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.remediationSucceeded, 0)).toBe(1);
    expect(counters.reduce((n, c) => n + c.remediationLatencyCount, 0)).toBe(1);
    expect(counters.reduce((n, c) => Math.max(n, c.remediationLatencyMaxMs), 0)).toBe(5_000);

    // A second threat in the same mailbox reuses the cached folder (no second create).
    const posts = folderPosts();
    expect(posts).toBe(1);
    const second = await journal(ALEX, { verdict: 'phishing', level: 'critical' });
    await drain(comps);
    expect((await actionsOfCopy(fx, second.copy.id))[0]!.status).toBe('succeeded');
    expect(folderPosts()).toBe(posts);
    expect(messageLocation(sims.script, ALEX, second.delivered!)!.folder!.displayName).toBe(FOLDER);
  });

  it('locates a journal copy by Message-ID (Sent Items ignored) and stores the found id', async () => {
    const located = await journal(BLAKE, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
      deliver: 'inbox+sent',
    });
    expect(located.copy.providerMessageId).toBeNull();
    await drain(comps);
    const [action] = await actionsOfCopy(fx, located.copy.id);
    expect(action!.status).toBe('succeeded');
    expect((action!.providerRefs as { before: string[] }).before).toEqual([located.delivered]);
    const stored = await fx.prisma.apiMessageCopy.findFirstOrThrow({
      where: { id: located.copy.id },
    });
    expect(stored.providerMessageId).toBe((action!.providerRefs as { after: string[] }).after[0]);
    expect(messageLocation(sims.script, BLAKE, located.delivered!)!.folder!.displayName).toBe(
      FOLDER,
    );
    // The Sent Items copy of the same Message-ID was not touched.
    const sentCopy = messageLocation(sims.script, BLAKE, located.sent!)!;
    expect(sentCopy).toMatchObject({ currentId: located.sent, state: 'present' });
    expect(sentCopy.folder!.wellKnownName).toBe('sentitems');
  });

  it('records already_in_target and fails message_not_found after the locate back-off', async () => {
    // The tag is already on the message (the user or an earlier run set it).
    const tagged = await journal(CASEY, { verdict: 'suspicious' });
    const mailbox = await mailboxOf(CASEY);
    const ctx = await loadConnectionContext(fx.prisma, mailbox.apiConnectionId);
    const graph = comps.runtime!.clientsFor(ctx!).graph!;
    await graph.setCategories(
      mailbox.providerUserId!,
      tagged.delivered!,
      [TAG],
      AbortSignal.timeout(10_000),
    );
    await drain(comps);
    expect((await actionsOfCopy(fx, tagged.copy.id))[0]).toMatchObject({
      status: 'succeeded',
      reasonCode: 'already_in_target',
    });

    const missing = await journal(DREW, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
      deliver: false,
    });
    await drain(comps);
    let [action] = await actionsOfCopy(fx, missing.copy.id);
    expect(action).toMatchObject({ status: 'pending', locateAttempts: 1, attempts: 0 });
    expect(action!.nextAttemptAt!.getTime()).toBe(clock.ms() + 60_000);
    await drain(comps);
    expect((await actionsOfCopy(fx, missing.copy.id))[0]!.status).toBe('pending');
    clock.advance(61_000);
    await drain(comps);
    [action] = await actionsOfCopy(fx, missing.copy.id);
    expect(action).toMatchObject({ status: 'failed', reasonCode: 'message_not_found' });
    expect(
      (await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: missing.copy.id } }))
        .remediationState,
    ).toBe('failed');
    const audit = await fx.prisma.auditLog.findFirstOrThrow({
      where: { action: 'api_mode.remediation_executed', resourceId: action!.publicId },
    });
    expect(audit.metadata).toMatchObject({ result: 'failed', reasonCode: 'message_not_found' });
  });

  it('tags with the category and removes it with remove_tag (next generation)', async () => {
    const tagged = await journal(ERIN, { verdict: 'suspicious' });
    await drain(comps);
    const [tag] = await actionsOfCopy(fx, tagged.copy.id);
    expect(tag).toMatchObject({ status: 'succeeded', action: 'tag' });
    expect(messageLocation(sims.script, ERIN, tagged.delivered!)!.categories).toEqual([TAG]);
    expect(await fx.prisma.quarantineMessage.count({ where: { apiCopyId: tagged.copy.id } })).toBe(
      0,
    );

    await queueAdminAction(fx, tagged.copy.id, 'remove_tag', clock.now(), tag!.id);
    await drain(comps);
    const rows = await actionsOfCopy(fx, tagged.copy.id);
    expect(rows.map((r) => [r.action, r.status])).toEqual([
      ['tag', 'succeeded'],
      ['remove_tag', 'succeeded'],
    ]);
    expect(rows[0]!.reversedByActionId).toBe(rows[1]!.id);
    expect(messageLocation(sims.script, ERIN, tagged.delivered!)!.categories).toEqual([]);
    expect(
      await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: tagged.copy.id } }),
    ).toMatchObject({
      remediationState: 'restored',
      remediationGeneration: 1,
    });
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.restoresSucceeded, 0)).toBeGreaterThanOrEqual(1);
  });
});

describe('errors, budgets and leases (R5.1, R5.6, R5.7)', () => {
  it('a 429 Retry-After pauses the family shared with feeds and counts no attempt', async () => {
    const threat = await journal(DREW, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
    });
    sims.script.inject({
      simulator: 'graph',
      method: 'POST',
      path: /\/messages\/[^/]+\/move$/,
      status: 429,
      retryAfter: '2',
      times: 1,
    });
    const moves = moveCalls().length;
    await comps.remediation!.tick();
    let [action] = await actionsOfCopy(fx, threat.copy.id);
    expect(action).toMatchObject({ status: 'pending', attempts: 0, lastHttpStatus: 429 });
    expect(action!.nextAttemptAt!.getTime()).toBe(clock.ms() + 2_000);
    expect(
      await fx.redis.pttl(RedisThrottleGate.key(conn.apiConnectionPublicId, 'graph')),
    ).toBeGreaterThan(0);
    // The feeds of the connection honour the same pause.
    const alex = await mailboxOf(ALEX);
    const ctx = await loadConnectionContext(fx.prisma, alex.apiConnectionId);
    expect(
      await comps.feeds!.syncMailbox(alex, ctx, await loadOrgApiModeState(fx.prisma, org.id)),
    ).toBe('throttled');

    await new Promise((r) => setTimeout(r, 2_200));
    clock.advance(3_000);
    await drain(comps);
    [action] = await actionsOfCopy(fx, threat.copy.id);
    expect(action).toMatchObject({ status: 'succeeded', attempts: 1 });
    expect(moveCalls().length).toBe(moves + 2);
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.remediationThrottled, 0)).toBe(1);
    expect(counters.reduce((n, c) => n + c.throttled429, 0)).toBeGreaterThanOrEqual(1);
  });

  it('a retryable 503 backs off (30 s doubling) until the maximum attempts', async () => {
    const threat = await journal(ERIN, { verdict: 'phishing', hardBlocks: ['hb.known_phishing'] });
    sims.script.inject({
      simulator: 'graph',
      method: 'POST',
      path: /\/messages\/[^/]+\/move$/,
      status: 503,
      times: Infinity,
    });
    try {
      await comps.remediation!.tick();
      let [action] = await actionsOfCopy(fx, threat.copy.id);
      expect(action).toMatchObject({ status: 'pending', attempts: 1, lastHttpStatus: 503 });
      expect(action!.nextAttemptAt!.getTime()).toBe(clock.ms() + 30_000);
      clock.advance(30_000);
      await comps.remediation!.tick();
      [action] = await actionsOfCopy(fx, threat.copy.id);
      expect(action).toMatchObject({ status: 'pending', attempts: 2 });
      expect(action!.nextAttemptAt!.getTime()).toBe(clock.ms() + 60_000);
      clock.advance(60_000);
      await comps.remediation!.tick();
      [action] = await actionsOfCopy(fx, threat.copy.id);
      expect(action).toMatchObject({
        status: 'failed',
        attempts: 3,
        reasonCode: 'provider_unavailable',
        lastErrorCode: 'provider_unavailable',
      });
    } finally {
      sims.script.reset();
    }
  });

  it('a grant revoked while actions wait fails them mailbox_access_revoked without a call', async () => {
    const threat = await journal(CASEY, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
    });
    await fx.prisma.providerConnectionGrant.update({
      where: { id: conn.grantId },
      data: { status: 'revoked' },
    });
    const calls = sims.script.calls({ simulator: 'graph' }).length;
    try {
      await drain(comps);
    } finally {
      await fx.prisma.providerConnectionGrant.update({
        where: { id: conn.grantId },
        data: { status: 'active' },
      });
    }
    expect((await actionsOfCopy(fx, threat.copy.id))[0]).toMatchObject({
      status: 'failed',
      reasonCode: 'mailbox_access_revoked',
      attempts: 0,
    });
    expect(sims.script.calls({ simulator: 'graph' }).length).toBe(calls);
  });

  it('a lease expiry re-claims the action and repeats no provider effect', async () => {
    const threat = await journal(ALEX, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
    });
    const [claim] = await claimDueActions(fx.prisma, {
      now: clock.now(),
      batch: 1,
      leaseSeconds: 120,
      perConnection: 2,
      organizationIds: fx.organizationIds,
    });
    expect(claim!.id).toBe((await actionsOfCopy(fx, threat.copy.id))[0]!.id);
    // A second replica sees nothing due while the lease holds.
    expect(
      await claimDueActions(fx.prisma, {
        now: clock.now(),
        batch: 10,
        leaseSeconds: 120,
        perConnection: 2,
        organizationIds: fx.organizationIds,
      }),
    ).toEqual([]);
    // The first replica moved the message, then crashed before writing the outcome.
    const mailbox = await mailboxOf(ALEX);
    const ctx = await loadConnectionContext(fx.prisma, mailbox.apiConnectionId);
    const moved = await executeGraph(
      comps.runtime!.clientsFor(ctx!).graph!,
      new GraphFolderIds(),
      'x',
      {
        action: 'move_quarantine',
        user: mailbox.providerUserId!,
        knownIds: [],
        internetMessageId: `<${threat.messageId}>`,
        containers: {
          quarantineId: (
            await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: mailbox.id } })
          ).quarantineContainerId,
          tagId: null,
        },
        names: {
          quarantineFolderName: FOLDER,
          quarantineFolderHidden: true,
          gmailQuarantineLabel: 'unused',
          tagName: TAG,
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    expect(moved.kind).toBe('done');
    const moves = moveCalls().length;
    clock.advance(121_000);
    await drain(comps);
    const [action] = await actionsOfCopy(fx, threat.copy.id);
    expect(action).toMatchObject({ status: 'succeeded', reasonCode: 'already_in_target' });
    expect(moveCalls().length).toBe(moves);
    // The crashed replica's late outcome is discarded (CAS on row_version).
    expect(await comps.remediation!.execute(claim!)).toBe('lost');
    expect(await fx.prisma.quarantineMessage.count({ where: { apiCopyId: threat.copy.id } })).toBe(
      1,
    );
  });
});

describe('copy state after a non-success outcome; stale and unwritable actions (review fixes)', () => {
  const copyRow = (id: bigint) => fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id } });

  it('a failed remove_tag gives the copy back `remediated` with the tag still in effect', async () => {
    const tagged = await journal(BLAKE, { verdict: 'suspicious' });
    await drain(comps);
    const [tag] = await actionsOfCopy(fx, tagged.copy.id);
    expect(tag).toMatchObject({ status: 'succeeded', action: 'tag' });

    await queueAdminAction(fx, tagged.copy.id, 'remove_tag', clock.now(), tag!.id);
    expect((await copyRow(tagged.copy.id)).remediationState).toBe('pending');
    sims.script.inject({
      simulator: 'graph',
      method: 'PATCH',
      path: /\/messages\/[^/]+$/,
      status: 403,
      times: 1,
    });
    try {
      await drain(comps);
    } finally {
      sims.script.reset();
    }
    const rows = await actionsOfCopy(fx, tagged.copy.id);
    expect(rows.map((r) => [r.action, r.status, r.reasonCode])).toEqual([
      ['tag', 'succeeded', null],
      ['remove_tag', 'failed', 'provider_forbidden'],
    ]);
    expect(rows[0]!.reversedByActionId).toBeNull();
    expect(await copyRow(tagged.copy.id)).toMatchObject({
      remediationState: 'remediated',
      remediationAction: 'tag',
      remediationGeneration: 0,
      lastActionId: tag!.id,
    });
    expect(messageLocation(sims.script, BLAKE, tagged.delivered!)!.categories).toEqual([TAG]);
  });

  it('an admin action of an older generation is cancelled without a provider call; the copy stays restored', async () => {
    const tagged = await journal(CASEY, { verdict: 'suspicious' });
    await drain(comps);
    const [tag] = await actionsOfCopy(fx, tagged.copy.id);
    const removeId = await queueAdminAction(fx, tagged.copy.id, 'remove_tag', clock.now(), tag!.id);
    await drain(comps);
    expect(await copyRow(tagged.copy.id)).toMatchObject({
      remediationState: 'restored',
      remediationGeneration: 1,
      lastActionId: removeId,
    });
    // A generation-0 admin move re-armed after the restore (what a retry of an old failed row
    // did before the api refused it): the copy is marked pending on it.
    const copy = await copyRow(tagged.copy.id);
    const stale = await fx.prisma.apiRemediationAction.create({
      data: {
        organizationId: copy.organizationId,
        apiConnectionId: copy.apiConnectionId,
        mailboxId: copy.mailboxId,
        copyId: copy.id,
        copyReceivedAt: copy.receivedAt,
        messageId: copy.messageId,
        action: 'move_junk',
        generation: 0,
        actionKey: remediationActionKey(copy.publicId, 'move_junk', 0),
        trigger: 'admin',
        status: 'pending',
        decision: { requestedAction: 'move_junk', reason: 'it' },
        requestedByType: 'user',
        nextAttemptAt: clock.now(),
      },
    });
    await fx.prisma.apiMessageCopy.updateMany({
      where: { id: copy.id, receivedAt: copy.receivedAt },
      data: { remediationState: 'pending', remediationAction: 'move_junk', lastActionId: stale.id },
    });
    const moves = moveCalls().length;
    await drain(comps);
    expect(
      await fx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id: stale.id } }),
    ).toMatchObject({ status: 'cancelled', quarantineEntryId: null });
    expect(moveCalls().length).toBe(moves);
    expect(await copyRow(tagged.copy.id)).toMatchObject({
      remediationState: 'restored',
      remediationAction: 'tag',
      remediationGeneration: 1,
      lastActionId: removeId,
    });
    expect(await fx.prisma.quarantineMessage.count({ where: { apiCopyId: copy.id } })).toBe(0);
  });

  it('an outcome write that keeps throwing is counted per lease and ends failed internal_error', async () => {
    const threat = await journal(DREW, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
    });
    const boom = Object.assign(new Error('outcome write failed'), { code: 'outcome_write_failed' });
    const spy = vi.spyOn(comps.remediation!.outcomes, 'succeed').mockRejectedValue(boom);
    try {
      await comps.remediation!.tick();
      let [action] = await actionsOfCopy(fx, threat.copy.id);
      expect(action).toMatchObject({
        status: 'in_progress',
        attempts: 0,
        lastErrorCode: 'outcome_write_failed',
      });
      // Each re-claim of the expired lease counts one attempt (maximum 3 in this suite).
      for (const attempts of [1, 2]) {
        clock.advance(121_000);
        await comps.remediation!.tick();
        [action] = await actionsOfCopy(fx, threat.copy.id);
        expect(action).toMatchObject({ status: 'in_progress', attempts });
      }
      const calls = spy.mock.calls.length;
      clock.advance(121_000);
      await comps.remediation!.tick();
      [action] = await actionsOfCopy(fx, threat.copy.id);
      expect(action).toMatchObject({
        status: 'failed',
        attempts: 3,
        reasonCode: 'internal_error',
        lastErrorCode: 'outcome_write_failed',
        leaseUntil: null,
      });
      // The budget check runs before any provider call.
      expect(spy.mock.calls.length).toBe(calls);
      expect(await copyRow(threat.copy.id)).toMatchObject({
        remediationState: 'failed',
        remediationAction: 'move_quarantine',
      });
      const audit = await fx.prisma.auditLog.findFirstOrThrow({
        where: { action: 'api_mode.remediation_executed', resourceId: action!.publicId },
      });
      expect(audit.metadata).toMatchObject({ result: 'failed', reasonCode: 'internal_error' });
      clock.advance(121_000);
      expect(await comps.remediation!.tick()).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });
});
