import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { domainSummary } from '@/features/domains/test-data';
import { ApiModePage } from './api-mode-page';
import { historyQuery } from './history-tab';
import { documentOf, draftOf, validateDraft } from './remediation-tab';
import { ruleConditionText } from './remediation-model';

/**
 * Step API-2 WP6 (docs/plan/steps/36-api-mode-remediation.md R15, §9.5): the Remediation tab
 * (editor, presets, hard-delete visibility, CAS conflict, domain overrides), the History tab
 * (filters, drawer, retry), the detection actions (remediate, restore with the quarantine
 * outcome), the coverage tiles and pause toggle, the new check titles and the read-only gating.
 * Synthetic values only.
 */

const T = '2026-11-26T09:00:00.000Z';
const CONN = '0193f400-0000-7000-8000-000000000001';
const MAILBOX = '0193f700-0000-7000-8000-000000000001';
const DETECTION = '0193fa00-0000-7000-8000-000000000001';
const ACTION = '0193fb00-0000-7000-8000-000000000001';
const ENTRY = '0193fc00-0000-7000-8000-000000000001';
const APPROVAL = '0193fd00-0000-7000-8000-000000000001';
const DOMAIN = '0193fe00-0000-7000-8000-000000000001';
const SHA = 'ab'.repeat(32);

type Policy = SuccessBody<'ApiModeRemediationController_getPolicy_v1'>;
type Document = Policy['organization']['document'];

const P1: Document = {
  v: 1,
  rules: [
    {
      id: 'p1-high-confidence-malware-phishing-hb',
      when: { verdicts: ['malware', 'phishing'], hardBlock: true },
      action: 'move_quarantine',
    },
    {
      id: 'p1-high-confidence-malware-phishing',
      when: { verdicts: ['malware', 'phishing'], minLevel: 'critical' },
      action: 'move_quarantine',
    },
    { id: 'p1-other-malware-phishing', when: { verdicts: ['malware', 'phishing'] }, action: 'tag' },
    { id: 'p1-suspicious', when: { verdicts: ['suspicious', 'bec'] }, action: 'tag' },
  ],
};
const STRICT: Document = {
  v: 1,
  rules: [
    ...P1.rules,
    { id: 'strict-spam-junk', when: { verdicts: ['spam'] }, action: 'move_junk' },
  ],
};

const MAPPING = {
  quarantine: 'move_quarantine',
  require_approval: 'move_quarantine',
  reject: 'move_quarantine',
  allow_tagged: 'tag',
} as const;

const policy = (over: Partial<Policy> = {}): Policy => ({
  organization: {
    source: 'platform_default',
    id: null,
    mode: 'enforce',
    document: P1,
    sha256: SHA,
    rowVersion: null,
    updatedAt: null,
    effectivePolicyMapping: MAPPING,
    detectOnly: null,
  },
  domains: [],
  presets: {
    p1: { mode: 'enforce', document: P1 },
    detectOnlyStart: { mode: 'detect_only', document: P1 },
    strict: { mode: 'enforce', document: STRICT },
  },
  hardDeleteAvailable: false,
  ...over,
});

type Row = SuccessBody<'ApiModeController_listConnections_v1'>['data'][number];
const row = (over: Partial<Row> = {}): Row => ({
  id: CONN,
  apiConnectionId: '0193f900-0000-7000-8000-000000000001',
  displayName: 'Contoso production',
  provider: 'microsoft_365',
  status: 'active',
  bound: true,
  feedsEnabled: true,
  feedMode: 'poll',
  feedsEnabledAt: T,
  inventoryStatus: 'ok',
  inventorySyncedAt: T,
  inventoryRequestedAt: null,
  mailboxesTotal: 10,
  health: { status: 'degraded', changedAt: T },
  throttledUntil: null,
  lastErrorCode: null,
  remediationPaused: false,
  remediationPausedAt: null,
  grant: { profile: 'm365.mailbox_remediation', status: 'active', authMethod: 'platform_app' },
  journalSources: [],
  rowVersion: 3,
  ...over,
});

type Overview = SuccessBody<'ApiModeController_overview_v1'>;
const summary = (over: Partial<Overview['remediation']> = {}): Overview['remediation'] => ({
  policyMode: 'detect_only',
  policySource: 'organization',
  paused: false,
  succeeded1h: 2,
  failed1h: 1,
  succeeded24h: 14,
  failed24h: 3,
  skipped24h: 4,
  simulated24h: 6,
  restores24h: 1,
  throttled24h: 2,
  backlog: { pending: 5, capped: false, oldestPendingAgeSeconds: 420 },
  latencyAvgSeconds24h: 6.5,
  latencyMaxSeconds24h: 41,
  ...over,
});
const lag = { p50Seconds1h: 45, p95Seconds1h: 300, p50Seconds24h: 60, p95Seconds24h: 420 };
const overview = (failingChecks: string[] = []): Overview => ({
  generatedAt: T,
  entitled: true,
  active: true,
  organizationMode: 'inline',
  domainsByEffectiveMode: { inline: 2, api: 1, hybrid: 1 },
  coverage: { covered: 8, gap: 1, total: 9, percent: 88.8 },
  connectionsByHealth: { unknown: 0, healthy: 0, degraded: 1, failing: 0 },
  lag,
  throttling: { events1h: 0, events24h: 2 },
  copiesToday: 17,
  remediation: summary(),
  internal: { copies24h: 3, enabled: true },
  clawback: {
    active: 0,
    reviewRequired: 0,
    pendingApproval: 0,
    completed24h: 0,
    targetsSucceeded24h: 0,
    targetsFailed24h: 0,
    oldestActiveAgeSeconds: null,
  },
  reports: {
    pendingTriage: 0,
    inReview: 0,
    received24h: 0,
    resolved24h: 0,
    oldestPendingAgeSeconds: null,
    reportMailboxes: 0,
  },
  policy: { enabled: true, evaluated24h: 0, errors24h: 0 },
  outbound: { detections24h: 0, enabled: true },
  scope: { excluded: 0 },
  connections: [
    {
      id: CONN,
      displayName: 'Contoso production',
      provider: 'microsoft_365',
      health: 'degraded',
      failingChecks,
      coverage: { covered: 8, gap: 1, total: 9, percent: 88.8 },
      feedsEnabled: true,
      feedMode: 'poll',
      grantStatus: 'active',
      inventoryStatus: 'ok',
      lag,
      throttling: { events1h: 0, events24h: 2 },
      copiesToday: 17,
      throttledUntil: null,
      remediation: summary({ succeeded24h: 9 }),
      internal: { copies24h: 3, enabled: true },
      clawback: { targetsQueued24h: 0, targetsSucceeded24h: 0, targetsFailed24h: 0 },
      reports: {
        pendingTriage: 0,
        inReview: 0,
        received24h: 0,
        resolved24h: 0,
        oldestPendingAgeSeconds: null,
        reportMailboxes: 0,
      },
    },
  ],
});

type Detection = SuccessBody<'ApiModeController_getDetection_v1'>;
const detection = (over: Partial<Detection> = {}): Detection => ({
  id: DETECTION,
  mailboxId: MAILBOX,
  mailboxAddress: 'ana@alpha.example.test',
  connectionId: CONN,
  source: 'journal',
  seenJournal: true,
  seenApi: false,
  status: 'scanned',
  verdict: 'phishing',
  riskScore: 870,
  verdictAuthority: 'copy',
  receivedAt: T,
  providerDeliveredAt: T,
  verdictAt: T,
  lagMs: 90_000,
  subject: null,
  subjectMasked: true,
  headerFrom: 'b***@fabrikam.example.test',
  remediationState: 'remediated',
  remediationAction: 'move_quarantine',
  remediationId: ACTION,
  quarantineEntryId: ENTRY,
  direction: 'inbound',
  policyState: 'none',
  policyDisposition: null,
  policyTagged: false,
  dlpAction: null,
  verdictRevision: 0,
  clawbacks: [],
  deliveredBasis: 'received_header',
  reasonCodes: ['url.reputation_malicious'],
  policy: null,
  dlp: null,
  ...over,
});
const listRow = (d: Detection) => {
  const { deliveredBasis: _b, reasonCodes: _r, ...rest } = d;
  return rest;
};

type Action = SuccessBody<'ApiModeRemediationController_detail_v1'>;
const action = (over: Partial<Action> = {}): Action => ({
  id: ACTION,
  action: 'move_quarantine',
  trigger: 'policy',
  status: 'failed',
  reasonCode: 'provider_unavailable',
  attempts: 8,
  lastErrorCode: 'provider_unavailable',
  generation: 0,
  mailbox: { id: MAILBOX, address: 'ana@alpha.example.test' },
  connectionId: CONN,
  detectionId: DETECTION,
  quarantineEntryId: ENTRY,
  createdAt: T,
  nextAttemptAt: null,
  completedAt: T,
  latencyMs: 4_000,
  decision: {
    v: 1,
    policy: { scope: 'organization', publicId: null, rowVersion: 3, sha256: SHA },
    mode: 'enforce',
    ruleId: 'p1-high-confidence-malware-phishing',
    inputs: {
      verdict: 'phishing',
      riskScore: 870,
      level: 'critical',
      hardBlocks: [],
      verdictAuthority: 'copy',
    },
    policyOutcome: null,
    notes: [],
  },
  requestedBy: { type: 'system', userId: null },
  requestReason: null,
  locateAttempts: 1,
  lastHttpStatus: 503,
  providerRefs: { container: null, before: 0, after: 0 },
  reverses: null,
  reversedBy: null,
  releaseId: null,
  verdictAt: T,
  startedAt: T,
  updatedAt: T,
  clawbackId: null,
  ...over,
});
const actionRow = (a: Action) => ({
  id: a.id,
  clawbackId: a.clawbackId,
  action: a.action,
  trigger: a.trigger,
  status: a.status,
  reasonCode: a.reasonCode,
  attempts: a.attempts,
  lastErrorCode: a.lastErrorCode,
  generation: a.generation,
  mailbox: a.mailbox,
  connectionId: a.connectionId,
  detectionId: a.detectionId,
  quarantineEntryId: a.quarantineEntryId,
  createdAt: a.createdAt,
  nextAttemptAt: a.nextAttemptAt,
  completedAt: a.completedAt,
  latencyMs: a.latencyMs,
});

function base(extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    ApiModeController_overview_v1: () => okJson(overview()),
    ApiModeController_listConnections_v1: () => okJson({ data: [row()] }),
    ...extra,
  });
}

// ---- Remediation tab ---------------------------------------------------------------------------

describe('/api-mode Remediation tab (R15)', () => {
  it('shows the platform default, applies the detect-only preset and saves with a reason (contract, CAS null)', async () => {
    const bodies: unknown[] = [];
    base({
      ApiModeRemediationController_getPolicy_v1: () => okJson(policy()),
      ApiModeRemediationController_putPolicy_v1: ({ body }) => {
        bodies.push(body);
        return okJson({
          scope: 'organization',
          id: '0193ff00-0000-7000-8000-000000000001',
          domainId: null,
          mode: 'detect_only',
          document: P1,
          sha256: SHA,
          rowVersion: 1,
          updatedAt: T,
          created: true,
        });
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=remediation',
    });
    const form = await screen.findByRole('form', { name: 'Remediation policy: organization' });
    expect(screen.getByText(/Platform default \(P1\)/)).toBeInTheDocument();
    expect(
      within(form).getByText(/Detect only is the recommended start for new tenants/),
    ).toBeInTheDocument();
    expect(within(form).getAllByRole('listitem', { name: /^Rule \d+$/ })).toHaveLength(4);
    await expectNoAxeViolations(container);

    await user.click(
      within(form).getByRole('button', {
        name: 'Apply Detect-only start (recommended for new tenants)',
      }),
    );
    expect(within(form).getByRole('radio', { name: 'Detect only' })).toBeChecked();
    expect(within(form).getByText(/Preset Detect-only start .* applied/)).toBeInTheDocument();
    // A reason is required before anything is sent.
    await user.click(within(form).getByRole('button', { name: 'Save policy' }));
    expect(await within(form).findByText('Enter a reason.')).toBeInTheDocument();
    expect(bodies).toHaveLength(0);
    await user.type(within(form).getByLabelText('Reason (required)'), 'Start in detect-only');
    await user.click(within(form).getByRole('button', { name: 'Save policy' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      mode: 'detect_only',
      document: P1,
      reason: 'Start in detect-only',
      expectedRowVersion: null,
    });
    expectRequestMatchesContract('ApiModeRemediationController_putPolicy_v1', bodies[0]);
  });

  it('orders, adds and validates rules; hard delete only when the platform allows it, with the warning', async () => {
    base({
      ApiModeRemediationController_getPolicy_v1: () =>
        okJson(policy({ hardDeleteAvailable: false })),
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=remediation' });
    const form = await screen.findByRole('form', { name: 'Remediation policy: organization' });
    await user.click(within(form).getByRole('combobox', { name: 'Action of rule 1' }));
    expect(await screen.findByRole('option', { name: 'Move to Junk' })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /Hard delete/ })).not.toBeInTheDocument();
    await user.keyboard('{Escape}');
    await user.click(within(form).getByRole('button', { name: 'Add rule' }));
    await user.type(within(form).getByLabelText('Reason (required)'), 'Add a rule');
    await user.click(within(form).getByRole('button', { name: 'Save policy' }));
    expect(
      await within(form).findByText('Rule 5: choose at least one verdict.'),
    ).toBeInTheDocument();
    await user.click(within(form).getByRole('button', { name: 'Move rule 1 down' }));
    const rules = within(form).getAllByRole('listitem', { name: /^Rule \d+$/ });
    expect(within(rules[1]!).getByLabelText('Rule ID of rule 2')).toHaveValue(
      'p1-high-confidence-malware-phishing-hb',
    );
  });

  it('offers hard delete when available and warns that it is irreversible', async () => {
    base({
      ApiModeRemediationController_getPolicy_v1: () =>
        okJson(policy({ hardDeleteAvailable: true })),
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=remediation' });
    const form = await screen.findByRole('form', { name: 'Remediation policy: organization' });
    await user.click(within(form).getByRole('combobox', { name: 'Action of rule 4' }));
    await user.click(await screen.findByRole('option', { name: 'Hard delete (irreversible)' }));
    expect(await within(form).findByText(/Irreversible\./)).toBeInTheDocument();
    expect(within(form).getByText(/It cannot be undone/)).toBeInTheDocument();
  });

  it('explains a CAS conflict, reloads the policy and saves again with the new row version', async () => {
    let reads = 0;
    const bodies: Array<{ expectedRowVersion: number | null }> = [];
    base({
      ApiModeRemediationController_getPolicy_v1: () => {
        reads += 1;
        return okJson(
          policy({
            organization: {
              source: 'organization',
              id: '0193ff00-0000-7000-8000-000000000001',
              mode: 'enforce',
              document: P1,
              sha256: SHA,
              rowVersion: reads === 1 ? 2 : 3,
              updatedAt: T,
              effectivePolicyMapping: MAPPING,
              detectOnly: null,
            },
          }),
        );
      },
      ApiModeRemediationController_putPolicy_v1: ({ body }) => {
        bodies.push(body as { expectedRowVersion: number | null });
        return bodies.length === 1
          ? apiErrorJson(409, 'api_mode_remediation_policy_conflict', 'stale', {
              extra: { currentRowVersion: 3 },
            })
          : okJson({
              scope: 'organization',
              id: '0193ff00-0000-7000-8000-000000000001',
              domainId: null,
              mode: 'enforce',
              document: P1,
              sha256: SHA,
              rowVersion: 4,
              updatedAt: T,
              effectivePolicyMapping: MAPPING,
              detectOnly: null,
              created: false,
            });
      },
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=remediation' });
    const form = await screen.findByRole('form', { name: 'Remediation policy: organization' });
    await user.type(within(form).getByLabelText('Reason (required)'), 'Tighten');
    await user.click(within(form).getByRole('button', { name: 'Save policy' }));
    expect(
      await within(form).findByText(/changed by someone else since you opened it/),
    ).toBeInTheDocument();
    await waitFor(() => expect(reads).toBeGreaterThanOrEqual(2));
    await user.click(within(form).getByRole('button', { name: 'Save policy' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies.map((b) => b.expectedRowVersion)).toEqual([2, 3]);
  });

  it('domain overrides: add from the domain list, edit with CAS and remove back to inheriting', async () => {
    const puts: Array<{ path: string; body: unknown }> = [];
    const deletes: string[] = [];
    const override = {
      id: '0193ff00-0000-7000-8000-000000000002',
      domainId: DOMAIN,
      domainName: 'hybrid.example.test',
      mode: 'detect_only' as const,
      document: P1,
      sha256: SHA,
      rowVersion: 2,
      updatedAt: T,
      effectivePolicyMapping: MAPPING,
      detectOnly: null,
    };
    const domain = { ...domainSummary(1), id: '0193fe00-0000-7000-8000-000000000009' };
    base({
      ApiModeRemediationController_getPolicy_v1: () => okJson(policy({ domains: [override] })),
      DomainsController_list_v1: () => okJson({ data: [domain], nextCursor: null }),
      ApiModeRemediationController_putDomainPolicy_v1: ({ params, body }) => {
        puts.push({ path: String(params.domainId), body });
        return okJson({
          scope: 'domain',
          id: override.id,
          domainId: String(params.domainId),
          mode: 'enforce',
          document: P1,
          sha256: SHA,
          rowVersion: 3,
          updatedAt: T,
          effectivePolicyMapping: MAPPING,
          detectOnly: null,
          created: false,
        });
      },
      ApiModeRemediationController_deleteDomainPolicy_v1: ({ params }) => {
        deletes.push(String(params.domainId));
        return noContentResponse();
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=remediation',
    });
    const table = await screen.findByRole('table', { name: 'Domain overrides' });
    expect(within(table).getByText('hybrid.example.test')).toBeInTheDocument();
    expect(within(table).getByText('Detect only')).toBeInTheDocument();
    await expectNoAxeViolations(container);

    await user.click(
      within(table).getByRole('button', { name: 'Edit override of hybrid.example.test' }),
    );
    let dialog = await screen.findByRole('dialog', { name: 'Override of hybrid.example.test' });
    await user.click(within(dialog).getByRole('radio', { name: 'Enforce' }));
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'Enforce for hybrid');
    await user.click(within(dialog).getByRole('button', { name: 'Save override' }));
    await waitFor(() => expect(puts).toHaveLength(1));
    expect(puts[0]).toEqual({
      path: DOMAIN,
      body: { mode: 'enforce', document: P1, reason: 'Enforce for hybrid', expectedRowVersion: 2 },
    });
    expectRequestMatchesContract('ApiModeRemediationController_putDomainPolicy_v1', puts[0]!.body);

    await user.click(screen.getByRole('button', { name: 'Add domain override' }));
    dialog = await screen.findByRole('dialog', { name: 'Add a domain override' });
    await user.click(within(dialog).getByRole('combobox', { name: 'Domain' }));
    await user.click(await screen.findByRole('option', { name: domain.unicodeName }));
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'New override');
    await user.click(within(dialog).getByRole('button', { name: 'Save override' }));
    await waitFor(() => expect(puts).toHaveLength(2));
    expect(puts[1]).toMatchObject({ path: domain.id, body: { expectedRowVersion: null } });

    await user.click(
      within(screen.getByRole('table', { name: 'Domain overrides' })).getByRole('button', {
        name: 'Remove override of hybrid.example.test',
      }),
    );
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Remove override' }));
    await waitFor(() => expect(deletes).toEqual([DOMAIN]));
  });

  it('builds the document from a draft with only the bounds that are set', () => {
    const draft = draftOf('enforce', P1);
    expect(documentOf(draft)).toEqual(P1);
    draft.rules[0]!.minScore = '1001';
    draft.rules[1]!.id = 'p1-high-confidence-malware-phishing-hb';
    draft.rules[2]!.minLevel = 'critical';
    draft.rules[2]!.maxLevel = 'low';
    expect(validateDraft(draft)).toEqual([
      'Rule 1: the minimum risk score is a whole number from 0 to 1000.',
      'Rule 2: the rule ID p1-high-confidence-malware-phishing-hb is used twice.',
      'Rule 3: the maximum level is below the minimum level.',
    ]);
    expect(ruleConditionText(P1.rules[1]!)).toBe('Malware or Phishing · level ≥ critical');
    expect(ruleConditionText(P1.rules[0]!)).toBe('Malware or Phishing · hard block');
  });
});

// ---- History tab -------------------------------------------------------------------------------

describe('/api-mode History tab (R15)', () => {
  it('lists actions with URL filters, opens the drawer with the decision record and retries a failed action', async () => {
    const requests: URL[] = [];
    const retries: string[] = [];
    const failed = action();
    base({
      ApiModeRemediationController_list_v1: ({ url }) => {
        requests.push(url);
        return okJson({ data: [actionRow(failed)], nextCursor: null });
      },
      ApiModeRemediationController_detail_v1: () => okJson(failed),
      ApiModeRemediationController_retry_v1: ({ params }) => {
        retries.push(String(params.remediationId));
        return okJson({ ...actionRow(failed), status: 'pending', attempts: 0 }, 202);
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=history&status=failed',
    });
    const table = await screen.findByRole('table', {
      name: 'Mailbox actions of API-mode remediation',
    });
    expect(await within(table).findByText('Move to quarantine folder')).toBeInTheDocument();
    expect(within(table).getByText(/unavailable after every retry/)).toBeInTheDocument();
    expect(requests.at(-1)?.searchParams.get('status')).toBe('failed');
    expect(requests.at(-1)?.searchParams.get('from')).toBeTruthy();
    await expectNoAxeViolations(container);

    await user.click(within(table).getByRole('button', { name: /open details/ }));
    const drawer = await screen.findByRole('dialog', { name: 'Mailbox action' });
    expect(
      await within(drawer).findByText('p1-high-confidence-malware-phishing'),
    ).toBeInTheDocument();
    expect(within(drawer).getByText(/provider_unavailable \(HTTP 503\)/)).toBeInTheDocument();
    expect(within(drawer).getByRole('link', { name: 'Open the detection' })).toHaveAttribute(
      'href',
      `/api-mode?tab=detections&detection=${DETECTION}`,
    );
    expect(within(drawer).getByRole('link', { name: 'Open the quarantine entry' })).toHaveAttribute(
      'href',
      `/quarantine/${ENTRY}`,
    );
    await user.click(within(drawer).getByRole('button', { name: 'Retry' }));
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(retries).toEqual([ACTION]));
  });

  it('explains a refused retry of a quarantine restore', async () => {
    const failed = action({ action: 'restore_inbox', trigger: 'release' });
    base({
      ApiModeRemediationController_list_v1: () =>
        okJson({ data: [actionRow(failed)], nextCursor: null }),
      ApiModeRemediationController_retry_v1: () =>
        apiErrorJson(409, 'api_mode_remediation_not_retryable', 'not retryable', {
          extra: { cause: 'use_quarantine_release' },
        }),
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=history' });
    await screen.findByText('Restore to Inbox');
    await user.click(screen.getByRole('button', { name: /^Actions for Restore to Inbox/ }));
    await user.click(await screen.findByRole('menuitem', { name: 'Retry' }));
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Retry' }));
    expect(
      await within(confirm).findByText(/release the quarantine entry again/),
    ).toBeInTheDocument();
  });

  it('builds the list query from the filters', () => {
    expect(
      historyQuery(
        { status: 'failed', trigger: 'admin', detection: DETECTION, connection: CONN },
        { from: T, to: T },
      ),
    ).toEqual({
      from: T,
      to: T,
      status: 'failed',
      trigger: 'admin',
      connectionId: CONN,
      detectionId: DETECTION,
    });
  });
});

// ---- Detections: columns, filter, remediate and restore -----------------------------------------

describe('/api-mode Detections remediation (R12, R15)', () => {
  it('shows the remediation state and action, filters by state and requests a manual remediation', async () => {
    const requests: URL[] = [];
    const bodies: unknown[] = [];
    const clean = detection({
      id: '0193fa00-0000-7000-8000-000000000002',
      verdict: 'clean',
      remediationState: 'none',
      remediationAction: null,
      remediationId: null,
      quarantineEntryId: null,
    });
    base({
      ApiModeController_listDetections_v1: ({ url }) => {
        requests.push(url);
        return okJson({ data: [listRow(detection()), listRow(clean)], nextCursor: null });
      },
      ApiModeRemediationController_remediate_v1: ({ body }) => {
        bodies.push(body);
        return okJson(
          {
            detectionId: clean.id,
            remediation: actionRow(
              action({ trigger: 'admin', status: 'pending', action: 'move_junk' }),
            ),
          },
          202,
        );
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=detections&remediationState=remediated',
    });
    const table = await screen.findByRole('table');
    expect(await within(table).findByText('Remediated')).toBeInTheDocument();
    expect(within(table).getByText('Move to quarantine folder')).toBeInTheDocument();
    expect(requests.at(-1)?.searchParams.get('remediationState')).toBe('remediated');
    await expectNoAxeViolations(container);

    const menus = within(table).getAllByRole('button', { name: /^Actions for / });
    await user.click(menus[1]!);
    expect(await screen.findByRole('menuitem', { name: 'Restore' })).toHaveAttribute(
      'data-disabled',
    );
    await user.click(screen.getByRole('menuitem', { name: 'Remediate…' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('combobox', { name: 'Mailbox action' }));
    expect(screen.queryByRole('option', { name: /Hard delete/ })).not.toBeInTheDocument();
    await user.click(await screen.findByRole('option', { name: 'Move to Junk' }));
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'Reported by the user');
    await user.click(within(dialog).getByRole('button', { name: 'Remediate' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({ action: 'move_junk', reason: 'Reported by the user' });
    expectRequestMatchesContract('ApiModeRemediationController_remediate_v1', bodies[0]);
  });

  it('restore delegates to the quarantine release and shows the approval-requested outcome', async () => {
    const bodies: unknown[] = [];
    base({
      ApiModeController_listDetections_v1: () =>
        okJson({ data: [listRow(detection())], nextCursor: null }),
      ApiModeRemediationController_restore_v1: ({ body }) => {
        bodies.push(body);
        return okJson(
          {
            detectionId: DETECTION,
            via: 'quarantine_release',
            remediation: null,
            release: {
              outcome: 'approval_requested',
              entryId: ENTRY,
              state: 'pending_approval',
              approvalRequestId: APPROVAL,
              approvalReasons: ['hard_block'],
              rowVersion: 3,
            },
          },
          202,
        );
      },
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=detections' });
    const table = await screen.findByRole('table');
    await user.click(await within(table).findByRole('button', { name: /^Actions for / }));
    await user.click(await screen.findByRole('menuitem', { name: 'Restore' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/releases the message's quarantine entry/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'False positive');
    await user.click(within(dialog).getByRole('button', { name: 'Restore to inbox' }));
    await waitFor(() => expect(bodies).toEqual([{ reason: 'False positive' }]));
    expectRequestMatchesContract('ApiModeRemediationController_restore_v1', bodies[0]);
    expect(await screen.findByText('Approval requested')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open the approval request' })).toHaveAttribute(
      'href',
      `/quarantine/approvals/${APPROVAL}`,
    );
  });

  it('explains a restore refused for lack of the quarantine release permission', async () => {
    base({
      ApiModeController_listDetections_v1: () =>
        okJson({ data: [listRow(detection())], nextCursor: null }),
      ApiModeRemediationController_restore_v1: () =>
        apiErrorJson(403, 'quarantine_permission_required', 'needs quarantine:release'),
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=detections' });
    await user.click(await screen.findByRole('button', { name: /^Actions for / }));
    await user.click(await screen.findByRole('menuitem', { name: 'Restore' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'Please');
    await user.click(within(dialog).getByRole('button', { name: 'Restore to inbox' }));
    expect(
      await within(dialog).findByText(/also needs the quarantine release permission/),
    ).toBeInTheDocument();
  });

  it('opens the detection drawer from the link target with remediation links and actions', async () => {
    base({
      ApiModeController_listDetections_v1: () =>
        okJson({ data: [listRow(detection())], nextCursor: null }),
      ApiModeController_getDetection_v1: () => okJson(detection()),
    });
    const { container } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=detections&detection=${DETECTION}`,
    });
    const drawer = await screen.findByRole('dialog', { name: 'Detection' });
    expect(await within(drawer).findByText('Remediated')).toBeInTheDocument();
    expect(
      within(drawer).getByRole('link', { name: 'Mailbox actions of this detection' }),
    ).toHaveAttribute('href', `/api-mode?tab=history&detection=${DETECTION}`);
    expect(within(drawer).getByRole('link', { name: 'Open the quarantine entry' })).toHaveAttribute(
      'href',
      `/quarantine/${ENTRY}`,
    );
    expect(within(drawer).getByRole('button', { name: 'Remediate…' })).toBeEnabled();
    expect(within(drawer).getByRole('button', { name: 'Restore' })).toBeEnabled();
    await expectNoAxeViolations(container);
  });
});

// ---- Coverage ----------------------------------------------------------------------------------

describe('/api-mode Coverage remediation (R14, R15)', () => {
  it('shows the remediation tiles, the new check titles and pauses remediation through the settings route', async () => {
    const bodies: unknown[] = [];
    mockApi({
      ApiModeController_overview_v1: () =>
        okJson(
          overview([
            'remediation.failures_1h',
            'remediation.backlog',
            'remediation.access',
            'remediation.paused',
          ]),
        ),
      ApiModeController_listConnections_v1: () => okJson({ data: [row()] }),
      ApiModeController_updateSettings_v1: ({ body }) => {
        bodies.push(body);
        return okJson(row({ remediationPaused: true, remediationPausedAt: T, rowVersion: 4 }));
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, { route: '/api-mode' });
    const tiles = await screen.findByRole('list', { name: 'Remediation summary' });
    expect(within(tiles).getByText('2 succeeded')).toBeInTheDocument();
    expect(within(tiles).getByText('1 failed')).toBeInTheDocument();
    expect(within(tiles).getByText('5 pending')).toBeInTheDocument();
    expect(within(tiles).getByText('oldest 7 min')).toBeInTheDocument();
    expect(within(tiles).getByText('Detect only')).toBeInTheDocument();
    const table = screen.getByRole('table');
    for (const title of [
      'Remediation failures (last hour)',
      'Remediation backlog',
      'Remediation possible (mailbox access for an enforcing policy)',
      'Remediation paused',
    ])
      expect(within(table).getByText(title)).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(
      screen.getByRole('switch', { name: 'Pause remediation for Contoso production' }),
    );
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      feedsEnabled: true,
      feedMode: 'poll',
      remediationPaused: true,
      expectedRowVersion: 3,
    });
    expectRequestMatchesContract('ApiModeController_updateSettings_v1', bodies[0]);
  });
});

// ---- read-only gating --------------------------------------------------------------------------

describe('/api-mode remediation for read-only users', () => {
  it('shows the policy, history and detections without any write control', async () => {
    base({
      ApiModeRemediationController_getPolicy_v1: () => okJson(policy()),
      ApiModeRemediationController_list_v1: () =>
        okJson({ data: [actionRow(action())], nextCursor: null }),
      ApiModeController_listDetections_v1: () =>
        okJson({ data: [listRow(detection())], nextCursor: null }),
    });
    const { user } = renderWithProviders(<ApiModePage />, {
      role: 'read_only_user',
      route: '/api-mode?tab=remediation',
    });
    expect(
      await screen.findByRole('table', { name: 'Rules of the organization policy' }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('form')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Apply / })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add domain override' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'History' }));
    await screen.findByText('Move to quarantine folder');
    await user.click(screen.getByRole('button', { name: /^Actions for / }));
    expect(await screen.findByRole('menuitem', { name: 'Details' })).toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Retry' })).not.toBeInTheDocument();
    await user.keyboard('{Escape}');

    await user.click(screen.getByRole('tab', { name: 'Detections' }));
    await screen.findByText('Remediated');
    await user.click(screen.getByRole('button', { name: /^Actions for / }));
    expect(await screen.findByRole('menuitem', { name: 'Details' })).toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Remediate…' })).not.toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Restore' })).not.toBeInTheDocument();
    await user.keyboard('{Escape}');

    await user.click(screen.getByRole('tab', { name: 'Coverage' }));
    await screen.findByRole('list', { name: 'Remediation summary' });
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
  });
});

// ---- step API-4 (A4.4, A12, B7): policy evaluation, DLP, outbound, mapping, detect-only ------

describe('Step API-4 parity on /api-mode', () => {
  const evaluation = {
    evaluationId: '7001',
    evaluationMode: 'detect' as const,
    disposition: 'reject' as const,
    decisionSource: 'tenant_rule' as const,
    decisiveRuleRef: 'pol-1#3/blocked‮senders',
    overrideApplied: false,
    matchedRules: [{ ruleRef: 'pol-1#3/blocked‮senders', actions: ['REJECT'] }],
    actions: [{ type: 'REJECT', status: 'requested', reason: 'mapped_to_mailbox_action' }],
    explanation: 'Rule <b>blocked</b> matched',
    postDelivery: [
      { type: 'REJECT', status: 'requested', reason: 'mapped_to_mailbox_action' },
      { type: 'SENDER_NOTICE', status: 'not_applicable', reason: 'post_delivery_no_bounce' },
    ],
    evaluatedAt: T,
  };

  it('Detections: policy and DLP columns and filters; outbound is never remediable', async () => {
    const queries: URLSearchParams[] = [];
    const outbound = detection({
      id: '0193fa00-0000-7000-8000-0000000000aa',
      direction: 'outbound',
      remediationState: 'skipped',
      remediationAction: null,
      remediationId: null,
      quarantineEntryId: null,
      policyState: 'evaluated',
      policyDisposition: 'reject',
      dlpAction: 'block',
      policy: {
        ...evaluation,
        actions: [{ type: 'REJECT', status: 'not_applicable', reason: 'outbound_already_sent' }],
      },
      dlp: { action: 'block', verdict: 'violation', categories: ['payment_card'] },
    });
    base({
      ApiModeController_listDetections_v1: ({ url }) => {
        queries.push(url.searchParams);
        return okJson({
          data: [
            listRow(
              detection({
                policyState: 'evaluated',
                policyDisposition: 'quarantine',
                policyTagged: true,
              }),
            ),
            listRow(outbound),
          ],
          nextCursor: null,
        });
      },
      ApiModeController_getDetection_v1: () => okJson(outbound),
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=detections',
    });
    const table = await screen.findByRole('table', { name: 'Detections of API-mode copies' });
    expect(await within(table).findByText('DLP Block')).toBeInTheDocument();
    expect(within(table).getByText('Quarantine')).toBeInTheDocument();
    expect(within(table).getByText('Tagged')).toBeInTheDocument();
    expect(within(table).getByText('Not remediable — already sent')).toBeInTheDocument();
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('combobox', { name: 'DLP action' }));
    await user.click(await screen.findByRole('option', { name: 'Block' }));
    await waitFor(() => expect(queries.at(-1)?.get('dlpAction')).toBe('block'));
    await user.click(screen.getByRole('combobox', { name: 'Policy disposition' }));
    await user.click(await screen.findByRole('option', { name: 'Reject' }));
    await waitFor(() => expect(queries.at(-1)?.get('policyDisposition')).toBe('reject'));
    await user.click(screen.getByRole('combobox', { name: 'Direction' }));
    await user.click(await screen.findByRole('option', { name: 'Outbound' }));
    await waitFor(() => expect(queries.at(-1)?.get('direction')).toBe('outbound'));
  });

  it('Detection detail: the policy evaluation (untrusted text) and the DLP block', async () => {
    const outbound = detection({
      direction: 'outbound',
      remediationState: 'skipped',
      remediationAction: null,
      remediationId: null,
      quarantineEntryId: null,
      policyState: 'evaluated',
      policyDisposition: 'reject',
      dlpAction: 'block',
      policy: evaluation,
      dlp: { action: 'block', verdict: 'violation', categories: ['payment_card', 'iban'] },
    });
    base({
      ApiModeController_listDetections_v1: () => okJson({ data: [], nextCursor: null }),
      ApiModeController_getDetection_v1: () => okJson(outbound),
    });
    const { container } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=detections&detection=${DETECTION}`,
    });
    const drawer = await screen.findByRole('dialog', { name: 'Detection' });
    const policyBlock = await within(drawer).findByRole('region', { name: 'Policy evaluation' });
    expect(within(policyBlock).getByText('Reject')).toBeInTheDocument();
    expect(within(policyBlock).getByText('Your policy rule')).toBeInTheDocument();
    expect(
      within(policyBlock).getByText(/No bounce or sender notice after delivery/),
    ).toBeInTheDocument();
    // The explanation is untrusted text: rendered, never as HTML.
    expect(within(policyBlock).getByText('Rule <b>blocked</b> matched')).toBeInTheDocument();
    expect(policyBlock.querySelector('b')).toBeNull();
    const dlp = within(drawer).getByRole('region', { name: 'Data loss prevention' });
    expect(within(dlp).getByText('payment_card')).toBeInTheDocument();
    expect(
      within(drawer).getByText(/Outbound · Not remediable — already sent/),
    ).toBeInTheDocument();
    expect(within(drawer).getByRole('button', { name: 'Remediate…' })).toBeDisabled();
    await expectNoAxeViolations(container);
  });

  it('History detail: decision v2 lanes with the policy outcome', async () => {
    const v2 = action({
      status: 'succeeded',
      decision: {
        v: 2,
        policy: { scope: 'organization', publicId: null, rowVersion: 3, sha256: SHA },
        mode: 'enforce',
        ruleId: 'policy-mapping:reject',
        inputs: {
          verdict: 'clean',
          riskScore: 10,
          level: 'low',
          hardBlocks: [],
          verdictAuthority: 'copy',
        },
        policyOutcome: {
          disposition: 'reject',
          tagged: false,
          overrideApplied: false,
          decisionSource: 'tenant_rule',
          decisiveRuleRef: 'pol-1#3/blocked',
          floorReasons: [],
          dlpAction: null,
          actionTypes: ['REJECT'],
        },
        notes: [],
        lanes: {
          verdict: null,
          policy: { key: 'reject', action: 'move_quarantine' },
          winner: 'policy',
          suppressedBy: null,
        },
        postDelivery: [
          { type: 'SENDER_NOTICE', status: 'not_applicable', reason: 'post_delivery_no_bounce' },
        ],
      },
    });
    base({
      ApiModeRemediationController_list_v1: () =>
        okJson({ data: [actionRow(v2)], nextCursor: null }),
      ApiModeRemediationController_detail_v1: () => okJson(v2),
    });
    renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=history&remediation=${ACTION}`,
    });
    const drawer = await screen.findByRole('dialog', { name: 'Mailbox action' });
    const lanes = await within(drawer).findByLabelText('Decision lanes');
    expect(lanes).toHaveTextContent('Verdict lane: no action');
    expect(lanes).toHaveTextContent(
      'Policy lane: Policy disposition Reject → Move to quarantine folder (decided)',
    );
    expect(lanes).toHaveTextContent(/No bounce or sender notice after delivery/);
  });

  it('Remediation: policy mapping and the detect-only period are sent; hard delete is never offered', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    base({
      ApiModeRemediationController_getPolicy_v1: () => okJson(policy()),
      ApiModeRemediationController_putPolicy_v1: ({ body }) => {
        bodies.push(body as Record<string, unknown>);
        return apiErrorJson(422, 'api_mode_detect_only_invalid', 'invalid', {
          extra: { reason: 'until_too_late' },
        });
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=remediation',
    });
    const form = await screen.findByRole('form', { name: 'Remediation policy: organization' });
    const reject = within(form).getByRole('combobox', { name: 'Policy disposition Reject' });
    await user.click(reject);
    expect(screen.queryByRole('option', { name: /Hard delete/ })).toBeNull();
    await user.click(await screen.findByRole('option', { name: 'Move to Junk' }));
    await user.click(within(form).getByRole('radio', { name: 'Detect only' }));
    const days = within(form).getByLabelText('Detect only for (days)');
    await user.type(days, '40');
    await user.type(within(form).getByLabelText('Reason (required)'), 'Start slowly');
    await user.click(within(form).getByRole('button', { name: 'Save policy' }));
    expect(
      await within(form).findByText(/The detect-only period is 1 to 30 days/),
    ).toBeInTheDocument();
    expect(bodies).toHaveLength(0);
    await user.clear(days);
    await user.type(days, '7');
    await user.click(within(form).getByRole('radio', { name: 'Switch to enforce automatically' }));
    await user.click(within(form).getByRole('button', { name: 'Save policy' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    const body = bodies[0]!;
    expect(body).toMatchObject({
      mode: 'detect_only',
      document: { policyMapping: { reject: 'move_junk', quarantine: 'move_quarantine' } },
      detectOnly: { then: 'enforce' },
    });
    expectRequestMatchesContract('ApiModeRemediationController_putPolicy_v1', body);
    await expectNoAxeViolations(container);
  });

  it('Remediation: the ended-period banner reviews, switches to enforce or extends 7 days', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    const ended = policy({
      organization: {
        source: 'organization',
        id: '0193ff00-0000-7000-8000-000000000001',
        mode: 'detect_only',
        document: P1,
        sha256: SHA,
        rowVersion: 5,
        updatedAt: T,
        effectivePolicyMapping: MAPPING,
        detectOnly: {
          until: '2026-11-20T09:00:00.000Z',
          then: 'remind',
          startedAt: '2026-11-13T09:00:00.000Z',
          ended: true,
          simulatedSinceStart: 12,
        },
      },
    });
    base({
      ApiModeRemediationController_getPolicy_v1: () => okJson(ended),
      ApiModeRemediationController_putPolicy_v1: ({ body }) => {
        bodies.push(body as Record<string, unknown>);
        return apiErrorJson(409, 'api_mode_remediation_policy_conflict', 'stale');
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=remediation',
    });
    const banner = await screen.findByRole('status', {
      name: 'Detect-only period ended: the organization policy',
    });
    expect(banner).toHaveTextContent('12 actions would have been taken');
    expect(within(banner).getByRole('link', { name: 'Review simulated actions' })).toHaveAttribute(
      'href',
      '/api-mode?tab=history&status=simulated',
    );
    await expectNoAxeViolations(container);
    await user.click(within(banner).getByRole('button', { name: 'Switch to enforce' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({ mode: 'enforce', expectedRowVersion: 5 });
    expect(bodies[0]).not.toHaveProperty('detectOnly');
    expectRequestMatchesContract('ApiModeRemediationController_putPolicy_v1', bodies[0]);
    await user.click(within(banner).getByRole('button', { name: 'Extend 7 days' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toMatchObject({ mode: 'detect_only', detectOnly: { then: 'remind' } });
    expect(await within(banner).findByText(/changed by someone else/)).toBeInTheDocument();
  });

  it('Settings and Coverage: the two toggles and the policy and outbound tiles', async () => {
    base({
      ApiModeSettingsController_get_v1: () =>
        okJson({
          settings: {
            internalMailEnabled: true,
            autoClawback: 'enforce',
            autoMaxMailboxes: 500,
            purgeApprovalMailboxes: 50,
            clawbackLookbackDays: 14,
            tiMinConfidence: 80,
            reportAckEnabled: true,
            reportFeedbackEnabled: true,
            policyEvaluationEnabled: true,
            outboundDetectionEnabled: false,
          },
          source: 'row',
          rowVersion: 2,
          updatedAt: T,
          defaults: {
            internalMailEnabled: true,
            autoClawback: 'enforce',
            autoMaxMailboxes: 500,
            purgeApprovalMailboxes: 50,
            clawbackLookbackDays: 14,
            tiMinConfidence: 80,
            reportAckEnabled: true,
            reportFeedbackEnabled: true,
            policyEvaluationEnabled: true,
            outboundDetectionEnabled: true,
          },
          bounds: {
            autoMaxMailboxes: { min: 1, max: 20_000 },
            purgeApprovalMailboxes: { min: 1, max: 10_000 },
            clawbackLookbackDays: { min: 1, max: 60 },
            tiMinConfidence: { min: 0, max: 100 },
          },
          platform: {
            hardDeleteAvailable: false,
            clawbackMaxWindowDays: 30,
            purgeApprovalTtlHours: 24,
            reportMailboxesMax: 20,
          },
        }),
      ApiModeReportsController_listMailboxes_v1: () => okJson({ data: [], nextCursor: null }),
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=settings' });
    const form = await screen.findByRole('form', { name: 'Organization settings' });
    expect(
      within(form).getByRole('switch', { name: 'Evaluate tenant policies on copies' }),
    ).toBeChecked();
    expect(
      within(form).getByRole('switch', { name: 'Detect outbound mail (DLP)' }),
    ).not.toBeChecked();
    await user.click(screen.getByRole('tab', { name: 'Coverage' }));
    const tiles = await screen.findByRole('list', { name: 'Policy and outbound summary' });
    expect(within(tiles).getByText('Policy evaluations, last 24 hours')).toBeInTheDocument();
    expect(within(tiles).getByText('Mailboxes excluded by scope')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Protection by mode' })).toHaveAttribute(
      'href',
      '/protection-by-mode',
    );
  });
});
