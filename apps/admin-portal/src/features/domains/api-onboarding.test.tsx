import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { hintHref, presetBody, presetOf } from './api-onboarding-steps';
import { DomainDetailPage } from './domain-detail-page';
import { DomainOnboardingPage } from './onboarding-page';
import {
  CONNECTION_ID,
  DOMAIN_ID,
  FIRST_COPY_ID,
  JOURNAL_SOURCE_ID,
  destinations,
  dnsRecords,
  domainDetail,
  onboardingSteps,
  onboardingView,
  scopeView,
  statusView,
  validation,
} from './test-data';

/**
 * Step API-4 WP6 (design B1, B2, B3, B5, B6, B7, B8, B9; §10.5): the mode-specific wizard step
 * lists (inline exactly as before, api without destinations, recipients or MX/SPF/DKIM/DMARC,
 * hybrid with both), the ownership step with the provider card (pending, result, 429
 * countdown), connect, intake, which mailboxes (CAS), threat action (detect-only default and
 * the PUT/DELETE bodies), review with activation and the first-copy check (waiting, hints,
 * received), read-only users ("ask an administrator") and the domain page per mode. No
 * `/api-mode/domains/*` request on the inline path: MSW fails a test on any unmocked request.
 */

const T = '2026-11-27T09:00:00.000Z';
const API = {
  configured: 'api' as const,
  effective: 'api' as const,
  inherited: false,
  changedAt: T,
};
const HYBRID = { ...API, configured: 'hybrid' as const, effective: 'hybrid' as const };

type Domain = SuccessBody<'DomainsController_get_v1'>;
const apiDomain = (over: Partial<Domain> = {}) =>
  domainDetail({
    status: 'pending_verification',
    verifiedAt: null,
    activatedAt: null,
    protectionMode: API,
    inboundEnabled: false,
    ownership: { method: null, providerCheck: null, providerCheckAvailable: false },
    verification: {
      ...domainDetail().verification!,
      status: 'pending',
      verifiedAt: null,
      lastOutcome: 'missing',
    },
    ...over,
  });

const providerRow = {
  id: CONNECTION_ID,
  provider: 'microsoft_365' as const,
  displayName: 'Contoso production',
  status: 'active' as const,
  tenantName: 'Contoso Ltd',
  outboundMode: 'off' as const,
  internalRouting: false,
  health: 'healthy' as const,
  healthChangedAt: T,
  domainCount: 1,
  createdAt: T,
};

const stepLabels = () =>
  within(screen.getByRole('navigation', { name: 'Onboarding steps' }))
    .getAllByRole('button')
    .map((b) => b.textContent ?? '');

describe('Add-domain wizard: step lists per mode (B1, B9)', () => {
  it('inline: exactly the step API-1 list and no /api-mode/domains request', async () => {
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ status: 'pending_verification', activatedAt: null })),
      DomainDestinationsController_get_v1: () =>
        okJson(destinations({ provider: null, servers: [] })),
      DomainRecipientsController_get_v1: () => okJson(validation()),
      DomainDnsController_dnsRecords_v1: () => okJson(dnsRecords()),
    });
    const { container } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=dns`,
    });
    expect(await screen.findByRole('heading', { name: '3. Publish DNS records' })).toBeVisible();
    const labels = stepLabels();
    expect(labels).toHaveLength(8);
    expect(labels[6]).toMatch(/Step 7 · skipped.*Mailbox protection/);
    expect(labels[7]).toMatch(/Activate/);
    for (const name of [/Connect mailboxes/, /Which mailboxes/, /Threat action/])
      expect(labels.some((l) => name.test(l))).toBe(false);
    await expectNoAxeViolations(container);
  });

  it('api: ownership, connect, intake, mailboxes, action, review; nothing inline is listed', async () => {
    mockApi({
      DomainsController_get_v1: () => okJson(apiDomain()),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(
          onboardingView({
            ownership: {
              status: 'pending',
              method: null,
              providerCheck: null,
              providerCheckAvailable: false,
            },
            steps: onboardingSteps({
              ownership: 'in_progress',
              connect: 'not_started',
              review: 'blocked',
            }),
          }),
        ),
    });
    const { container } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}`,
    });
    expect(await screen.findByRole('heading', { name: '3. Verify ownership' })).toBeVisible();
    const labels = stepLabels().join(' | ');
    for (const name of [
      'Protection mode',
      'Add domain',
      'Verify ownership',
      'Connect mailboxes',
      'Intake',
      'Which mailboxes',
      'Threat action',
      'Review and activate',
    ])
      expect(labels).toContain(name);
    for (const name of ['Destination', 'Recipient', 'Publish DNS', 'skipped', 'MX'])
      expect(labels).not.toContain(name);
    const txt = screen.getByRole('region', { name: 'Ownership TXT record' });
    expect(within(txt).getByText('_emailgateway-verify.alpha.example.test')).toBeVisible();
    expect(within(txt).getByRole('button', { name: 'Copy host' })).toBeVisible();
    expect(within(txt).getByRole('button', { name: 'Copy value' })).toBeVisible();
    expect(within(txt).getByRole('button', { name: 'Check now' })).toBeVisible();
    expect(screen.queryByRole('list', { name: 'DNS checks' })).toBeNull();
    expect(screen.queryByText('Not required in API mode')).toBeNull();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
    await expectNoAxeViolations(container);
  });

  it('hybrid: the inline steps plus the API steps', async () => {
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ status: 'verified', activatedAt: null, protectionMode: HYBRID })),
      DomainDestinationsController_get_v1: () => okJson(destinations()),
      DomainRecipientsController_get_v1: () => okJson(validation()),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(
          onboardingView({
            effectiveMode: 'hybrid',
            steps: onboardingSteps({ intake: 'not_started', review: 'not_started' }),
          }),
        ),
      ApiModeController_listConnections_v1: () => okJson({ data: [] }),
    });
    renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}`,
    });
    // Resumes at the first API step the server says is not done.
    expect(await screen.findByRole('heading', { name: '8. Intake' })).toBeVisible();
    const labels = stepLabels();
    expect(labels).toHaveLength(11);
    expect(labels.join(' | ')).toMatch(
      /Publish DNS records.*Verify ownership.*Destination mail server.*Recipient validation.*Connect mailboxes.*Intake.*Which mailboxes.*Threat action.*Review and activate/,
    );
    const journal = screen.getByRole('region', { name: 'Journal copy' });
    expect(within(journal).getByRole('link', { name: /Journal source/ })).toHaveAttribute(
      'href',
      `/settings/journaling/intake/${JOURNAL_SOURCE_ID}`,
    );
    expect(
      within(journal).getByRole('link', { name: 'Setup guide (journal rule)' }),
    ).toHaveAttribute('href', `/settings/journaling/intake/${JOURNAL_SOURCE_ID}?tab=guide`);
  });
});

describe('Ownership through the bound provider tenant (B3)', () => {
  it('requests the check, shows the pending state and the verified result', async () => {
    let checked = false;
    const bodies: unknown[] = [];
    const pending = {
      id: '9001',
      status: 'pending' as const,
      result: null,
      connectionId: CONNECTION_ID,
      requestedAt: T,
      checkedAt: null,
      expiresAt: T,
    };
    mockApi({
      DomainsController_get_v1: () =>
        okJson(
          apiDomain({
            ownership: {
              method: null,
              providerCheck: checked ? pending : null,
              providerCheckAvailable: true,
            },
          }),
        ),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(onboardingView({ steps: onboardingSteps({ ownership: 'in_progress' }) })),
      ProviderConnectionsController_list_v1: () =>
        okJson({ data: [providerRow], nextCursor: null }),
      DomainsController_providerOwnershipCheck_v1: ({ body }) => {
        bodies.push(body);
        checked = true;
        return okJson(
          {
            verificationId: '9001',
            status: 'pending',
            connectionId: CONNECTION_ID,
            expiresAt: T,
            reused: false,
          },
          202,
        );
      },
    });
    const { user, container } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=ownership`,
    });
    const card = await screen.findByRole('region', { name: 'Automatic ownership verification' });
    expect(
      await within(card).findByRole('heading', {
        name: 'Verify automatically through Microsoft 365 (Contoso production)',
      }),
    ).toBeVisible();
    await expectNoAxeViolations(container);
    await user.click(within(card).getByRole('button', { name: 'Verify automatically' }));
    await waitFor(() => expect(bodies).toEqual([{}]));
    expectRequestMatchesContract('DomainsController_providerOwnershipCheck_v1', bodies[0]);
    expect(await within(card).findByText(/Checking with your provider/)).toBeVisible();
    expect(within(card).getByRole('button', { name: 'Checking …' })).toBeDisabled();
  });

  it('a failed check explains the result; the rate limit shows a countdown', async () => {
    mockApi({
      DomainsController_get_v1: () =>
        okJson(
          apiDomain({
            ownership: {
              method: null,
              providerCheck: {
                id: '9002',
                status: 'failed',
                result: 'absent',
                connectionId: CONNECTION_ID,
                requestedAt: T,
                checkedAt: T,
                expiresAt: T,
              },
              providerCheckAvailable: true,
            },
          }),
        ),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(onboardingView({ steps: onboardingSteps({ ownership: 'in_progress' }) })),
      ProviderConnectionsController_list_v1: () =>
        okJson({ data: [providerRow], nextCursor: null }),
      DomainsController_providerOwnershipCheck_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many checks', { headers: { 'retry-after': '42' } }),
    });
    const { user } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=ownership`,
    });
    const card = await screen.findByRole('region', { name: 'Automatic ownership verification' });
    expect(within(card).getByText(/not listed in the provider tenant/)).toBeVisible();
    await user.click(within(card).getByRole('button', { name: 'Verify automatically' }));
    expect(await within(card).findByRole('button', { name: /Try again in \d+ s/ })).toBeDisabled();
    expect(within(card).getByRole('alert')).toHaveTextContent(/Too many automatic checks/);
  });
});

describe('Connect, intake and which mailboxes (B1, B4, B6)', () => {
  it('connect: links the verified domain to an existing connection (existing links kept)', async () => {
    const bodies: unknown[] = [];
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ status: 'verified', activatedAt: null, protectionMode: API })),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(
          onboardingView({
            connection: null,
            steps: onboardingSteps({ connect: 'not_started', intake: 'blocked' }),
          }),
        ),
      ProviderConnectionsController_list_v1: () =>
        okJson({ data: [providerRow], nextCursor: null }),
      ProviderConnectionsController_get_v1: () =>
        okJson({
          id: CONNECTION_ID,
          domains: [{ id: 'aaaaaaaa-0000-7000-8000-000000000002', name: 'other.example.test' }],
        }),
      ProviderDomainsController_replace_v1: ({ body }) => {
        bodies.push(body);
        return okJson({ data: [] });
      },
    });
    const { user, container } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=connect`,
    });
    expect(await screen.findByRole('heading', { name: '4. Connect mailboxes' })).toBeVisible();
    expect(
      screen.getByText(/No Microsoft 365 or Google Workspace connection is linked/),
    ).toBeVisible();
    await user.click(await screen.findByRole('combobox', { name: 'Existing connection' }));
    await user.click(await screen.findByRole('option', { name: /Contoso production/ }));
    await user.click(screen.getByRole('button', { name: 'Link alpha.example.test' }));
    await waitFor(() =>
      expect(bodies).toEqual([{ domainIds: ['aaaaaaaa-0000-7000-8000-000000000002', DOMAIN_ID] }]),
    );
    expectRequestMatchesContract('ProviderDomainsController_replace_v1', bodies[0]);
    expect(screen.getByRole('link', { name: 'Create a new connection' })).toHaveAttribute(
      'href',
      '/integrations/providers/new',
    );
    await expectNoAxeViolations(container);
  });

  it('which mailboxes: selected mailboxes with CAS; a conflict reloads and explains', async () => {
    const bodies: Array<{ expectedRowVersion: number | null }> = [];
    let reads = 0;
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ status: 'verified', activatedAt: null, protectionMode: API })),
      ApiModeOnboardingController_domainOnboarding_v1: () => okJson(onboardingView()),
      ApiModeOnboardingController_getScope_v1: () => {
        reads += 1;
        return okJson(scopeView({ rowVersion: reads === 1 ? null : 1 }));
      },
      DepartmentsController_list_v1: () => okJson({ data: [], nextCursor: null }),
      ApiModeController_listMailboxes_v1: () =>
        okJson({
          data: [0, 1].map((i) => ({
            id: `0193f700-0000-7000-8000-00000000000${i + 1}`,
            connectionId: CONNECTION_ID,
            address: `user${i}@alpha.example.test`,
            domain: { id: DOMAIN_ID, name: 'alpha.example.test' },
            status: 'active',
            coverage: 'covered',
            coverageChangedAt: T,
            feedStatus: 'off',
            journalLastSeenAt: T,
            lastSyncAt: T,
            lastErrorCode: null,
          })),
          nextCursor: null,
        }),
      ApiModeOnboardingController_putScope_v1: ({ body }) => {
        bodies.push(body as { expectedRowVersion: number | null });
        return apiErrorJson(409, 'api_mode_scope_conflict', 'stale', {
          extra: { currentRowVersion: 1 },
        });
      },
    });
    const { user, container } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=mailboxes`,
    });
    const form = await screen.findByRole('form', { name: 'Which mailboxes' });
    expect(screen.getByText(/All mailboxes: 9 in scope, 0 excluded/)).toBeVisible();
    await user.click(within(form).getByRole('radio', { name: 'Selected mailboxes' }));
    await user.click(
      await within(form).findByRole('checkbox', { name: 'user1@alpha.example.test' }),
    );
    await user.type(within(form).getByLabelText('Reason (required)'), 'Pilot group');
    await user.click(within(form).getByRole('button', { name: 'Save mailbox scope' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      scope: { kind: 'mailboxes' },
      mailboxIds: ['0193f700-0000-7000-8000-000000000002'],
      reason: 'Pilot group',
      expectedRowVersion: null,
    });
    expectRequestMatchesContract('ApiModeOnboardingController_putScope_v1', bodies[0]);
    expect(await screen.findByText(/Someone else changed the scope/)).toBeVisible();
    await waitFor(() => expect(reads).toBeGreaterThanOrEqual(2));
    await expectNoAxeViolations(container);
  });
});

describe('Threat action (B7)', () => {
  const policyView = (
    domains: SuccessBody<'ApiModeRemediationController_getPolicy_v1'>['domains'] = [],
  ) => {
    const doc = {
      v: 1 as const,
      rules: [
        {
          id: 'p1-malware',
          when: { verdicts: ['malware' as const, 'phishing' as const] },
          action: 'move_quarantine' as const,
        },
      ],
    };
    const mapping = {
      quarantine: 'move_quarantine' as const,
      require_approval: 'move_quarantine' as const,
      reject: 'move_quarantine' as const,
      allow_tagged: 'tag' as const,
    };
    return {
      organization: {
        source: 'platform_default' as const,
        id: null,
        mode: 'enforce' as const,
        document: doc,
        sha256: 'a'.repeat(64),
        rowVersion: null,
        updatedAt: null,
        effectivePolicyMapping: mapping,
        detectOnly: null,
      },
      domains,
      presets: {
        p1: { mode: 'enforce' as const, document: doc },
        detectOnlyStart: { mode: 'detect_only' as const, document: doc },
        strict: { mode: 'enforce' as const, document: doc },
      },
      hardDeleteAvailable: false,
    };
  };

  it('defaults to detect only for 7 days with a reminder and PUTs the domain policy', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ status: 'verified', activatedAt: null, protectionMode: API })),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(
          onboardingView({
            action: {
              source: 'platform_default',
              mode: 'enforce',
              presetKey: 'p1',
              detectOnly: null,
            },
            steps: onboardingSteps({ action: 'not_started' }),
          }),
        ),
      ApiModeRemediationController_getPolicy_v1: () => okJson(policyView()),
      ApiModeRemediationController_putDomainPolicy_v1: ({ body }) => {
        bodies.push(body as Record<string, unknown>);
        return apiErrorJson(500, 'internal_error', 'stop here');
      },
    });
    const { user, container } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=action`,
    });
    const radio = await screen.findByRole('radio', {
      name: 'Detect only for 7 days, then remind me (recommended)',
    });
    expect(radio).toBeChecked();
    const explanation = screen.getByLabelText('What this choice does');
    expect(explanation).toHaveTextContent(/Malware: Move to quarantine folder .*\(simulated\)/);
    expect(explanation).toHaveTextContent(/Policy disposition Reject: Move to quarantine folder/);
    expect(explanation).toHaveTextContent(
      /risk recommendation alone never overrides the verdict rows/,
    );
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Save threat action' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    const body = bodies[0]!;
    expect(body).toMatchObject({
      mode: 'detect_only',
      detectOnly: { then: 'remind' },
      expectedRowVersion: null,
    });
    const until = Date.parse((body.detectOnly as { until: string }).until);
    expect(Math.round((until - Date.now()) / 86_400_000)).toBe(7);
    expectRequestMatchesContract('ApiModeRemediationController_putDomainPolicy_v1', body);
  });

  it('"Use the organization policy" deletes the domain override', async () => {
    const deletes: string[] = [];
    const override = {
      id: '0193ff00-0000-7000-8000-000000000002',
      domainId: DOMAIN_ID,
      domainName: 'alpha.example.test',
      mode: 'enforce' as const,
      document: policyView().presets.p1.document,
      sha256: 'b'.repeat(64),
      rowVersion: 3,
      updatedAt: T,
      effectivePolicyMapping: policyView().organization.effectivePolicyMapping,
      detectOnly: null,
    };
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ status: 'verified', activatedAt: null, protectionMode: API })),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(
          onboardingView({
            action: { source: 'domain', mode: 'enforce', presetKey: 'p1', detectOnly: null },
          }),
        ),
      ApiModeRemediationController_getPolicy_v1: () => okJson(policyView([override])),
      ApiModeRemediationController_deleteDomainPolicy_v1: ({ params }) => {
        deletes.push(String(params.domainId));
        return noContentResponse();
      },
    });
    const { user } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=action`,
    });
    expect(await screen.findByRole('radio', { name: 'Enforce now (standard P1)' })).toBeChecked();
    await user.click(screen.getByRole('radio', { name: 'Use the organization policy' }));
    await user.click(screen.getByRole('button', { name: 'Save threat action' }));
    await waitFor(() => expect(deletes).toEqual([DOMAIN_ID]));
  });

  it('presetOf and presetBody follow the server state and B7', () => {
    expect(
      presetOf({
        source: 'domain',
        mode: 'detect_only',
        presetKey: 'detectOnlyStart',
        detectOnly: null,
      }),
    ).toBe('detectOnlyRemind');
    expect(
      presetOf({
        source: 'domain',
        mode: 'detect_only',
        presetKey: 'detectOnlyStart',
        detectOnly: { until: T, then: 'enforce', ended: false },
      }),
    ).toBe('detectOnlyEnforce');
    expect(
      presetOf({ source: 'organization', mode: 'enforce', presetKey: null, detectOnly: null }),
    ).toBe('organization');
    expect(
      presetOf({ source: 'domain', mode: 'enforce', presetKey: null, detectOnly: null }),
    ).toBeNull();
    const now = Date.parse(T);
    expect(presetBody('detectOnlyEnforce', policyView().presets, 4, now)).toMatchObject({
      mode: 'detect_only',
      detectOnly: { until: '2026-12-04T09:00:00.000Z', then: 'enforce' },
      expectedRowVersion: 4,
    });
    expect(presetBody('strict', policyView().presets, null, now)).not.toHaveProperty('detectOnly');
  });
});

describe('Review and the first-copy check (B1, B8)', () => {
  it('review: the summary of every step with edit links', async () => {
    const bodies: unknown[] = [];
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ status: 'verified', activatedAt: null, protectionMode: API })),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(onboardingView({ steps: onboardingSteps({ review: 'not_started' }) })),
      ApiModeController_listConnections_v1: () => okJson({ data: [] }),
      DomainsController_changeStatus_v1: ({ body }) => {
        bodies.push(body);
        return okJson(domainDetail({ protectionMode: API }));
      },
    });
    const { user, container } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=review`,
    });
    const summary = await screen.findByRole('list', { name: 'Summary' });
    expect(within(summary).getAllByText('Connect mailboxes')[0]).toBeVisible();
    await expectNoAxeViolations(container);
    await user.click(within(summary).getByRole('button', { name: /Edit.*Intake/ }));
    expect(currentTestUrl()).toContain('step=intake');
  });

  it('waiting shows the hints the server sends; received shows verdict, lag, source and the link', async () => {
    let received = false;
    mockApi({
      DomainsController_get_v1: () => okJson(domainDetail({ protectionMode: API })),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(
          onboardingView({
            steps: onboardingSteps({ review: received ? 'done' : 'in_progress' }),
            firstCopy: received
              ? {
                  status: 'received',
                  copy: {
                    detectionId: FIRST_COPY_ID,
                    receivedAt: T,
                    verdict: 'clean',
                    lagMs: 45_000,
                    source: 'journal',
                    policyState: 'evaluated',
                    remediationState: 'none',
                  },
                  waitingSinceMinutes: null,
                  hints: [],
                }
              : {
                  status: 'waiting',
                  copy: null,
                  waitingSinceMinutes: 14,
                  hints: [
                    { code: 'journal_source_unverified', severity: 'warn', link: '/journaling' },
                    { code: 'send_test_message', severity: 'info', link: null },
                  ],
                },
          }),
        ),
    });
    const { container, queryClient } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=review`,
    });
    const check = await screen.findByRole('region', { name: 'First copy' });
    expect(within(check).getByText('Waiting for the first message…')).toBeVisible();
    expect(within(check).getByText(/Waiting for 14 minutes/)).toBeVisible();
    const hints = within(check).getByRole('list', { name: 'Troubleshooting hints' });
    expect(within(hints).getByRole('link', { name: /Fix/ })).toHaveAttribute(
      'href',
      '/settings?tab=journaling',
    );
    await expectNoAxeViolations(container);
    received = true;
    await queryClient.invalidateQueries({
      queryKey: ['ApiModeOnboardingController_domainOnboarding_v1'],
    });
    expect(await screen.findByText('First message received')).toBeVisible();
    expect(screen.getByRole('link', { name: 'Open the detection' })).toHaveAttribute(
      'href',
      `/api-mode?tab=detections&detection=${FIRST_COPY_ID}`,
    );
    expect(screen.getByText('Journal copy')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeEnabled();
  });

  it('maps the api hint links to portal pages', () => {
    expect(hintHref({ link: '/journaling' })).toBe('/settings?tab=journaling');
    expect(hintHref({ link: '/integrations/providers' })).toBe('/integrations');
    expect(hintHref({ link: '/api-mode?tab=connections' })).toBe('/api-mode?tab=coverage');
    expect(hintHref({ link: `/domains/${DOMAIN_ID}` })).toBe(`/domains/${DOMAIN_ID}`);
    expect(hintHref({ link: null })).toBeNull();
  });
});

describe('Read-only users (B2)', () => {
  it('see the steps with "ask an administrator" and no write control', async () => {
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ status: 'verified', activatedAt: null, protectionMode: API })),
      ApiModeOnboardingController_domainOnboarding_v1: () => okJson(onboardingView()),
      ApiModeOnboardingController_getScope_v1: () => okJson(scopeView()),
      DepartmentsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    });
    renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=mailboxes`,
      role: 'domain_admin',
    });
    expect(await screen.findByText(/changing the mailbox scope/)).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Save mailbox scope' })).toBeNull();
    expect(screen.getByRole('radio', { name: 'All mailboxes (recommended)' })).toBeDisabled();
  });
});

describe('Domain page per mode (B5, API4-18)', () => {
  it('api: ownership, mode and API protection only — no DNS, DKIM, destinations or recipients', async () => {
    mockApi({
      DomainsController_get_v1: () =>
        okJson(domainDetail({ protectionMode: API, inboundEnabled: false })),
      DomainDnsController_status_v1: () => okJson(statusView()),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(
          onboardingView({
            steps: onboardingSteps(),
            scope: { kind: 'mailboxes', inScope: 4, excluded: 5 },
            action: {
              source: 'domain',
              mode: 'detect_only',
              presetKey: 'detectOnlyStart',
              detectOnly: { until: '2026-12-04T09:00:00.000Z', then: 'remind', ended: false },
            },
            firstCopy: {
              status: 'received',
              copy: {
                detectionId: FIRST_COPY_ID,
                receivedAt: T,
                verdict: 'phishing',
                lagMs: 60_000,
                source: 'graph',
                policyState: 'evaluated',
                remediationState: 'simulated',
              },
              waitingSinceMinutes: null,
              hints: [],
            },
          }),
        ),
      ProtectionModeController_getOrganization_v1: () =>
        okJson({
          mode: 'inline',
          changedAt: null,
          entitled: true,
          active: true,
          domainsByEffectiveMode: { inline: 1, api: 1, hybrid: 0 },
        }),
    });
    const { container } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      route: `/domains/${DOMAIN_ID}`,
    });
    expect(await screen.findByRole('heading', { name: 'API protection' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Ownership' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Protection mode' })).toBeVisible();
    expect(screen.queryByRole('tab', { name: 'DNS records' })).toBeNull();
    expect(screen.queryByRole('tab', { name: 'Destinations' })).toBeNull();
    expect(screen.queryByRole('tab', { name: 'Recipients' })).toBeNull();
    expect(screen.queryByRole('heading', { name: 'DKIM signing keys' })).toBeNull();
    expect(screen.queryByRole('list', { name: 'DNS checks' })).toBeNull();
    expect(await screen.findByText('Selected mailboxes: 4 in scope, 5 excluded')).toBeVisible();
    expect(screen.getByText(/Detect only for 7 days, then remind me/)).toBeVisible();
    expect(screen.getByText('First message received')).toBeVisible();
    expect(screen.getByText('DNS TXT record')).toBeVisible();
    await expectNoAxeViolations(container);
  });

  it('hybrid: the inline tabs plus API protection; inline: no API protection request', async () => {
    mockApi({
      DomainsController_get_v1: () => okJson(domainDetail({ protectionMode: HYBRID })),
      DomainDnsController_status_v1: () => okJson(statusView()),
      ApiModeOnboardingController_domainOnboarding_v1: () =>
        okJson(onboardingView({ effectiveMode: 'hybrid', steps: onboardingSteps() })),
      ProtectionModeController_getOrganization_v1: () =>
        okJson({
          mode: 'inline',
          changedAt: null,
          entitled: true,
          active: true,
          domainsByEffectiveMode: { inline: 1, api: 0, hybrid: 1 },
        }),
    });
    renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      route: `/domains/${DOMAIN_ID}`,
    });
    expect(await screen.findByRole('heading', { name: 'API protection' })).toBeVisible();
    expect(screen.getByRole('tab', { name: 'DNS records' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Verification' })).toBeVisible();
    // A complete onboarding needs no "Continue onboarding".
    expect(screen.queryByRole('link', { name: 'Continue onboarding' })).toBeNull();
  });
});
