import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  MIGRATED_ADMIN_PERMISSIONS,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { archiveDownloadNavigation } from '@/features/archive/download-dialog';
import {
  CASE,
  CASE_ID,
  CUSTODIAN,
  EXPORT_ID,
  HOLD,
  HOLD_ID,
  MALICIOUS_ID,
  MESSAGE_ID,
  SEARCH_ID,
  SECRET_SUBJECT,
  exportItem,
  hit,
  search,
} from '@/features/archive/test-data';
import { CasePage, holdBody, exportBody } from './case-page';
import { CasesPage, caseCreateBody } from './cases-page';
import { LegalHoldDetailPage, LegalHoldsPage } from './legal-holds';
import { completenessOf } from './model';
import { CaseSearchPage, reviewBody } from './search-page';

afterEach(() => vi.restoreAllMocks());

const mfa = { id: '01930000-0000-7000-8000-000000000501', mfaAuthenticated: true };
const auditor = () =>
  makeMe({ role: 'compliance_auditor', overrides: { mfaEnabled: true, session: mfa } });
const admin = () =>
  // Step 8.6: an existing admin keeps archive access through the migrated compliance_officer.
  makeMe({
    role: 'organization_admin',
    permissions: MIGRATED_ADMIN_PERMISSIONS,
    overrides: { mfaEnabled: true, session: mfa },
  });

describe('eDiscovery bodies and completeness (A18)', () => {
  it('builds contract-valid bodies', () => {
    expectRequestMatchesContract(
      'EdiscoveryCasesController_create_v1',
      caseCreateBody({
        name: ' EXAMPLE case ',
        description: '',
        matterReference: 'M-1',
        custodians: `${CUSTODIAN}\nBob@Corp.example.test`,
      }),
    );
    expect(
      caseCreateBody({
        name: 'x',
        description: '',
        matterReference: '',
        custodians: 'A@b.example.test, a@B.example.test',
      }).custodians,
    ).toEqual(['a@b.example.test']);
    const hold = holdBody({
      name: 'H',
      reason: 'R',
      useCaseCustodians: true,
      custodians: '',
      range: 'custom',
      from: '2026-01-01',
      to: '2026-06-30',
      directions: ['inbound'],
    });
    expect(hold).toEqual({
      name: 'H',
      reason: 'R',
      useCaseCustodians: true,
      criteria: { from: '2026-01-01', to: '2026-06-30', directions: ['inbound'] },
    });
    expectRequestMatchesContract('EdiscoveryCasesController_createHold_v1', hold);
    expectRequestMatchesContract(
      'EdiscoveryExportsController_create_v1',
      exportBody(SEARCH_ID, ['relevant'], true),
    );
    expectRequestMatchesContract(
      'EdiscoverySearchesController_review_v1',
      reviewBody('privileged', [MESSAGE_ID]),
    );
  });

  it('reports completeness instead of assuming it', () => {
    expect(completenessOf(search())).toEqual({ complete: true, lines: [] });
    expect(
      completenessOf(search({ indexComplete: false, incompleteReason: 'index_lag' })).lines[0],
    ).toMatch(/index was behind/);
    expect(completenessOf(search({ truncated: true })).lines[0]).toMatch(/maximum number of hits/);
    expect(completenessOf(search({ status: 'running' })).complete).toBe(false);
  });
});

describe('/ediscovery (cases)', () => {
  it('lists cases and opens a new one, then navigates to it', async () => {
    let body: unknown = null;
    mockApi({
      EdiscoveryCasesController_list_v1: () =>
        okJson({
          data: [{ ...CASE, custodians: undefined, counts: undefined }].map(
            ({ custodians: _c, counts: _n, ...rest }) => rest,
          ),
          nextCursor: null,
        }),
      EdiscoveryCasesController_create_v1: ({ body: b }) => {
        body = b;
        return okJson({ ...CASE, id: '01930000-0000-7000-8000-00000000c3ff' }, 201);
      },
    });
    const { user, container } = renderWithProviders(<CasesPage />, {
      me: auditor(),
      route: '/ediscovery',
    });
    expect(
      await screen.findByRole('link', { name: 'EXAMPLE board investigation' }),
    ).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'New case' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Open case' }));
    expect(within(dialog).getByText('Enter a case name')).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Case name (required)'), 'EXAMPLE new matter');
    await user.type(within(dialog).getByLabelText(/Custodians/), 'not-an-address');
    await user.click(within(dialog).getByRole('button', { name: 'Open case' }));
    expect(within(dialog).getByText(/Not an email address/)).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText(/Custodians/));
    await user.type(within(dialog).getByLabelText(/Custodians/), CUSTODIAN);
    await user.click(within(dialog).getByRole('button', { name: 'Open case' }));
    await waitFor(() =>
      expect(currentTestUrl()).toBe('/ediscovery/01930000-0000-7000-8000-00000000c3ff'),
    );
    expect(body).toEqual({ name: 'EXAMPLE new matter', custodians: [CUSTODIAN] });
  });

  it('is forbidden for a security analyst (no ediscovery:manage)', async () => {
    renderWithProviders(<CasesPage />, { role: 'security_analyst', route: '/ediscovery' });
    expect(
      await screen.findByText(/You do not have access|do not have permission/i),
    ).toBeInTheDocument();
  });
});

function mockCase(extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    EdiscoveryCasesController_get_v1: () => okJson(CASE),
    LegalHoldsController_list_v1: () => okJson({ data: [HOLD], nextCursor: null }),
    EdiscoverySearchesController_list_v1: () => okJson({ data: [search()], nextCursor: null }),
    EdiscoveryExportsController_list_v1: () => okJson({ data: [exportItem()], nextCursor: null }),
    ...extra,
  });
}

describe('/ediscovery/[caseId] (A18, A28)', () => {
  it('edits the custodians with CAS and offers reload/overwrite on a conflict', async () => {
    const versions: number[] = [];
    mockCase({
      EdiscoveryCasesController_update_v1: ({ body }) => {
        const b = body as { expectedRowVersion: number; custodians: string[] };
        versions.push(b.expectedRowVersion);
        expectRequestMatchesContract('EdiscoveryCasesController_update_v1', body);
        return b.expectedRowVersion === 3
          ? apiErrorJson(409, 'ediscovery_case_conflict', 'stale', {
              extra: { currentRowVersion: 5 },
            })
          : okJson({ ...CASE, rowVersion: 6 });
      },
    });
    const { user, container } = renderWithProviders(<CasePage caseId={CASE_ID} />, {
      me: auditor(),
      route: `/ediscovery/${CASE_ID}?tab=custodians`,
    });
    const field = await screen.findByLabelText('Custodian addresses (one per line)');
    await expectNoAxeViolations(container);
    await user.type(field, '\nnew.person@corp.example.test');
    await user.click(screen.getByRole('button', { name: 'Save custodians' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Overwrite with my edit' }));
    await waitFor(() => expect(versions).toEqual([3, 5]));
  });

  it('a custom role without message:reveal sees the custodians but cannot write addresses', async () => {
    mockCase();
    // A custom role: case management, search and holds, no message:reveal.
    const custom = makeMe({
      role: 'organization_admin',
      permissions: ['ediscovery:manage', 'archive:search', 'archive:read', 'archive:legal_hold'],
      overrides: { mfaEnabled: true, session: mfa },
    });
    const view = renderWithProviders(<CasePage caseId={CASE_ID} />, {
      me: custom,
      route: `/ediscovery/${CASE_ID}?tab=custodians`,
    });
    expect((await screen.findAllByText(CUSTODIAN)).length).toBeGreaterThan(0);
    expect(screen.queryByLabelText('Custodian addresses (one per line)')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save custodians' })).not.toBeInTheDocument();
    expect(screen.getByText(/can be set only by users who may reveal/)).toBeInTheDocument();
    view.unmount();
    // The hold dialog only offers the case's own custodians.
    const holds = renderWithProviders(<CasePage caseId={CASE_ID} />, {
      me: custom,
      route: `/ediscovery/${CASE_ID}?tab=holds`,
    });
    await holds.user.click(await screen.findByRole('button', { name: 'Place a hold' }));
    const dialog = await screen.findByRole('dialog');
    expect(
      within(dialog).getByRole('checkbox', { name: /Hold the case’s custodians/ }),
    ).toBeDisabled();
    expect(
      within(dialog).queryByLabelText('Custodian addresses (one per line)'),
    ).not.toBeInTheDocument();
  });

  it('holds tab: a compliance auditor (no archive:legal_hold) cannot place or release holds', async () => {
    mockCase();
    renderWithProviders(<CasePage caseId={CASE_ID} />, {
      me: auditor(),
      route: `/ediscovery/${CASE_ID}?tab=holds`,
    });
    expect(await screen.findByRole('link', { name: 'EXAMPLE board hold' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Place a hold' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Release' })).not.toBeInTheDocument();
    expect(screen.getByText(/needs the archive:legal_hold permission/)).toBeInTheDocument();
  });

  it('holds tab: an admin places a hold on the case custodians', async () => {
    let body: unknown = null;
    mockCase({
      EdiscoveryCasesController_createHold_v1: ({ body: b }) => {
        body = b;
        return okJson(HOLD, 201);
      },
    });
    const { user } = renderWithProviders(<CasePage caseId={CASE_ID} />, {
      me: admin(),
      route: `/ediscovery/${CASE_ID}?tab=holds`,
    });
    await user.click(await screen.findByRole('button', { name: 'Place a hold' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText('Hold name (required)'), 'EXAMPLE hold 2');
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'EXAMPLE notice');
    await user.click(within(dialog).getByRole('button', { name: 'Place hold' }));
    await waitFor(() =>
      expect(body).toEqual({
        name: 'EXAMPLE hold 2',
        reason: 'EXAMPLE notice',
        useCaseCustodians: true,
      }),
    );
  });

  it('searches tab: queues a search from the archive filter form and polls until it completes', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let created: unknown = null;
    let status: 'queued' | 'completed' = 'completed';
    mockCase({
      EdiscoverySearchesController_list_v1: () =>
        okJson({
          data: [
            search({
              status,
              indexComplete: status === 'completed' ? false : null,
              incompleteReason: status === 'completed' ? 'unverified_days' : null,
            }),
          ],
          nextCursor: null,
        }),
      EdiscoverySearchesController_create_v1: ({ body }) => {
        created = body;
        status = 'queued';
        return okJson(search({ status: 'queued' }), 202);
      },
    });
    const { user } = renderWithProviders(<CasePage caseId={CASE_ID} />, {
      me: auditor(),
      route: `/ediscovery/${CASE_ID}?tab=searches`,
    });
    expect(await screen.findByText('Possibly incomplete')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'New search' }));
    const form = screen.getByRole('form', { name: 'New case search' });
    expect(
      within(form).getByRole('checkbox', { name: /Mail of the case’s custodians/ }),
    ).toBeChecked();
    await user.click(within(form).getByRole('button', { name: 'Run search' }));
    await waitFor(() => expect(created).not.toBeNull());
    expect((created as { criteria: { custodians: string } }).criteria.custodians).toBe('case');
    expectRequestMatchesContract('EdiscoverySearchesController_create_v1', created);
    expect(await screen.findByText('Queued')).toBeInTheDocument();
    status = 'completed';
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_500);
    });
    expect(await screen.findByText('Possibly incomplete')).toBeInTheDocument();
    vi.useRealTimers();
  });

  it('exports tab: requires the malicious acknowledgement and downloads through re-authentication', async () => {
    const bodies: unknown[] = [];
    mockCase({
      EdiscoveryExportsController_create_v1: ({ body }) => {
        bodies.push(body);
        return (body as { acknowledgeMalicious?: boolean }).acknowledgeMalicious
          ? okJson(
              exportItem({ status: 'queued', id: '01930000-0000-7000-8000-00000000c5ff' }),
              202,
            )
          : apiErrorJson(409, 'ediscovery_export_malicious_ack_required', 'malicious', {
              extra: { maliciousCount: 1 },
            });
      },
      EdiscoveryExportsController_grant_v1: () =>
        okJson(
          {
            token: 'v1.EXAMPLE-export.sig',
            expiresAt: '2026-11-17T08:01:00.000Z',
            filename: 'export.zip',
            sizeBytes: 20_480,
            sha256: 'c'.repeat(64),
          },
          201,
        ),
    });
    const assign = vi
      .spyOn(archiveDownloadNavigation, 'assign')
      .mockImplementation(() => undefined);
    const { user } = renderWithProviders(<CasePage caseId={CASE_ID} />, {
      me: auditor(),
      route: `/ediscovery/${CASE_ID}?tab=exports`,
    });
    expect(await screen.findByText('eg-export-EXAMPLE-1')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'New export' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(await within(dialog).findByRole('button', { name: 'Create export' }));
    expect(await within(dialog).findByText(/contains 1 malicious message/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('checkbox', { name: 'Include malicious messages' }));
    await user.click(within(dialog).getByRole('button', { name: 'Create export' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({
      searchId: SEARCH_ID,
      reviewTags: ['untagged', 'relevant', 'privileged'],
      acknowledgeMalicious: true,
    });
    await user.click(await screen.findByRole('button', { name: 'Download' }));
    const grant = await screen.findByRole('dialog');
    await user.type(within(grant).getByLabelText('Your password (required)'), 'EXAMPLE-password');
    await user.type(within(grant).getByLabelText('Authenticator code (required)'), '123456');
    await user.click(within(grant).getByRole('button', { name: 'Download' }));
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith('/bff/api/v1/archive/downloads/v1.EXAMPLE-export.sig'),
    );
    expect(EXPORT_ID).toBeTruthy();
  });
});

describe('/ediscovery/[caseId]/searches/[searchId] (review)', () => {
  it('shows the completeness banner, masked hits, bulk review tagging and a per-message reveal', async () => {
    const reviews: unknown[] = [];
    mockApi({
      EdiscoverySearchesController_get_v1: () =>
        okJson(search({ indexComplete: false, incompleteReason: 'index_lag' })),
      EdiscoverySearchesController_hits_v1: () =>
        okJson({
          data: [hit(MESSAGE_ID), hit(MALICIOUS_ID, { reviewTag: 'relevant' })],
          nextCursor: null,
        }),
      EdiscoverySearchesController_review_v1: ({ body }) => {
        reviews.push(body);
        return okJson({ searchId: SEARCH_ID, tag: 'privileged', updated: 2, notFound: 0 });
      },
      ArchiveMessagesController_reveal_v1: ({ params }) =>
        okJson({
          messageId: params.messageId,
          revealedAt: '2026-11-17T08:00:00.000Z',
          subject: SECRET_SUBJECT,
          recipients: [],
        }),
    });
    const { user, container } = renderWithProviders(
      <CaseSearchPage caseId={CASE_ID} searchId={SEARCH_ID} />,
      {
        me: admin(),
      },
    );
    expect(await screen.findByText(/search index was behind/)).toBeInTheDocument();
    expect(await screen.findAllByRole('link', { name: /open archived message/ })).toHaveLength(2);
    expect(screen.queryByText(SECRET_SUBJECT)).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('checkbox', { name: /Select all/i }));
    await user.click(screen.getByRole('combobox', { name: 'Tag as' }));
    await user.click(await screen.findByRole('option', { name: 'Privileged' }));
    await user.click(screen.getByRole('button', { name: 'Tag 2 hits as privileged' }));
    await waitFor(() =>
      expect(reviews).toEqual([{ tag: 'privileged', messageIds: [MESSAGE_ID, MALICIOUS_ID] }]),
    );
    await user.click(screen.getAllByRole('button', { name: /Actions for/ })[0]!);
    await user.click(
      await screen.findByRole('menuitem', { name: 'Reveal subject and recipients' }),
    );
    expect(await screen.findByText(SECRET_SUBJECT)).toBeInTheDocument();
  });

  it('does not load hits while the search runs', async () => {
    let hits = 0;
    mockApi({
      EdiscoverySearchesController_get_v1: () =>
        okJson(search({ status: 'running', completedAt: null, indexComplete: null })),
      EdiscoverySearchesController_hits_v1: () => {
        hits += 1;
        return okJson({ data: [], nextCursor: null });
      },
    });
    renderWithProviders(<CaseSearchPage caseId={CASE_ID} searchId={SEARCH_ID} />, {
      me: auditor(),
    });
    expect(await screen.findByText(/The search is running/)).toBeInTheDocument();
    expect(hits).toBe(0);
  });
});

describe('/legal-holds', () => {
  it('lists holds for a compliance auditor; the detail shows criteria and the records link, no release', async () => {
    mockApi({
      LegalHoldsController_list_v1: () => okJson({ data: [HOLD], nextCursor: null }),
      LegalHoldsController_get_v1: () => okJson(HOLD),
    });
    const list = renderWithProviders(<LegalHoldsPage />, { me: auditor(), route: '/legal-holds' });
    expect(await screen.findByRole('link', { name: 'EXAMPLE board hold' })).toBeInTheDocument();
    await expectNoAxeViolations(list.container);
    list.unmount();
    renderWithProviders(<LegalHoldDetailPage holdId={HOLD_ID} />, { me: auditor() });
    expect(await screen.findByText(CUSTODIAN)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Records under this hold/ })).toHaveAttribute(
      'href',
      `/archive?range=365d&holdId=${HOLD_ID}`,
    );
    expect(screen.queryByRole('button', { name: 'Release hold' })).not.toBeInTheDocument();
  });

  it('an admin releases a hold with a reason', async () => {
    let body: unknown = null;
    mockApi({
      LegalHoldsController_get_v1: () => okJson(HOLD),
      LegalHoldsController_release_v1: ({ body: b }) => {
        body = b;
        return okJson({ ...HOLD, status: 'released' });
      },
    });
    const { user } = renderWithProviders(<LegalHoldDetailPage holdId={HOLD_ID} />, { me: admin() });
    await user.click(await screen.findByRole('button', { name: 'Release hold' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'EXAMPLE matter settled');
    await user.click(within(dialog).getByRole('button', { name: 'Release hold' }));
    await waitFor(() => expect(body).toEqual({ reason: 'EXAMPLE matter settled' }));
    expectRequestMatchesContract('LegalHoldsController_release_v1', body);
  });

  it('is forbidden for a read-only user', async () => {
    renderWithProviders(<LegalHoldsPage />, { role: 'read_only_user', route: '/legal-holds' });
    expect(
      await screen.findByText(/You do not have access|do not have permission/i),
    ).toBeInTheDocument();
  });
});
