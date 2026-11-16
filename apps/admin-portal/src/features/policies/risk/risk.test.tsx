import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
  type SystemRoleKey,
} from '@/test';
import { PoliciesPage } from '../policies-page';
import {
  PLATFORM_PROFILE,
  PLATFORM_VIEW,
  RISK_ACTIVE_ID,
  RISK_PROFILE,
  RISK_VERSION_ID,
  riskVersion,
  riskVersionRow,
} from '../test-data';
import { mergeOverrides, overridesOf } from './risk-model';
import { RiskProfileVersionPage } from './risk-profile-page';

function mockRiskReads() {
  mockApi({
    RiskProfilesController_profile_v1: () => okJson(RISK_PROFILE),
    RiskProfilesController_platformProfile_v1: () => okJson(PLATFORM_VIEW),
    RiskProfilesController_listVersions_v1: () =>
      okJson({ data: [riskVersionRow(3), riskVersionRow(2), riskVersionRow(1)], nextCursor: null }),
    RiskProfilesController_getVersion_v1: ({ params }) =>
      okJson(
        params.versionId === RISK_VERSION_ID
          ? riskVersion()
          : riskVersion({
              id: params.versionId ?? '',
              versionNo: 1,
              status: 'published',
              publishedAt: '2026-10-01T09:00:00.000Z',
            }),
      ),
  });
}

const editorPage = (role: SystemRoleKey = 'organization_admin', versionId = RISK_VERSION_ID) =>
  renderWithProviders(<RiskProfileVersionPage versionId={versionId} />, {
    role,
    route: `/policies/risk-profile/${versionId}`,
  });

describe('risk-model (design B13: only overrides that differ from the platform profile)', () => {
  it('merges stored overrides into the platform profile and diffs back to the same document', () => {
    const stored = { thresholds: { high: 500 }, groupMultipliersPermille: { url_threat: 1200 } };
    const values = mergeOverrides(PLATFORM_PROFILE, stored);
    expect(values.thresholds.high).toBe(500);
    expect(values.thresholds.low).toBe(PLATFORM_PROFILE.thresholds.low);
    expect(overridesOf(values, PLATFORM_PROFILE, PLATFORM_VIEW.bounds.tunableGroups)).toEqual(
      stored,
    );
    // A value set back to the platform default leaves the overrides document.
    const back = mergeOverrides(PLATFORM_PROFILE, { thresholds: { high: 550 } });
    expect(overridesOf(back, PLATFORM_PROFILE, PLATFORM_VIEW.bounds.tunableGroups)).toEqual({});
    // Locked groups and unknown keys are never written.
    const locked = mergeOverrides(PLATFORM_PROFILE, {
      groupMultipliersPermille: { sandbox: 1500 },
      unknown: 1,
    });
    expect(overridesOf(locked, PLATFORM_PROFILE, PLATFORM_VIEW.bounds.tunableGroups)).toEqual({});
  });
});

describe('Risk tab (page 13, design B13)', () => {
  it('lists versions with actions per permission; new draft from the active version opens its editor', async () => {
    mockRiskReads();
    const created: unknown[] = [];
    mockApi({
      RiskProfilesController_createDraft_v1: ({ body }) => {
        created.push(body);
        return okJson(riskVersion({ id: RISK_VERSION_ID, versionNo: 4 }), 201);
      },
      // The test router keeps PoliciesPage mounted after navigating to the draft editor; without
      // ?tab=risk it falls back to the email tab, which lists policies.
      PolicyManagementController_list_v1: () =>
        okJson({ data: [], nextCursor: null, generation: '1' }),
    });
    const { user, container } = renderWithProviders(<PoliciesPage />, {
      route: '/policies?tab=risk',
    });
    expect(await screen.findByText('Tenant version v2')).toBeInTheDocument();
    await user.click(
      await screen.findByRole('button', { name: 'Actions for risk profile version 1' }),
    );
    expect(
      within(await screen.findByRole('menu'))
        .getAllByRole('menuitem')
        .map((i) => i.textContent),
    ).toEqual(['Open', 'Roll back to v1…']);
    await user.keyboard('{Escape}');
    await user.click(screen.getByRole('button', { name: 'Actions for risk profile version 3' }));
    expect(
      within(await screen.findByRole('menu'))
        .getAllByRole('menuitem')
        .map((i) => i.textContent),
    ).toEqual(['Edit draft', 'Publish…', 'Delete draft…']);
    await user.keyboard('{Escape}');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'New draft' }));
    const dialog = await screen.findByRole('dialog', { name: 'New risk-profile draft' });
    expect(within(dialog).getByRole('radio', { name: 'The active version (v2)' })).toBeChecked();
    await user.type(within(dialog).getByLabelText('Change note'), 'Try stricter links');
    await user.click(within(dialog).getByRole('button', { name: 'Create draft' }));
    await waitFor(() => expect(created).toHaveLength(1));
    expectRequestMatchesContract('RiskProfilesController_createDraft_v1', created[0]);
    expect(created[0]).toEqual({
      basedOnVersionId: RISK_ACTIVE_ID,
      changeNote: 'Try stricter links',
    });
    await waitFor(() => expect(currentTestUrl()).toBe(`/policies/risk-profile/${RISK_VERSION_ID}`));
  });

  it('rolls back to an older version and resets to the platform profile, each with an Idempotency-Key reused on retry', async () => {
    mockRiskReads();
    const activations: Array<{ key: string | null; body: unknown }> = [];
    const resets: Array<{ key: string | null; body: unknown }> = [];
    mockApi({
      RiskProfilesController_activate_v1: ({ request, body }) => {
        activations.push({ key: request.headers.get('idempotency-key'), body });
        return activations.length === 1
          ? apiErrorJson(503, 'inconsistent_read', 'Retry')
          : okJson(RISK_PROFILE);
      },
      RiskProfilesController_reset_v1: ({ request, body }) => {
        resets.push({ key: request.headers.get('idempotency-key'), body });
        return resets.length === 1
          ? apiErrorJson(503, 'inconsistent_read', 'Retry')
          : okJson(RISK_PROFILE);
      },
    });
    const { user } = renderWithProviders(<PoliciesPage />, { route: '/policies?tab=risk' });
    await user.click(
      await screen.findByRole('button', { name: 'Actions for risk profile version 1' }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Roll back to v1…' }));
    const activate = await screen.findByRole('dialog', { name: 'Roll back to v1?' });
    expect(within(activate).getByText('Active now: v2. After this: v1.')).toBeInTheDocument();
    await user.click(within(activate).getByRole('button', { name: 'Roll back to v1' }));
    await user.click(await within(activate).findByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(activations).toHaveLength(2));
    expect(activations[1]?.key).toBe(activations[0]?.key);
    expect(activations[0]?.body).toEqual({ expectedProfileVersion: 7 });
    expectRequestMatchesContract('RiskProfilesController_activate_v1', activations[0]?.body);

    await user.click(await screen.findByRole('button', { name: 'Reset to the platform profile' }));
    const reset = await screen.findByRole('dialog', { name: 'Reset to the platform profile?' });
    await user.click(within(reset).getByRole('button', { name: 'Reset to the platform profile' }));
    await user.click(await within(reset).findByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(resets).toHaveLength(2));
    expect(resets[0]?.key).toBeTruthy();
    expect(resets[1]?.key).toBe(resets[0]?.key);
    expectRequestMatchesContract('RiskProfilesController_reset_v1', resets[0]?.body);
  });
});

describe('Risk-profile draft editor (/policies/risk-profile/[versionId], design B13)', () => {
  it('generates the form from the platform bounds and saves only the changed keys (contract)', async () => {
    mockRiskReads();
    const puts: unknown[] = [];
    mockApi({
      RiskProfilesController_updateDraft_v1: ({ body }) => {
        puts.push(body);
        return okJson(riskVersion({ rowVersion: 5 }));
      },
    });
    const { user, container } = editorPage();
    expect(
      await screen.findByRole('heading', { name: 'Risk profile v3', level: 1 }),
    ).toBeInTheDocument();
    const high = screen.getByLabelText('High from score');
    expect(high).toHaveValue(500);
    expect(high).toHaveAttribute('min', '400');
    expect(high).toHaveAttribute('max', '700');
    expect(screen.getByText(/Locked at 1000: Attachment malware/)).toBeInTheDocument();
    expect(screen.getAllByRole('switch', { name: 'Enabled' }).length).toBeGreaterThan(0);
    await expectNoAxeViolations(container);
    fireEvent.change(screen.getByLabelText('Spam'), { target: { value: '1500' } });
    // Back to the platform default: the key disappears from the overrides.
    fireEvent.change(high, { target: { value: '550' } });
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(puts).toHaveLength(1));
    expectRequestMatchesContract('RiskProfilesController_updateDraft_v1', puts[0]);
    expect(puts[0]).toEqual({
      overrides: { groupMultipliersPermille: { url_threat: 1200, spam: 1500 } },
      changeNote: 'Stricter on links',
      expectedRowVersion: 4,
    });
  });

  it('maps 400 risk_profile_invalid violations onto their inputs; a conflict offers a reload', async () => {
    mockRiskReads();
    let call = 0;
    mockApi({
      RiskProfilesController_updateDraft_v1: () => {
        call += 1;
        return call === 1
          ? apiErrorJson(400, 'risk_profile_invalid', 'Invalid', {
              extra: {
                violations: [
                  {
                    path: 'thresholds.high',
                    message: 'must exceed thresholds.medium by at least 50',
                  },
                  { path: 'baseProfile', message: 'base_profile_retired' },
                ],
              },
            })
          : apiErrorJson(409, 'risk_profile_version_conflict', 'Changed', {
              extra: { currentRowVersion: 6 },
            });
      },
    });
    const { user } = editorPage();
    const high = await screen.findByLabelText('High from score');
    fireEvent.change(high, { target: { value: '420' } });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(
      await screen.findByText('must exceed thresholds.medium by at least 50'),
    ).toBeInTheDocument();
    expect(high.getAttribute('aria-describedby')).toBeTruthy();
    expect(screen.getByRole('list', { name: 'Problems with the profile' })).toHaveTextContent(
      'baseProfile: base_profile_retired',
    );
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/row version 6/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload the version' })).toBeInTheDocument();
  });

  it('publishes a draft (activate default on, Idempotency-Key reused on retry) and deletes drafts', async () => {
    mockRiskReads();
    const publishes: Array<{ key: string | null; body: unknown }> = [];
    let deleted: string | null = null;
    mockApi({
      RiskProfilesController_publish_v1: ({ request, body }) => {
        publishes.push({ key: request.headers.get('idempotency-key'), body });
        return publishes.length === 1
          ? apiErrorJson(503, 'inconsistent_read', 'Retry')
          : okJson({ version: riskVersion({ status: 'published' }), profile: RISK_PROFILE });
      },
      RiskProfilesController_deleteDraft_v1: ({ url }) => {
        deleted = url.searchParams.get('expectedRowVersion');
        return noContentResponse();
      },
    });
    const { user } = editorPage();
    await user.click(await screen.findByRole('button', { name: 'Publish…' }));
    const dialog = await screen.findByRole('dialog', { name: 'Publish risk profile v3?' });
    expect(within(dialog).getByRole('switch', { name: 'Activate now' })).toBeChecked();
    await user.click(within(dialog).getByRole('button', { name: 'Publish and activate' }));
    await user.click(await within(dialog).findByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(publishes).toHaveLength(2));
    expect(publishes[1]?.key).toBe(publishes[0]?.key);
    expect(publishes[0]?.body).toEqual({ activate: true, expectedRowVersion: 4 });
    expectRequestMatchesContract('RiskProfilesController_publish_v1', publishes[0]?.body);
    await user.click(await screen.findByRole('button', { name: 'Delete draft' }));
    const confirm = await screen.findByRole('alertdialog', {
      name: 'Delete risk-profile draft v3?',
    });
    await user.click(within(confirm).getByRole('button', { name: 'Delete draft' }));
    await waitFor(() => expect(deleted).toBe('4'));
    await waitFor(() => expect(currentTestUrl()).toBe('/policies?tab=risk'));
  });

  it('published versions and read-only users get the profile as text, no inputs', async () => {
    mockRiskReads();
    renderWithProviders(<RiskProfileVersionPage versionId={RISK_VERSION_ID} />, {
      role: 'read_only_user',
      route: `/policies/risk-profile/${RISK_VERSION_ID}`,
    });
    expect(await screen.findByText('View mode')).toBeInTheDocument();
    expect(screen.queryAllByRole('spinbutton')).toHaveLength(0);
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Publish/ })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Risk-profile overrides')).toHaveTextContent('"url_threat": 1200');
  });
});
