import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { DlpTab } from '../dlp-bec';
import { PATTERN_ID, dlpPattern, page } from './test-data';

const ROUTE = '/policies?tab=dlp&section=patterns';

async function openNewPattern(user: ReturnType<typeof renderWithProviders>['user']) {
  await screen.findByText('Employee ID');
  await user.click(screen.getByRole('button', { name: 'New pattern' }));
  return screen.findByRole('dialog', { name: 'New custom pattern' });
}

describe('DLP custom patterns (WP5)', () => {
  it('creates a pattern: the safety refusal (400 pattern code) is explained on the pattern, 409 name taken, then 201', async () => {
    const bodies: unknown[] = [];
    mockApi({
      DlpPatternsController_list_v1: () => okJson(page([dlpPattern()])),
      DlpPatternsController_create_v1: ({ body }) => {
        bodies.push(body);
        if (bodies.length === 1) {
          return apiErrorJson(400, 'pattern_too_complex', 'The custom pattern was refused', {
            extra: { repetitionProduct: 2500, length: 18 },
          });
        }
        if (bodies.length === 2) {
          return apiErrorJson(409, 'dlp_pattern_exists', 'Exists', { extra: { id: PATTERN_ID } });
        }
        return okJson(
          dlpPattern({ id: '01933c3a-1b2c-7d4e-8f00-0000000d0202', name: 'Badge' }),
          201,
        );
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    const sheet = await openNewPattern(user);
    expect(sheet).toHaveClass('w-full', 'sm:max-w-3xl');
    await expectNoAxeViolations(document.body);
    await user.type(within(sheet).getByLabelText(/^Name/), 'Badge');
    await user.type(within(sheet).getByLabelText(/^Pattern/), 'BADGE-[[0-9]{{4}');
    await user.selectOptions(within(sheet).getByLabelText(/^Severity/), 'high');
    await user.selectOptions(within(sheet).getByLabelText(/^Checksum validator/), 'luhn');
    await user.type(within(sheet).getByLabelText(/^Context keywords/), 'badge{Enter}staff card');
    await user.click(within(sheet).getByRole('switch', { name: 'Case-insensitive' }));
    await user.click(within(sheet).getByRole('button', { name: 'Create pattern' }));
    expect(
      await within(sheet).findByText(
        /The pattern is too long or too complex .* \(length 18, repetition product 2,500\) Code: pattern_too_complex\./,
      ),
    ).toBeInTheDocument();
    expect(within(sheet).getByLabelText(/^Pattern/)).toHaveAttribute('aria-invalid', 'true');
    expect(bodies[0]).toEqual({
      name: 'Badge',
      pattern: 'BADGE-[0-9]{4}',
      caseInsensitive: true,
      validator: 'luhn',
      contextKeywords: ['badge', 'staff card'],
      requireContext: false,
      severity: 'high',
      baseConfidence: 0.8,
      maskStyle: 'last4',
      enabled: true,
    });
    expectRequestMatchesContract('DlpPatternsController_create_v1', bodies[0]);

    await user.click(within(sheet).getByRole('button', { name: 'Create pattern' }));
    expect(
      await within(sheet).findByText(
        'A custom pattern with this name exists. Choose another name.',
      ),
    ).toBeInTheDocument();
    await user.click(within(sheet).getByRole('button', { name: 'Create pattern' }));
    expect(await screen.findByText('Custom pattern created.')).toBeInTheDocument();
  });

  it('Test pattern sends the pattern, its options and the sample only on the button and shows the server result', async () => {
    const tests: unknown[] = [];
    mockApi({
      DlpPatternsController_list_v1: () => okJson(page([dlpPattern()])),
      DlpPatternsController_test_v1: ({ body }) => {
        tests.push(body);
        return okJson({
          valid: true,
          code: null,
          complexity: { repetitionProduct: 6, length: 12 },
          matches: [
            { start: 10, end: 20, masked: '******1234', validated: true, contextMatched: true },
            { start: 40, end: 50, masked: '******5678', validated: false, contextMatched: false },
          ],
        });
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    const sheet = await openNewPattern(user);
    await user.type(within(sheet).getByLabelText(/^Pattern/), 'EMP-[[0-9]{{6}');
    await user.type(within(sheet).getByLabelText(/^Context keywords/), 'employee');
    await user.type(
      within(sheet).getByLabelText('Synthetic sample text'),
      'Employee EMP-001234 and EMP-005678',
    );
    expect(tests).toHaveLength(0);
    await user.click(within(sheet).getByRole('button', { name: 'Test pattern' }));
    expect(await within(sheet).findByText('The server accepted the pattern.')).toBeInTheDocument();
    expect(within(sheet).getByText('******1234')).toBeInTheDocument();
    expect(within(sheet).getByText('******5678')).toBeInTheDocument();
    expect(within(sheet).getByText(/2 matches in the sample/)).toBeInTheDocument();
    expect(tests).toEqual([
      {
        pattern: 'EMP-[0-9]{6}',
        caseInsensitive: false,
        validator: 'none',
        contextKeywords: ['employee'],
        requireContext: false,
        maskStyle: 'last4',
        sample: 'Employee EMP-001234 and EMP-005678',
      },
    ]);
    expectRequestMatchesContract('DlpPatternsController_test_v1', tests[0]);
    await expectNoAxeViolations(document.body);

    await user.type(within(sheet).getByLabelText('Synthetic sample text'), ' more');
    expect(within(sheet).getByText(/changed since this result/)).toBeInTheDocument();
    expect(tests).toHaveLength(1);
  });

  it('Test pattern shows the server refusal: a 400 for the request and valid=false with the safety code', async () => {
    let call = 0;
    mockApi({
      DlpPatternsController_list_v1: () => okJson(page([dlpPattern()])),
      DlpPatternsController_test_v1: () => {
        call += 1;
        return call === 1
          ? apiErrorJson(
              400,
              'validation_failed',
              ['sample: Too big: expected string to have <=4096 characters'],
              { requestId: 'req-test-400' },
            )
          : okJson({
              valid: false,
              code: 'pattern_unsupported',
              complexity: { repetitionProduct: 0, length: 9 },
              matches: [],
            });
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'organization_admin', route: ROUTE });
    const sheet = await openNewPattern(user);
    await user.type(within(sheet).getByLabelText(/^Pattern/), '(a)\\1');
    await user.type(within(sheet).getByLabelText('Synthetic sample text'), 'aa');
    await user.click(within(sheet).getByRole('button', { name: 'Test pattern' }));
    expect(
      await within(sheet).findByText('The server did not accept the test'),
    ).toBeInTheDocument();
    expect(
      within(sheet).getByText('Sample: Too big: expected string to have <=4096 characters'),
    ).toBeInTheDocument();
    expect(within(sheet).getByText('validation_failed')).toBeInTheDocument();
    expect(within(sheet).getByText('req-test-400')).toBeInTheDocument();

    await user.click(within(sheet).getByRole('button', { name: 'Test pattern' }));
    expect(await within(sheet).findByText('The server refused the pattern:')).toBeInTheDocument();
    expect(
      within(sheet).getByText(
        /Backreferences, lookaround and possessive constructs are not supported/,
      ),
    ).toBeInTheDocument();
    expect(within(sheet).getByText('(pattern_unsupported)')).toBeInTheDocument();
  });

  it('Test pattern: 429 with Retry-After disables the button and shows the wait, the code and the request ID', async () => {
    mockApi({
      DlpPatternsController_list_v1: () => okJson(page([dlpPattern()])),
      DlpPatternsController_test_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many requests', {
          requestId: 'req-test-429',
          headers: { 'retry-after': '42' },
          extra: { scope: 'route' },
        }),
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    const sheet = await openNewPattern(user);
    await user.type(within(sheet).getByLabelText(/^Pattern/), 'X-[[0-9]+');
    const button = within(sheet).getByRole('button', { name: 'Test pattern' });
    await user.click(button);
    expect(
      await within(sheet).findByText(/the API allows 30 per minute for each user/),
    ).toBeInTheDocument();
    expect(within(sheet).getByText('rate_limited')).toBeInTheDocument();
    expect(within(sheet).getByText('req-test-429')).toBeInTheDocument();
    expect(within(sheet).getByText(/Try again in (42|41) s\./)).toBeInTheDocument();
    expect(button).toBeDisabled();
  });

  it('requires a pattern before testing (no request)', async () => {
    let calls = 0;
    mockApi({
      DlpPatternsController_list_v1: () => okJson(page([dlpPattern()])),
      DlpPatternsController_test_v1: () => ((calls += 1), okJson({})),
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    const sheet = await openNewPattern(user);
    await user.click(within(sheet).getByRole('button', { name: 'Test pattern' }));
    expect(await within(sheet).findByText('Enter a pattern above first.')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it('edits a pattern with its version and only the changed fields', async () => {
    const bodies: unknown[] = [];
    mockApi({
      DlpPatternsController_list_v1: () => okJson(page([dlpPattern()])),
      DlpPatternsController_update_v1: ({ body, params }) => {
        bodies.push(body);
        expect(params.id).toBe(PATTERN_ID);
        return okJson(dlpPattern({ severity: 'critical', version: 3 }));
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await user.click(await screen.findByRole('button', { name: 'Actions for Employee ID' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Edit and test' }));
    const sheet = await screen.findByRole('dialog', { name: 'Edit Employee ID' });
    expect(within(sheet).getByLabelText(/^Pattern/)).toHaveValue('EMP-[0-9]{6}');
    await user.selectOptions(within(sheet).getByLabelText(/^Severity/), 'critical');
    await user.click(within(sheet).getByRole('switch', { name: 'Enabled' }));
    await user.click(within(sheet).getByRole('button', { name: 'Save pattern' }));
    expect(await screen.findByText('Custom pattern saved.')).toBeInTheDocument();
    expect(bodies[0]).toEqual({ version: 2, severity: 'critical', enabled: false });
    expectRequestMatchesContract('DlpPatternsController_update_v1', bodies[0]);
  });

  it('deletes a pattern with a confirm; 409 dlp_pattern_in_use is explained', async () => {
    const versions: (string | null)[] = [];
    mockApi({
      DlpPatternsController_list_v1: () => okJson(page([dlpPattern()])),
      DlpPatternsController_remove_v1: ({ url }) => {
        versions.push(url.searchParams.get('version'));
        return versions.length === 1
          ? apiErrorJson(409, 'dlp_pattern_in_use', 'Rules select this pattern', {
              extra: { references: 3 },
            })
          : noContentResponse();
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await user.click(await screen.findByRole('button', { name: 'Actions for Employee ID' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Delete pattern' }));
    expect(
      await within(confirm).findByText(
        'Rules select this custom pattern (3). Change those first, then delete again.',
      ),
    ).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Delete pattern' }));
    expect(await screen.findByText('Custom pattern deleted.')).toBeInTheDocument();
    await waitFor(() => expect(versions).toEqual(['2', '2']));
  });
});
