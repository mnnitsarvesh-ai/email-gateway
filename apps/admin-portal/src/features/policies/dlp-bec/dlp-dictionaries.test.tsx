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
import { DICTIONARY_ID, dlpDictionary, dlpDictionaryRow, page } from './test-data';

const ROUTE = '/policies?tab=dlp&section=dictionaries';

describe('DLP keyword dictionaries (WP5)', () => {
  it('creates a dictionary: a refused term is named by its line, 409 name taken, then 201; axe', async () => {
    const bodies: unknown[] = [];
    mockApi({
      DlpDictionariesController_list_v1: () => okJson(page([dlpDictionaryRow()])),
      DlpDictionariesController_create_v1: ({ body }) => {
        bodies.push(body);
        if (bodies.length === 1) {
          return apiErrorJson(400, 'dictionary_term_invalid', 'The dictionary terms were refused', {
            extra: { index: 1 },
          });
        }
        if (bodies.length === 2) {
          return apiErrorJson(409, 'dlp_dictionary_exists', 'Exists', {
            extra: { id: DICTIONARY_ID },
          });
        }
        return okJson(dlpDictionary({ name: 'Finance terms' }), 201);
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await screen.findByText('Project names');
    await user.click(screen.getByRole('button', { name: 'New dictionary' }));
    const sheet = await screen.findByRole('dialog', { name: 'New keyword dictionary' });
    await expectNoAxeViolations(document.body);
    await user.type(within(sheet).getByLabelText(/^Name/), 'Finance terms');
    await user.selectOptions(within(sheet).getByLabelText(/^Category/), 'financial');
    await user.type(
      within(sheet).getByLabelText(/^Terms/),
      'quarterly forecast{Enter}{Enter}board pack{Enter}payroll export',
    );
    await user.clear(within(sheet).getByLabelText(/^Minimum distinct terms/));
    await user.type(within(sheet).getByLabelText(/^Minimum distinct terms/), '2');
    expect(
      within(sheet).getByText(/One per line \(3 of at most 10000 terms\)/),
    ).toBeInTheDocument();
    await user.click(within(sheet).getByRole('button', { name: 'Create dictionary' }));
    expect(await within(sheet).findByText(/Line 3: this term was refused/)).toBeInTheDocument();
    expect(within(sheet).getByText('dictionary_term_invalid')).toBeInTheDocument();
    expect(bodies[0]).toEqual({
      name: 'Finance terms',
      category: 'financial',
      terms: ['quarterly forecast', 'board pack', 'payroll export'],
      severity: 'medium',
      baseConfidence: 0.7,
      minMatches: 2,
      enabled: true,
    });
    expectRequestMatchesContract('DlpDictionariesController_create_v1', bodies[0]);

    await user.click(within(sheet).getByRole('button', { name: 'Create dictionary' }));
    expect(
      await within(sheet).findByText('A dictionary with this name exists. Choose another name.'),
    ).toBeInTheDocument();
    await user.click(within(sheet).getByRole('button', { name: 'Create dictionary' }));
    expect(await screen.findByText('Keyword dictionary created.')).toBeInTheDocument();
  });

  it('loads the terms only when the editor opens and replaces them with the version', async () => {
    const seen: string[] = [];
    const bodies: unknown[] = [];
    mockApi({
      DlpDictionariesController_list_v1: () => okJson(page([dlpDictionaryRow()])),
      DlpDictionariesController_get_v1: ({ params }) => {
        seen.push(params.id ?? '');
        return okJson(dlpDictionary());
      },
      DlpDictionariesController_update_v1: ({ body }) => {
        bodies.push(body);
        return okJson(dlpDictionary({ version: 5 }));
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'organization_admin', route: ROUTE });
    await screen.findByText('Project names');
    expect(seen).toEqual([]);
    expect(screen.queryByText('falcon roadmap')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Actions for Project names' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const sheet = await screen.findByRole('dialog', { name: 'Edit Project names' });
    const terms = await within(sheet).findByLabelText(/^Terms/);
    expect(terms).toHaveValue('falcon roadmap\nheron merger');
    expect(seen).toEqual([DICTIONARY_ID]);
    await user.type(terms, '{Enter}blue harbor');
    await user.click(within(sheet).getByRole('button', { name: 'Save dictionary' }));
    expect(await screen.findByText('Keyword dictionary saved.')).toBeInTheDocument();
    expect(bodies[0]).toEqual({
      version: 4,
      terms: ['falcon roadmap', 'heron merger', 'blue harbor'],
    });
    expectRequestMatchesContract('DlpDictionariesController_update_v1', bodies[0]);
  });

  it('deletes a dictionary with a confirm; 409 dlp_dictionary_in_use is explained', async () => {
    const versions: (string | null)[] = [];
    mockApi({
      DlpDictionariesController_list_v1: () => okJson(page([dlpDictionaryRow()])),
      DlpDictionariesController_remove_v1: ({ url }) => {
        versions.push(url.searchParams.get('version'));
        return versions.length === 1
          ? apiErrorJson(409, 'dlp_dictionary_in_use', 'Rules select this dictionary', {
              extra: { references: 1 },
            })
          : noContentResponse();
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await user.click(await screen.findByRole('button', { name: 'Actions for Project names' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Delete dictionary' }));
    expect(
      await within(confirm).findByText(
        'Rules select this dictionary (1). Change those first, then delete again.',
      ),
    ).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Delete dictionary' }));
    expect(await screen.findByText('Keyword dictionary deleted.')).toBeInTheDocument();
    await waitFor(() => expect(versions).toEqual(['4', '4']));
  });
});
