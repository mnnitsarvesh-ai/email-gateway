import { screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { diffDefinitions } from './diff';
import { DefinitionDiffView } from './diff-view';
import { EvaluationResultView } from './result-view';
import { summarizeDefinition, summaryToText } from './summary';
import { PolicySummaryView } from './summary-view';
import { TEST_CATALOG } from './test-support/catalog';
import { BRIEF_EXAMPLE, BRIEF_EXAMPLE_TEXT } from './test-support/documents';
import { EDITED_POLICY, TEST_RESPONSE } from './test-support/responses';

describe('PolicySummaryView', () => {
  const rich = {
    ...BRIEF_EXAMPLE,
    rules: [
      { ...BRIEF_EXAMPLE.rules[0]!, stop: true },
      {
        id: 'tag-external',
        priority: 20,
        enabled: false,
        when: { field: 'sender.envelope.domain', op: 'not_in', value: ['corp.example'] },
        unless: [{ field: 'sender.trusted', op: 'is', value: true }],
        actions: [{ type: 'TAG', label: 'external' }],
      },
    ],
    exceptions: [
      { field: 'sender.authenticated.domain', op: 'domain_in', value: ['partner.example'] },
    ],
  };

  it('renders structured lines with emphasized keywords, notes, exceptions and the floor note; Copy summary copies the text', async () => {
    const summary = summarizeDefinition(rich, TEST_CATALOG);
    const { user, container } = renderWithProviders(<PolicySummaryView summary={summary} />);
    const rule = screen.getByRole('article', { name: /Rule quarantine-confidential/ });
    expect(within(rule).getByText('IF:')).toHaveClass('font-semibold');
    expect(
      within(rule).getByRole('list', { name: 'Conditions of rule quarantine-confidential' }),
    ).toHaveTextContent('AND DLP data categories contain any of Confidential');
    expect(within(rule).getByText('Then stop evaluating later rules')).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Rule tag-external (priority 20) (disabled)' }),
    ).toBeInTheDocument();
    expect(screen.getByText('UNLESS:')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Policy-wide exceptions' })).toHaveTextContent(
      'partner.example',
    );
    expect(screen.getByText(TEST_CATALOG.enforcement)).toBeInTheDocument();
    const write = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy summary' }));
    expect(write).toHaveBeenCalledWith(summaryToText(summary));
    await expectNoAxeViolations(container);
  });

  it("copies exactly the B5 text for the brief's example; compact mode is denser", async () => {
    const write = vi.spyOn(navigator.clipboard, 'writeText');
    const { user, container } = renderWithProviders(
      <PolicySummaryView summary={summarizeDefinition(BRIEF_EXAMPLE, TEST_CATALOG)} compact />,
    );
    await user.click(screen.getByRole('button', { name: 'Copy summary' }));
    expect(write).toHaveBeenCalledWith(BRIEF_EXAMPLE_TEXT);
    expect(container.querySelector('[data-compact]')).toHaveClass('text-xs');
    await expectNoAxeViolations(container);
  });
});

describe('DefinitionDiffView', () => {
  const before = BRIEF_EXAMPLE;
  const after = {
    ...BRIEF_EXAMPLE,
    priority: 20,
    rules: [
      {
        ...BRIEF_EXAMPLE.rules[0]!,
        when: {
          all: [
            { field: 'dlp.categories', op: 'contains_any', value: ['confidential', 'source_code'] },
          ],
        },
      },
      {
        id: 'archive-legal',
        priority: 30,
        when: { field: 'urls.count', op: 'gt', value: 0 },
        actions: [{ type: 'ARCHIVE' }],
      },
    ],
  };

  it('shows counts, policy changes and rule cards with +/− markers and text labels', async () => {
    const diff = diffDefinitions(before, after, TEST_CATALOG);
    const { container } = renderWithProviders(
      <DefinitionDiffView diff={diff} fromLabel="v1" toLabel="v2" />,
    );
    expect(
      screen.getByText('From v1 to v2: 1 rule added, 0 removed, 1 changed.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Policy settings' })).toHaveTextContent('v1: 10');
    const changed = screen.getByRole('article', { name: 'Rule quarantine-confidential' });
    expect(within(changed).getByText('Changed')).toBeInTheDocument();
    const lines = within(changed).getByRole('list', {
      name: 'IF lines of rule quarantine-confidential',
    });
    const removed = within(lines).getByText('DLP data categories contain any of Confidential');
    expect(removed.closest('li')).toHaveAttribute('data-op', 'delete');
    expect(removed.closest('li')).toHaveTextContent('−Removed: DLP data categories');
    expect(
      within(screen.getByRole('article', { name: 'Rule archive-legal' })).getByText('Added'),
    ).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('switches to the raw JSON tab (controlled or not) and folds long unchanged runs', async () => {
    const diff = diffDefinitions(before, after, TEST_CATALOG);
    const onViewChange = vi.fn();
    const { user, container } = renderWithProviders(
      <DefinitionDiffView diff={diff} fromLabel="v1" toLabel="v2" onViewChange={onViewChange} />,
    );
    await user.click(screen.getByRole('tab', { name: 'Raw JSON' }));
    expect(onViewChange).toHaveBeenCalledWith('json');
    const json = screen.getByRole('list', { name: 'Canonical JSON from v1 to v2' });
    expect(within(json).getAllByText(/"source_code"/).length).toBeGreaterThan(0);
    const fold = within(json).getAllByRole('button', { name: /^Show \d+ unchanged lines$/ });
    expect(fold.length).toBeGreaterThan(0);
    await user.click(fold[0]!);
    await expectNoAxeViolations(container);
  });
});

describe('EvaluationResultView', () => {
  it('renders the server response as returned, with Show in editor on the edited version only', async () => {
    const shown: string[] = [];
    const { user, container } = renderWithProviders(
      <EvaluationResultView
        response={TEST_RESPONSE}
        catalog={TEST_CATALOG}
        onShowPath={(path) => shown.push(path)}
        isEditorRef={(ref) => ref.startsWith(`${EDITED_POLICY}#3/`)}
      />,
    );
    expect(screen.getAllByText('Quarantine').length).toBeGreaterThan(0);
    expect(screen.getByText('DLP violation')).toBeInTheDocument();
    expect(screen.getByText(/Decided by rule/)).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Recipient decisions' })).toHaveTextContent('#1');
    expect(screen.getByRole('table', { name: 'Matched rules' })).toHaveTextContent(
      'Quarantine, Alert administrators',
    );
    expect(
      screen.getByRole('table', { name: 'Actions with their applicability' }),
    ).toHaveTextContent('No (not applicable)');
    // Floor reasons and reason codes are listed as returned.
    expect(screen.getAllByText('policy.floor.dlp_alert')).toHaveLength(2);
    expect(screen.getByText('No delivery edits (nothing is delivered).')).toBeInTheDocument();
    expect(screen.getByText(/Unknown field \(unknown_field\)/)).toBeInTheDocument();
    const trace = screen.getByRole('table', { name: 'Evaluation trace' });
    expect(trace).toHaveTextContent('DLP data categories contain any of');
    const buttons = within(trace).getAllByRole('button', { name: /^Show in editor/ });
    expect(buttons).toHaveLength(1);
    await user.click(buttons[0]!);
    expect(shown).toEqual(['rules[0].when.all[0]']);
    await expectNoAxeViolations(container);
  });

  it('offers no Show in editor without a handler', () => {
    renderWithProviders(<EvaluationResultView response={TEST_RESPONSE} catalog={TEST_CATALOG} />);
    expect(screen.queryByRole('button', { name: /^Show in editor/ })).not.toBeInTheDocument();
  });
});
