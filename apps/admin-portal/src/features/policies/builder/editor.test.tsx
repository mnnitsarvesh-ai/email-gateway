import { screen, waitFor, within } from '@testing-library/react';
import type userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { toBuilderCatalog } from './catalog';
import type { Violation } from './context';
import { ViolationList } from './violation-list';
import { RAW_TEST_CATALOG, TEST_CATALOG } from './test-support/catalog';
import { BRIEF_EXAMPLE } from './test-support/documents';
import { currentDefinition, EditorHarness, modelOf, ruleOf } from './test-support/harness';

type User = ReturnType<typeof userEvent.setup>;

const doc = (rules: unknown[], extra: Record<string, unknown> = {}) => ({
  dslVersion: 'policy-dsl/1',
  direction: 'inbound',
  priority: 10,
  rules,
  ...extra,
});
const SPF_RULE = {
  id: 'r1',
  priority: 10,
  when: { all: [{ field: 'auth.spf', op: 'equals', value: 'fail' }] },
  actions: [{ type: 'TAG', label: 'spf' }],
};

const whenOf = (i = 0) => ruleOf(currentDefinition(), i).when as Record<string, unknown[]>;
const row = (name: string) => screen.getByRole('group', { name });
const liveText = (text: string) =>
  waitFor(() =>
    expect(
      [...document.querySelectorAll('[aria-live="polite"][aria-atomic="true"]')].some((el) =>
        el.textContent?.includes(text),
      ),
    ).toBe(true),
  );

async function press(user: User, element: HTMLElement) {
  element.focus();
  await user.keyboard('{Enter}');
}

describe('PolicyBuilderEditor: keyboard-only group editing (design B14)', () => {
  it('adds, nests, toggles, negates, moves and removes with the keyboard; focus and live region follow', async () => {
    const { user, container } = renderWithProviders(
      <EditorHarness initial={modelOf(doc([SPF_RULE]))} />,
    );

    // Add a condition: a new empty row; focus on its field picker; announced.
    await press(user, screen.getByRole('button', { name: 'Add condition' }));
    const second = row('Condition 2 of 2 in all of the following (AND), level 1');
    expect(within(second).getByRole('combobox', { name: 'Field Choose a field' })).toHaveFocus();
    await liveText('Condition added. Choose its field.');
    expect(whenOf().all).toEqual([{ field: 'auth.spf', op: 'equals', value: 'fail' }, {}]);

    // Add a nested group (the opposite joiner) with one condition; focus on that condition.
    await press(user, screen.getByRole('button', { name: 'Add group' }));
    const nested = screen.getByRole('group', {
      name: 'Group 3, any of the following (OR), level 2',
    });
    expect(
      within(row('Condition 1 of 1 in any of the following (OR), level 2')).getByRole('combobox', {
        name: 'Field Choose a field',
      }),
    ).toHaveFocus();
    expect(whenOf().all![2]).toEqual({ any: [{}] });

    // AND/OR toggle of the nested group.
    await press(user, within(nested).getAllByRole('button', { name: 'All (AND)' })[0]!);
    expect(whenOf().all![2]).toEqual({ all: [{}] });
    await liveText('The group now matches all of the following (AND).');

    // NOT on condition 1: wrapped, pressed, focus kept on the toggle.
    const first = row('Condition 1 of 3 in all of the following (AND), level 1');
    await press(user, within(first).getByRole('button', { name: 'NOT: negate condition 1' }));
    expect(whenOf().all![0]).toEqual({ not: { field: 'auth.spf', op: 'equals', value: 'fail' } });
    const notButton = screen.getByRole('button', { name: 'NOT: negate condition 1' });
    expect(notButton).toHaveAttribute('aria-pressed', 'true');
    expect(notButton).toHaveFocus();

    // Move condition 1 down (array order; the NOT moves with it); focus stays on the button.
    await press(user, screen.getByRole('button', { name: 'Move condition 1 down' }));
    expect(whenOf().all).toEqual([
      {},
      { not: { field: 'auth.spf', op: 'equals', value: 'fail' } },
      { all: [{}] },
    ]);
    expect(screen.getByRole('button', { name: 'Move condition 2 down' })).toHaveFocus();
    await liveText('Condition moved down, now 2 of 3.');

    // Remove condition 2: focus moves to the previous row's field picker.
    await press(user, screen.getByRole('button', { name: 'Remove condition 2' }));
    expect(whenOf().all).toEqual([{}, { all: [{}] }]);
    expect(
      within(row('Condition 1 of 2 in all of the following (AND), level 1')).getByRole('combobox', {
        name: /^Field/,
      }),
    ).toHaveFocus();
    await liveText('Condition 2 removed.');

    // Removing the first row moves the focus to the group's add button.
    await press(user, screen.getByRole('button', { name: 'Remove condition 1' }));
    expect(screen.getAllByRole('button', { name: 'Add condition' })[1]).toHaveFocus();
    await expectNoAxeViolations(container);
  });

  it('wraps a root condition into a group when adding beside it', async () => {
    const single = { ...SPF_RULE, when: { field: 'auth.spf', op: 'equals', value: 'fail' } };
    const { user } = renderWithProviders(<EditorHarness initial={modelOf(doc([single]))} />);
    expect(screen.queryByRole('button', { name: /Remove condition/ })).not.toBeInTheDocument();
    await press(user, screen.getByRole('button', { name: 'Add condition' }));
    expect(whenOf()).toEqual({ all: [{ field: 'auth.spf', op: 'equals', value: 'fail' }, {}] });
    await liveText('both conditions now form a group');
  });

  it('disables add controls at the catalogue limits and says why', () => {
    const catalog = toBuilderCatalog({
      ...RAW_TEST_CATALOG,
      limits: { ...RAW_TEST_CATALOG.limits, childrenPerGroup: 1, depth: 1 },
    });
    renderWithProviders(<EditorHarness catalog={catalog} initial={modelOf(doc([SPF_RULE]))} />);
    expect(screen.getByRole('button', { name: 'Add condition' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Add group' })).toBeDisabled();
    expect(screen.getByText('A group holds at most 1 conditions.')).toBeInTheDocument();
    // NOT needs one more level: refused at depth 1.
    expect(screen.getByRole('button', { name: 'NOT: negate condition 1' })).toBeDisabled();
  });
});

describe('PolicyBuilderEditor: rules', () => {
  it('lists rules by priority; move swaps priorities; add focuses the new rule; remove focuses the previous rule', async () => {
    const rules = [
      { ...SPF_RULE, id: 'late', priority: 50 },
      { ...SPF_RULE, id: 'early', priority: 5 },
    ];
    const { user } = renderWithProviders(<EditorHarness initial={modelOf(doc(rules))} />);
    const headings = screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent);
    expect(headings).toEqual(['Rule early', 'Rule late']);
    await press(user, screen.getByRole('button', { name: 'Move rule late up' }));
    expect(
      (currentDefinition().rules as Array<{ id: string; priority: number }>).map((r) => [
        r.id,
        r.priority,
      ]),
    ).toEqual([
      ['late', 5],
      ['early', 50],
    ]);
    expect(screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)).toEqual([
      'Rule late',
      'Rule early',
    ]);
    expect(screen.getByRole('button', { name: 'Move rule late down' })).toHaveFocus();

    await press(user, screen.getByRole('button', { name: 'Add rule' }));
    expect(ruleOf(currentDefinition(), 2)).toEqual({
      id: 'rule-1',
      priority: 60,
      when: { all: [{}] },
      actions: [],
    });
    expect(
      within(screen.getByRole('region', { name: 'Conditions (IF) of rule rule-1' })).getByRole(
        'combobox',
        {
          name: 'Field Choose a field',
        },
      ),
    ).toHaveFocus();

    await press(user, screen.getByRole('button', { name: 'Remove rule rule-1' }));
    expect(currentDefinition().rules).toHaveLength(2);
    expect(screen.getByRole('heading', { name: 'Rule early' })).toHaveFocus();
  });

  it('edits rule settings; optional keys are written only when set', async () => {
    const { user } = renderWithProviders(
      <EditorHarness initial={modelOf(doc([SPF_RULE], { direction: 'any' }))} />,
    );
    const card = screen.getByRole('region', { name: 'Rule r1' });
    await user.clear(within(card).getByLabelText('Priority'));
    await user.type(within(card).getByLabelText('Priority'), '25');
    await user.type(within(card).getByLabelText('Description (optional)'), 'Fail SPF');
    await user.click(within(card).getByRole('switch', { name: 'Enabled' }));
    // Directions chips (policy direction "any"): catalogue message directions.
    await user.click(within(card).getByRole('button', { name: 'Internal' }));
    await user.click(within(card).getByRole('button', { name: 'Inbound' }));
    await user.click(within(card).getByRole('combobox', { name: 'After a match' }));
    await user.click(await screen.findByRole('option', { name: 'Continue with later rules' }));
    expect(ruleOf(currentDefinition())).toEqual({
      ...SPF_RULE,
      priority: 25,
      description: 'Fail SPF',
      enabled: false,
      directions: ['inbound', 'internal'],
      stop: false,
    });
    // Back to defaults removes the keys again.
    await user.click(within(card).getByRole('switch', { name: 'Enabled' }));
    await user.click(within(card).getByRole('button', { name: 'Inbound' }));
    await user.click(within(card).getByRole('button', { name: 'Internal' }));
    await user.clear(within(card).getByLabelText('Description (optional)'));
    await user.click(within(card).getByRole('combobox', { name: 'After a match' }));
    await user.click(await screen.findByRole('option', { name: 'Default' }));
    expect(ruleOf(currentDefinition())).toEqual({ ...SPF_RULE, priority: 25 });
    // A non-integer priority is refused by the input, the model keeps the last integer.
    await user.type(within(card).getByLabelText('Priority'), '.5');
    expect(within(card).getByText('Enter a whole number.')).toBeInTheDocument();
    expect(ruleOf(currentDefinition()).priority).toBe(25);
  });

  it('shows direction chips only for an all-directions policy and the override switch only with a decision', () => {
    renderWithProviders(
      <EditorHarness
        initial={modelOf(
          doc([
            SPF_RULE,
            { ...SPF_RULE, id: 'q', priority: 20, actions: [{ type: 'QUARANTINE' }] },
          ]),
        )}
      />,
    );
    expect(screen.queryByRole('group', { name: /^Directions of rule/ })).not.toBeInTheDocument();
    const tagRule = screen.getByRole('region', { name: 'Rule r1' });
    const quarantineRule = screen.getByRole('region', { name: 'Rule q' });
    expect(within(tagRule).queryByRole('switch', { name: /override/ })).not.toBeInTheDocument();
    expect(within(quarantineRule).getByRole('switch', { name: /override/ })).not.toBeChecked();
  });

  it('starts large policies collapsed and opens the card of a highlighted node', () => {
    const rules = Array.from({ length: 11 }, (_, i) => ({ ...SPF_RULE, id: `r${i}`, priority: i }));
    const model = modelOf(doc(rules));
    const { rerender } = renderWithProviders(<EditorHarness initial={model} />);
    expect(screen.getAllByRole('button', { name: /^Expand Rule/ })).toHaveLength(11);
    expect(screen.queryByRole('combobox', { name: /^Field/ })).not.toBeInTheDocument();
    rerender(<EditorHarness initial={model} highlightPath="rules[3].when.all[0].value" />);
    const highlighted = screen.getByRole('group', {
      name: 'Condition 1 of 1 in all of the following (AND), level 1',
    });
    expect(highlighted.className).toContain('ring-2');
    expect(screen.getAllByRole('button', { name: /^Expand Rule/ })).toHaveLength(10);
  });
});

describe('PolicyBuilderEditor: exceptions and catalogue restrictions', () => {
  it('offers only exception fields, forces the exception quantifier and offers no NOT', async () => {
    const { user } = renderWithProviders(<EditorHarness initial={modelOf(doc([SPF_RULE]))} />);
    await press(user, screen.getByRole('button', { name: 'Add exception' }));
    const exception = row('Exception 1 of rule r1');
    const picker = within(exception).getByRole('combobox', { name: 'Field Choose a field' });
    expect(picker).toHaveFocus();
    await user.click(picker);
    const options = screen.getAllByRole('option').map((o) => o.textContent ?? '');
    expect(options.some((o) => o.startsWith('Recipient department'))).toBe(true);
    expect(options.some((o) => o.startsWith('Authenticated sender domain'))).toBe(true);
    expect(options.some((o) => o.startsWith('Envelope sender domain'))).toBe(false);
    expect(options.some((o) => o.startsWith('BEC verdict (with AI)'))).toBe(false);
    await user.click(
      screen.getByRole('option', { name: (name) => name.startsWith('Recipient department') }),
    );
    expect(ruleOf(currentDefinition()).unless).toEqual([
      { field: 'recipient.department', op: 'in', value: [], quantifier: 'all' },
    ]);
    expect(within(exception).getByText('Applies to: Every recipient')).toBeInTheDocument();
    expect(within(exception).queryByRole('button', { name: /^NOT/ })).not.toBeInTheDocument();
    await user.click(within(exception).getByRole('combobox', { name: 'Operator' }));
    const ops = (await screen.findAllByRole('option')).map((o) => o.textContent);
    expect(ops).toEqual(['is one of']);
  });

  it('warns about conditions the server refuses at their place (catalogue contexts)', () => {
    const allowRaw = {
      id: 'allow-partner',
      priority: 1,
      when: { all: [{ field: 'sender.envelope.domain', op: 'equals', value: 'partner.example' }] },
      actions: [{ type: 'ALLOW' }],
    };
    const holdAi = {
      id: 'hold-ai',
      priority: 2,
      when: { all: [{ field: 'bec.verdict', op: 'equals', value: 'malicious' }] },
      actions: [{ type: 'QUARANTINE' }],
    };
    const exceptionProblems = {
      id: 'exceptions',
      priority: 3,
      when: { all: [{ field: 'auth.spf', op: 'equals', value: 'fail' }] },
      unless: [
        { field: 'recipient.domain', op: 'in', value: ['corp.example'] },
        { not: { field: 'sender.trusted', op: 'is', value: true } },
      ],
      actions: [{ type: 'TAG', label: 'x' }],
    };
    renderWithProviders(
      <EditorHarness initial={modelOf(doc([allowRaw, holdAi, exceptionProblems]))} />,
    );
    expect(
      screen.getByText(
        /Envelope sender domain is not accepted in a rule with Allow or an override/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /BEC verdict \(with AI\) is not accepted in a rule with Require approval, Quarantine or Reject/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/applies to “Every recipient” only/)).toBeInTheDocument();
    expect(screen.getByText(/Exceptions cannot be negated/)).toBeInTheDocument();
    // A warning, not an error: nothing was changed.
    expect(currentDefinition()).toEqual(doc([allowRaw, holdAi, exceptionProblems]));
    // The picker of a relaxing rule offers no raw sender field.
  });

  it('offers only fields allowed in a relaxing rule in its condition picker', async () => {
    const allow = { id: 'a', priority: 1, when: { all: [{}] }, actions: [{ type: 'ALLOW' }] };
    const { user } = renderWithProviders(<EditorHarness initial={modelOf(doc([allow]))} />);
    await user.click(screen.getByRole('combobox', { name: 'Field Choose a field' }));
    const options = screen.getAllByRole('option').map((o) => o.textContent ?? '');
    expect(options.some((o) => o.startsWith('Envelope sender address'))).toBe(false);
    expect(options.some((o) => o.startsWith('Authenticated sender address'))).toBe(true);
  });

  it('moves and removes rule and policy-wide exceptions as list entries; focus follows', async () => {
    const rule = {
      ...SPF_RULE,
      unless: [
        { field: 'sender.trusted', op: 'is', value: true },
        { field: 'recipient.domain', op: 'in', value: ['corp.example'], quantifier: 'all' },
      ],
    };
    const { user, container } = renderWithProviders(
      <EditorHarness initial={modelOf(doc([rule]))} />,
    );
    await press(user, screen.getByRole('button', { name: 'Move exception 2 of rule r1 up' }));
    expect(
      (ruleOf(currentDefinition()).unless as Array<{ field: string }>).map((u) => u.field),
    ).toEqual(['recipient.domain', 'sender.trusted']);
    expect(screen.getByRole('button', { name: 'Move exception 1 of rule r1 down' })).toHaveFocus();
    await press(user, screen.getByRole('button', { name: 'Remove exception 2 of rule r1' }));
    expect(
      within(row('Exception 1 of rule r1')).getByRole('combobox', { name: /^Field/ }),
    ).toHaveFocus();
    await press(user, screen.getByRole('button', { name: 'Remove exception 1 of rule r1' }));
    expect('unless' in ruleOf(currentDefinition())).toBe(false);
    expect(screen.getByRole('button', { name: 'Add exception' })).toHaveFocus();
    await press(user, screen.getByRole('button', { name: 'Add policy-wide exception' }));
    expect(currentDefinition().exceptions).toEqual([{}]);
    expect(
      within(row('Policy-wide exception 1')).getByRole('combobox', {
        name: 'Field Choose a field',
      }),
    ).toHaveFocus();
    await expectNoAxeViolations(container);
  });
});

describe('ActionsEditor', () => {
  it('adds actions from the catalogue (one decision, other actions once) with parameter forms', async () => {
    const rule = {
      id: 'r1',
      priority: 1,
      when: { all: [{ field: 'auth.spf', op: 'equals', value: 'fail' }] },
      actions: [],
    };
    const { user, container } = renderWithProviders(
      <EditorHarness initial={modelOf(doc([rule]))} />,
    );
    expect(
      screen.getByText('No action yet. A rule needs at least one action.'),
    ).toBeInTheDocument();
    const add = screen.getByRole('button', { name: 'Add action' });
    await user.click(add);
    const menu = await screen.findByRole('menu');
    expect(
      within(menu)
        .getAllByRole('menuitem')
        .map((i) => i.textContent),
    ).toEqual([
      'Allow',
      'Require approval',
      'Quarantine',
      'Reject',
      'Tag',
      'Warn recipients',
      'Require URL rewriting',
      'Archive',
      'Alert administrators',
    ]);
    await user.click(within(menu).getByRole('menuitem', { name: 'Quarantine' }));
    await user.click(screen.getByRole('button', { name: 'Add action' }));
    const second = await screen.findByRole('menu');
    const offered = within(second)
      .getAllByRole('menuitem')
      .map((i) => i.textContent);
    expect(offered).not.toContain('Allow');
    expect(offered).not.toContain('Quarantine');
    await user.click(within(second).getByRole('menuitem', { name: 'Alert administrators' }));
    // Required enum parameter: marked, not written until chosen; focus on it.
    const alert = screen.getByRole('group', { name: 'Action 2 of 2: Alert administrators' });
    const severity = within(alert).getByRole('combobox', { name: 'Severity (required)' });
    await waitFor(() => expect(severity).toHaveFocus());
    expect(ruleOf(currentDefinition()).actions).toEqual([
      { type: 'QUARANTINE' },
      { type: 'ALERT' },
    ]);
    await user.click(severity);
    await user.click(await screen.findByRole('option', { name: 'Warning' }));
    // Tag: string parameters with maxLength; optional ones only when set.
    await user.click(screen.getByRole('button', { name: 'Add action' }));
    await user.click(
      within(await screen.findByRole('menu')).getByRole('menuitem', { name: 'Tag' }),
    );
    const tag = screen.getByRole('group', { name: 'Action 3 of 3: Tag' });
    const label = within(tag).getByRole('textbox', { name: 'Label (required)' });
    expect(label).toHaveAttribute('maxlength', '32');
    await user.type(label, 'external');
    expect(within(tag).getByRole('combobox', { name: 'Add the tag header' })).toHaveTextContent(
      'Default (yes)',
    );
    expect(ruleOf(currentDefinition()).actions).toEqual([
      { type: 'QUARANTINE' },
      { type: 'ALERT', severity: 'warning' },
      { type: 'TAG', label: 'external' },
    ]);
    // Reorder and remove with buttons.
    await user.click(within(tag).getByRole('button', { name: 'Move action Tag up' }));
    expect(
      (ruleOf(currentDefinition()).actions as Array<{ type: string }>).map((a) => a.type),
    ).toEqual(['QUARANTINE', 'TAG', 'ALERT']);
    await user.click(screen.getByRole('button', { name: 'Remove action Quarantine' }));
    expect(
      (ruleOf(currentDefinition()).actions as Array<{ type: string }>).map((a) => a.type),
    ).toEqual(['TAG', 'ALERT']);
    await expectNoAxeViolations(container);
  });

  it('keeps unknown parameters and action types (lossless) and lets the user remove them', async () => {
    const rule = {
      ...SPF_RULE,
      actions: [
        { type: 'TAG', label: 'x', legacy: 1 },
        { type: 'FUTURE', a: true },
      ],
    };
    const { user } = renderWithProviders(<EditorHarness initial={modelOf(doc([rule]))} />);
    expect(screen.getByText('Action not in the catalogue')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Remove legacy' }));
    expect(ruleOf(currentDefinition()).actions).toEqual([
      { type: 'TAG', label: 'x' },
      { type: 'FUTURE', a: true },
    ]);
  });
});

describe('Server violations', () => {
  const violations: Violation[] = [
    { path: 'rules[0].when.all[0].value', code: 'value_invalid', message: 'Invalid enum value' },
    {
      path: 'rules[0].actions[0].label',
      code: 'value_invalid',
      message: 'Label: [a-z0-9][a-z0-9._-]{0,31}',
    },
    { path: 'rules[0].id', code: 'duplicate_rule_id', message: 'Rule ids are unique in a policy' },
    { path: 'priority', code: 'value_invalid', message: 'Expected an integer 0..10000' },
  ];

  it('maps violations onto nodes (aria-describedby), lists policy-level ones, and the error summary focuses the node', async () => {
    const { user, container } = renderWithProviders(
      <EditorHarness initial={modelOf(doc([SPF_RULE]))} violations={violations}>
        <ViolationList violations={violations} />
      </EditorHarness>,
    );
    const condition = row('Condition 1 of 1 in all of the following (AND), level 1');
    expect(within(condition).getByText('Invalid enum value')).toBeInTheDocument();
    const describedBy = condition.getAttribute('aria-describedby') ?? '';
    expect(
      describedBy
        .split(' ')
        .some((id) => document.getElementById(id)?.textContent?.includes('Invalid enum value')),
    ).toBe(true);
    expect(
      within(screen.getByRole('group', { name: 'Action 1 of 1: Tag' })).getByText(
        /Label: \[a-z0-9\]/,
      ),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole('region', { name: 'Rule r1' })).getByText(
        'Rule ids are unique in a policy',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('Problems with the policy as a whole')).toBeInTheDocument();
    const summary = screen.getByRole('region', { name: 'The server reported 4 problems' });
    await user.click(
      within(summary).getByRole('button', { name: /Rule 1 › conditions › item 1 › value/ }),
    );
    expect(within(condition).getByRole('combobox', { name: /^Field/ })).toHaveFocus();
    await user.click(within(summary).getByRole('button', { name: /Rule 1 › action 1 › label/ }));
    expect(screen.getByRole('group', { name: 'Action 1 of 1: Tag' })).toHaveFocus();
    await expectNoAxeViolations(container);
  });

  it('calls onSelect with the path, also outside a provider', async () => {
    const selected: string[] = [];
    const { user } = renderWithProviders(
      <ViolationList violations={violations} onSelect={(path) => selected.push(path)} />,
    );
    await user.click(screen.getByRole('button', { name: /^Policy › priority|^priority/ }));
    expect(selected).toEqual(['priority']);
  });

  it('in view mode the error summary focuses the node itself (no controls there)', async () => {
    const { user, container } = renderWithProviders(
      <EditorHarness readOnly initial={modelOf(doc([SPF_RULE]))} violations={violations}>
        <ViolationList violations={violations} />
      </EditorHarness>,
    );
    await user.click(screen.getByRole('button', { name: /Rule 1 › conditions › item 1 › value/ }));
    expect(row('Condition 1 of 1 in all of the following (AND), level 1')).toHaveFocus();
    await expectNoAxeViolations(container);
  });
});

describe('Read-only mode and layout', () => {
  it('renders the same tree with no edit control', async () => {
    const full = {
      ...BRIEF_EXAMPLE,
      rules: [
        {
          ...BRIEF_EXAMPLE.rules[0]!,
          unless: [
            { field: 'recipient.domain', op: 'in', value: ['partner.example'], quantifier: 'all' },
          ],
          stop: true,
        },
      ],
      exceptions: [{ field: 'sender.trusted', op: 'is', value: true }],
    };
    const { container } = renderWithProviders(<EditorHarness readOnly initial={modelOf(full)} />);
    for (const role of [
      'textbox',
      'combobox',
      'spinbutton',
      'checkbox',
      'switch',
      'radio',
      'menuitem',
    ] as const) {
      expect(screen.queryAllByRole(role), role).toEqual([]);
    }
    const buttons = screen
      .queryAllByRole('button')
      .map((b) => b.getAttribute('aria-label') ?? b.textContent ?? '');
    expect(buttons.filter((name) => /^(Add|Remove|Move|NOT|All|Any|Use)/.test(name))).toEqual([]);
    expect(screen.getByText('DLP data categories')).toBeInTheDocument();
    expect(screen.getByText('Confidential')).toBeInTheDocument();
    expect(screen.getByText('Stop evaluating later rules')).toBeInTheDocument();
    expect(screen.getByText('Applies to: Every recipient')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('stacks the condition row below 640 px (single column, the breakpoint class adds columns)', () => {
    renderWithProviders(<EditorHarness initial={modelOf(doc([SPF_RULE]))} />);
    const fields = row('Condition 1 of 1 in all of the following (AND), level 1').querySelector(
      '[data-layout="condition-fields"]',
    );
    expect(fields?.className).toContain('grid-cols-1');
    expect(fields?.className).toMatch(/sm:grid-cols-\[/);
  });

  it('indents nested groups with a 2 px rule and a "Level n" label', () => {
    const nested = {
      ...SPF_RULE,
      when: { all: [{ any: [{ field: 'auth.spf', op: 'equals', value: 'fail' }] }] },
    };
    renderWithProviders(<EditorHarness initial={modelOf(doc([nested]))} />);
    const group = screen.getByRole('group', {
      name: 'Group 1, any of the following (OR), level 2',
    });
    expect(group.className).toContain('border-l-2');
    expect(within(group).getByText('Level 2')).toHaveClass('sm:hidden');
  });

  it('shows the canonical document size against the catalogue limit', () => {
    renderWithProviders(<EditorHarness initial={modelOf(BRIEF_EXAMPLE)} />);
    expect(screen.getByText(/Document size: \d+ B of 256\.0 KiB/)).toBeInTheDocument();
  });

  it('starts dirty-free and keeps the catalogue the same object', () => {
    renderWithProviders(<EditorHarness initial={modelOf(BRIEF_EXAMPLE)} catalog={TEST_CATALOG} />);
    expect(screen.getByTestId('definition')).toHaveAttribute('data-dirty', 'false');
  });
});
