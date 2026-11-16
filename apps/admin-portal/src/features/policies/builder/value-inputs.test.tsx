import { fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { toBuilderCatalog } from './catalog';
import {
  DEPT_FINANCE,
  DEPT_LEGAL,
  RAW_TEST_CATALOG,
  TEST_DIRECTORY,
  USER_ALICE,
} from './test-support/catalog';
import { currentDefinition, EditorHarness, modelOf, ruleOf } from './test-support/harness';
import type { BuilderDirectory } from './context';
import type { BuilderCatalog } from './catalog';

const ROW = 'Condition 1 of 1 in all of the following (AND), level 1';

function setup(
  leaf: Record<string, unknown>,
  options: { catalog?: BuilderCatalog; directory?: BuilderDirectory } = {},
) {
  const doc = {
    dslVersion: 'policy-dsl/1',
    direction: 'outbound',
    priority: 10,
    rules: [
      { id: 'r1', priority: 10, when: { all: [leaf] }, actions: [{ type: 'TAG', label: 'x' }] },
    ],
  };
  const result = renderWithProviders(
    <EditorHarness
      initial={modelOf(doc)}
      catalog={options.catalog}
      directory={options.directory}
    />,
  );
  const row = screen.getByRole('group', { name: ROW });
  return { ...result, row };
}

const leafNow = () =>
  (ruleOf(currentDefinition()).when as { all: Array<Record<string, unknown>> }).all[0]!;

describe('field-driven value inputs (design §4.7)', () => {
  it('resets operator and value on a field change; keeps the value for the same operator shape', async () => {
    const { user, row } = setup({ field: 'recipient.domain', op: 'in', value: ['a.example'] });
    await user.click(within(row).getByRole('combobox', { name: 'Operator' }));
    await user.click(await screen.findByRole('option', { name: 'is in domain' }));
    expect(leafNow()).toEqual({ field: 'recipient.domain', op: 'domain_in', value: ['a.example'] });
    await user.click(within(row).getByRole('combobox', { name: 'Operator' }));
    await user.click(await screen.findByRole('option', { name: 'is' }));
    expect(leafNow()).toEqual({ field: 'recipient.domain', op: 'equals' });
    await user.click(within(row).getByRole('combobox', { name: /^Field/ }));
    await user.type(screen.getByPlaceholderText('Search fields …'), 'SPF');
    await user.keyboard('{Enter}');
    expect(leafNow()).toEqual({ field: 'auth.spf', op: 'equals' });
    // Operators come from the field's catalogue ops.
    await user.click(within(row).getByRole('combobox', { name: 'Operator' }));
    expect((await screen.findAllByRole('option')).map((o) => o.textContent)).toEqual([
      'is',
      'is one of',
    ]);
  });

  it('enum: a select of the field vocabulary, humanized', async () => {
    const { user, row, container } = setup({ field: 'auth.spf', op: 'equals' });
    await user.click(within(row).getByRole('combobox', { name: 'Value' }));
    const options = (await screen.findAllByRole('option')).map((o) => o.textContent);
    expect(options).toEqual([
      'Pass',
      'Fail',
      'Softfail',
      'Neutral',
      'None',
      'Temperror',
      'Permerror',
    ]);
    await user.click(screen.getByRole('option', { name: 'Fail' }));
    expect(leafNow()).toEqual({ field: 'auth.spf', op: 'equals', value: 'fail' });
    await expectNoAxeViolations(container);
  });

  it('enum list: checkboxes of the vocabulary', async () => {
    const { user, row, container } = setup({ field: 'auth.dmarc', op: 'in', value: [] });
    await user.click(within(row).getByRole('checkbox', { name: 'Fail' }));
    await user.click(within(row).getByRole('checkbox', { name: 'None' }));
    await user.click(within(row).getByRole('checkbox', { name: 'Fail' }));
    await user.click(within(row).getByRole('checkbox', { name: 'Permerror' }));
    expect(leafNow().value).toEqual(['none', 'permerror']);
    await expectNoAxeViolations(container);
  });

  it('bytes: a whole number and a unit (B/KiB/MiB/GiB), stored as integer bytes', async () => {
    const { user, row } = setup({ field: 'message.size_bytes', op: 'gt' });
    const input = within(row).getByRole('spinbutton', { name: 'Value' });
    expect(input).toHaveAttribute('min', '0');
    await user.type(input, '10');
    expect(leafNow().value).toBe(10);
    await user.click(within(row).getByRole('combobox', { name: 'Unit' }));
    await user.click(await screen.findByRole('option', { name: 'MiB' }));
    expect(leafNow().value).toBe(10 * 1024 * 1024);
    await user.type(input, '.5');
    expect(within(row).getByText('Enter a whole number.')).toBeInTheDocument();
    expect('value' in leafNow()).toBe(false);
  });

  it('bytes: an existing value shows in its largest exact unit', () => {
    const { row } = setup({ field: 'attachments.total_bytes', op: 'lte', value: 2 * 1024 * 1024 });
    expect(within(row).getByRole('spinbutton', { name: 'Value' })).toHaveValue(2);
    expect(within(row).getByRole('combobox', { name: 'Unit' })).toHaveTextContent('MiB');
  });

  it('count and score: whole numbers with the catalogue bounds as attributes', async () => {
    const { user, row } = setup({ field: 'risk.score', op: 'gte' });
    const input = within(row).getByRole('spinbutton', { name: 'Value' });
    expect(input).toHaveAttribute('max', '1000');
    expect(within(row).queryByRole('combobox', { name: 'Unit' })).not.toBeInTheDocument();
    await user.type(input, '700');
    expect(leafNow().value).toBe(700);
  });

  it('range: [low, high] written once both are whole numbers', async () => {
    const { user, row } = setup({ field: 'attachments.total_bytes', op: 'between' });
    await user.type(within(row).getByRole('spinbutton', { name: 'From' }), '1');
    expect('value' in leafNow()).toBe(false);
    await user.type(within(row).getByRole('spinbutton', { name: 'To' }), '2');
    expect(leafNow().value).toEqual([1, 2]);
    await user.click(within(row).getByRole('combobox', { name: 'Unit' }));
    await user.click(await screen.findByRole('option', { name: 'KiB' }));
    expect(leafNow().value).toEqual([1024, 2048]);
  });

  it('list: chips (trimmed, de-duplicated) with the operator item limit', async () => {
    const catalog = toBuilderCatalog({
      ...RAW_TEST_CATALOG,
      operatorDefinitions: RAW_TEST_CATALOG.operatorDefinitions.map((o) =>
        o.op === 'in' ? { ...o, maxItems: 2 } : o,
      ),
    });
    const { user, row, container } = setup(
      { field: 'recipient.domain', op: 'in', value: [] },
      { catalog },
    );
    const input = within(row).getByRole('textbox', { name: 'Add value' });
    await user.type(input, '  a.example  {Enter}');
    await user.type(input, 'a.example{Enter}');
    await user.type(input, 'b.example');
    await user.click(within(row).getByRole('button', { name: 'Add' }));
    expect(leafNow().value).toEqual(['a.example', 'b.example']);
    expect(input).toBeDisabled();
    expect(within(row).getByText('At most 2 values.')).toBeInTheDocument();
    await user.click(within(row).getByRole('button', { name: 'Remove a.example' }));
    expect(leafNow().value).toEqual(['b.example']);
    await expectNoAxeViolations(container);
  });

  it('CIDR list: a pasted comma list becomes several networks', async () => {
    const { user, row } = setup({ field: 'client.ip', op: 'in_cidr', value: [] });
    await user.type(
      within(row).getByRole('textbox', { name: 'Add network' }),
      '198.51.100.0/24, 2001:db8:25::/48{Enter}',
    );
    expect(leafNow().value).toEqual(['198.51.100.0/24', '2001:db8:25::/48']);
    expect(within(row).getByText('Canonical CIDRs such as 198.51.100.0/24.')).toBeInTheDocument();
  });

  it('regex list: pattern + case-insensitive flag; never compiled in the browser', async () => {
    const { user, row, container } = setup({
      field: 'attachment.filename',
      op: 'regex',
      value: [],
    });
    const pattern = within(row).getByRole('textbox', { name: 'Add pattern' });
    expect(pattern).toHaveAttribute('maxlength', '256');
    await user.type(pattern, '^invoice-(');
    await user.click(within(row).getByRole('checkbox', { name: 'Case-insensitive' }));
    await user.click(within(row).getByRole('button', { name: 'Add' }));
    await user.type(pattern, 'x+{Enter}');
    // An invalid RE2 pattern is accepted as text: the server validates it.
    expect(leafNow().value).toEqual([{ pattern: '^invoice-(', flags: 'i' }, 'x+']);
    await user.click(within(row).getByRole('button', { name: 'Case-insensitive: /x+/' }));
    expect(leafNow().value).toEqual([
      { pattern: '^invoice-(', flags: 'i' },
      { pattern: 'x+', flags: 'i' },
    ]);
    await user.click(within(row).getByRole('button', { name: 'Edit /^invoice-(/i' }));
    expect(pattern).toHaveValue('^invoice-(');
    expect(within(row).getByRole('checkbox', { name: 'Case-insensitive' })).toBeChecked();
    expect(leafNow().value).toEqual([{ pattern: 'x+', flags: 'i' }]);
    await expectNoAxeViolations(container);
  });

  it('glob list', async () => {
    const { user, row } = setup({ field: 'url.host', op: 'glob', value: [] });
    const input = within(row).getByRole('textbox', { name: 'Add pattern' });
    expect(input).toHaveAttribute('maxlength', '128');
    await user.type(input, '*.example{Enter}');
    expect(leafNow().value).toEqual(['*.example']);
  });

  it('open codes: free entry with the catalogue suggestions; closed codes: checkboxes', async () => {
    const { user, row, unmount } = setup({
      field: 'attachment.reason_codes',
      op: 'contains_any',
      value: [],
    });
    // An input with suggestions (a datalist) is a combobox.
    const input = within(row).getByRole('combobox', { name: 'Add code' });
    const list = document.getElementById(input.getAttribute('list') ?? '');
    expect(
      [...(list?.querySelectorAll('option') ?? [])].map((o) => o.getAttribute('value')),
    ).toEqual(['attachment.clamav_match', 'attachment.malware', 'attachment.encrypted']);
    await user.type(input, 'attachment.malware{Enter}vendor.custom_code{Enter}');
    expect(leafNow().value).toEqual(['attachment.malware', 'vendor.custom_code']);
    unmount();
    const closed = setup({ field: 'dlp.categories', op: 'contains_all', value: [] });
    await closed.user.click(within(closed.row).getByRole('checkbox', { name: 'Payment card' }));
    expect(leafNow().value).toEqual(['payment_card']);
  });

  it('time window: zone from the catalogue, weekday toggles, HH:MM (24:00 allowed)', async () => {
    const { user, row, container } = setup({ field: 'time.window', op: 'within' });
    await user.click(within(row).getByRole('combobox', { name: 'Time zone' }));
    await user.type(screen.getByPlaceholderText('Search time zones …'), 'Kolkata');
    await user.keyboard('{Enter}');
    await user.click(within(row).getByRole('button', { name: 'Tue' }));
    await user.click(within(row).getByRole('button', { name: 'Mon' }));
    await user.type(within(row).getByRole('textbox', { name: 'From (HH:MM)' }), '09:00');
    await user.type(
      within(row).getByRole('textbox', { name: 'To (HH:MM, 24:00 = midnight)' }),
      '24:00',
    );
    expect(leafNow().value).toEqual({
      timeZone: 'Asia/Kolkata',
      days: ['mon', 'tue'],
      from: '09:00',
      to: '24:00',
    });
    expect(Object.keys(leafNow().value as object)).toEqual(['timeZone', 'days', 'from', 'to']);
    expect(within(row).getByRole('button', { name: 'Mon' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await expectNoAxeViolations(container);
  });

  it('date range: zone and two dates', async () => {
    const { user, row } = setup({ field: 'time.date_range', op: 'within' });
    await user.click(within(row).getByRole('combobox', { name: 'Time zone' }));
    await user.click(await screen.findByRole('option', { name: 'Europe/London' }));
    fireEvent.change(within(row).getByLabelText('From date'), { target: { value: '2026-12-24' } });
    fireEvent.change(within(row).getByLabelText('To date'), { target: { value: '2026-12-26' } });
    expect(leafNow().value).toEqual({
      timeZone: 'Europe/London',
      from: '2026-12-24',
      to: '2026-12-26',
    });
    expect(within(row).queryByRole('group', { name: 'Days' })).not.toBeInTheDocument();
  });

  it('directory ids: department options from the provider (names shown), users not offered for a department field', async () => {
    const { user, row, container } = setup(
      { field: 'sender.department', op: 'in', value: [DEPT_LEGAL] },
      { directory: TEST_DIRECTORY },
    );
    expect(within(row).getByText('Legal')).toBeInTheDocument();
    await user.click(within(row).getByRole('button', { name: 'Add department' }));
    expect(screen.queryByRole('option', { name: 'alice@example.com' })).not.toBeInTheDocument();
    await user.click(await screen.findByRole('option', { name: 'Finance' }));
    expect(leafNow().value).toEqual([DEPT_LEGAL, DEPT_FINANCE]);
    await user.click(within(row).getByRole('button', { name: 'Remove Legal' }));
    expect(leafNow().value).toEqual([DEPT_FINANCE]);
    await expectNoAxeViolations(container);
  });

  it('directory ids: plain UUID entry when the provider has no options', async () => {
    const { user, row } = setup({ field: 'recipient.user', op: 'in', value: [] });
    expect(
      within(row).getByText(/Enter the user public id; names are not available here/),
    ).toBeInTheDocument();
    await user.type(
      within(row).getByRole('textbox', { name: 'Add user id' }),
      `${USER_ALICE}{Enter}`,
    );
    expect(leafNow().value).toEqual([USER_ALICE]);
  });

  it('boolean: yes or no', async () => {
    const { user, row } = setup({ field: 'sender.trusted', op: 'is' });
    await user.click(within(row).getByRole('combobox', { name: 'Value' }));
    await user.click(await screen.findByRole('option', { name: 'No' }));
    expect(leafNow().value).toBe(false);
  });

  it('exists: no value input', () => {
    const { row } = setup({ field: 'risk.hard_blocks', op: 'exists' });
    expect(within(row).getByText('No value needed.')).toBeInTheDocument();
  });

  it('quantifier of a list field in a when: default (not written), any or every', async () => {
    const { user, row } = setup({ field: 'recipient.domain', op: 'equals', value: 'corp.example' });
    const select = within(row).getByRole('combobox', { name: 'Applies to' });
    expect(select).toHaveTextContent('Default (Any recipient)');
    await user.click(select);
    await user.click(await screen.findByRole('option', { name: 'Every recipient' }));
    expect(leafNow().quantifier).toBe('all');
    await user.click(select);
    await user.click(await screen.findByRole('option', { name: 'Default (Any recipient)' }));
    expect('quantifier' in leafNow()).toBe(false);
  });

  it('keeps values of operators it cannot edit (unknown operator) and says so', () => {
    const { row } = setup({ field: 'auth.spf', op: 'future_op', value: { x: 1 } });
    expect(within(row).getByText('{"x":1}')).toBeInTheDocument();
    expect(within(row).getByText(/does not support the operator future_op/)).toBeInTheDocument();
    expect(leafNow()).toEqual({ field: 'auth.spf', op: 'future_op', value: { x: 1 } });
  });
});
