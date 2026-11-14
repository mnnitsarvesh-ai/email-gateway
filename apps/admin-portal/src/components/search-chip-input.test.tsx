import { screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { SearchChipInput, type SearchChip, type SearchChipField } from './search-chip-input';

const FIELDS: SearchChipField[] = [
  {
    id: 'sender',
    label: 'Sender',
    hint: 'The exact sender.',
    validate: (raw) =>
      /^[^\s@]+@[^\s@]+$/.test(raw)
        ? { ok: true, value: raw.toLowerCase() }
        : { ok: false, message: 'Enter a complete address.' },
  },
  {
    id: 'prefix',
    label: 'Starts with',
    validate: (raw) =>
      raw.length >= 3 ? { ok: true, value: raw } : { ok: false, message: 'At least 3 characters.' },
  },
];

function Harness({
  onCommit = () => undefined,
  initial = [],
  delay = 100,
}: {
  onCommit?: (fieldId: string, value: string) => void;
  initial?: SearchChip[];
  delay?: number;
}) {
  const [chips, setChips] = useState<SearchChip[]>(initial);
  return (
    <SearchChipInput
      label="Search messages"
      fields={FIELDS}
      chips={chips}
      debounceMs={delay}
      onCommit={(fieldId, value) => {
        onCommit(fieldId, value);
        setChips((current) => [
          ...current.filter((c) => c.fieldId !== fieldId),
          { fieldId, value },
        ]);
      }}
      onRemove={(fieldId) => setChips((current) => current.filter((c) => c.fieldId !== fieldId))}
      assist={(fieldId, text) =>
        fieldId === 'prefix' && text === 'help' ? <span>Assist</span> : null
      }
    />
  );
}

describe('SearchChipInput', () => {
  it('commits once after the idle delay, only valid values, never per keystroke', async () => {
    const onCommit = vi.fn();
    const { user, container } = renderWithProviders(<Harness onCommit={onCommit} />);
    expect(screen.getByRole('search', { name: 'Search messages' })).toBeInTheDocument();
    const input = screen.getByRole('searchbox', { name: 'Search by Sender' });
    await user.type(input, 'Jane@Example.com');
    expect(onCommit).not.toHaveBeenCalled();
    await waitFor(() => expect(onCommit).toHaveBeenCalledTimes(1));
    expect(onCommit).toHaveBeenCalledWith('sender', 'jane@example.com');
    expect(
      within(screen.getByRole('list', { name: 'Active searches' })).getByText('Sender:'),
    ).toBeInTheDocument();
    // Enter with the same (normalized) value: no second commit.
    await user.type(input, '{Enter}');
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(onCommit).toHaveBeenCalledTimes(1);
    await expectNoAxeViolations(container);
  });

  it('shows the validator message (polite) and commits nothing for an invalid value', async () => {
    const onCommit = vi.fn();
    const { user } = renderWithProviders(<Harness onCommit={onCommit} />);
    const input = screen.getByRole('searchbox', { name: 'Search by Sender' });
    await user.type(input, 'jane{Enter}');
    const message = screen.getByText('Enter a complete address.');
    expect(message).toHaveAttribute('aria-live', 'polite');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input.getAttribute('aria-describedby')).toContain(message.id);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(onCommit).not.toHaveBeenCalled();
  });

  it('switching the field loads that field’s committed value; chips can be edited and removed', async () => {
    const { user } = renderWithProviders(
      <Harness
        initial={[
          { fieldId: 'prefix', value: 'Invoice' },
          { fieldId: 'sender', value: 'a@b.example' },
        ]}
      />,
    );
    expect(screen.getByRole('searchbox', { name: 'Search by Sender' })).toHaveValue('a@b.example');
    await user.click(screen.getByRole('button', { name: 'Edit search Starts with: Invoice' }));
    expect(screen.getByRole('searchbox', { name: 'Search by Starts with' })).toHaveValue('Invoice');
    await user.click(screen.getByRole('button', { name: 'Remove search Starts with' }));
    expect(screen.getByRole('searchbox', { name: 'Search by Starts with' })).toHaveValue('');
    expect(
      screen.queryByRole('button', { name: /Edit search Starts with/ }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: 'Search field' }));
    await user.click(await screen.findByRole('option', { name: 'Sender' }));
    expect(screen.getByRole('searchbox', { name: 'Search by Sender' })).toHaveValue('a@b.example');
  });

  it('commits on Enter at once and renders the assist slot for the current text', async () => {
    const onCommit = vi.fn();
    const { user } = renderWithProviders(<Harness onCommit={onCommit} delay={10_000} />);
    await user.click(screen.getByRole('combobox', { name: 'Search field' }));
    await user.click(await screen.findByRole('option', { name: 'Starts with' }));
    const input = screen.getByRole('searchbox', { name: 'Search by Starts with' });
    await user.type(input, 'help');
    expect(screen.getByText('Assist')).toBeInTheDocument();
    await user.type(input, '{Enter}');
    expect(onCommit).toHaveBeenCalledWith('prefix', 'help');
  });

  it('renders chip values as text only', () => {
    const { container } = renderWithProviders(
      <Harness
        initial={[{ fieldId: 'sender', value: '<img src=x onerror=alert(1)>@x.example' }]}
      />,
    );
    expect(container.querySelector('img')).toBeNull();
    expect(
      screen.getByText('<img src=x onerror=alert(1)>@x.example', { selector: '[data-untrusted]' }),
    ).toBeInTheDocument();
  });
});
