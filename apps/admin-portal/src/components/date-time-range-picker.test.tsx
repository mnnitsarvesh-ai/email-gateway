import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { toLocalInput, type DateTimeRangeValue } from '@/lib/date-time-range';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { DateTimeRangePicker } from './date-time-range-picker';

const NOW = Date.parse('2026-11-14T10:20:30.000Z');

function Harness({
  initial = { kind: '24h' },
  onChange,
}: {
  initial?: DateTimeRangeValue;
  onChange?: (value: DateTimeRangeValue) => void;
}) {
  const [value, setValue] = useState<DateTimeRangeValue>(initial);
  return (
    <DateTimeRangePicker
      value={value}
      now={() => NOW}
      onChange={(next) => {
        setValue(next);
        onChange?.(next);
      }}
    />
  );
}

describe('DateTimeRangePicker', () => {
  it('offers the four presets and a custom range, labelled with its current value', async () => {
    const onChange = vi.fn();
    const { user, container } = renderWithProviders(<Harness onChange={onChange} />);
    const trigger = screen.getByRole('combobox', { name: 'Time range Last 24 hours' });
    await expectNoAxeViolations(container);
    await user.click(trigger);
    expect(screen.getAllByRole('option').map((o) => o.textContent)).toEqual([
      'Last hour',
      'Last 24 hours',
      'Last 7 days',
      'Last 30 days',
      'Custom range …',
    ]);
    await user.click(screen.getByRole('option', { name: 'Last hour' }));
    expect(onChange).toHaveBeenCalledWith({ kind: '1h' });
    expect(screen.getByRole('combobox', { name: 'Time range Last hour' })).toBeInTheDocument();
  });

  it('applies a custom range typed in the browser time zone as UTC ISO', async () => {
    const onChange = vi.fn();
    const { user } = renderWithProviders(<Harness onChange={onChange} />);
    await user.click(screen.getByRole('button', { name: 'Choose a custom time range' }));
    const dialog = await screen.findByRole('dialog');
    expect(
      within(dialog).getByText(/Times in your time zone .*, sent as UTC. At most 31 days./),
    ).toBeInTheDocument();
    await expectNoAxeViolations(dialog);
    fireEvent.change(within(dialog).getByLabelText('From'), {
      target: { value: toLocalInput('2026-11-12T06:00:00.000Z') },
    });
    fireEvent.change(within(dialog).getByLabelText('To'), {
      target: { value: toLocalInput('2026-11-13T18:30:00.000Z') },
    });
    await user.click(within(dialog).getByRole('button', { name: 'Apply' }));
    expect(onChange).toHaveBeenCalledWith({
      kind: 'custom',
      from: '2026-11-12T06:00:00.000Z',
      to: '2026-11-13T18:30:00.000Z',
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByRole('combobox', { name: /^Time range Custom:/ })).toBeInTheDocument();
  });

  it('validates inline: nothing is applied while a bound is wrong or the range exceeds 31 days', async () => {
    const onChange = vi.fn();
    const { user } = renderWithProviders(<Harness onChange={onChange} />);
    await user.click(screen.getByRole('button', { name: 'Choose a custom time range' }));
    const dialog = await screen.findByRole('dialog');
    const from = within(dialog).getByLabelText('From');
    const to = within(dialog).getByLabelText('To');
    fireEvent.change(from, { target: { value: toLocalInput('2026-11-13T00:00:00.000Z') } });
    fireEvent.change(to, { target: { value: toLocalInput('2026-11-12T00:00:00.000Z') } });
    await user.click(within(dialog).getByRole('button', { name: 'Apply' }));
    expect(within(dialog).getByText('The end must be after the start.')).toBeInTheDocument();
    expect(to).toHaveAttribute('aria-invalid', 'true');
    expect(to.getAttribute('aria-describedby')).toContain(
      within(dialog).getByText('The end must be after the start.').id,
    );
    fireEvent.change(from, { target: { value: toLocalInput('2026-10-01T00:00:00.000Z') } });
    fireEvent.change(to, { target: { value: toLocalInput('2026-11-02T00:00:00.000Z') } });
    await user.click(within(dialog).getByRole('button', { name: 'Apply' }));
    expect(within(dialog).getByRole('alert')).toHaveTextContent(
      'Choose a range of at most 31 days.',
    );
    expect(onChange).not.toHaveBeenCalled();
    await expectNoAxeViolations(dialog);
  });

  it('pre-fills the inputs from the current custom range', async () => {
    const { user } = renderWithProviders(
      <Harness
        initial={{
          kind: 'custom',
          from: '2026-11-01T08:00:00.000Z',
          to: '2026-11-02T08:00:00.000Z',
        }}
      />,
    );
    await user.click(screen.getByRole('button', { name: 'Choose a custom time range' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText('From')).toHaveValue(
      toLocalInput('2026-11-01T08:00:00.000Z'),
    );
    expect(within(dialog).getByLabelText('To')).toHaveValue(
      toLocalInput('2026-11-02T08:00:00.000Z'),
    );
  });
});
