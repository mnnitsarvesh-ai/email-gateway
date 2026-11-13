import { screen } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { Combobox } from './combobox';

function Harness() {
  const [value, setValue] = useState<string | null>(null);
  return (
    <>
      <Combobox
        label="Domain"
        value={value}
        onChange={setValue}
        options={[
          { value: 'd1', label: 'alpha.example.test' },
          { value: 'd2', label: 'bravo.example.test' },
        ]}
      />
      <span>value: {value ?? 'none'}</span>
    </>
  );
}

describe('Combobox', () => {
  it('filters locally and selects with the keyboard', async () => {
    const { container, user } = renderWithProviders(<Harness />);
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('combobox', { name: 'Domain' }));
    await user.type(screen.getByPlaceholderText('Search …'), 'bravo');
    expect(screen.queryByText('alpha.example.test')).not.toBeInTheDocument();
    await user.keyboard('{Enter}');
    expect(screen.getByText('value: d2')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Domain' })).toHaveTextContent(
      'bravo.example.test',
    );
  });
});
