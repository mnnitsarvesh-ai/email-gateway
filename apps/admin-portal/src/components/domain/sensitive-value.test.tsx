import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { MASKED_VALUE_EXPLANATION, SensitiveValue } from './sensitive-value';

describe('SensitiveValue (step 7.2 §2 E5, E11)', () => {
  it('masked text: lock icon, "Hidden", sr-only "masked", a tooltip about reveal and audit', async () => {
    const { container, user } = renderWithProviders(
      <ul>
        <li>
          <SensitiveValue value={null} masked />
        </li>
      </ul>,
    );
    const node = container.querySelector('[data-sensitive="masked"]') as HTMLElement;
    expect(node).toHaveTextContent('Hidden(masked)');
    expect(within(node).getByText('(masked)')).toHaveClass('sr-only');
    expect(node.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
    await expectNoAxeViolations(container);
    await user.hover(node);
    expect(await screen.findByRole('tooltip')).toHaveTextContent(MASKED_VALUE_EXPLANATION);
  });

  it('masked address: the api’s masked form in monospace, never a copy button', () => {
    const { container } = renderWithProviders(
      <SensitiveValue value="f***@acme.example" masked kind="address" copy />,
    );
    const node = container.querySelector('[data-sensitive="masked"]') as HTMLElement;
    expect(node).toHaveTextContent('f***@acme.example');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('revealed: the clear value as text plus a "Revealed" badge (not colour alone)', async () => {
    const { container } = renderWithProviders(
      <SensitiveValue value="<script>alert(1)</script> Invoice" masked revealed />,
    );
    const node = container.querySelector('[data-sensitive="revealed"]') as HTMLElement;
    expect(within(node).getByText('Revealed')).toBeInTheDocument();
    expect(within(node).getByText('<script>alert(1)</script> Invoice')).toBeInTheDocument();
    expect(container.innerHTML).not.toContain('<script>alert');
    await expectNoAxeViolations(container);
  });

  it('revealed without a value shows the empty label; clear values render as UntrustedText', () => {
    const { container, rerender } = renderWithProviders(
      <SensitiveValue value={null} masked revealed emptyLabel="(no subject)" />,
    );
    expect(screen.getByText('(no subject)')).toBeInTheDocument();
    rerender(
      <SensitiveValue
        value="jane.doe@alpha.example.test"
        masked={false}
        kind="address"
        copy
        copyLabel="Copy recipient"
      />,
    );
    expect(container.querySelector('[data-sensitive]')).toBeNull();
    expect(screen.getByText('jane.doe@alpha.example.test')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy recipient' })).toBeInTheDocument();
  });

  it('neutralizes bidi overrides in masked address forms', () => {
    const { container } = renderWithProviders(
      <SensitiveValue value={'f***@‮elpmaxe.test'} masked kind="address" />,
    );
    expect(container.textContent).not.toContain('‮');
  });
});
