import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import {
  CopyableId,
  DateTime,
  DeliveryStatusBadge,
  DirectionBadge,
  QuarantineStateBadge,
  RiskScore,
  SeverityBadge,
  UntrustedText,
  VerdictBadge,
  middleTruncate,
  riskBand,
  sanitizeDisplay,
} from '.';

describe('domain components', () => {
  it('badges print the label and carry the semantic tone', async () => {
    const { container } = renderWithProviders(
      <div>
        <VerdictBadge verdict="dlp_violation" />
        <VerdictBadge verdict="malware" />
        <VerdictBadge verdict={null} />
        <SeverityBadge severity="critical" />
        <DeliveryStatusBadge status="in_progress" />
        <QuarantineStateBadge state="pending_approval" />
        <DirectionBadge direction="inbound" />
        <VerdictBadge verdict="brand_new_value" />
      </div>,
    );
    expect(screen.getByText('DLP violation')).toHaveAttribute('data-tone', 'purple');
    expect(screen.getByText('Malware')).toHaveAttribute('data-tone', 'danger');
    expect(screen.getByText('No verdict')).toHaveAttribute('data-tone', 'neutral');
    expect(screen.getByText('Critical')).toHaveAttribute('data-tone', 'danger');
    expect(screen.getByText('In progress')).toHaveAttribute('data-tone', 'info');
    expect(screen.getByText('Pending approval')).toHaveAttribute('data-tone', 'purple');
    expect(screen.getByText('Inbound')).toHaveAttribute('data-tone', 'info');
    expect(screen.getByText('Brand new value')).toHaveAttribute('data-tone', 'neutral');
    await expectNoAxeViolations(container);
  });

  it('RiskScore is a labelled meter with a band; null is "Not scored"', () => {
    const { rerender } = renderWithProviders(<RiskScore score={850} />);
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '850');
    expect(screen.getByRole('meter')).toHaveAccessibleName('Risk score 850 of 1000, Critical');
    rerender(<RiskScore score={null} />);
    expect(screen.getByText('Not scored')).toBeInTheDocument();
    expect(riskBand(299).label).toBe('Low');
    expect(riskBand(600).label).toBe('High');
  });

  it('DateTime renders <time> with UTC in the title', () => {
    renderWithProviders(<DateTime value="2026-11-13T09:14:03.120Z" mode="absolute" />);
    const time = screen.getByText((_, el) => el?.tagName === 'TIME');
    expect(time).toHaveAttribute('datetime', '2026-11-13T09:14:03.120Z');
    expect(time).toHaveAttribute('title', '2026-11-13 09:14:03 UTC');
  });

  it('CopyableId middle-truncates and copies the full value', async () => {
    const { user } = renderWithProviders(
      <CopyableId value="01930000-0000-7000-8000-000000000001" label="message ID" />,
    );
    expect(middleTruncate('abcdefghijklmnopqrstuvwxyz', 10)).toBe('abcd…wxyz');
    expect(screen.getByTitle('01930000-0000-7000-8000-000000000001')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Copy message ID' }));
    expect(await screen.findByText('Copied to clipboard')).toBeInTheDocument();
  });

  it('UntrustedText never renders a link or markup and neutralizes bidi controls', () => {
    const { container } = renderWithProviders(
      <UntrustedText
        value={'<a href="https://evil.example">click</a>‮gnp.exe'}
        copy
        copyLabel="Copy URL"
        maxLength={20}
      />,
    );
    expect(container.querySelector('a')).toBeNull();
    const span = container.querySelector('[data-untrusted]');
    expect(span?.textContent).toHaveLength(20);
    expect(span?.getAttribute('title')).toContain('�');
    expect(screen.getByRole('button', { name: 'Copy URL' })).toBeInTheDocument();
    expect(sanitizeDisplay('a\u0000b⁦c')).toBe('a�b�c');
  });
});
