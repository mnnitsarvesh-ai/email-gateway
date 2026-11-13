import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { KpiTile } from './kpi-tile';
import { PageHeader } from './page-header';

describe('PageHeader and Breadcrumbs', () => {
  it('renders one h1, breadcrumbs with the current page and sets the document title', async () => {
    const { container } = renderWithProviders(
      <PageHeader
        title="Domains"
        description="Your mail domains."
        breadcrumbs={[{ label: 'Directory', href: '/domains' }, { label: 'Domains' }]}
        actions={<button type="button">Add domain</button>}
      />,
    );
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('navigation', { name: 'Breadcrumb' })).toBeInTheDocument();
    expect(screen.getByText('Domains', { selector: '[aria-current="page"]' })).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe('Domains · Email Security Gateway'));
    await expectNoAxeViolations(container);
  });
});

describe('KpiTile', () => {
  it('shows the value, definition, generatedAt and link', async () => {
    const { container, user } = renderWithProviders(
      <KpiTile
        label="Total emails processed"
        value={12345}
        definition="All messages received"
        generatedAt="2026-11-13T09:00:00.000Z"
        href="/reports?range=7d"
      />,
    );
    expect(screen.getByText('12,345')).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'View details: Total emails processed' }),
    ).toHaveAttribute('href', '/reports?range=7d');
    await user.hover(screen.getByRole('button', { name: 'Definition of Total emails processed' }));
    expect((await screen.findAllByText('All messages received')).length).toBeGreaterThan(0);
    await expectNoAxeViolations(container);
  });

  it('never invents a number: null shows the empty text; loading and error states', () => {
    const { rerender } = renderWithProviders(
      <KpiTile
        label="Delivery success rate"
        value={null}
        emptyText="No completed deliveries in range"
      />,
    );
    expect(screen.getByText('No completed deliveries in range')).toBeInTheDocument();
    rerender(<KpiTile label="Delivery success rate" value={1} loading />);
    expect(screen.getByText('Loading Delivery success rate …')).toBeInTheDocument();
    rerender(<KpiTile label="Delivery success rate" value={1} error={new Error('x')} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });
});
