import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { CopyButton } from '@/components/copy-button';
import { DataGrid } from './parts';

describe('DataGrid', () => {
  it('contains absolutely positioned descendants in its horizontal scroller', () => {
    // A copy button's visually hidden live region is `position: absolute`. Without a positioned
    // scroller its containing block is the page, so it escapes the scroller's clipping and widens
    // the page at 390 px (found by the step 7.2 Playwright suite on the attachment analysis
    // section). jsdom has no layout: the class is the contract, the e2e suite measures it.
    render(
      <DataGrid
        caption="Results"
        columns={[
          { header: 'Value', cell: (row: { v: string }) => row.v, rowHeader: true },
          {
            header: 'Copy',
            cell: (row: { v: string }) => <CopyButton value={row.v} label="Copy value" />,
          },
        ]}
        rows={[{ v: 'a'.repeat(64) }]}
        rowKey={(row) => row.v}
      />,
    );
    const scroller = screen.getByRole('table').parentElement!;
    expect(scroller).toHaveClass('overflow-x-auto');
    expect(scroller).toHaveClass('relative');
  });

  it('makes its horizontal scroller reachable by keyboard and named', () => {
    // Wider than a phone, the grid scrolls; a scrollable region without focusable content must be
    // focusable (axe scrollable-region-focusable, WCAG 2.1.1; found at 390 px by the step 7.2
    // Playwright suite on the email headers section).
    render(
      <DataGrid
        caption="Stored headers"
        columns={[{ header: 'Name', cell: (row: { v: string }) => row.v, rowHeader: true }]}
        rows={[{ v: 'From' }]}
        rowKey={(row) => row.v}
      />,
    );
    const region = screen.getByRole('group', { name: 'Stored headers' });
    expect(region).toHaveAttribute('tabindex', '0');
    expect(region).toContainElement(screen.getByRole('table'));
  });
});
