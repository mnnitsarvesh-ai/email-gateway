import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { BarChart, DonutChart, Sparkline, TimeSeriesChart, groupSlices, summarizeSeries } from '.';

const rows = [
  { start: 'Mon', spam: 10, phishing: 2 },
  { start: 'Tue', spam: 30, phishing: 5 },
  { start: 'Wed', spam: null, phishing: null },
  { start: 'Thu', spam: 40, phishing: 1 },
];
const series = [
  { key: 'spam', label: 'Spam' },
  { key: 'phishing', label: 'Phishing' },
];

describe('chart summaries', () => {
  it('computes total, peak and trend, skipping missing values', () => {
    expect(summarizeSeries(rows, 'start', series)).toBe(
      'Total 88 across 4 points. Peak 41 at Thu. Trend rising. Largest: Spam 80, Phishing 8.',
    );
    expect(summarizeSeries([], 'start', series)).toBe('No data in this range.');
  });

  it('groups donut slices beyond six into Other', () => {
    const slices = Array.from({ length: 8 }, (_, i) => ({ label: `s${i}`, value: 10 - i }));
    const grouped = groupSlices(slices);
    expect(grouped).toHaveLength(6);
    expect(grouped.at(-1)).toEqual({ label: 'Other', value: 5 + 4 + 3 });
  });
});

describe('ChartFigure wrappers (design P13)', () => {
  it('TimeSeriesChart: figure, role=img summary, legend, table fallback and keyboard read-out', async () => {
    const { container, user } = renderWithProviders(
      <TimeSeriesChart
        title="Threat trends"
        description="Threat verdicts per day"
        rows={rows}
        xKey="start"
        xLabel="Day"
        series={series}
        variant="stacked-area"
      />,
    );
    expect(screen.getByRole('figure', { name: 'Threat trends' })).toBeInTheDocument();
    expect(
      screen.getByRole('img', { name: /Threat trends\. Total 88 across 4 points/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Threat trends legend' })).toHaveTextContent(
      'SpamPhishing',
    );
    await user.click(screen.getByRole('button', { name: 'View data as table' }));
    const table = screen.getByRole('table', { name: 'Threat trends: data table' });
    expect(table).toHaveTextContent('Wed');
    expect(table).toHaveTextContent('No data');
    expect(screen.getByRole('button', { name: 'Hide data table' })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
    const region = screen.getByRole('application', { name: /use the arrow keys/ });
    region.focus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getByText('Mon: Spam 10, Phishing 2')).toBeInTheDocument();
    await user.keyboard('{End}');
    expect(screen.getByText('Thu: Spam 40, Phishing 1')).toBeInTheDocument();
    await user.keyboard('{ArrowLeft}');
    expect(screen.getByText('Wed: Spam No data, Phishing No data')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('BarChart (horizontal, stacked) and DonutChart expose summaries and tables', async () => {
    const { container, user } = renderWithProviders(
      <div>
        <BarChart
          title="Top attacked domains"
          rows={[{ name: 'alpha.example.test', spam: 4, malware: 1 }]}
          categoryKey="name"
          categoryLabel="Domain"
          series={[
            { key: 'spam', label: 'Spam' },
            { key: 'malware', label: 'Malware' },
          ]}
          layout="horizontal"
          stacked
        />
        <DonutChart
          title="Verdicts"
          slices={[
            { label: 'Clean', value: 90 },
            { label: 'Spam', value: 10 },
          ]}
        />
      </div>,
    );
    expect(screen.getByRole('img', { name: /Top attacked domains\. Total 5/ })).toBeInTheDocument();
    expect(
      screen.getByRole('img', { name: 'Verdicts. Total 100. Clean 90 (90 %), Spam 10 (10 %).' }),
    ).toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: 'View data as table' })[0]!);
    expect(
      screen.getByRole('table', { name: 'Top attacked domains: data table' }),
    ).toHaveTextContent('alpha.example.test');
    await expectNoAxeViolations(container);
  });

  it('Sparkline is decorative and draws gaps for missing points', () => {
    const { container } = renderWithProviders(<Sparkline values={[1, 2, null, 4, 5]} />);
    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('aria-hidden', 'true');
    expect(container.querySelectorAll('path')).toHaveLength(2);
    const { container: none } = renderWithProviders(<Sparkline values={[1]} />);
    expect(none.querySelector('svg')).toBeNull();
  });
});
