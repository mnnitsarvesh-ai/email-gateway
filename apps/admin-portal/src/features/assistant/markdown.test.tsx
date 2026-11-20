import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { NAV_ITEMS } from '@/lib/navigation';
import { expectNoAxeViolations } from '@/test';
import { AssistantMarkdown, parseBlocks } from './markdown';
import { DETAIL_ROUTE_PATTERNS, safePortalHref } from './portal-routes';

const POLICY = '01930000-0000-7000-8000-00000000f001';

describe('safePortalHref (D9 allow-list)', () => {
  it('allows navigation hrefs and detail pages with a plain query', () => {
    for (const href of [
      '/policies',
      `/policies/${POLICY}`,
      `/policies/${POLICY}/versions/3`,
      '/quarantine/approvals',
      `/ato/accounts/${POLICY}`,
      '/roles/security_analyst',
      '/settings?tab=journaling',
      '/messages?verdict=malicious,spam&range=7d',
      '/archive/retention',
    ])
      expect(safePortalHref(href), href).toBe(href);
  });

  it('refuses other origins, protocols, the BFF and API, traversal, encodings and callbacks', () => {
    for (const href of [
      'https://evil.example/x',
      '//evil.example/policies',
      'javascript:alert(1)',
      'data:text/html,<b>x</b>',
      '/bff/api/v1/policies',
      '/api/v1/policies',
      '/policies/../bff/api/v1/x',
      '/policies/./x',
      `/policies/${POLICY}%2F..`,
      '/policies/a b',
      '/policies#frag',
      '/integrations/providers/consent-callback',
      '/policies/new',
      '/forbidden',
      '/nowhere',
      '/settings?tab=<script>',
      '/settings?',
      '/settings?a=1?b=2',
      '\\\\evil',
      '',
    ])
      expect(safePortalHref(href), href).toBeNull();
  });

  it('has a page under app/(console) for every navigation href and detail pattern', () => {
    const root = join(__dirname, '../../app/(console)');
    for (const pattern of [...NAV_ITEMS.map((item) => item.href), ...DETAIL_ROUTE_PATTERNS]) {
      const dir = pattern
        .split('/')
        .slice(1)
        .map((segment) => (segment.startsWith(':') ? `[${segment.slice(1)}]` : segment))
        .join('/');
      expect(existsSync(join(root, dir, 'page.tsx')), pattern).toBe(true);
    }
  });
});

describe('AssistantMarkdown (restricted subset, no HTML)', () => {
  it('renders script and HTML as literal text, never as elements', () => {
    const { container } = render(
      <AssistantMarkdown
        source={'Hello <script>alert(1)</script> <b>bold</b> <img src=x onerror=alert(1)>'}
      />,
    );
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain('<script>alert(1)</script>');
    expect(container.textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('keeps external links, images and unsafe targets as text; links internal routes', async () => {
    const onNavigate = vi.fn();
    const { container } = render(
      <AssistantMarkdown
        onNavigate={onNavigate}
        source={[
          'See [the policy](/policies/' + POLICY + ') and [docs](https://evil.example/steal?d=1).',
          '![chart](https://evil.example/pixel.png?secret=1)',
          '[click](javascript:alert(1)) [api](/bff/api/v1/policies) <https://evil.example>',
        ].join('\n')}
      />,
    );
    const links = screen.getAllByRole('link');
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute('href', `/policies/${POLICY}`);
    expect(links[0]).toHaveTextContent('the policy');
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain('[docs](https://evil.example/steal?d=1)');
    expect(container.textContent).toContain('![chart](https://evil.example/pixel.png?secret=1)');
    expect(container.textContent).toContain('[click](javascript:alert(1))');
    expect(container.textContent).toContain('[api](/bff/api/v1/policies)');
    links[0]!.click();
    expect(onNavigate).toHaveBeenCalled();
    await expectNoAxeViolations(container);
  });

  it('renders emphasis, inline code, lists, code blocks and tables', async () => {
    const { container } = render(
      <AssistantMarkdown
        source={[
          '# Summary',
          'There are **2 active** policies and *one* draft; tool `policy_management_list` ran.',
          'snake_case_name stays plain and 2 * 3 * 4 too.',
          '',
          '- first',
          '- second with **bold**',
          '',
          '1. one',
          '2. two',
          '',
          '```json',
          '{"a": "<b>x</b>"}',
          '```',
          '',
          '| Name | Status |',
          '| --- | :---: |',
          '| Block executables | active |',
          '| Pipe \\| inside | draft |',
        ].join('\n')}
      />,
    );
    expect(screen.getByText('2 active').tagName).toBe('STRONG');
    expect(container.querySelector('em')?.textContent).toBe('one');
    expect(screen.getByText('policy_management_list').tagName).toBe('CODE');
    expect(container.textContent).toContain('snake_case_name stays plain and 2 * 3 * 4 too.');
    expect(container.querySelectorAll('em')).toHaveLength(1);
    const lists = screen.getAllByRole('list');
    expect(lists).toHaveLength(2);
    expect(within(lists[1]!).getAllByRole('listitem')).toHaveLength(2);
    expect(container.querySelector('pre code')?.textContent).toBe('{"a": "<b>x</b>"}');
    const table = screen.getByRole('table');
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((th) => th.textContent),
    ).toEqual(['Name', 'Status']);
    expect(within(table).getByText('Pipe | inside')).toBeInTheDocument();
    expect(screen.queryByRole('heading')).toBeNull();
    await expectNoAxeViolations(container);
  });

  it('strips bidi and control characters and caps the source', () => {
    const blocks = parseBlocks('a‮b\u0007c');
    expect(blocks).toEqual([{ kind: 'paragraph', lines: ['a�b�c'] }]);
    const huge = parseBlocks('x'.repeat(100_000));
    expect(huge[0]?.kind).toBe('paragraph');
    expect((huge[0] as { lines: string[] }).lines[0]!.length).toBeLessThanOrEqual(32_000);
  });
});
