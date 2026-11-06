import { describe, expect, it } from 'vitest';
import {
  blockedPage,
  errorPage,
  escapeHtml,
  expiredPage,
  invalidPage,
  notFoundPage,
  rateLimitedPage,
  STYLESHEET,
  unavailablePage,
  warnPage,
} from './pages';

const all = [
  invalidPage(),
  notFoundPage(),
  expiredPage(),
  rateLimitedPage(),
  unavailablePage(),
  errorPage(),
  blockedPage('0190f000-0000-7000-8000-000000000000'),
  warnPage({ domain: 'evil.test', unicodeDomain: null, continuePath: '/c/t/continue?n=x' }),
];

describe('pages', () => {
  it('contain no JavaScript, no inline styles, no external resources', () => {
    for (const page of all) {
      expect(page).not.toMatch(/<script/i);
      expect(page).not.toMatch(/\son[a-z]+=/i);
      expect(page).not.toMatch(/javascript:/i);
      expect(page).not.toMatch(/style=/i);
      expect(page).not.toMatch(/https?:\/\//i);
      expect(page).toContain('<link rel="stylesheet" href="/static/click.css">');
    }
    expect(STYLESHEET).not.toMatch(/url\(|@import/);
  });

  it('templates take no tenant data (only domain, continue path and reference id)', () => {
    const page = warnPage({
      domain: 'xn--exmplebank-0qi.test',
      unicodeDomain: 'exаmplebank.test',
      continuePath: null,
    });
    expect(page).toContain('xn--exmplebank-0qi.test');
    expect(page).toContain('exаmplebank.test');
    expect(page).not.toContain('/continue');
    expect(blockedPage('ref-1')).toContain('ref-1');
  });

  it('escapes every dynamic value', () => {
    const page = warnPage({
      domain: '<b>"x"</b>',
      unicodeDomain: "'&'",
      continuePath: '/c/"><script>',
    });
    expect(page).not.toContain('<b>');
    expect(page).not.toContain('"><script>');
    expect(escapeHtml(`<>&"'\``)).toBe('&lt;&gt;&amp;&quot;&#39;&#96;');
  });
});
