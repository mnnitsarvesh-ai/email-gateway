import axe from 'axe-core';
import { expect } from 'vitest';

/**
 * Runs axe-core on a container; violations of impact serious or critical fail with a readable
 * list. Colour contrast is checked separately on the tokens (jsdom does not compute styles).
 */
export async function axeViolations(
  container: Element,
  impacts: readonly string[] = ['serious', 'critical'],
  options: { iframes?: boolean } = {},
) {
  const result = await axe.run(container, {
    resultTypes: ['violations'],
    // jsdom cannot message into frames; a sandboxed `srcdoc` report frame (step AI-R) is checked
    // by the Playwright suite instead.
    iframes: options.iframes ?? true,
    rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
  });
  return result.violations.filter((v) => impacts.includes(v.impact ?? ''));
}

export async function expectNoAxeViolations(
  container: Element,
  options: { iframes?: boolean } = {},
): Promise<void> {
  const violations = await axeViolations(container, ['serious', 'critical'], options);
  const report = violations
    .map(
      (v) =>
        `${v.impact}: ${v.id} — ${v.help}\n${v.nodes.map((n) => `    ${n.html.slice(0, 160)}`).join('\n')}`,
    )
    .join('\n');
  expect(violations, report).toEqual([]);
}
