import axe from 'axe-core';
import { expect } from 'vitest';

/**
 * Runs axe-core on a container; violations of impact serious or critical fail with a readable
 * list. Colour contrast is checked separately on the tokens (jsdom does not compute styles).
 */
export async function axeViolations(
  container: Element,
  impacts: readonly string[] = ['serious', 'critical'],
) {
  const result = await axe.run(container, {
    resultTypes: ['violations'],
    rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
  });
  return result.violations.filter((v) => impacts.includes(v.impact ?? ''));
}

export async function expectNoAxeViolations(container: Element): Promise<void> {
  const violations = await axeViolations(container);
  const report = violations
    .map(
      (v) =>
        `${v.impact}: ${v.id} — ${v.help}\n${v.nodes.map((n) => `    ${n.html.slice(0, 160)}`).join('\n')}`,
    )
    .join('\n');
  expect(violations, report).toEqual([]);
}
