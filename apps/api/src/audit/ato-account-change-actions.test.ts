import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ATO_ACCOUNT_CHANGE_ACTIONS } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { isAtoAccountChangeAction } from './audit.service';

/** Every non-test TypeScript source of the api. */
function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return name.endsWith('.ts') && !name.endsWith('.test.ts') ? [path] : [];
  });
}

/**
 * Step 8.4 D2/D5 (WP3): `ATO_ACCOUNT_CHANGE_ACTIONS` names audit actions the api really writes.
 * A name that no api source contains as a string literal would never produce
 * `auth.account.changed.v1` (WP3 corrected `quarantine.entry_released`, which the api never
 * audits, to `quarantine.release_requested` and `quarantine.self_released`).
 */
describe('ATO account-change actions (step 8.4 D2)', () => {
  const code = sources(join(__dirname, '..'))
    .filter((path) => !path.includes(`${join('modules', 'audit-logs')}`))
    .map((path) => readFileSync(path, 'utf8'))
    .join('\n');

  it.each([...ATO_ACCOUNT_CHANGE_ACTIONS])('%s is an audit action written by the api', (action) => {
    expect(code).toContain(`'${action}'`);
    expect(isAtoAccountChangeAction(action)).toBe(true);
  });

  it('does not publish other actions', () => {
    for (const action of ['domain.created', 'quarantine.searched', 'quarantine.entry_released']) {
      expect(isAtoAccountChangeAction(action)).toBe(false);
    }
  });
});
