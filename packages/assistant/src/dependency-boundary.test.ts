import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/** Design D1/§9: only apps/api depends on @email-gateway/assistant (I7: mail processing never does). */
const REPO = join(__dirname, '../../..');
const PACKAGE = '@email-gateway/assistant';

function manifests(): Array<{ path: string; name: string; deps: string[] }> {
  const out: Array<{ path: string; name: string; deps: string[] }> = [];
  for (const root of ['apps', 'packages']) {
    for (const dir of readdirSync(join(REPO, root))) {
      const path = join(REPO, root, dir, 'package.json');
      if (!existsSync(path)) continue;
      const json = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
      const deps = [
        'dependencies',
        'devDependencies',
        'peerDependencies',
        'optionalDependencies',
      ].flatMap((key) => Object.keys((json[key] as Record<string, string> | undefined) ?? {}));
      out.push({ path: `${root}/${dir}`, name: String(json.name), deps });
    }
  }
  return out;
}

describe('dependency boundary', () => {
  it('only apps/api may depend on @email-gateway/assistant', () => {
    const all = manifests();
    expect(all.length).toBeGreaterThan(10);
    const dependents = all.filter((m) => m.deps.includes(PACKAGE)).map((m) => m.path);
    expect(dependents.filter((path) => path !== 'apps/api')).toEqual([]);
  });

  it('the assistant package depends on no app and no mail-processing package', () => {
    const self = manifests().find((m) => m.name === PACKAGE)!;
    expect(self.deps.filter((dep) => dep.startsWith('@email-gateway/'))).toEqual([]);
  });
});
