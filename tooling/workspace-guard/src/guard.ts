import fs from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';

export type WorkspaceKind = 'service' | 'package' | 'migrations' | 'e2e' | 'tooling';

export interface Workspace {
  name: string;
  dir: string; // repo-relative, posix
  kind: WorkspaceKind;
  deps: string[];
}

export interface Violation {
  dependent: Workspace;
  dependency: Workspace;
}

const DEP_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'] as const;

export function classify(dir: string): WorkspaceKind | undefined {
  if (dir.startsWith('services/')) return 'service';
  if (dir.startsWith('packages/')) return 'package';
  if (dir === 'db') return 'migrations';
  if (dir === 'test/e2e') return 'e2e';
  if (dir.startsWith('tooling/')) return 'tooling';
  return undefined;
}

function expandGlob(root: string, glob: string): string[] {
  if (glob.endsWith('/*')) {
    const base = glob.slice(0, -2);
    const abs = path.join(root, base);
    if (!fs.existsSync(abs)) return [];
    return fs
      .readdirSync(abs, { withFileTypes: true })
      .filter((d) => d.isDirectory() && d.name !== 'node_modules')
      .map((d) => `${base}/${d.name}`);
  }
  if (glob.includes('*')) throw new Error(`Unsupported workspace glob: ${glob}`);
  return fs.existsSync(path.join(root, glob)) ? [glob] : [];
}

export function loadWorkspaces(root: string): Workspace[] {
  const yamlPath = path.join(root, 'pnpm-workspace.yaml');
  const parsed = parse(fs.readFileSync(yamlPath, 'utf8')) as { packages?: string[] } | null;
  const globs = parsed?.packages ?? [];
  const result: Workspace[] = [];
  for (const glob of globs) {
    for (const dir of expandGlob(root, glob)) {
      const pkgPath = path.join(root, dir, 'package.json');
      if (!fs.existsSync(pkgPath)) continue;
      const kind = classify(dir);
      if (!kind) continue;
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
      const deps = DEP_FIELDS.flatMap((f) => {
        const field = pkg[f];
        return field && typeof field === 'object' ? Object.keys(field) : [];
      });
      result.push({ name: typeof pkg['name'] === 'string' ? pkg['name'] : dir, dir, kind, deps });
    }
  }
  return result;
}

/** No workspace may depend on a service; a package may depend only on packages. */
export function findViolations(workspaces: Workspace[]): Violation[] {
  const byName = new Map(workspaces.map((w) => [w.name, w]));
  const violations: Violation[] = [];
  for (const w of workspaces) {
    for (const depName of new Set(w.deps)) {
      const dep = byName.get(depName);
      if (!dep) continue;
      const toService = dep.kind === 'service';
      const packageToNonPackage = w.kind === 'package' && dep.kind !== 'package';
      if (toService || packageToNonPackage) violations.push({ dependent: w, dependency: dep });
    }
  }
  return violations;
}

export function formatViolation(v: Violation): string {
  return `${v.dependent.name} (${v.dependent.dir}) depends on ${v.dependency.kind} ${v.dependency.name} (${v.dependency.dir})`;
}
