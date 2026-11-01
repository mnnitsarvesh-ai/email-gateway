import fs from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';

export type WorkspaceKind = 'root' | 'service' | 'package' | 'migrations' | 'e2e' | 'tooling';

export interface Workspace {
  name: string;
  dir: string; // repo-relative, posix
  kind: WorkspaceKind;
  /** Dependency keys as written in package.json. */
  deps: string[];
  /** Raw [key, spec] pairs, resolved to their real target by findViolations. */
  specs: [string, string][];
}

export interface Violation {
  dependent: Workspace;
  dependency: Workspace;
}

const DEP_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'] as const;

export function classify(dir: string): WorkspaceKind | undefined {
  if (dir === '.') return 'root';
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

function readWorkspace(root: string, dir: string): Workspace | undefined {
  const pkgPath = path.join(root, dir, 'package.json');
  if (!fs.existsSync(pkgPath)) return undefined;
  const kind = classify(dir);
  if (!kind) return undefined;
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<string, unknown>;
  const specs = DEP_FIELDS.flatMap((f): [string, string][] => {
    const field = pkg[f];
    if (!field || typeof field !== 'object') return [];
    return Object.entries(field).map(([k, v]): [string, string] => [k, typeof v === 'string' ? v : '']);
  });
  // overrides / pnpm.overrides / resolutions can also redirect a dependency into a service.
  const pnpmField = pkg['pnpm'];
  const overrideFields = [pkg['overrides'], pkg['resolutions'], pnpmField && typeof pnpmField === 'object' ? (pnpmField as Record<string, unknown>)['overrides'] : undefined];
  for (const field of overrideFields) {
    if (!field || typeof field !== 'object') continue;
    for (const [k, v] of Object.entries(field)) if (typeof v === 'string') specs.push([k, v]);
  }
  return { name: typeof pkg['name'] === 'string' ? pkg['name'] : dir, dir, kind, deps: specs.map(([k]) => k), specs };
}

export function loadWorkspaces(root: string): Workspace[] {
  const yamlPath = path.join(root, 'pnpm-workspace.yaml');
  const parsed = parse(fs.readFileSync(yamlPath, 'utf8')) as { packages?: string[] } | null;
  const globs = parsed?.packages ?? [];
  const result: Workspace[] = [];
  const rootWs = readWorkspace(root, '.');
  if (rootWs) {
    const yamlFull = parsed as Record<string, unknown> | null;
    const maps = [yamlFull?.['overrides'], yamlFull?.['catalog'], ...Object.values((yamlFull?.['catalogs'] as Record<string, unknown> | undefined) ?? {})];
    for (const m of maps) {
      if (!m || typeof m !== 'object') continue;
      for (const [k, v] of Object.entries(m)) if (typeof v === 'string') rootWs.specs.push([k, v]);
    }
    rootWs.deps = rootWs.specs.map(([k]) => k);
    result.push(rootWs);
  }
  for (const glob of globs) {
    for (const dir of expandGlob(root, glob)) {
      const ws = readWorkspace(root, dir);
      if (ws) result.push(ws);
    }
  }
  return result;
}

/**
 * Resolve a dependency (key + spec) to the workspace it really points at: by alias
 * (`npm:<name>@x`, `workspace:<name>@x`), by path (`link:`, `file:`, `workspace:<path>`), else by key.
 */
export function resolveTarget(
  dependent: Workspace,
  key: string,
  spec: string,
  byName: Map<string, Workspace>,
  byDir: Map<string, Workspace>,
  root = '',
): Workspace | undefined {
  const alias = /^(?:npm|workspace):(@[^/@]+\/[^@]+|[^@./*^~<>=\s][^@]*)(?:@.*)?$/.exec(spec);
  if (alias?.[1] && !/^\d/.test(alias[1])) return byName.get(alias[1]) ?? byName.get(key);
  // link:/file:/portal: always carry a path (bare or relative or absolute); workspace: only when path-like.
  const pathSpec = /^(?:(?:link|file|portal):(.+)|workspace:((?:\.{1,2}(?:\/.*)?|\/.*)))$/.exec(spec);
  const rawPath = pathSpec?.[1] ?? pathSpec?.[2];
  if (rawPath) {
    let target: string;
    if (rawPath.startsWith('/')) {
      target = root ? path.posix.normalize(path.relative(root, rawPath).split(path.sep).join('/')) : rawPath;
    } else {
      target = path.posix.normalize(path.posix.join(dependent.dir, rawPath));
    }
    target = target.replace(/\/$/, '');
    const hit = byDir.get(target);
    if (hit) return hit;
    // A path into services/ with no package.json yet still counts as a service dependency.
    const k = classify(target);
    if (k === 'service') return { name: target, dir: target, kind: k, deps: [], specs: [] };
    return undefined;
  }
  return byName.get(key);
}

/** No workspace may depend on a service; a package may depend only on packages. */
export function findViolations(workspaces: Workspace[], root = ''): Violation[] {
  const byName = new Map(workspaces.map((w) => [w.name, w]));
  const byDir = new Map(workspaces.map((w) => [w.dir, w]));
  const violations: Violation[] = [];
  for (const w of workspaces) {
    const seen = new Set<Workspace>();
    for (const [key, spec] of w.specs) {
      const dep = resolveTarget(w, key, spec, byName, byDir, root);
      if (!dep || dep === w || seen.has(dep)) continue;
      const toService = dep.kind === 'service';
      const packageToNonPackage = w.kind === 'package' && dep.kind !== 'package';
      if (toService || packageToNonPackage) {
        seen.add(dep);
        violations.push({ dependent: w, dependency: dep });
      }
    }
  }
  return violations;
}

export function formatViolation(v: Violation): string {
  return `${v.dependent.name} (${v.dependent.dir}) depends on ${v.dependency.kind} ${v.dependency.name} (${v.dependency.dir})`;
}
