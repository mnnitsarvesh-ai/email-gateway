/**
 * Registry generator (design D3).
 *
 *   tsx scripts/generate-registry.ts           writes src/registry/operations.generated.ts and
 *                                              docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md
 *   tsx scripts/generate-registry.ts --check   regenerates in memory; exit 1 when either file is
 *                                              stale (the package `test` runs it)
 *
 * Inputs: ../../docs/api/openapi.json, src/registry/manifest.ts and the portal's operation usage
 * (operation-id strings `<Name>Controller_<method>_v1` in ../../apps/admin-portal/src/features/**,
 * the app shell excluded by the manifest). Output is formatted with the repository Prettier
 * config and is deterministic.
 */
import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { buildRegistry, type OpenApiDocument, type RegistryBuild } from '../src/registry/build';
import { registryConsistencyIssues } from '../src/registry/consistency';
import { renderMatrix, renderOperationsModule } from '../src/registry/render';

export const PACKAGE_DIR = join(__dirname, '..');
export const REPO_DIR = join(PACKAGE_DIR, '../..');
export const OPENAPI_PATH = join(REPO_DIR, 'docs/api/openapi.json');
export const FEATURES_DIR = join(REPO_DIR, 'apps/admin-portal/src/features');
export const OPERATIONS_OUT = join(PACKAGE_DIR, 'src/registry/operations.generated.ts');
export const MATRIX_OUT = join(REPO_DIR, 'docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md');

const OPERATION_ID = /[A-Z][A-Za-z0-9]*Controller_[A-Za-z0-9]+_v1/g;
const SOURCE_FILE = /\.(ts|tsx|js|jsx|mjs)$/;

function filesOf(dir: string): string[] {
  return readdirSync(dir)
    .sort()
    .flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? filesOf(path) : SOURCE_FILE.test(name) ? [path] : [];
    });
}

/** operationId → feature folders referencing it (every source file of the feature). */
export function readPortalUsage(featuresDir = FEATURES_DIR): Map<string, string[]> {
  const usage = new Map<string, string[]>();
  for (const feature of readdirSync(featuresDir).sort()) {
    const dir = join(featuresDir, feature);
    if (!statSync(dir).isDirectory()) continue;
    for (const file of filesOf(dir)) {
      for (const match of readFileSync(file, 'utf8').matchAll(OPERATION_ID)) {
        const list = usage.get(match[0]) ?? [];
        if (!list.includes(feature)) list.push(feature);
        usage.set(match[0], list);
      }
    }
  }
  return usage;
}

export function readOpenApi(path = OPENAPI_PATH): OpenApiDocument {
  return JSON.parse(readFileSync(path, 'utf8')) as OpenApiDocument;
}

async function format(source: string, filepath: string): Promise<string> {
  const prettier = await import('prettier');
  const config = (await prettier.resolveConfig(filepath)) ?? {};
  return prettier.format(source, { ...config, filepath });
}

export interface GeneratedOutputs {
  build: RegistryBuild;
  files: Record<string, string>;
}

/** Builds and formats both outputs in memory. */
export async function generateOutputs(): Promise<GeneratedOutputs> {
  const document = readOpenApi();
  const build = buildRegistry(document, readPortalUsage());
  const issues = registryConsistencyIssues(build.tools);
  if (issues.length > 0)
    throw new Error(`Assistant registry consistency check failed:\n- ${issues.join('\n- ')}`);
  const idempotency = new Map<string, string>();
  for (const item of Object.values(document.paths))
    for (const op of Object.values(item))
      if (op?.operationId) idempotency.set(op.operationId, op['x-eg-idempotency'] ?? '');
  return {
    build,
    files: {
      [OPERATIONS_OUT]: await format(renderOperationsModule(build), OPERATIONS_OUT),
      [MATRIX_OUT]: await format(
        renderMatrix(build, (id) => idempotency.get(id) ?? ''),
        MATRIX_OUT,
      ),
    },
  };
}

/** Paths whose committed content differs from the regenerated content. */
export async function staleOutputs(): Promise<string[]> {
  const { files } = await generateOutputs();
  return Object.entries(files)
    .filter(([path, content]) => !existsSync(path) || readFileSync(path, 'utf8') !== content)
    .map(([path]) => relative(REPO_DIR, path));
}

async function main(): Promise<void> {
  const check = process.argv.includes('--check');
  if (check) {
    const stale = await staleOutputs();
    if (stale.length > 0) {
      process.stderr.write(
        `Assistant registry outputs are stale: ${stale.join(', ')}. Run: pnpm --filter @email-gateway/assistant registry:generate\n`,
      );
      process.exit(1);
    }
    process.stdout.write('Assistant registry outputs are up to date.\n');
    return;
  }
  const { build, files } = await generateOutputs();
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
    process.stdout.write(`wrote ${relative(REPO_DIR, path)}\n`);
  }
  const enabled = build.tools.filter((tool) => tool.enabled).length;
  process.stdout.write(
    `registry ${build.version}: ${build.tools.length} tools (${enabled} enabled), ${build.notApplicable.length} not applicable\n`,
  );
}

if (require.main === module) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
    );
    process.exit(1);
  });
}
