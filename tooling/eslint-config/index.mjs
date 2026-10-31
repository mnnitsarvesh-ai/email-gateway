// @ts-check
import fs from 'node:fs';
import path from 'node:path';
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

/**
 * Workspaces allowed to import the control-plane DB / config entry points
 * (hard rule 2: the data plane uses the MySQL writer only). This is the single
 * place the allow-list is defined; exceptions must be visible in review.
 */
export const CONTROL_PLANE_DB_CONSUMERS = ['services/api'];

const TS_FILES = ['**/*.{ts,tsx,mts,cts}'];
const JS_FILES = ['**/*.{js,mjs,cjs}'];

const CONTROL_PLANE_ENTRIES = ['@esg/db/control-plane', '@esg/config/control-plane'];

/**
 * Relative imports that leave the current workspace. Trade-off: a workspace may
 * not name an internal folder `services/`, `packages/`, `tooling/`, `db/` or
 * `test/e2e/` and reach it with `../`; use a sibling path or the package name.
 */
const RELATIVE_ESCAPE_REGEX = '^(\\.\\./)+(.*/)?(services|packages|tooling|db|test/e2e)/';

/** @param {string} dir @returns {string[]} */
function listDirs(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && d.name !== 'node_modules')
    .map((d) => d.name);
}

/**
 * Read the services under <root>/services/* so new services are picked up
 * automatically (no hand-kept list).
 * @param {string} root
 * @returns {{ dir: string, name: string | undefined }[]}
 */
function readServices(root) {
  return listDirs(path.join(root, 'services')).map((dir) => {
    const pkgPath = path.join(root, 'services', dir, 'package.json');
    if (!fs.existsSync(pkgPath)) return { dir, name: undefined };
    const pkg = /** @type {{ name?: string }} */ (JSON.parse(fs.readFileSync(pkgPath, 'utf8')));
    return { dir, name: pkg.name };
  });
}

/**
 * One `no-restricted-imports` option object per file group (ESLint replaces,
 * not merges, the option across matching config objects).
 * @param {{ blockedServices: string[], controlPlane: boolean }} opts
 */
function restrictions({ blockedServices, controlPlane }) {
  /** @type {{ name: string, message: string }[]} */
  const paths = blockedServices.map((name) => ({
    name,
    message: `[boundary] Services must not be imported by other workspaces (hard rule 8). Move shared code to a package under packages/.`,
  }));
  /** @type {({ group: string[], message: string } | { regex: string, message: string })[]} */
  const patterns = blockedServices.map((name) => ({
    group: [`${name}/*`],
    message: `[boundary] Services must not be imported by other workspaces (hard rule 8). Move shared code to a package under packages/.`,
  }));
  patterns.push({
    regex: RELATIVE_ESCAPE_REGEX,
    message: '[boundary] Relative import leaves this workspace. Import the package by name (@esg/<name>) instead.',
  });
  if (controlPlane) {
    for (const name of CONTROL_PLANE_ENTRIES) {
      paths.push({
        name,
        message: `[control-plane] ${name} is reserved for ${CONTROL_PLANE_DB_CONSUMERS.join(', ')} (hard rule 2). Data-plane services use the writer connection; the portal talks only to api.`,
      });
      patterns.push({
        group: [`${name}/*`],
        message: `[control-plane] ${name} is reserved for ${CONTROL_PLANE_DB_CONSUMERS.join(', ')} (hard rule 2).`,
      });
    }
  }
  return ['error', { paths, patterns }];
}

/**
 * Build the flat config. `root` is the directory holding services/, packages/, ...
 * @param {{ root: string }} options
 * @returns {import('eslint').Linter.Config[]}
 */
export function createConfig({ root }) {
  const services = readServices(root);
  const allServiceNames = services.flatMap((s) => (s.name ? [s.name] : []));
  const isControlPlaneConsumer = (/** @type {string} */ dir) =>
    CONTROL_PLANE_DB_CONSUMERS.includes(`services/${dir}`);

  /** @type {import('eslint').Linter.Config[]} */
  const config = [
    { ...js.configs.recommended, files: [...TS_FILES, ...JS_FILES] },
    ...tseslint.configs.strictTypeChecked.map((c) => ({ ...c, files: TS_FILES })),
    {
      files: TS_FILES,
      languageOptions: {
        parserOptions: { projectService: true, tsconfigRootDir: root },
      },
      rules: {
        '@typescript-eslint/no-explicit-any': 'error',
        '@typescript-eslint/consistent-type-assertions': [
          'error',
          { assertionStyle: 'as', objectLiteralTypeAssertions: 'never' },
        ],
      },
    },
    { ...tseslint.configs.disableTypeChecked, files: JS_FILES },
    // Cross-service boundary (hard rule 8) and writer-only data plane (hard rule 2).
    // Base group for any file under services/** (covers a service dir that has no package.json yet).
    {
      files: ['services/**'],
      rules: { 'no-restricted-imports': restrictions({ blockedServices: allServiceNames, controlPlane: true }) },
    },
    // Per-service groups: a service may reference itself; api may use the control plane.
    ...services.map((s) => ({
      files: [`services/${s.dir}/**`],
      rules: {
        'no-restricted-imports': restrictions({
          blockedServices: allServiceNames.filter((n) => n !== s.name),
          controlPlane: !isControlPlaneConsumer(s.dir),
        }),
      },
    })),
    {
      files: ['packages/**', 'db/**', 'test/e2e/**'],
      rules: { 'no-restricted-imports': restrictions({ blockedServices: allServiceNames, controlPlane: false }) },
    },
  ];
  return config;
}
