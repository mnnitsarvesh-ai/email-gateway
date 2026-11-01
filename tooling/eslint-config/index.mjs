// @ts-check
import fs from 'node:fs';
import path from 'node:path';
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import { CONTROL_PLANE_REGEX_SOURCE, importBoundaries } from './import-boundaries.mjs';

/**
 * Workspaces allowed to import the control-plane DB / config entry points
 * (hard rule 2: the data plane uses the MySQL writer only). This is the single
 * place the allow-list is defined; exceptions must be visible in review.
 */
export const CONTROL_PLANE_DB_CONSUMERS = ['services/api'];

const TS_FILES = ['**/*.{ts,tsx,mts,cts}'];
const JS_FILES = ['**/*.{js,jsx,mjs,cjs}'];
const ALL_FILES = [...TS_FILES, ...JS_FILES];

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
 * not merges, the option across matching config objects). Covers static imports by
 * package name; relative, dynamic and require() forms are handled by `esg/import-boundaries`.
 * @param {{ blockedServices: string[], controlPlane: boolean }} opts
 */
function restrictions({ blockedServices, controlPlane }) {
  const boundaryMessage =
    '[boundary] Services must not be imported by other workspaces (hard rule 8). Move shared code to a package under packages/.';
  /** @type {{ name: string, message: string }[]} */
  const paths = blockedServices.map((name) => ({ name, message: boundaryMessage }));
  /** @type {({ group: string[], message: string } | { regex: string, message: string })[]} */
  const patterns = blockedServices.map((name) => ({ group: [`${name}/*`], message: boundaryMessage }));
  if (controlPlane) {
    patterns.push({
      regex: CONTROL_PLANE_REGEX_SOURCE,
      message: `[control-plane] The control-plane entry points of @esg/db and @esg/config are reserved for ${CONTROL_PLANE_DB_CONSUMERS.join(', ')} (hard rule 2). Data-plane code uses the writer connection; the portal talks only to api.`,
    });
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

  const GOVERNED = ['services/**', 'packages/**', 'db/**', 'test/e2e/**', 'tooling/**'];
  const NO_INLINE = { noInlineConfig: true };

  /** @type {import('eslint').Linter.Config[]} */
  const config = [
    { linterOptions: { reportUnusedDisableDirectives: 'error' } },
    // Inline directives cannot switch off the boundary rules in governed workspaces.
    { files: GOVERNED, linterOptions: NO_INLINE },
    { ...js.configs.recommended, files: ALL_FILES },
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
    // Local rule: relative escapes (all forms), dynamic import()/require of services and control plane.
    {
      files: ALL_FILES,
      plugins: { esg: { rules: { 'import-boundaries': importBoundaries } } },
      rules: {
        'esg/import-boundaries': [
          'error',
          { root, services, controlPlaneAllow: CONTROL_PLANE_DB_CONSUMERS },
        ],
      },
    },
    // Static name-based boundary (hard rule 8) and writer-only data plane (hard rule 2).
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
      files: ['packages/**', 'db/**', 'test/e2e/**', 'tooling/**'],
      rules: { 'no-restricted-imports': restrictions({ blockedServices: allServiceNames, controlPlane: true }) },
    },
  ];
  return config;
}
