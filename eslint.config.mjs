// Root flat config shared by every workspace. Next.js lint rules live in apps/admin-portal.
import { createRequire } from 'node:module';
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// The admin portal's React/Next/a11y plugins are dev dependencies of apps/admin-portal (pnpm
// strict layout), so they are resolved from there.
const portalRequire = createRequire(new URL('./apps/admin-portal/package.json', import.meta.url));
const reactHooks = portalRequire('eslint-plugin-react-hooks');
const jsxA11y = portalRequire('eslint-plugin-jsx-a11y');
const nextPlugin = portalRequire('@next/eslint-plugin-next');

/** Boundary patterns shared by every no-restricted-imports block (flat config replaces options). */
const appBoundaryPatterns = [
  {
    group: [
      '**/apps/*',
      '@email-gateway/api',
      '@email-gateway/*-worker',
      '@email-gateway/smtp-adapter',
      '@email-gateway/policy-engine',
      '@email-gateway/admin-portal',
    ],
    message: 'Apps are deployable units. Share code through packages/* only.',
  },
  {
    group: ['../../packages/*', '../../../packages/*'],
    message: 'Import packages by name (@email-gateway/*), not by relative path.',
  },
];

const PORTAL = 'apps/admin-portal/src';
const noInnerHtml = {
  selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
  message: 'Never render HTML (design P12): render text, or use the sanitized preview components.',
};
const noBffFetch = [
  {
    selector: "CallExpression[callee.name='fetch'] > Literal[value=/^\\/bff\\/api/]",
    message: 'Call the api through src/lib/api (typed client), not fetch (design P7).',
  },
  {
    selector: "CallExpression[callee.property.name='fetch'] > Literal[value=/^\\/bff\\/api/]",
    message: 'Call the api through src/lib/api (typed client), not fetch (design P7).',
  },
  {
    selector:
      "CallExpression[callee.name='fetch'] > TemplateLiteral > TemplateElement[value.raw=/^\\/bff\\/api/]",
    message: 'Call the api through src/lib/api (typed client), not fetch (design P7).',
  },
  {
    selector:
      "CallExpression[callee.property.name='fetch'] > TemplateLiteral > TemplateElement[value.raw=/^\\/bff\\/api/]",
    message: 'Call the api through src/lib/api (typed client), not fetch (design P7).',
  },
];

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/coverage/**',
      '**/next-env.d.ts',
      // Generated from docs/api/openapi.json (apps/admin-portal/scripts/generate-api.mjs).
      'apps/admin-portal/src/lib/api/*.gen.ts',
      '**/*.config.{js,mjs,cjs}',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', ignoreRestSiblings: true },
      ],
      '@typescript-eslint/no-floating-promises': 'error',
      // Nest relies on runtime class references for DI; type-only imports break injection.
      '@typescript-eslint/no-extraneous-class': 'off',
      'no-console': 'error',
    },
  },
  {
    // Module boundaries: apps never import other apps; packages never import apps.
    files: ['apps/**/*.ts', 'apps/**/*.tsx', 'packages/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                '**/apps/*',
                '@email-gateway/api',
                '@email-gateway/*-worker',
                '@email-gateway/smtp-adapter',
                '@email-gateway/policy-engine',
                '@email-gateway/admin-portal',
              ],
              message: 'Apps are deployable units. Share code through packages/* only.',
            },
            {
              group: ['../../packages/*', '../../../packages/*'],
              message: 'Import packages by name (@email-gateway/*), not by relative path.',
            },
          ],
        },
      ],
    },
  },
  {
    // Data plane is writer-only (ADR-0014). Flat config replaces rule options, so the boundary
    // patterns above are repeated here. Tests are exempt so they can assert the reader is absent.
    files: [
      'apps/{smtp-adapter,email-worker,policy-engine,delivery-worker,archive-worker}/**/*.ts',
    ],
    ignores: ['**/*.test.ts', '**/*.spec.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@email-gateway/common',
              importNames: ['PrismaReadService'],
              message:
                'Data-plane services use the writer only (ADR-0014). Replica lag must never affect a mail decision.',
            },
          ],
          patterns: [
            {
              group: [
                '**/apps/*',
                '@email-gateway/api',
                '@email-gateway/*-worker',
                '@email-gateway/smtp-adapter',
                '@email-gateway/policy-engine',
                '@email-gateway/admin-portal',
              ],
              message: 'Apps are deployable units. Share code through packages/* only.',
            },
            {
              group: ['../../packages/*', '../../../packages/*'],
              message: 'Import packages by name (@email-gateway/*), not by relative path.',
            },
          ],
        },
      ],
    },
  },
  {
    // Repository rule (design D2 of steps 1.2/1.3): inside API feature modules only
    // *.repository.ts files talk to Prisma; services use repositories and TransactionRunner.
    // Flat config replaces rule options, so the boundary patterns above are repeated here.
    files: ['apps/api/src/modules/**/*.ts'],
    ignores: ['**/*.repository.ts', '**/*.test.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@email-gateway/common',
              importNames: ['PrismaService', 'PrismaReadService'],
              message: 'Only *.repository.ts files may use Prisma (design D2)',
            },
          ],
          patterns: [
            {
              group: [
                '**/apps/*',
                '@email-gateway/api',
                '@email-gateway/*-worker',
                '@email-gateway/smtp-adapter',
                '@email-gateway/policy-engine',
                '@email-gateway/admin-portal',
              ],
              message: 'Apps are deployable units. Share code through packages/* only.',
            },
            {
              group: ['../../packages/*', '../../../packages/*'],
              message: 'Import packages by name (@email-gateway/*), not by relative path.',
            },
          ],
        },
      ],
    },
  },
  {
    // Admin portal (step 7.1, ADR-0058/0059): React hooks, accessibility, Next core-web-vitals,
    // content safety (no HTML injection) and the typed-client rule.
    files: [`${PORTAL}/**/*.ts`, `${PORTAL}/**/*.tsx`],
    plugins: {
      'react-hooks': reactHooks,
      'jsx-a11y': jsxA11y,
      '@next/next': nextPlugin,
    },
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    settings: { next: { rootDir: 'apps/admin-portal' } },
    rules: {
      // Classic hooks rules; the React Compiler rule set of the plugin's preset is not used
      // because the portal does not run the React Compiler.
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'error',
      ...jsxA11y.flatConfigs.recommended.rules,
      ...nextPlugin.configs.recommended.rules,
      ...nextPlugin.configs['core-web-vitals'].rules,
      // App Router only: there is no pages/ directory to check links against.
      '@next/next/no-html-link-for-pages': 'off',
      'no-restricted-syntax': ['error', noInnerHtml, ...noBffFetch],
    },
  },
  {
    // src/lib/api is the one place allowed to call the BFF proxy directly.
    files: [`${PORTAL}/lib/api/**/*.ts`, `${PORTAL}/lib/api/**/*.tsx`],
    rules: { 'no-restricted-syntax': ['error', noInnerHtml] },
  },
  {
    // Client-facing modules never import server code (tokens, config, the BFF).
    files: [
      `${PORTAL}/components/**/*.{ts,tsx}`,
      `${PORTAL}/features/**/*.{ts,tsx}`,
      `${PORTAL}/hooks/**/*.{ts,tsx}`,
      `${PORTAL}/lib/**/*.{ts,tsx}`,
      `${PORTAL}/app/(console)/**/*.{ts,tsx}`,
      `${PORTAL}/app/(auth)/**/*.{ts,tsx}`,
      `${PORTAL}/app/auth/**/*.{ts,tsx}`,
      `${PORTAL}/app/mfa/**/*.{ts,tsx}`,
    ],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            ...appBoundaryPatterns,
            {
              group: ['@/server', '@/server/*', '**/server/*'],
              message:
                'Client-facing code must not import src/server/** (server-only, design P10).',
            },
          ],
        },
      ],
    },
  },
  {
    files: [`${PORTAL}/**/*.test.tsx`, `${PORTAL}/test/**/*.{ts,tsx}`],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/unbound-method': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
    },
  },
  {
    files: [
      '**/*.test.ts',
      '**/*.spec.ts',
      '**/test/**/*.ts',
      'tests/**/*.ts',
      'apps/*/integration/**/*.ts',
    ],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/unbound-method': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
    },
  },
  prettier,
);
