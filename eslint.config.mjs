// Root flat config shared by every workspace. Next.js lint rules live in apps/admin-portal.
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/coverage/**',
      '**/next-env.d.ts',
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
    files: ['**/*.test.ts', '**/*.spec.ts', '**/test/**/*.ts', 'tests/**/*.ts'],
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
