// @ts-check
import { createConfig } from '@esg/eslint-config';

export default [
  ...createConfig({ root: import.meta.dirname }),
  {
    ignores: [
      'tooling/lint-fixtures/fixtures/**',
      'tooling/workspace-guard/fixtures/**',
      '**/dist/**',
      '**/.turbo/**',
      '**/coverage/**',
    ],
  },
];
