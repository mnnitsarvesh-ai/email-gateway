import type { Linter } from 'eslint';

export const CONTROL_PLANE_DB_CONSUMERS: string[];
export function createConfig(options: { root: string }): Linter.Config[];
