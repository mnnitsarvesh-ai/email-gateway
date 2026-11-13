import 'server-only';
import type { UpstreamFetch } from '@/server/upstream';

/**
 * Production builds resolve the fixture module to this file (next.config.ts webpack alias), so
 * neither the bundle nor the file trace can contain the dev fixture layer (design P9).
 */
export function createMockFetch(): UpstreamFetch {
  throw new Error('Dev fixture mode is not part of this build');
}
