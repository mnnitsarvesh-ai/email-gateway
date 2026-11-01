import path from 'node:path';
import { findViolations, formatViolation, loadWorkspaces } from './guard.ts';

const root = path.resolve(process.argv[2] ?? path.join(import.meta.dirname, '..', '..', '..'));
const violations = findViolations(loadWorkspaces(root), root);

if (violations.length > 0) {
  for (const v of violations) console.error(formatViolation(v));
  console.error(`workspace-guard: ${String(violations.length)} violation(s)`);
  process.exit(1);
}
console.log('workspace-guard: ok');
