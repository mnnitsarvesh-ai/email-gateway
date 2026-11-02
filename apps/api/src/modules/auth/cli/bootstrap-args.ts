import { z } from 'zod';

export interface BootstrapArgs {
  email: string;
  displayName: string;
  additional: boolean;
}

export const BOOTSTRAP_USAGE =
  'Usage: pnpm --filter @email-gateway/api auth:bootstrap -- --email <email> ' +
  '[--display-name <name>] [--additional]';

const EmailSchema = z.email().max(320);
const DisplayNameSchema = z.string().trim().min(1).max(255);

/** Thrown for invalid command-line arguments; the message is safe to print. */
export class BootstrapUsageError extends Error {
  constructor(message: string) {
    super(`${message}\n${BOOTSTRAP_USAGE}`);
    this.name = 'BootstrapUsageError';
  }
}

/**
 * Parses `--email <e> [--display-name <n>] [--additional]` (also `--flag=value`). A leading `--`
 * (pnpm argument separator) is ignored. Unknown flags and positional arguments are errors.
 */
export function parseBootstrapArgs(argv: readonly string[]): BootstrapArgs {
  let email: string | undefined;
  let displayName: string | undefined;
  let additional = false;
  const args = argv[0] === '--' ? argv.slice(1) : [...argv];

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === '--') continue;
    const eq = arg.indexOf('=');
    const flag = eq > 0 ? arg.slice(0, eq) : arg;
    const inline = eq > 0 ? arg.slice(eq + 1) : undefined;
    const value = (): string => {
      if (inline !== undefined) return inline;
      const next = args[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new BootstrapUsageError(`${flag} needs a value`);
      }
      i += 1;
      return next;
    };
    switch (flag) {
      case '--email':
        email = value();
        break;
      case '--display-name':
        displayName = value();
        break;
      case '--additional':
        if (inline !== undefined) throw new BootstrapUsageError('--additional takes no value');
        additional = true;
        break;
      default:
        throw new BootstrapUsageError(
          `Unknown argument: ${flag.startsWith('--') ? flag : '(positional)'}`,
        );
    }
  }

  if (email === undefined) throw new BootstrapUsageError('--email is required');
  const normalized = email.trim().toLowerCase();
  if (!EmailSchema.safeParse(normalized).success) {
    throw new BootstrapUsageError('--email must be a valid email address');
  }
  const name = DisplayNameSchema.safeParse(displayName ?? normalized.split('@')[0]);
  if (!name.success) throw new BootstrapUsageError('--display-name must be 1-255 characters');
  return { email: normalized, displayName: name.data, additional };
}
