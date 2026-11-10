import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { ARTIFACT_KINDS, type ArtifactKind } from '@email-gateway/security-contracts';
import { SandboxEnvelopeError } from '../envelope/errors';
import { openArtifact } from '../envelope/artifact';
import { parseArtifactPrivateKey, SandboxKeyError } from '../keys';

/**
 * Ops tooling (step 4.6 X12, runbook sandbox-controller "reading an artifact"): opens one sealed
 * `sandbox-artifact/1` object with the artifact private key. No service holds that key in 4.6;
 * the operator runs this with the key from the secret store in the environment:
 *
 *   SANDBOX_ARTIFACT_PRIVATE_KEY=… pnpm --filter @email-gateway/sandbox artifact:open -- \
 *     --object <sealed object file> --wrapped-key <x1.…> --task-id <uuid> --seq <0..15> \
 *     --kind <artifact kind> --out <plaintext file>
 *
 * The plaintext is written to `--out` (mode 0600, never to the terminal: artifacts are hostile
 * content); stdout gets the plaintext SHA-256 and size only. Exit codes: 0 ok, 1 cannot open
 * (wrong key, ids or tampered), 2 usage or key configuration error. Nothing secret is printed.
 */

export interface ArtifactOpenIo {
  readFile(path: string): Buffer;
  writeFile(path: string, data: Buffer): void;
  stdout(line: string): void;
  stderr(line: string): void;
}

const USAGE =
  'usage: artifact-open --object <file> --wrapped-key <x1...> --task-id <uuid> --seq <0..15> --kind <kind> --out <file>';

class UsageError extends Error {}

function parseArgs(argv: readonly string[]): Record<string, string> {
  const allowed = new Set(['--object', '--wrapped-key', '--task-id', '--seq', '--kind', '--out']);
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i]!;
    if (flag === '--') continue;
    if (!allowed.has(flag)) throw new UsageError(`unknown argument ${JSON.stringify(flag)}`);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--'))
      throw new UsageError(`${flag} needs a value`);
    if (out[flag] !== undefined) throw new UsageError(`${flag} given twice`);
    out[flag] = value;
    i += 1;
  }
  for (const flag of allowed) {
    if (out[flag] === undefined) throw new UsageError(`missing ${flag}`);
  }
  return out;
}

/** Runs the command; returns the exit code. */
export function runArtifactOpen(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  io: ArtifactOpenIo,
): number {
  let args: Record<string, string>;
  try {
    args = parseArgs(argv);
  } catch (error) {
    io.stderr(`artifact-open: ${error instanceof Error ? error.message : 'invalid arguments'}`);
    io.stderr(USAGE);
    return 2;
  }
  const seq = Number(args['--seq']);
  const kind = args['--kind']!;
  if (!/^\d{1,2}$/.test(args['--seq']!) || seq > 15) {
    io.stderr('artifact-open: --seq must be 0..15');
    return 2;
  }
  if (!(ARTIFACT_KINDS as readonly string[]).includes(kind)) {
    io.stderr(`artifact-open: --kind must be one of ${ARTIFACT_KINDS.join(', ')}`);
    return 2;
  }
  let privateKey;
  try {
    privateKey = parseArtifactPrivateKey(env.SANDBOX_ARTIFACT_PRIVATE_KEY);
  } catch (error) {
    io.stderr(
      `artifact-open: ${error instanceof SandboxKeyError ? error.message : 'invalid private key'}`,
    );
    return 2;
  }
  let object: Buffer;
  try {
    object = io.readFile(args['--object']!);
  } catch {
    io.stderr('artifact-open: cannot read the object file');
    return 2;
  }
  let plaintext: Buffer;
  try {
    plaintext = openArtifact(privateKey, object, args['--wrapped-key']!, {
      taskId: args['--task-id']!,
      seq,
      kind: kind as ArtifactKind,
    });
  } catch (error) {
    io.stderr(
      `artifact-open: ${error instanceof SandboxEnvelopeError ? error.message : 'unable to open the artifact'}`,
    );
    return 1;
  }
  try {
    io.writeFile(args['--out']!, plaintext);
  } catch {
    io.stderr('artifact-open: cannot write the output file');
    return 2;
  }
  io.stdout(
    `artifact-open: wrote ${plaintext.length} bytes, sha256 ${createHash('sha256').update(plaintext).digest('hex')}`,
  );
  return 0;
}

/* c8 ignore start */
if (require.main === module) {
  process.exitCode = runArtifactOpen(process.argv.slice(2), process.env, {
    readFile: (path) => readFileSync(path),
    writeFile: (path, data) => writeFileSync(path, data, { mode: 0o600, flag: 'wx' }),
    stdout: (line) => process.stdout.write(`${line}\n`),
    stderr: (line) => process.stderr.write(`${line}\n`),
  });
}
/* c8 ignore stop */
