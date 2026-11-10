import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { sealArtifact } from '../envelope/artifact';
import { generateArtifactKeyPair, parseArtifactPublicKey } from '../keys';
import { type ArtifactOpenIo, runArtifactOpen } from './artifact-open';

const TASK = '01890a5d-ac96-774b-bcce-b302099a8070';
const pair = generateArtifactKeyPair();
const plaintext = Buffer.from('trace excerpt: execve sh');
const sealed = sealArtifact(parseArtifactPublicKey(pair.publicKey), plaintext, {
  taskId: TASK,
  seq: 2,
  kind: 'process_log',
});

function fakeIo(files: Record<string, Buffer> = { '/in/object.bin': sealed.object }) {
  const written: Record<string, Buffer> = {};
  const out: string[] = [];
  const err: string[] = [];
  const io: ArtifactOpenIo = {
    readFile: (path) => {
      const file = files[path];
      if (!file) throw new Error('ENOENT');
      return file;
    },
    writeFile: (path, data) => {
      if (path.includes('readonly')) throw new Error('EACCES');
      written[path] = data;
    },
    stdout: (line) => out.push(line),
    stderr: (line) => err.push(line),
  };
  return { io, written, out, err };
}

const args = (overrides: Record<string, string> = {}) =>
  Object.entries({
    '--object': '/in/object.bin',
    '--wrapped-key': sealed.wrappedKey,
    '--task-id': TASK,
    '--seq': '2',
    '--kind': 'process_log',
    '--out': '/out/plain.bin',
    ...overrides,
  }).flat();

describe('artifact:open ops script', () => {
  it('opens an artifact with the private key from the environment and prints only hash and size', () => {
    const t = fakeIo();
    expect(
      runArtifactOpen(['--', ...args()], { SANDBOX_ARTIFACT_PRIVATE_KEY: pair.privateKey }, t.io),
    ).toBe(0);
    expect(t.written['/out/plain.bin']).toEqual(plaintext);
    const sha = createHash('sha256').update(plaintext).digest('hex');
    expect(t.out).toEqual([`artifact-open: wrote ${plaintext.length} bytes, sha256 ${sha}`]);
    expect(t.out.join('\n')).not.toContain('execve');
    expect(t.err).toEqual([]);
  });

  it('exits 1 for the wrong ids or key, without writing anything', () => {
    const wrong: Record<string, string>[] = [
      { '--seq': '3' },
      { '--kind': 'network_log' },
      { '--task-id': '01890a5d-ac96-774b-bcce-b302099a8071' },
    ];
    for (const overrides of wrong) {
      const t = fakeIo();
      expect(
        runArtifactOpen(args(overrides), { SANDBOX_ARTIFACT_PRIVATE_KEY: pair.privateKey }, t.io),
      ).toBe(1);
      expect(t.written).toEqual({});
    }
    const t = fakeIo();
    const other = generateArtifactKeyPair().privateKey;
    expect(runArtifactOpen(args(), { SANDBOX_ARTIFACT_PRIVATE_KEY: other }, t.io)).toBe(1);
    expect(t.err.join('\n')).not.toContain(other);
  });

  it('exits 2 for usage and configuration errors, never echoing the key', () => {
    const env = { SANDBOX_ARTIFACT_PRIVATE_KEY: pair.privateKey };
    const cases: [string[], Record<string, string | undefined>][] = [
      [args().slice(0, 4), env],
      [[...args(), '--extra', 'x'], env],
      [args({ '--seq': '16' }), env],
      [args({ '--seq': 'x' }), env],
      [args({ '--kind': 'memory_dump' }), env],
      [args(), {}],
      [args(), { SANDBOX_ARTIFACT_PRIVATE_KEY: 'not-a-key' }],
      [args({ '--object': '/missing' }), env],
      [args({ '--out': '/readonly/x' }), env],
      [[...args(), '--seq', '1'], env],
    ];
    for (const [argv, environment] of cases) {
      const t = fakeIo();
      expect(runArtifactOpen(argv, environment, t.io), argv.join(' ')).toBe(2);
      expect(t.err.join('\n')).not.toContain(pair.privateKey);
    }
  });
});
