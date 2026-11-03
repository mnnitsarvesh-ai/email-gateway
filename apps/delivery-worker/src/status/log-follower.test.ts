import {
  appendFileSync,
  mkdtempSync,
  renameSync,
  rmSync,
  statSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { fileIdentity, LogFollower } from './log-follower';

let dir: string;
let path: string;
let clock = 0;
const follower = () => new LogFollower(path, { rotationGraceMs: 1000, clock: () => clock });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'dw-follow-'));
  path = join(dir, 'maillog');
  clock = 0;
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('LogFollower', () => {
  it('reports a missing file as not opened', async () => {
    expect(await follower().open(null)).toEqual({ opened: false, resumed: false });
  });

  it('hands out complete lines only and resumes at the committed offset', async () => {
    writeFileSync(path, 'one\ntwo\npart');
    const f = follower();
    await f.open(null);
    const first = await f.read(1024);
    expect(first?.lines).toEqual(['one', 'two']);
    expect(first?.offset).toBe(8);
    appendFileSync(path, 'ial\nthree\n');
    expect((await f.read(1024))?.lines).toEqual(['partial', 'three']);
    const position = f.position!;
    await f.close();

    const resumed = follower();
    expect(await resumed.open(position)).toEqual({ opened: true, resumed: true });
    appendFileSync(path, 'four\n');
    expect((await resumed.read(1024))?.lines).toEqual(['four']);
    await resumed.close();
  });

  it('reads in bounded chunks and reports more', async () => {
    writeFileSync(path, 'a'.repeat(10) + '\n' + 'b'.repeat(10) + '\n');
    const f = follower();
    await f.open(null);
    const chunk = await f.read(12);
    expect(chunk).toMatchObject({ lines: ['a'.repeat(10)], more: true });
    expect((await f.read(12))?.lines).toEqual(['b'.repeat(10)]);
    await f.close();
  });

  it('starts at 0 when the cursor names another file (rotated while down)', async () => {
    writeFileSync(path, 'new-file-line\n');
    const f = follower();
    expect(await f.open({ fileId: '1:2', offset: 999 })).toEqual({ opened: true, resumed: false });
    expect((await f.read(1024))?.lines).toEqual(['new-file-line']);
    await f.close();
  });

  it('follows a rename rotation by device+inode, draining the old file first', async () => {
    writeFileSync(path, 'old-1\n');
    const f = follower();
    await f.open(null);
    expect((await f.read(1024))?.lines).toEqual(['old-1']);
    const oldId = fileIdentity(statSync(path));
    renameSync(path, `${path}.20261103-120000`);
    // postlogd writes a last line to the old inode before reopening.
    appendFileSync(`${path}.20261103-120000`, 'old-2\n');
    writeFileSync(path, 'new-1\n');
    expect((await f.read(1024))?.lines).toEqual(['old-2']);
    // EOF of the old file: wait for the grace period before switching.
    expect(await f.read(1024)).toMatchObject({ lines: [], rotated: false, fileId: oldId });
    clock += 1000;
    const switched = await f.read(1024);
    expect(switched).toMatchObject({ rotated: true, offset: 0 });
    expect(switched?.fileId).not.toBe(oldId);
    expect((await f.read(1024))?.lines).toEqual(['new-1']);
    // The rotated file is gzipped (unlinked): nothing changes for the follower.
    rmSync(`${path}.20261103-120000`);
    appendFileSync(path, 'new-2\n');
    expect((await f.read(1024))?.lines).toEqual(['new-2']);
    await f.close();
  });

  it('treats a briefly missing path as "not yet" and keeps the old descriptor', async () => {
    writeFileSync(path, 'a\n');
    const f = follower();
    await f.open(null);
    await f.read(1024);
    renameSync(path, `${path}.1`);
    clock += 5000;
    expect(await f.read(1024)).toMatchObject({ lines: [], rotated: false });
    appendFileSync(`${path}.1`, 'b\n');
    expect((await f.read(1024))?.lines).toEqual(['b']);
    await f.close();
  });

  it('restarts at 0 after an in-place truncation', async () => {
    writeFileSync(path, 'long-line-1\nlong-line-2\n');
    const f = follower();
    await f.open(null);
    await f.read(1024);
    truncateSync(path, 0);
    appendFileSync(path, 'x\n');
    expect((await f.read(1024))?.lines).toEqual(['x']);
    await f.close();
  });
});
