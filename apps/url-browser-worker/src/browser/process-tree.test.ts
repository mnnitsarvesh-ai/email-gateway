import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { descendantRssBytes } from './process-tree';

const dir = mkdtempSync(join(tmpdir(), 'proc-'));
function proc(pid: number, ppid: number, rssPages: number, comm = 'chrome'): void {
  mkdirSync(join(dir, String(pid)));
  writeFileSync(join(dir, String(pid), 'stat'), `${pid} (${comm}) S ${ppid} 1 1 0 -1`);
  writeFileSync(join(dir, String(pid), 'statm'), `1000 ${rssPages} 10 1 0 100 0`);
}

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('descendantRssBytes', () => {
  it('sums the RSS of every descendant of the root (not the root itself)', () => {
    proc(100, 1, 999, 'node'); // root
    proc(101, 100, 10); // browser
    proc(102, 101, 20, 'chrome (renderer) x'); // renderer: comm with spaces and parens
    proc(103, 102, 5);
    proc(200, 1, 7777); // unrelated
    expect(descendantRssBytes(100, dir, 4096)).toBe((10 + 20 + 5) * 4096);
  });

  it('returns null without /proc', () => {
    expect(descendantRssBytes(1, join(dir, 'missing'))).toBeNull();
  });
});
