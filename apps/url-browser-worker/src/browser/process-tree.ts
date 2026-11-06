import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Resident memory of the browser process tree (U15) read from `/proc`: every descendant of this
 * Node process (Chromium and its renderer/GPU/utility children), excluding Node itself. Returns
 * null where `/proc` is not available (macOS development hosts).
 */
export function descendantRssBytes(
  rootPid: number = process.pid,
  procDir = '/proc',
  pageSize = 4096,
): number | null {
  let entries: string[];
  try {
    entries = readdirSync(procDir);
  } catch {
    return null;
  }
  const parents = new Map<number, number>();
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    try {
      const stat = readFileSync(join(procDir, entry, 'stat'), 'utf8');
      // pid (comm) state ppid ... — comm may contain spaces and parentheses.
      const after = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      parents.set(pid, Number(after[1]));
    } catch {
      // The process exited meanwhile.
    }
  }
  const children = new Map<number, number[]>();
  for (const [pid, ppid] of parents) {
    const list = children.get(ppid) ?? [];
    list.push(pid);
    children.set(ppid, list);
  }
  let total = 0;
  const stack = [...(children.get(rootPid) ?? [])];
  const seen = new Set<number>();
  while (stack.length > 0) {
    const pid = stack.pop() as number;
    if (seen.has(pid)) continue;
    seen.add(pid);
    try {
      const statm = readFileSync(join(procDir, String(pid), 'statm'), 'utf8')
        .trim()
        .split(/\s+/);
      total += Number(statm[1] ?? 0) * pageSize;
    } catch {
      // Exited.
    }
    stack.push(...(children.get(pid) ?? []));
  }
  return total;
}
