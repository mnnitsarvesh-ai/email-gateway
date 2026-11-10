import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';

/**
 * CPU time and RSS of the analyzer child (step 4.6 X4: the parent samples `/proc/<pid>` on
 * Linux and kills on the configured limits). Elsewhere (the macOS development host) `ps` with a
 * fixed argument list. The same approach as the email-worker's inspector pool (ADR-0028/0036),
 * which cannot be imported across apps.
 */

export interface ProcessSample {
  cpuSeconds: number;
  rssMb: number;
}

export type ProcessSampler = (pid: number) => Promise<ProcessSample | null>;

/** Linux clock ticks per second (`getconf CLK_TCK`; 100 on every Linux ABI Node supports). */
const CLOCK_TICKS = 100;

/** `utime + stime` of `/proc/<pid>/stat` (fields 14 and 15, after the parenthesized comm). */
export function parseProcStat(text: string): number | null {
  const close = text.lastIndexOf(')');
  if (close < 0) return null;
  const fields = text.slice(close + 2).split(' ');
  const utime = Number(fields[11]);
  const stime = Number(fields[12]);
  if (!Number.isFinite(utime) || !Number.isFinite(stime)) return null;
  return (utime + stime) / CLOCK_TICKS;
}

/** `VmRSS` of `/proc/<pid>/status` in MiB. */
export function parseProcStatusRss(text: string): number | null {
  const match = /^VmRSS:\s+(\d+)\s+kB$/m.exec(text);
  return match ? Number(match[1]) / 1024 : null;
}

/** `ps -o time=` → seconds: `[[dd-]hh:]mm:ss[.ff]`. */
export function parsePsTime(text: string): number | null {
  const match = /^\s*(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)\s*$/.exec(text);
  if (!match) return null;
  const [, days, hours, minutes, seconds] = match;
  return (
    Number(days ?? 0) * 86_400 + Number(hours ?? 0) * 3_600 + Number(minutes) * 60 + Number(seconds)
  );
}

export const procSampler: ProcessSampler = async (pid) => {
  try {
    const [stat, status] = await Promise.all([
      readFile(`/proc/${String(pid)}/stat`, 'latin1'),
      readFile(`/proc/${String(pid)}/status`, 'latin1'),
    ]);
    const cpuSeconds = parseProcStat(stat);
    const rssMb = parseProcStatusRss(status);
    return cpuSeconds === null || rssMb === null ? null : { cpuSeconds, rssMb };
  } catch {
    return null;
  }
};

export const psSampler: ProcessSampler = (pid) =>
  new Promise((resolve) => {
    execFile(
      'ps',
      ['-o', 'time=,rss=', '-p', String(pid)],
      { timeout: 1_000, env: { PATH: '/usr/bin:/bin' } },
      (error, stdout) => {
        if (error) return resolve(null);
        const [time, rss] = stdout.trim().split(/\s+/);
        const cpuSeconds = parsePsTime(time ?? '');
        const rssKb = Number(rss);
        resolve(
          cpuSeconds === null || !Number.isFinite(rssKb)
            ? null
            : { cpuSeconds, rssMb: rssKb / 1024 },
        );
      },
    );
  });

export const defaultSampler = (): ProcessSampler =>
  process.platform === 'linux' ? procSampler : psSampler;
