import { describe, expect, it } from 'vitest';
import { resolveDayWindow, resolveInstantWindow, resolveOptionalWindow } from './window';

const NOW = new Date('2026-11-26T15:30:00.000Z');
const DAY = 86_400_000;

async function codeOf(run: () => unknown): Promise<unknown> {
  try {
    await run();
  } catch (err) {
    return (err as { getResponse?: () => unknown }).getResponse?.() ?? err;
  }
  return null;
}

describe('resolveDayWindow (D1: UTC days, ≤ 92 days)', () => {
  it('defaults to the last 30 days ending today', () => {
    const w = resolveDayWindow({}, NOW);
    expect(w.to.toISOString()).toBe('2026-11-26T00:00:00.000Z');
    expect(w.from.toISOString()).toBe('2026-10-28T00:00:00.000Z');
  });

  it('accepts exactly 92 days and refuses 93 or a reversed window', async () => {
    const ok = resolveDayWindow({ from: '2026-08-27', to: '2026-11-26' }, NOW);
    expect((ok.to.getTime() - ok.from.getTime()) / DAY + 1).toBe(92);
    expect(
      await codeOf(() => resolveDayWindow({ from: '2026-08-26', to: '2026-11-26' }, NOW)),
    ).toMatchObject({ statusCode: 400 });
    expect(
      await codeOf(() => resolveDayWindow({ from: '2026-11-27', to: '2026-11-26' }, NOW)),
    ).toMatchObject({ statusCode: 400 });
    // One day is a valid window.
    expect(resolveDayWindow({ from: '2026-11-01', to: '2026-11-01' }, NOW).from).toEqual(
      new Date('2026-11-01T00:00:00.000Z'),
    );
  });
});

describe('resolveInstantWindow / resolveOptionalWindow (D2, D4)', () => {
  it('defaults to 30 days ending now and caps at 92 days', async () => {
    const w = resolveInstantWindow({}, NOW, undefined);
    expect(w.to).toEqual(NOW);
    expect(NOW.getTime() - w.from.getTime()).toBe(30 * DAY);
    const from = new Date(NOW.getTime() - 93 * DAY);
    expect(await codeOf(() => resolveInstantWindow({ from }, NOW, undefined))).toMatchObject({
      statusCode: 400,
    });
  });

  it('reuses the window of a cursor and refuses a different one', async () => {
    const window: [number, number] = [NOW.getTime() - DAY, NOW.getTime()];
    const later = new Date(NOW.getTime() + 3_600_000);
    expect(resolveInstantWindow({}, later, window)).toEqual({
      from: new Date(window[0]),
      to: new Date(window[1]),
    });
    expect(await codeOf(() => resolveInstantWindow({ to: later }, later, window))).toMatchObject({
      code: 'cursor_invalid',
    });
  });

  it('has no window when neither bound nor a cursor window is given', () => {
    expect(resolveOptionalWindow({}, NOW, undefined)).toBeNull();
    expect(resolveOptionalWindow({ from: new Date(NOW.getTime() - DAY) }, NOW, undefined)).toEqual({
      from: new Date(NOW.getTime() - DAY),
      to: NOW,
    });
  });
});
