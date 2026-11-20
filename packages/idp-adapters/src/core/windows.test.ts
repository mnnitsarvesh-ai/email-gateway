import { describe, expect, it } from 'vitest';
import { WINDOW_DEFAULTS, hasMoreWindows, nextWindow, streamLagSeconds } from './windows';

const NOW = new Date('2026-11-10T12:00:00.000Z');
const minutes = (n: number) => n * 60_000;
const at = (offsetMs: number) => new Date(NOW.getTime() + offsetMs);

describe('polling windows (D7.2)', () => {
  it('has the per-family overlap and settle defaults of the design', () => {
    expect(WINDOW_DEFAULTS.graph_sign_ins).toEqual({
      overlapMs: minutes(15),
      settleMs: minutes(2),
    });
    expect(WINDOW_DEFAULTS.graph_risk).toEqual({ overlapMs: minutes(15), settleMs: minutes(2) });
    expect(WINDOW_DEFAULTS.graph_audits).toEqual({ overlapMs: minutes(30), settleMs: minutes(5) });
    expect(WINDOW_DEFAULTS.o365_management).toMatchObject({
      overlapMs: minutes(60),
      settleMs: minutes(10),
    });
    expect(WINDOW_DEFAULTS.google_reports).toEqual({
      overlapMs: minutes(60),
      settleMs: minutes(5),
    });
  });

  it('starts a stream without watermark at now − overlap and ends at now − settle', () => {
    expect(
      nextWindow({ family: 'graph_sign_ins', watermark: null, now: NOW, retentionDays: 30 }),
    ).toEqual({
      start: at(-minutes(15)),
      end: at(-minutes(2)),
    });
  });

  it('re-reads the overlap before the watermark', () => {
    const window = nextWindow({
      family: 'graph_audits',
      watermark: at(-minutes(20)),
      now: NOW,
      retentionDays: 30,
    });
    expect(window).toEqual({ start: at(-minutes(50)), end: at(-minutes(5)) });
  });

  it('returns null when nothing new has settled', () => {
    expect(
      nextWindow({
        family: 'graph_sign_ins',
        watermark: at(-minutes(2)),
        now: NOW,
        retentionDays: 30,
      }),
    ).toBeNull();
    expect(
      nextWindow({
        family: 'graph_sign_ins',
        watermark: at(-minutes(1)),
        now: NOW,
        retentionDays: 30,
      }),
    ).toBeNull();
  });

  it('clamps the start to the provider retention (backfill, D8.1)', () => {
    const window = nextWindow({
      family: 'graph_sign_ins',
      watermark: at(-minutes(60 * 24 * 90)),
      now: NOW,
      retentionDays: 30,
    });
    expect(window?.start).toEqual(at(-minutes(60 * 24 * 30)));
  });

  it('slices Office 365 windows to 24 h and never starts before now − 7 days', () => {
    const window = nextWindow({
      family: 'o365_management',
      watermark: at(-minutes(60 * 24 * 10)),
      now: NOW,
      retentionDays: 7,
    });
    expect(window).not.toBeNull();
    expect(window!.start.getTime()).toBeGreaterThan(NOW.getTime() - minutes(60 * 24 * 7));
    expect(window!.end.getTime() - window!.start.getTime()).toBe(minutes(60 * 24));
    expect(hasMoreWindows({ family: 'o365_management', watermark: window!.end, now: NOW })).toBe(
      true,
    );
  });

  it('reports more windows only while more than one overlap of settled time remains', () => {
    expect(hasMoreWindows({ family: 'graph_sign_ins', watermark: at(-minutes(2)), now: NOW })).toBe(
      false,
    );
    expect(
      hasMoreWindows({ family: 'graph_sign_ins', watermark: at(-minutes(60)), now: NOW }),
    ).toBe(true);
  });

  it('computes stream lag in seconds', () => {
    expect(streamLagSeconds(at(-minutes(5)), NOW)).toBe(300);
    expect(streamLagSeconds(null, NOW)).toBeNull();
    expect(streamLagSeconds(at(minutes(5)), NOW)).toBe(0);
  });
});
