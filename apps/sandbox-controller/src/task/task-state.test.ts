import { describe, expect, it } from 'vitest';
import {
  allPaths,
  canTransition,
  InvalidTransitionError,
  pathViolations,
  TASK_STATES,
  TASK_TRANSITIONS,
  TaskStateTracker,
  TERMINAL_STATES,
} from './task-state';

describe('task state machine (X7)', () => {
  it('has a transition list for every state and only known targets', () => {
    for (const state of TASK_STATES) {
      expect(TASK_TRANSITIONS[state]).toBeDefined();
      for (const next of TASK_TRANSITIONS[state]) expect(TASK_STATES).toContain(next);
    }
    for (const terminal of TERMINAL_STATES) expect(TASK_TRANSITIONS[terminal]).toEqual([]);
  });

  it('every state is reachable from received and every path ends in a terminal state', () => {
    const paths = allPaths();
    const seen = new Set(paths.flat());
    for (const state of TASK_STATES) expect(seen.has(state), state).toBe(true);
    for (const path of paths) expect(TERMINAL_STATES).toContain(path[path.length - 1]);
  });

  it('holds the invariants on every path of the table', () => {
    for (const path of allPaths()) expect(pathViolations(path), path.join(' → ')).toEqual([]);
  });

  it('cleans up before publishing, acking or retrying once scratch/runner exist', () => {
    for (const path of allPaths().filter((p) => p.includes('running'))) {
      const cleaned = path.indexOf('cleaned');
      for (const exit of ['published', 'acked', 'transient_failure'] as const) {
        const at = path.indexOf(exit);
        if (at >= 0) expect(cleaned).toBeGreaterThanOrEqual(0);
        if (at >= 0) expect(cleaned).toBeLessThan(at);
      }
    }
  });

  it('publishes before acking (except an in-process duplicate, which never runs)', () => {
    for (const path of allPaths().filter((p) => p.includes('acked'))) {
      const acked = path.indexOf('acked');
      const published = path.indexOf('published');
      if (path.includes('duplicate')) expect(path).toEqual(['received', 'duplicate', 'acked']);
      else expect(published).toBeGreaterThanOrEqual(0);
      if (published >= 0) expect(published).toBeLessThan(acked);
    }
  });

  it('has no verdict state (the controller never produces clean)', () => {
    expect(
      TASK_STATES.some((s) => /clean$|verdict|malicious|suspicious/.test(s) && s !== 'cleaned'),
    ).toBe(false);
  });

  it('detects violations in hand-made bad paths', () => {
    expect(
      pathViolations([
        'received',
        'validated',
        'admitted',
        'fetching',
        'running',
        'collected',
        'published',
        'acked',
      ]),
    ).toEqual(['published before cleaned', 'acked before cleaned']);
    expect(pathViolations(['received', 'acked'])).toEqual(['acked without a confirmed publish']);
  });

  it('tracker refuses transitions outside the table', () => {
    const t = new TaskStateTracker();
    t.to('validated');
    t.to('admitted');
    expect(() => t.to('published')).toThrow(InvalidTransitionError);
    t.to('fetching');
    t.to('running');
    expect(t.createdResources).toBe(true);
    expect(() => t.to('cleaned')).toThrow(InvalidTransitionError);
    t.to('collected');
    t.to('cleaned');
    t.to('stored');
    t.to('published');
    t.to('acked');
    expect(t.history).toEqual([
      'received',
      'validated',
      'admitted',
      'fetching',
      'running',
      'collected',
      'cleaned',
      'stored',
      'published',
      'acked',
    ]);
    expect(t.is('acked')).toBe(true);
    expect(canTransition('acked', 'published')).toBe(false);
  });
});
