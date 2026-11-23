import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  clampPanelWidth,
  hasWideContent,
  maxPanelWidth,
  PANEL_DEFAULT_WIDTH,
  PANEL_MAX_WIDTH,
  PANEL_MIN_WIDTH,
  PANEL_WIDE_WIDTH,
  usePanelSize,
} from './panel-size';

function mockDesktop(matches: boolean) {
  vi.spyOn(window, 'matchMedia').mockImplementation((query: string) => ({
    matches,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }));
}

afterEach(() => {
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe('assistant panel size', () => {
  it('clamps between the minimum and 92% of the viewport, capped at the maximum', () => {
    expect(clampPanelWidth(100, 1600)).toBe(PANEL_MIN_WIDTH);
    expect(clampPanelWidth(700, 1600)).toBe(700);
    expect(clampPanelWidth(5000, 3000)).toBe(PANEL_MAX_WIDTH);
    expect(maxPanelWidth(1000)).toBe(920);
    expect(clampPanelWidth(1000, 1000)).toBe(920);
    expect(maxPanelWidth(300)).toBe(PANEL_MIN_WIDTH);
  });

  it('detects tables and horizontally overflowing content', () => {
    const container = document.createElement('div');
    expect(hasWideContent(container)).toBe(false);
    container.innerHTML = '<table><tbody><tr><td>x</td></tr></tbody></table>';
    expect(hasWideContent(container)).toBe(true);
    const plain = document.createElement('div');
    Object.defineProperty(plain, 'scrollWidth', { value: 900 });
    Object.defineProperty(plain, 'clientWidth', { value: 500 });
    expect(hasWideContent(plain)).toBe(true);
  });

  it('grows for wide content, keeps a chosen width and resets to automatic', () => {
    mockDesktop(true);
    vi.spyOn(window, 'innerWidth', 'get').mockReturnValue(1600);
    const { result } = renderHook(() => usePanelSize());
    expect(result.current.desktop).toBe(true);
    expect(result.current.width).toBe(PANEL_DEFAULT_WIDTH);

    act(() => result.current.setWideContent(true));
    expect(result.current.width).toBe(PANEL_WIDE_WIDTH);

    act(() => result.current.setManualWidth(640, true));
    expect(result.current.width).toBe(640);
    expect(window.localStorage.getItem('eg:assistant.panelWidth')).toBe('640');

    act(() => result.current.resetWidth());
    expect(result.current.manualWidth).toBeNull();
    expect(result.current.width).toBe(PANEL_WIDE_WIDTH);
  });

  it('restores a stored width and ignores an invalid one', () => {
    mockDesktop(true);
    vi.spyOn(window, 'innerWidth', 'get').mockReturnValue(1600);
    window.localStorage.setItem('eg:assistant.panelWidth', '700');
    expect(renderHook(() => usePanelSize()).result.current.width).toBe(700);
    window.localStorage.setItem('eg:assistant.panelWidth', '"wide"');
    expect(renderHook(() => usePanelSize()).result.current.width).toBe(PANEL_DEFAULT_WIDTH);
  });

  it('does not apply a desktop width below md', () => {
    mockDesktop(false);
    expect(renderHook(() => usePanelSize()).result.current.desktop).toBe(false);
  });
});
