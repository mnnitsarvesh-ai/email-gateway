'use client';

import { useCallback, useEffect, useState } from 'react';
import { readPreference, writePreference } from '@/lib/local-preference';

/**
 * Width of the assistant side panel on `md` and wider screens. The panel grows to `WIDE` while the
 * conversation holds wide content (tables, result cards) and the viewer has not chosen a width;
 * a width the viewer drags or sets with the keyboard is remembered per browser (a UI convenience,
 * never user data). Below `md` the panel is full screen and none of this applies.
 */
export const PANEL_MIN_WIDTH = 384;
export const PANEL_DEFAULT_WIDTH = 544;
export const PANEL_WIDE_WIDTH = 832;
export const PANEL_MAX_WIDTH = 1280;
export const PANEL_KEY_STEP = 32;
const PREFERENCE_KEY = 'assistant.panelWidth';
const DESKTOP_QUERY = '(min-width: 768px)';

const isWidth = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);

/** Largest width the viewport allows: leave at least 8% of the window visible beside the panel. */
export function maxPanelWidth(viewportWidth: number): number {
  return Math.max(PANEL_MIN_WIDTH, Math.min(PANEL_MAX_WIDTH, Math.floor(viewportWidth * 0.92)));
}

export function clampPanelWidth(width: number, viewportWidth: number): number {
  return Math.round(Math.min(maxPanelWidth(viewportWidth), Math.max(PANEL_MIN_WIDTH, width)));
}

/** True when the conversation content is wider than a normal panel can show. */
export function hasWideContent(container: HTMLElement): boolean {
  return (
    container.querySelector('table, [data-wide-content]') !== null ||
    container.scrollWidth > container.clientWidth + 4
  );
}

function viewportWidth(): number {
  return typeof window === 'undefined' ? PANEL_MAX_WIDTH : window.innerWidth;
}

export interface PanelSize {
  /** Whether the resizable desktop layout applies (`md` and wider). */
  desktop: boolean;
  /** Width in pixels to apply on desktop. */
  width: number;
  /** A width the viewer chose, or null for automatic sizing. */
  manualWidth: number | null;
  minWidth: number;
  maxWidth: number;
  /** Set a viewer-chosen width (clamped); `persist` stores it for the next visit. */
  setManualWidth: (width: number, persist?: boolean) => void;
  /** Back to automatic sizing and forget the stored width. */
  resetWidth: () => void;
  /** Report whether the conversation currently holds wide content. */
  setWideContent: (wide: boolean) => void;
}

export function usePanelSize(): PanelSize {
  const [desktop, setDesktop] = useState(false);
  const [viewport, setViewport] = useState(PANEL_MAX_WIDTH);
  const [manualWidth, setManual] = useState<number | null>(null);
  const [wideContent, setWideContent] = useState(false);

  useEffect(() => {
    const media = window.matchMedia(DESKTOP_QUERY);
    const update = () => {
      setDesktop(media.matches);
      setViewport(viewportWidth());
    };
    update();
    const stored = readPreference<number | null>(PREFERENCE_KEY, null, (v): v is number | null =>
      v === null ? true : isWidth(v),
    );
    if (stored !== null) setManual(stored);
    media.addEventListener?.('change', update);
    window.addEventListener('resize', update);
    return () => {
      media.removeEventListener?.('change', update);
      window.removeEventListener('resize', update);
    };
  }, []);

  const setManualWidth = useCallback((width: number, persist = false) => {
    const next = clampPanelWidth(width, viewportWidth());
    setManual(next);
    if (persist) writePreference(PREFERENCE_KEY, next);
  }, []);

  const resetWidth = useCallback(() => {
    setManual(null);
    writePreference(PREFERENCE_KEY, null);
  }, []);

  const automatic = wideContent ? PANEL_WIDE_WIDTH : PANEL_DEFAULT_WIDTH;
  return {
    desktop,
    width: clampPanelWidth(manualWidth ?? automatic, viewport),
    manualWidth,
    minWidth: PANEL_MIN_WIDTH,
    maxWidth: maxPanelWidth(viewport),
    setManualWidth,
    resetWidth,
    setWideContent,
  };
}
