'use client';

import { useEffect, useState } from 'react';

/** Seconds left of a `Retry-After`; counts down to 0. */
export function useCountdown(): [number, (seconds: number | null) => void] {
  const [left, setLeft] = useState(0);
  useEffect(() => {
    if (left <= 0) return;
    const timer = setTimeout(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(timer);
  }, [left]);
  return [left, (seconds) => setLeft(seconds && seconds > 0 ? seconds : 0)];
}
