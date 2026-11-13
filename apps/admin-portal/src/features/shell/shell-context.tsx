'use client';

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

/** Lets a page put controls (e.g. the global RangePicker) into the top bar slot. */
interface ShellSlots {
  readonly topBarSlot: ReactNode;
  readonly setTopBarSlot: (node: ReactNode) => void;
}

const ShellSlotContext = createContext<ShellSlots | null>(null);

export function ShellSlotProvider({ children }: { children: ReactNode }) {
  const [topBarSlot, setTopBarSlot] = useState<ReactNode>(null);
  return (
    <ShellSlotContext.Provider value={{ topBarSlot, setTopBarSlot }}>
      {children}
    </ShellSlotContext.Provider>
  );
}

export function useShellSlots(): ShellSlots {
  return useContext(ShellSlotContext) ?? { topBarSlot: null, setTopBarSlot: () => undefined };
}

/** Renders `node` in the top bar while the calling page is mounted. */
export function TopBarSlot({ children }: { children: ReactNode }) {
  const { setTopBarSlot } = useShellSlots();
  useEffect(() => {
    setTopBarSlot(children);
    return () => setTopBarSlot(null);
  }, [children, setTopBarSlot]);
  return null;
}
