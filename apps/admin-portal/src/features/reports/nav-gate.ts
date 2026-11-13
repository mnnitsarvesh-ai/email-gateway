import { NAV_ITEMS, type Gate } from '@/lib/navigation';

/** The navigation gate of a page (design P11: the same gate guards the route). */
export function navGate(id: string): Gate {
  const item = NAV_ITEMS.find((candidate) => candidate.id === id);
  if (!item) throw new Error(`Unknown navigation item ${id}`);
  return item.gate;
}
