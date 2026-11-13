'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import type { ReactNode } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import type { OperationId } from '@/lib/api/types';
import { useMe, usePermissions } from '@/lib/auth/me';
import { canPerform } from '@/lib/auth/permissions';

export interface TabDefinition {
  readonly id: string;
  readonly label: string;
  /** The tab is shown when the user may perform ANY of these operations (none = everyone). */
  readonly ops?: readonly OperationId[];
}

/** The tabs a user may open (design §1.3: "tabs gated"); the api stays authoritative. */
export function useVisibleTabs(tabs: readonly TabDefinition[]): TabDefinition[] {
  const permissions = usePermissions();
  const me = useMe();
  if (!me.isSuccess) return [];
  return tabs.filter((tab) => !tab.ops || tab.ops.some((op) => canPerform(op, permissions)));
}

/**
 * Tabs whose value lives in `?tab=` (shareable, back-button safe). Only permitted tabs are
 * rendered; an unknown or forbidden `tab` falls back to the first permitted one. Changing the
 * tab drops the other tab's filters except the range.
 */
export function GatedTabs({
  tabs,
  label,
  render,
  keepParams = ['range', 'from', 'to'],
}: {
  tabs: readonly TabDefinition[];
  label: string;
  render: (tabId: string) => ReactNode;
  keepParams?: readonly string[];
}) {
  const visible = useVisibleTabs(tabs);
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const requested = searchParams.get('tab');
  const current = visible.find((tab) => tab.id === requested)?.id ?? visible[0]?.id;
  if (!current) return null;
  const select = (id: string) => {
    const next = new URLSearchParams();
    for (const key of keepParams) {
      const value = searchParams.get(key);
      if (value) next.set(key, value);
    }
    next.set('tab', id);
    router.replace(`${pathname}?${next.toString()}`, { scroll: false });
  };
  return (
    <Tabs value={current} onValueChange={select}>
      <div className="overflow-x-auto">
        <TabsList aria-label={label}>
          {visible.map((tab) => (
            <TabsTrigger key={tab.id} value={tab.id}>
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </div>
      {visible.map((tab) => (
        <TabsContent key={tab.id} value={tab.id}>
          {tab.id === current ? render(tab.id) : null}
        </TabsContent>
      ))}
    </Tabs>
  );
}
