'use client';

import { useId, type ReactNode } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DESKTOP_QUERY, MOBILE_QUERY, useMediaQuery } from '@/hooks/use-media-query';
import { cn } from '@/lib/utils';
import type { SectionDefinition, SectionId } from './sections';

export type NavMode = 'desktop' | 'tablet' | 'mobile';

/** Desktop ≥ 1280 px, mobile < 768 px, tablet in between (7.1 breakpoints, design P11). */
export function useNavMode(): NavMode {
  const desktop = useMediaQuery(DESKTOP_QUERY);
  const mobile = useMediaQuery(MOBILE_QUERY);
  return desktop ? 'desktop' : mobile ? 'mobile' : 'tablet';
}

/**
 * Section navigation of the details page (§2 E11, E15): vertical Radix Tabs on desktop, a
 * horizontally scrollable tab list on tablet, a labelled native `<select>` on mobile. Only the
 * active section's panel is mounted (its queries run only then). `allowed = false` renders the
 * panel (the forbidden state) without a matching tab.
 */
export function SectionNav({
  sections,
  active,
  allowed,
  onChange,
  children,
}: {
  sections: readonly SectionDefinition[];
  active: SectionDefinition;
  allowed: boolean;
  onChange: (section: SectionId) => void;
  children: ReactNode;
}) {
  const mode = useNavMode();
  const selectId = useId();
  if (mode === 'mobile') {
    return (
      <div className="grid gap-4">
        <div className="grid gap-1">
          <label htmlFor={selectId} className="text-xs font-medium text-muted-foreground">
            Section
          </label>
          <select
            id={selectId}
            className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            value={allowed ? active.id : ''}
            onChange={(event) => onChange(event.target.value as SectionId)}
          >
            {allowed ? null : <option value="">{active.label} (no access)</option>}
            {sections.map((section) => (
              <option key={section.id} value={section.id}>
                {section.label}
              </option>
            ))}
          </select>
        </div>
        <div className="min-w-0">{children}</div>
      </div>
    );
  }
  const desktop = mode === 'desktop';
  return (
    <Tabs
      value={active.id}
      onValueChange={(value) => onChange(value as SectionId)}
      orientation={desktop ? 'vertical' : 'horizontal'}
      activationMode="manual"
      className={cn(desktop && 'grid grid-cols-[15rem_minmax(0,1fr)] items-start gap-6')}
    >
      <TabsList
        aria-label="Message sections"
        className={cn(
          desktop
            ? 'sticky top-4 h-auto w-full flex-col items-stretch gap-0.5 overflow-visible'
            : 'w-full max-w-full justify-start',
        )}
      >
        {sections.map((section) => (
          <TabsTrigger
            key={section.id}
            value={section.id}
            className={cn(desktop && 'h-8 justify-start')}
          >
            {section.label}
          </TabsTrigger>
        ))}
      </TabsList>
      {allowed ? (
        <TabsContent value={active.id} className="min-w-0">
          {children}
        </TabsContent>
      ) : (
        <div className="min-w-0">{children}</div>
      )}
    </Tabs>
  );
}
