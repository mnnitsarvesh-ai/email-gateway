'use client';

import { useEffect, type ReactNode } from 'react';
import { Breadcrumbs, type Crumb } from '@/components/breadcrumbs';
import { cn } from '@/lib/utils';

/** Top of every page: the single `<h1>`, description, actions; sets the document title. */
export function PageHeader({
  title,
  description,
  actions,
  breadcrumbs,
  className,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  breadcrumbs?: readonly Crumb[];
  className?: string;
}) {
  const documentTitle = `${title} · Email Security Gateway`;
  useEffect(() => {
    document.title = documentTitle;
  }, [documentTitle]);
  return (
    <header className={cn('flex flex-col gap-2 pb-4', className)}>
      {/* React hoists this into <head> and keeps it while the page is mounted. A URL-state change
          (router.replace of a tab, section or filter) re-renders Next's metadata, which removes
          its own <title> until the new payload resolves; without this element the document had
          no title in between (axe document-title, step 7.3 verification). */}
      <title>{documentTitle}</title>
      {breadcrumbs ? <Breadcrumbs items={breadcrumbs} /> : null}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid min-w-0 gap-1">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {description ? (
            <p className="max-w-3xl text-sm text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </header>
  );
}
