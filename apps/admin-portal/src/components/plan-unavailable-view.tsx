import { PackageXIcon } from 'lucide-react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';

/**
 * The standard "not available for this plan" state (step 8.6 D13, ADR-0090): a route of a
 * gateway page opened by an organization on the archive-only plan. The api decides what the
 * plan allows; this only explains why the page is not shown.
 */
export function PlanUnavailableView({ page }: { page?: string }) {
  return (
    <section
      className="mx-auto flex max-w-lg flex-col items-center gap-3 py-16 text-center"
      aria-labelledby="plan-unavailable-title"
    >
      <span className="flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <PackageXIcon className="size-6" aria-hidden />
      </span>
      <h1 id="plan-unavailable-title" className="text-2xl font-semibold">
        Not available for this plan
      </h1>
      <p className="text-sm text-muted-foreground">
        {page ? `${page} is part of` : 'This page is part of'} the email security gateway. Your
        organization uses the archive-only plan: mail is captured through journal intake and kept in
        the archive, without filtering, quarantine or delivery through the gateway.
      </p>
      <p className="text-sm text-muted-foreground">
        Ask your platform operator if your organization should move to a gateway plan.
      </p>
      <Button asChild variant="outline">
        <Link href="/">Go to your start page</Link>
      </Button>
    </section>
  );
}
