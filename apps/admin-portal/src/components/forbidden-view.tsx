import { LockIcon } from 'lucide-react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { describeRequirement } from '@/lib/auth/permissions';
import type { Gate } from '@/lib/navigation';

/** The 403 page content used by `<RouteGate>` and `/forbidden`. */
export function ForbiddenView({ gate }: { gate?: Gate }) {
  const requirements =
    gate && gate !== 'authenticated'
      ? [...new Set(gate.flatMap((op) => describeRequirement(op)))]
      : [];
  return (
    <section
      className="mx-auto flex max-w-lg flex-col items-center gap-3 py-16 text-center"
      aria-labelledby="forbidden-title"
    >
      <span className="flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <LockIcon className="size-6" aria-hidden />
      </span>
      <h1 id="forbidden-title" className="text-2xl font-semibold">
        You do not have access to this page
      </h1>
      <p className="text-sm text-muted-foreground">
        Your role does not include the permission this page needs. Ask an organization administrator
        if you need access.
      </p>
      {requirements.length > 0 ? (
        <p className="text-sm text-muted-foreground">
          Requires one of:{' '}
          {requirements.map((r, i) => (
            <code
              key={i}
              className="mx-0.5 rounded-sm bg-muted px-1 py-0.5 font-mono text-xs text-foreground"
            >
              {r}
            </code>
          ))}
        </p>
      ) : null}
      <Button asChild variant="outline">
        <Link href="/">Go to your start page</Link>
      </Button>
    </section>
  );
}
