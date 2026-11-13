import { SearchXIcon } from 'lucide-react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';

/** 404: also what another tenant's ids look like (design P8). */
export function NotFoundView() {
  return (
    <section
      className="mx-auto flex max-w-lg flex-col items-center gap-3 py-16 text-center"
      aria-labelledby="not-found-title"
    >
      <span className="flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <SearchXIcon className="size-6" aria-hidden />
      </span>
      <h1 id="not-found-title" className="text-2xl font-semibold">
        Page not found
      </h1>
      <p className="text-sm text-muted-foreground">
        It does not exist, or you do not have access to it.
      </p>
      <Button asChild variant="outline">
        <Link href="/">Go to your start page</Link>
      </Button>
    </section>
  );
}
