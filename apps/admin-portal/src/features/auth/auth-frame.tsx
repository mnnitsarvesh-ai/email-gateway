import { ShieldIcon } from 'lucide-react';
import type { ReactNode } from 'react';

/** Minimal frame of the public pages: product name, one card, nothing else. */
export function AuthFrame({
  title,
  description,
  children,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
}) {
  return (
    <main
      id="main"
      className="flex min-h-screen items-center justify-center bg-background px-4 py-10"
    >
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-center gap-2 text-foreground">
          <ShieldIcon className="size-6 text-primary" aria-hidden />
          <span className="text-lg font-semibold">Email Security Gateway</span>
        </div>
        <section className="rounded-lg border bg-card p-6 shadow-sm" aria-labelledby="auth-title">
          <h1 id="auth-title" className="text-xl font-semibold">
            {title}
          </h1>
          {description ? <p className="mt-1 text-sm text-muted-foreground">{description}</p> : null}
          <div className="mt-5">{children}</div>
        </section>
      </div>
    </main>
  );
}
