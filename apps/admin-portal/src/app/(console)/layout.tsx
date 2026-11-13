import type { ReactNode } from 'react';
import { AppShell } from '@/features/shell/app-shell';

// Every console route is dynamic: CSP nonces are per request (design P1, P10).
export const dynamic = 'force-dynamic';

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
