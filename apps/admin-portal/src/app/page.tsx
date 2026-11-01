import { Inbox, MailWarning, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { fetchPlatformHealth } from '@/lib/platform-health';

export const dynamic = 'force-dynamic';

const metrics = [
  { label: 'Messages processed (24h)', icon: Inbox },
  { label: 'Threats blocked (24h)', icon: ShieldAlert },
  { label: 'In quarantine', icon: MailWarning },
];

const statusBadge = {
  ok: <Badge variant="success">Operational</Badge>,
  degraded: <Badge variant="destructive">Degraded</Badge>,
  unreachable: <Badge variant="destructive">API unreachable</Badge>,
} as const;

export default async function DashboardPage() {
  const health = await fetchPlatformHealth();

  return (
    <main className="mx-auto flex max-w-6xl flex-col gap-8 px-6 py-10">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <ShieldCheck className="size-8" aria-hidden />
          <div>
            <h1 className="text-2xl font-semibold">Email Security Gateway</h1>
            <p className="text-sm text-muted-foreground">Administration console</p>
          </div>
        </div>
        {statusBadge[health.status]}
      </header>

      <section className="grid gap-4 sm:grid-cols-3" aria-label="Mail flow summary">
        {metrics.map(({ label, icon: Icon }) => (
          <Card key={label}>
            <CardHeader>
              <CardDescription className="flex items-center gap-2">
                <Icon className="size-4" aria-hidden />
                {label}
              </CardDescription>
              <CardTitle className="text-3xl tabular-nums">—</CardTitle>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              Available once the reporting service is connected.
            </CardContent>
          </Card>
        ))}
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Platform dependencies</CardTitle>
          <CardDescription>
            Readiness reported by the API{health.version ? ` (version ${health.version})` : ''}.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {health.checks.length === 0 ? (
            <p className="text-sm text-muted-foreground">No readiness data available.</p>
          ) : (
            <ul className="divide-y">
              {health.checks.map((check) => (
                <li key={check.name} className="flex items-center justify-between py-3">
                  <span className="font-mono text-sm">{check.name}</span>
                  <span className="flex items-center gap-3 text-sm text-muted-foreground">
                    {check.latencyMs} ms
                    <Badge variant={check.status === 'ok' ? 'success' : 'destructive'}>
                      {check.status}
                    </Badge>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
