import { cn } from '@/lib/utils';
import { riskBand } from './semantic';

const BAR: Record<string, string> = {
  success: 'bg-success',
  warning: 'bg-warning',
  orange: 'bg-chart-3',
  danger: 'bg-destructive',
};

/** 0–1000 risk score: bar, number and band label (`null` → "Not scored"). */
export function RiskScore({
  score,
  level,
  className,
}: {
  score: number | null | undefined;
  /** The API's own risk level, when it returns one, overrides the display band label. */
  level?: string | null;
  className?: string;
}) {
  if (score === null || score === undefined || !Number.isFinite(score)) {
    return <span className={cn('text-sm text-muted-foreground', className)}>Not scored</span>;
  }
  const clamped = Math.max(0, Math.min(1000, Math.round(score)));
  const band = riskBand(clamped);
  const bandLabel = level ? level.charAt(0).toUpperCase() + level.slice(1) : band.label;
  return (
    <span className={cn('inline-flex items-center gap-2', className)}>
      <span
        role="meter"
        aria-valuemin={0}
        aria-valuemax={1000}
        aria-valuenow={clamped}
        aria-label={`Risk score ${clamped} of 1000, ${bandLabel}`}
        className="relative h-1.5 w-16 overflow-hidden rounded-full bg-muted"
      >
        <span
          className={cn('absolute inset-y-0 left-0 rounded-full', BAR[band.tone])}
          style={{ width: `${clamped / 10}%` }}
        />
      </span>
      <span className="font-mono text-sm tabular-nums">{clamped}</span>
      <span className="text-xs text-muted-foreground">{bandLabel}</span>
    </span>
  );
}
