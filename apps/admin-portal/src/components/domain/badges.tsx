import { ArrowDownLeftIcon, ArrowLeftRightIcon, ArrowUpRightIcon } from 'lucide-react';
import { humanize } from '@/lib/format';
import {
  DELIVERY_TONE,
  DIRECTION_TONE,
  QUARANTINE_TONE,
  SEVERITY_TONE,
  VERDICT_TONE,
  toneOf,
} from './semantic';
import { ToneBadge } from './tone-badge';

type Value = string | null | undefined;

function label(value: Value, fallback: string): string {
  return value ? humanize(value) : fallback;
}

export function VerdictBadge({ verdict, className }: { verdict: Value; className?: string }) {
  return (
    <ToneBadge tone={toneOf(VERDICT_TONE, verdict)} className={className}>
      {label(verdict, 'No verdict')}
    </ToneBadge>
  );
}

export function SeverityBadge({ severity, className }: { severity: Value; className?: string }) {
  return (
    <ToneBadge tone={toneOf(SEVERITY_TONE, severity)} className={className}>
      {label(severity, 'None')}
    </ToneBadge>
  );
}

export function DeliveryStatusBadge({ status, className }: { status: Value; className?: string }) {
  return (
    <ToneBadge tone={toneOf(DELIVERY_TONE, status)} className={className}>
      {label(status, 'Unknown')}
    </ToneBadge>
  );
}

export function QuarantineStateBadge({ state, className }: { state: Value; className?: string }) {
  return (
    <ToneBadge tone={toneOf(QUARANTINE_TONE, state)} className={className}>
      {label(state, 'Unknown')}
    </ToneBadge>
  );
}

const DIRECTION_ICON = {
  inbound: ArrowDownLeftIcon,
  outbound: ArrowUpRightIcon,
  internal: ArrowLeftRightIcon,
} as const;

export function DirectionBadge({ direction, className }: { direction: Value; className?: string }) {
  const Icon =
    direction && direction in DIRECTION_ICON
      ? DIRECTION_ICON[direction as keyof typeof DIRECTION_ICON]
      : null;
  return (
    <ToneBadge tone={toneOf(DIRECTION_TONE, direction)} className={className}>
      {Icon ? <Icon aria-hidden /> : null}
      {label(direction, 'Unknown')}
    </ToneBadge>
  );
}
