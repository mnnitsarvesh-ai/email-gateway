import type { ReactNode } from 'react';
import { Badge } from '@/components/ui/badge';
import type { Tone } from '@/lib/design/tokens';
import { cn } from '@/lib/utils';

export function ToneBadge({
  tone,
  children,
  className,
  title,
}: {
  tone: Tone;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <Badge variant={tone} className={cn(className)} title={title} data-tone={tone}>
      {children}
    </Badge>
  );
}
