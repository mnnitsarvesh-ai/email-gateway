import { cn } from '@/lib/utils';

/**
 * Decorative trend line for tiles (`aria-hidden`): the value it illustrates must be stated in
 * text next to it. Missing points (`null`) break the line.
 */
export function Sparkline({
  values,
  width = 96,
  height = 28,
  colorIndex = 0,
  className,
}: {
  values: readonly (number | null)[];
  width?: number;
  height?: number;
  colorIndex?: number;
  className?: string;
}) {
  const present = values.filter((v): v is number => v !== null && Number.isFinite(v));
  if (present.length < 2) return null;
  const min = Math.min(...present);
  const max = Math.max(...present);
  const span = max - min || 1;
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const segments: string[] = [];
  let current = '';
  values.forEach((value, index) => {
    if (value === null || !Number.isFinite(value)) {
      if (current) segments.push(current);
      current = '';
      return;
    }
    const x = (index * step).toFixed(1);
    const y = (height - 2 - ((value - min) / span) * (height - 4)).toFixed(1);
    current += `${current ? 'L' : 'M'}${x},${y}`;
  });
  if (current) segments.push(current);
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className={cn('overflow-visible', className)}
    >
      {segments.map((d, i) => (
        <path
          key={i}
          d={d}
          fill="none"
          stroke={`var(--chart-${(colorIndex % 8) + 1})`}
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      ))}
    </svg>
  );
}
