/** Visible whenever the BFF answers from dev fixtures (design P9). */
export function DevFixturesBadge() {
  return (
    <span
      className="rounded-sm border border-warning bg-warning px-1.5 py-0.5 font-mono text-xs font-semibold text-warning-foreground"
      title="The portal answers from synthetic development fixtures, not the API"
    >
      DEV FIXTURES
    </span>
  );
}
