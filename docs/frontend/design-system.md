# Admin portal design system

The visual and interaction rules of the admin portal (`apps/admin-portal`), step 7.1. Decisions: [ADR-0059](../architecture/adr/0059-admin-portal-design-system.md) (design system) and [ADR-0058](../architecture/adr/0058-admin-portal-architecture.md) (architecture); design note [docs/plan/steps/20-admin-portal.md](../plan/steps/20-admin-portal.md) P8, P11–P14. This document is binding for every page package: use these tokens and components, do not invent local variants. If a shared component blocks you, work around it in your feature folder and record it in §13 of the design note.

Contents: [principles](#principles) · [tokens](#tokens) · [typography](#typography) · [spacing, radius, elevation, motion](#spacing-radius-elevation-motion) · [layout and breakpoints](#layout-and-breakpoints) · [components](#components) · [states](#states) · [tables](#tables) · [forms](#forms) · [charts](#charts) · [data fetching](#data-fetching) · [accessibility rules](#accessibility-rules) · [content-safety rules](#content-safety-rules-p12) · [dark mode](#dark-mode) · [dev fixtures](#dev-fixtures) · [testing pages](#testing-pages) · [token tables](#token-tables)

## Principles

1. **Real data or an honest state.** Every number comes from an API operation. Missing data is an `EmptyState`; missing features are an `UnavailableState` naming the step; failures are an `ErrorState` with the `requestId`. Never a placeholder number, never an estimate, never "—" pretending to be a value.
2. **Security data is dense; keep it calm.** Neutral surfaces, one accent (primary blue), colour reserved for meaning (verdicts, severities, states). Colour is never the only cue: badges carry text, charts carry text legends and a table.
3. **The API is authoritative.** The UI hides what a user cannot do (`<Can>`, `<RouteGate>`), but every rule is enforced by the API; a `403` from the API is rendered, not swallowed.
4. **Accessible by construction.** WCAG 2.2 AA: contrast is tested on the tokens, components are keyboard operable and labelled, and every page test runs axe.

## Tokens

All tokens are CSS custom properties in `src/app/globals.css`, in OKLCH, defined for light (`:root`) and dark (`.dark`), and mapped into Tailwind 4 with `@theme inline` (so `bg-card`, `text-muted-foreground`, `bg-tone-danger`, `text-sidebar-foreground` … exist). Use the Tailwind classes; reference raw variables (`var(--chart-3)`) only where a class cannot be used (SVG attributes in charts).

| Group                         | Tokens                                                                                                                                               | Use                                                                                  |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Surfaces                      | `background`, `card`, `popover`, `muted` (+ `-foreground`)                                                                                           | Workspace, cards and panels, menus and dialogs, subdued areas                        |
| Lines                         | `border` (decorative separators), `input` (form-control boundaries, ≥ 3:1), `ring` (focus indicator, ≥ 3:1)                                          | Never use `border` for an input boundary                                             |
| Actions                       | `primary`, `secondary`, `accent`, `destructive` (+ `-foreground`)                                                                                    | One primary action per view; `destructive` only for irreversible or removing actions |
| Feedback                      | `success`, `warning`, `info` (+ `-foreground`)                                                                                                       | Solid status surfaces (rare); badges use tones                                       |
| Sidebar (navy in both themes) | `sidebar`, `sidebar-foreground`, `sidebar-muted`, `sidebar-accent`, `sidebar-accent-foreground`, `sidebar-primary`, `sidebar-border`, `sidebar-ring` | The navigation rail and drawer only                                                  |
| Override banner               | `banner`, `banner-foreground`                                                                                                                        | The persistent "Acting in …" banner only                                             |
| Tones                         | `tone-{neutral,info,success,warning,orange,danger,purple,magenta}` (+ `-foreground`)                                                                 | Badge backgrounds and text; the semantic scales below map values to tones            |
| Charts                        | `chart-1` … `chart-8`, `chart-grid`                                                                                                                  | Categorical series in this order; each ≥ 3:1 against `card` in both themes           |

**Semantic scales** (`src/components/domain/semantic.ts`, the only place that maps a value to a tone; every badge also prints the label):

| Scale            | Value → tone                                                                                                                                                                                  |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Verdict          | `clean` success · `spam` warning · `bulk` neutral · `phishing` orange · `malware` danger · `bec` magenta · `dlp_violation` purple · `suspicious` warning · `unknown` neutral · `none` neutral |
| Severity         | `none` neutral · `info` info · `low` info · `medium` warning · `high` orange · `critical` danger                                                                                              |
| Delivery status  | `delivered` success · `pending`, `in_progress`, `queued` info · `deferred` warning · `bounced`, `failed` danger · `expired` orange · `suppressed`, `unknown` neutral                          |
| Quarantine state | `held` warning · `pending_approval` purple · `releasing` info · `released` success · `rejected` danger · `deleted`, `expired`, `superseded` neutral                                           |
| Direction        | `inbound` info · `outbound` purple · `internal` neutral (with an arrow icon and the word)                                                                                                     |
| Risk score       | 0–1000 bar: < 300 success · < 600 warning · < 800 orange · ≥ 800 danger (bands are display only; the API's `riskLevel`, when present, wins)                                                   |

Values and measured contrast ratios are in the [token tables](#token-tables) at the end (generated from `globals.css`; the test `src/lib/design/tokens.test.ts` recomputes them on every run and fails below AA).

## Typography

- **Inter Variable** for the UI and **JetBrains Mono Variable** for ids, hashes, header values, codes and secrets; both self-hosted from `@fontsource-variable/*` (no external font requests).
- Scale (`text-*`): 12/16 (`xs`), 13/18 (`2xs`), **14/20 (`sm`, body default)**, 16/24 (`base`), 18/26 (`lg`), 20/28 (`xl`), 24/32 (`2xl`), 30/36 (`3xl`). Page title `text-2xl font-semibold`; section title `text-lg font-semibold`; card title `text-base font-semibold`; table text `text-sm`; captions and meta `text-xs text-muted-foreground`.
- Numbers use `tabular-nums` (table cells do by default). Format counts with `formatNumber` (`Intl.NumberFormat`, browser locale); percentages with one decimal; durations with `formatDuration` (`ms`, `s`, `min`).
- Never use colour alone to carry emphasis; use weight or an icon with a label.

## Spacing, radius, elevation, motion

- 4 px grid (Tailwind spacing). Page padding `px-4 md:px-6 lg:px-8`, section gap `gap-6`, card padding `p-4 md:p-5`, form field gap `gap-4`.
- Radius: `rounded-sm` 6 px (badges, inputs inside tables), `rounded-md` 8 px (buttons, inputs), `rounded-lg` 10 px (cards, dialogs), `rounded-xl` 14 px (hero panels only).
- Elevation: `shadow-xs` (cards), `shadow-sm` (popovers, menus, sticky headers), `shadow-lg` (dialogs, drawers). Dark mode relies more on surface steps than shadows.
- Motion ≤ 200 ms (`--motion-fast` 120 ms for hover/press, `--motion-base` 200 ms for overlays); everything is disabled under `prefers-reduced-motion: reduce` (global rule in `globals.css`).
- Density: table rows 36 px (compact, default) or 44 px (comfortable toggle in the DataTable toolbar). Interactive targets are at least 24 × 24 px (WCAG 2.5.8); icon buttons are 32 px (`size="icon"`), 36 px in toolbars.

## Layout and breakpoints

| Width       | Name    | Sidebar                                                                                                          | Tables                                                            |
| ----------- | ------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| < 768 px    | mobile  | Hidden; a menu button in the top bar opens it as a modal drawer (focus-trapped, closes on navigation and Escape) | Stacked card list (`mobileCard` renderer of the DataTable)        |
| 768–1279 px | tablet  | Collapsed icon rail (64 px) with tooltips; expandable                                                            | Horizontal scroll inside the table container, sticky first column |
| ≥ 1280 px   | desktop | Expanded (256 px), collapsible; the collapsed state is remembered in `localStorage`                              | Full table                                                        |

- The top bar is sticky (`--topbar-height` 56 px); `scroll-padding-top` keeps focused elements visible below it (WCAG 2.4.11).
- Page structure: `<PageHeader title description actions breadcrumbs />`, then content sections. Content width is fluid; forms are limited to `max-w-2xl`; detail pages use a two-column grid from `lg`.
- No horizontal page scroll at any width ≥ 320 px. Wide content scrolls inside its own container. Grid items inside `<main id="main">` get `min-width: 0` from a base-layer rule in `globals.css` (a grid item's automatic minimum is its min-content width, so one wide table or filter bar used to widen the whole page; correction of step 7.1 WP6, checked by the e2e overflow test at 1440, 834 and 390 px).

## Components

Primitives live in `src/components/ui/` (shadcn/ui, new-york style, themed only through tokens); composites in `src/components/`; domain components in `src/components/domain/`; charts in `src/components/charts/`. Import with the `@/components/...` alias.

| Component                                                                                                   | Use it for                                                                                                       | Notes                                                                                                                                                |
| ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Button` (`default`, `secondary`, `outline`, `ghost`, `destructive`, `link`; `sm`, `default`, `lg`, `icon`) | Actions                                                                                                          | Icon-only buttons need `aria-label`. One `default` (primary) button per view                                                                         |
| `Input`, `Textarea`, `Select`, `Checkbox`, `Switch`, `RadioGroup`, `Label`                                  | Form controls                                                                                                    | Always inside `FormField` (forms) or with a `Label` (filters)                                                                                        |
| `Combobox`                                                                                                  | Pick one value from a long or searchable list (organizations, domains)                                           | `cmdk` based; async search with `onSearch`                                                                                                           |
| `Form`, `FormField`, `FormItem`, `FormLabel`, `FormControl`, `FormDescription`, `FormMessage`               | Every form (react-hook-form bindings)                                                                            | See [forms](#forms)                                                                                                                                  |
| `Badge`, `ToneBadge`                                                                                        | Short status labels                                                                                              | Domain badges below wrap `ToneBadge`                                                                                                                 |
| `Card`                                                                                                      | Grouping a section                                                                                               | Not for every element; prefer whitespace                                                                                                             |
| `Tabs`                                                                                                      | Sub-views of one page                                                                                            | Tab value in the URL (`useUrlState`, `?tab=`)                                                                                                        |
| `Dialog`, `Sheet`                                                                                           | Focused tasks (create, edit), side panels and the mobile navigation                                              | Title required; Escape closes; focus returns to the trigger                                                                                          |
| `ConfirmDialog`                                                                                             | Every destructive or state-changing confirmation                                                                 | `typedConfirmation="<name>"` for irreversible actions (delete domain, delete organization): the confirm button stays disabled until the text matches |
| `SecretRevealDialog`                                                                                        | Secrets returned once (API keys, SMTP passwords, webhook secrets, TOTP secret, recovery codes)                   | Copy buttons, an acknowledgement checkbox before closing, `gcTime: 0`, calls `reset()` of the mutation on close; never log or persist                |
| `DropdownMenu`                                                                                              | Row actions and overflow menus                                                                                   | Trigger is an icon button with an `aria-label` naming the row                                                                                        |
| `Popover`, `Tooltip`                                                                                        | Pickers; definitions of terms                                                                                    | Tooltips hold supplementary text only; never the only place of required information                                                                  |
| `DataTable`                                                                                                 | Every list                                                                                                       | See [tables](#tables)                                                                                                                                |
| `LoadingState`, `EmptyState`, `ErrorState`, `UnavailableState`                                              | The four non-success states                                                                                      | See [states](#states)                                                                                                                                |
| `KpiTile`                                                                                                   | One reported number with its label, definition tooltip, `generatedAt` and a link to the detailed page            | `value: null` → its `emptyText` ("No completed deliveries in range"); loading and error built in                                                     |
| `RangePicker`, `useRangeState`                                                                              | Report ranges: `24h` (hour buckets), `7d`, `30d` (day) and custom from/to (UTC days, ≤ 31 days)                  | URL state `?range=7d` or `?from=&to=`; the bound is `REPORTS_MAX_RANGE_DAYS` (31, the api default); a `400` from the api is shown with its message   |
| `PageHeader`, `Breadcrumbs`                                                                                 | Top of every page                                                                                                | `title` becomes the document title                                                                                                                   |
| `Toaster` (sonner; `toast.success/error`)                                                                   | Transient confirmations and background errors                                                                    | Never the only place of an error that blocks the user; forms show errors inline                                                                      |
| `VerdictBadge`, `DirectionBadge`, `DeliveryStatusBadge`, `QuarantineStateBadge`, `SeverityBadge`            | Security values                                                                                                  | Unknown values render as neutral with the raw value                                                                                                  |
| `RiskScore`                                                                                                 | 0–1000 score                                                                                                     | Bar + number + band label; `null` → "Not scored"                                                                                                     |
| `DateTime`                                                                                                  | Every timestamp                                                                                                  | Relative text ("5 min ago") with the absolute UTC time in `title`; `<time dateTime>`                                                                 |
| `CopyableId`                                                                                                | Ids, hashes, request ids                                                                                         | Monospace, middle-truncated, copy button with a status message                                                                                       |
| `UntrustedText`                                                                                             | Every attacker-controlled string (subjects, senders, filenames, URLs, webhook response snippets, audit metadata) | Text only, truncated with the full value in `title`, never a link; `copy` prop adds a copy button for URLs                                           |
| `PlatformHealthCard` (`src/features/shell`)                                                                 | Platform readiness on the dashboard                                                                              | Renders only for `platform:operations`                                                                                                               |

Permission helpers: `<Can op="DomainsController_create_v1">…</Can>` hides children the user cannot use; `<RouteGate gate={[...]}>` wraps a page (the console layout already applies the navigation item's gate to every route under its href; pages without a navigation entry wrap themselves); `useCan(op)` returns a boolean.

## States

| State       | Component          | Content                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Loading     | `LoadingState`     | Skeletons shaped like the content (tables: skeleton rows; tiles: skeleton value). `aria-busy` on the region and a visually hidden "Loading …" label. No spinners for page content                                                                                                                                                                                                                                                           |
| Empty       | `EmptyState`       | Icon, title ("No domains yet"), one sentence, the primary action when the user may perform it. Filtered empty: "No results match these filters" with "Clear filters"                                                                                                                                                                                                                                                                        |
| Error       | `ErrorState`       | Title by status (`400` "The request was not accepted", `403` "You do not have access", `404` "Not found", `409` "Conflict", `429` "Too many requests", `5xx`/network "Something went wrong"), the API message, the `code`, the `requestId` with a copy button, Retry. `403` lists the permissions the operation requires (from `operations.gen.ts`). `404` uses the not-found wording (another tenant's ids look exactly like missing ones) |
| Unavailable | `UnavailableState` | "Arrives in step 8.1", what is missing in one sentence, the plan reference. For features the platform does not offer at all (prices, invoices), the same component with `step={null}` and the reason                                                                                                                                                                                                                                        |

## Tables

`DataTable` (`src/components/data-table/`) wraps TanStack Table for server-side cursor lists:

- **Data:** pass the result of `useCursorList(operationId, filters)`. It reads `data` or `items` (the 5.3 quarantine lists), handles cursor v0 and v1, keeps a cursor stack (Previous pops it), resets to page 1 on any filter change, and shows "Page N · R rows" (no totals exist). A short page with a `nextCursor` (scan budget) shows "More results may exist further back — Load next page".
- **Filter bar:** `filters` slot (render `Select`/`Input` bound to `useUrlState`), `search` (debounced 300 ms, written to the URL), "Clear filters".
- **Sort:** only when the operation declares `sort` (`operations[id].sort`); the header button cycles through the allowed values only. v0 lists have a fixed order and show no sort control.
- **Columns:** `ColumnDef<Row>[]` with `meta: { label, hideable?, className? }`; a column visibility menu persisted per `tableId` in `localStorage` (guarded by try/catch; nothing else of the table is persisted).
- **Rows:** `rowActions(row)` renders a `DropdownMenu` per row; `enableSelection` adds checkboxes and the `bulkActions(selectedRows)` slot (selection is per page and cleared on page change).
- **Responsive:** sticky first column and horizontal scroll inside the container at tablet; `mobileCard(row)` renders a stacked card per row below 768 px (required for every table used on mobile).
- **States:** skeleton rows while loading, `EmptyState` (or the filtered-empty variant), `ErrorState` with `requestId`; previous data stays visible while the next page loads.
- **Accessibility:** a real `<table>` with a visually hidden `<caption>`, `aria-sort` on sorted headers, `aria-busy` while fetching, row action buttons named after the row.

## Forms

- `react-hook-form` + `zod` (v4) with `zodResolver`. One schema per form in the feature folder, a **strict** object (`z.object({...}).strict()`) mirroring the operation's request schema. Every form has a test calling `expectRequestMatchesContract(operationId, body)` on its output.
- Submit through `useApiMutation(operationId)`: `submit(input)` resolves to `{ ok: true, data }` or `{ ok: false, error }` (it never throws); one `Idempotency-Key` per submission, reused by `retry()`; replays toast "Already applied"; `429` disables the submit button with a countdown (`retryAfterSeconds`); `403 mfa_required` opens the MFA dialog.
- Errors: `applyApiErrors(form, error)` maps `400 validation_failed` lines (`"<path>: <issue>"`) to fields and puts the rest, and every other `4xx` message, in a `FormErrorSummary` at the top of the form (`role="alert"`). Field errors use `FormMessage` (`aria-describedby`, `aria-invalid`).
- Labels are visible (no placeholder-only fields); required fields are marked "(required)" in text; helper text under the field; passwords show the policy (12–128 characters) and a show/hide toggle.
- Destructive submits go through `ConfirmDialog`.

## Charts

Recharts wrapped in `src/components/charts/`; never use Recharts directly in a page.

- `ChartFigure` renders `<figure>` with a `<figcaption>` (title + description), the chart in a container with `role="img"` and an `aria-label` built from a computed summary (total, peak, trend), a "View data as table" toggle that renders a real `<table>` with a `<caption>`, and text legends. The chart region is focusable; arrow keys move the active point and the tooltip follows (keyboard reachable).
- Wrappers: `TimeSeriesChart` (line or stacked area over buckets), `BarChart` (horizontal or vertical, optionally stacked), `DonutChart` (≤ 6 slices, others grouped), `Sparkline` (decorative trend inside a tile, `aria-hidden` with the value stated in text).
- Colours come from `--chart-1…8` in series order (blue, orange, aqua, yellow, magenta, green, violet, red; checked with a colour-vision-deficiency validator: lightness band, chroma floor and normal-vision separation pass in both themes; the worst adjacent light-mode pair is ΔE 6.5 under protanopia, which is acceptable only because every chart also has a text legend and the table view, so never drop them); verdict series keep a fixed order (spam, phishing, malware, bec, suspicious, dlp_violation) so position also distinguishes them. Grid lines use `--chart-grid`; axis text uses `muted-foreground`.
- Never draw a number the API did not return: missing buckets are gaps, not zeros, unless the API returned zero.

## Data fetching

- `api.GET('/api/v1/…')` (typed, `src/lib/api/client.ts`) or `callOperation(operationId, { path, query, body })`; hooks `useApiQuery(operationId, { path, query })`, `useCursorList(operationId, filters)`, `useApiMutation(operationId)`; URL state with `useUrlState(shape)`. No other `fetch` to `/bff/api` (lint rule).
- Query keys are `[operationId, params]`; invalidate by operation id (`invalidates: ['DomainsController_list_v1']`). Lists are stale after 30 s, reports after 60 s (no refetch on focus). Retries happen only for network errors and `503`.
- The current user: `useMe()` (`GET /auth/me`: `permissions`, `organization`, `override`). The session (no tokens): `useSession()`.
- Errors are `ApiError { status, code, apiMessage, requestId, correlationId, retryAfterSeconds, details }`.

## Accessibility rules

- WCAG 2.2 AA. Text contrast ≥ 4.5:1 (large ≥ 3:1), non-text ≥ 3:1: enforced on the tokens.
- Every interactive element is reachable and operable by keyboard with a visible focus ring (`ring` token, 2 px outline, offset 2 px). No positive `tabindex`.
- Landmarks: one `<header>` (top bar), `<nav aria-label="Main">` (sidebar), `<main id="main">` with a "Skip to content" link first in the document.
- One `<h1>` per page (`PageHeader`); headings in order.
- Icon-only buttons have `aria-label`; decorative icons `aria-hidden`.
- Dialogs: labelled by their title, focus trapped, Escape closes, focus returns to the trigger. A dialog or drawer opened by a plain button (not its Radix `Trigger`) returns focus explicitly (`onCloseAutoFocus` → the button), as the mobile navigation drawer does.
- Label in name (WCAG 2.5.3): when a control has visible text, that text is part of its accessible name. Prefer a name from content (`<span className="sr-only">Account menu for</span> <name>`) over `aria-label`; decorative content (avatar initials) is `aria-hidden`; a filter button showing its value is named `aria-labelledby="<label id> <value id>"`.
- Links inside running text (a sentence or paragraph) are underlined (`underline underline-offset-2`): colour alone does not distinguish them (axe `link-in-text-block`). Links in tables, navigation and button-like positions may rely on position and hover.
- Live feedback: toasts are announced by sonner's live region; inline form errors use `role="alert"` for the summary.
- Targets ≥ 24 × 24 px; content reflows at 320 px without horizontal page scroll; respects `prefers-reduced-motion`.
- Every page test runs `expectNoAxeViolations` (serious and critical impact fail).

## Content-safety rules (P12)

- **Never render message bodies or attachment content.** The only message text shown is the sanitized quarantine preview, rendered as React text in a `pre-wrap` block (`<PreviewText>` in the quarantine feature). `dangerouslySetInnerHTML` is forbidden by lint (no exceptions); no `iframe`, no `blob:`/`data:` URLs of message content.
- Downloads only through the quarantine download grants: create the grant, then navigate to `/bff/api/v1/quarantine/downloads/{token}`; never store the token.
- Attacker-controlled strings go through `UntrustedText` (text, truncated, `title` tooltip, never a link; URLs get a copy button instead).
- Secrets are shown once in `SecretRevealDialog`, never logged, never put in query caches (`gcTime: 0`) and removed on close.
- No tokens, codes or user data in `localStorage`/`sessionStorage`/IndexedDB. `localStorage` keeps only UI conveniences (column visibility, sidebar collapsed, theme) behind try/catch.

## Dark mode

- `next-themes` with the `class` strategy, default `system`, toggle in the top bar (Light, Dark, System), stored by next-themes in `localStorage` (`theme`). The theme script receives the CSP nonce.
- Both themes define every token; the sidebar stays navy. Charts switch palette through the tokens. Test new UI in both themes; the contrast test covers both.

## Dev fixtures

`PORTAL_DEV_MOCKS=enabled` with `pnpm --filter @email-gateway/admin-portal dev` makes the BFF answer from typed fixtures instead of the api (design P9); the top bar shows **DEV FIXTURES**. Production builds contain no fixture code (`scripts/assert-no-mock-layer.mjs` fails the build otherwise).

- Sign in with any password as `<role key>@example.com` (e.g. `organization_admin@example.com`, `read_only_user@example.com`, `platform_admin@example.com`), `mfa.<role key>@example.com` (MFA enabled: any 6-digit code) or `enroll.<role key>@example.com` (MFA enrollment required). Fixture tokens are opaque `dev…` strings.
- Each feature owns `src/server/dev-mocks/fixtures/<feature>.ts` exporting `fixtures: FixtureHandlers` (keyed by OperationId). Use `ok(operationId, body)` (typed against the OpenAPI schema), `apiError(status, code, message)`, `paginate(items, query, listKey)` and the seeded generator (`SeededRandom`, `syntheticDomain`, `syntheticPerson`; `*.example.test`, `example.com` only). `resolveFixturePrincipal(request.token)` gives the role, permissions and organization of the caller. Unhandled operations answer `501 mock_not_implemented`. Keep mutable fixture state on `globalThis` (as `fixtures/session.ts` does): `next dev` compiles every route handler into its own bundle, so module-level state is not shared between the login route and the proxy.

## Testing pages

The kit lives in `src/test/` (Vitest + Testing Library + jsdom + MSW in node mode + axe):

```tsx
import { mockApi, okJson, renderWithProviders, expectNoAxeViolations } from '@/test';

it('lists domains', async () => {
  mockApi({
    DomainsController_list_v1: () => okJson({ data: [domainFixture], nextCursor: null }),
  });
  const { container } = renderWithProviders(<DomainsPage />, {
    role: 'domain_admin',
    route: '/domains?status=active',
  });
  expect(await screen.findByRole('cell', { name: 'alpha.example.test' })).toBeInTheDocument();
  await expectNoAxeViolations(container);
});
```

- `renderWithProviders(ui, { role?, permissions?, me?, route?, session? })`: QueryClient (no retries), theme, tooltip provider, toaster, a mocked Next router (`useRouter`, `usePathname`, `useSearchParams` reflect `route`; `router.push/replace` update it and are spies on `result.router`), and the current user injected into the `GET /auth/me` cache (role from `src/test/roles.ts`, or explicit `permissions`).
- `mockApi({ [operationId]: handler })`: MSW handlers resolved through `operations.gen.ts` (requests go to `/bff/api/v1/...`). Handlers receive `{ request, params, url, body }` and return a `Response` (`okJson(body, status?, headers?)`, `noContentResponse()`, `apiErrorJson(status, code, message, { requestId, headers, extra })`); `mockBff(method, path, handler)` covers `/bff/session/*`. Any request no handler answers fails the test that made it (after the test, with the method and path). Sign-out clears the query cache and navigates away; an override start or end resets the tenant caches with `resetTenantCaches` (`src/lib/auth/me.ts`: inactive queries removed, mounted ones reset and refetched at once), so mock the queries a mounted component refetches (`AuthController_me_v1`, `GET /bff/session`). Correction of step 7.1 WP6: `queryClient.clear()` alone does **not** refetch mounted queries.
- `expectRequestMatchesContract(operationId, body)`: Ajv validation against the request schema from `docs/api/openapi.json`; unknown keys fail.
- `expectNoAxeViolations(container)`: axe-core; violations of impact serious or critical fail with a readable list.
- `ROLE_PERMISSIONS` and `SYSTEM_ROLE_KEYS` (`src/test/roles.ts`): the permission sets of the 9 system roles, checked against `docs/security/rbac.md` by a test.
- Every page test covers: loading, empty, error (`code` + `requestId` visible), success, filters writing the URL, permission-hidden actions, form contract tests, axe.
- End to end, every page is also visited in a real Chromium against the real api with axe, the CSP-violation guard and the overflow check (`tests/portal-e2e`, [running and testing](running-and-testing.md#end-to-end-suite-testsportal-e2e)).
- Zod runs `jitless` in the browser (`src/lib/zod-config.ts`, loaded first by `src/instrumentation-client.ts`): its JIT probes `new Function`, which the CSP refuses. Keep that import first.

## Token tables

Generated from `src/app/globals.css` (ratios after sRGB clamping, the way browsers render; the test recomputes them).

### Contrast of every declared pair

| Foreground                    | Background         | Kind (AA)      | Light |  Dark |
| ----------------------------- | ------------------ | -------------- | ----: | ----: |
| `--foreground`                | `--background`     | text (≥ 4.5:1) | 16.85 | 16.46 |
| `--foreground`                | `--card`           | text (≥ 4.5:1) | 17.77 | 15.22 |
| `--foreground`                | `--muted`          | text (≥ 4.5:1) | 15.56 | 13.45 |
| `--card-foreground`           | `--card`           | text (≥ 4.5:1) | 17.77 | 15.22 |
| `--popover-foreground`        | `--popover`        | text (≥ 4.5:1) | 17.77 | 14.47 |
| `--muted-foreground`          | `--background`     | text (≥ 4.5:1) |  6.50 |  8.57 |
| `--muted-foreground`          | `--card`           | text (≥ 4.5:1) |  6.86 |  7.93 |
| `--muted-foreground`          | `--muted`          | text (≥ 4.5:1) |  6.01 |  7.01 |
| `--primary-foreground`        | `--primary`        | text (≥ 4.5:1) |  6.22 |  8.21 |
| `--secondary-foreground`      | `--secondary`      | text (≥ 4.5:1) | 13.58 | 12.63 |
| `--accent-foreground`         | `--accent`         | text (≥ 4.5:1) | 13.39 | 11.78 |
| `--destructive-foreground`    | `--destructive`    | text (≥ 4.5:1) |  5.86 |  6.55 |
| `--success-foreground`        | `--success`        | text (≥ 4.5:1) |  5.66 |  8.67 |
| `--warning-foreground`        | `--warning`        | text (≥ 4.5:1) |  8.05 | 10.29 |
| `--info-foreground`           | `--info`           | text (≥ 4.5:1) |  5.78 |  8.35 |
| `--primary`                   | `--background`     | text (≥ 4.5:1) |  5.90 |  8.29 |
| `--primary`                   | `--card`           | text (≥ 4.5:1) |  6.22 |  7.66 |
| `--destructive`               | `--card`           | text (≥ 4.5:1) |  5.86 |  6.11 |
| `--destructive`               | `--background`     | text (≥ 4.5:1) |  5.56 |  6.61 |
| `--sidebar-foreground`        | `--sidebar`        | text (≥ 4.5:1) | 13.36 | 15.27 |
| `--sidebar-muted`             | `--sidebar`        | text (≥ 4.5:1) |  7.40 |  7.87 |
| `--sidebar-accent-foreground` | `--sidebar-accent` | text (≥ 4.5:1) | 11.88 | 13.66 |
| `--sidebar-foreground`        | `--sidebar-accent` | text (≥ 4.5:1) |  9.99 | 11.48 |
| `--banner-foreground`         | `--banner`         | text (≥ 4.5:1) | 11.25 |  7.87 |
| `--tone-neutral-foreground`   | `--tone-neutral`   | text (≥ 4.5:1) |  8.36 |  9.51 |
| `--tone-info-foreground`      | `--tone-info`      | text (≥ 4.5:1) |  6.97 |  9.00 |
| `--tone-success-foreground`   | `--tone-success`   | text (≥ 4.5:1) |  7.53 |  9.05 |
| `--tone-warning-foreground`   | `--tone-warning`   | text (≥ 4.5:1) |  7.40 |  9.43 |
| `--tone-orange-foreground`    | `--tone-orange`    | text (≥ 4.5:1) |  6.39 |  8.58 |
| `--tone-danger-foreground`    | `--tone-danger`    | text (≥ 4.5:1) |  6.12 |  8.62 |
| `--tone-purple-foreground`    | `--tone-purple`    | text (≥ 4.5:1) |  6.70 |  8.95 |
| `--tone-magenta-foreground`   | `--tone-magenta`   | text (≥ 4.5:1) |  6.48 |  8.96 |
| `--tone-neutral-foreground`   | `--card`           | text (≥ 4.5:1) |  9.98 | 12.25 |
| `--tone-info-foreground`      | `--card`           | text (≥ 4.5:1) |  8.27 | 11.62 |
| `--tone-success-foreground`   | `--card`           | text (≥ 4.5:1) |  8.83 | 11.91 |
| `--tone-warning-foreground`   | `--card`           | text (≥ 4.5:1) |  8.60 | 13.01 |
| `--tone-orange-foreground`    | `--card`           | text (≥ 4.5:1) |  7.84 | 11.64 |
| `--tone-danger-foreground`    | `--card`           | text (≥ 4.5:1) |  7.48 | 11.54 |
| `--tone-purple-foreground`    | `--card`           | text (≥ 4.5:1) |  8.07 | 11.61 |
| `--tone-magenta-foreground`   | `--card`           | text (≥ 4.5:1) |  7.87 | 11.50 |
| `--input`                     | `--background`     | ui (≥ 3:1)     |  3.44 |  4.08 |
| `--input`                     | `--card`           | ui (≥ 3:1)     |  3.62 |  3.77 |
| `--ring`                      | `--background`     | ui (≥ 3:1)     |  5.39 |  7.64 |
| `--ring`                      | `--card`           | ui (≥ 3:1)     |  5.69 |  7.07 |
| `--primary`                   | `--background`     | ui (≥ 3:1)     |  5.90 |  8.29 |
| `--sidebar-ring`              | `--sidebar`        | ui (≥ 3:1)     |  7.49 |  8.56 |
| `--sidebar-primary`           | `--sidebar`        | ui (≥ 3:1)     |  7.49 |  8.56 |
| `--chart-1`                   | `--card`           | ui (≥ 3:1)     |  4.42 |  4.83 |
| `--chart-2`                   | `--card`           | ui (≥ 3:1)     |  3.20 |  4.53 |
| `--chart-3`                   | `--card`           | ui (≥ 3:1)     |  3.88 |  5.16 |
| `--chart-4`                   | `--card`           | ui (≥ 3:1)     |  3.41 |  5.72 |
| `--chart-5`                   | `--card`           | ui (≥ 3:1)     |  3.78 |  4.46 |
| `--chart-6`                   | `--card`           | ui (≥ 3:1)     |  4.95 |  3.55 |
| `--chart-7`                   | `--card`           | ui (≥ 3:1)     |  5.77 |  5.62 |
| `--chart-8`                   | `--card`           | ui (≥ 3:1)     |  3.95 |  5.44 |

### Token values

| Token                         | Light                      | Dark                       |
| ----------------------------- | -------------------------- | -------------------------- |
| `--background`                | `oklch(0.982 0.004 255)`   | `oklch(0.175 0.022 264)`   |
| `--foreground`                | `oklch(0.21 0.032 262)`    | `oklch(0.95 0.008 258)`    |
| `--card`                      | `oklch(1 0 0)`             | `oklch(0.215 0.026 264)`   |
| `--card-foreground`           | `oklch(0.21 0.032 262)`    | `oklch(0.95 0.008 258)`    |
| `--popover`                   | `oklch(1 0 0)`             | `oklch(0.235 0.028 264)`   |
| `--popover-foreground`        | `oklch(0.21 0.032 262)`    | `oklch(0.95 0.008 258)`    |
| `--muted`                     | `oklch(0.955 0.008 258)`   | `oklch(0.26 0.026 264)`    |
| `--muted-foreground`          | `oklch(0.47 0.03 260)`     | `oklch(0.75 0.02 258)`     |
| `--border`                    | `oklch(0.905 0.012 258)`   | `oklch(0.32 0.026 264)`    |
| `--input`                     | `oklch(0.62 0.022 260)`    | `oklch(0.56 0.03 260)`     |
| `--ring`                      | `oklch(0.52 0.19 258)`     | `oklch(0.72 0.14 252)`     |
| `--primary`                   | `oklch(0.5 0.19 259)`      | `oklch(0.74 0.13 250)`     |
| `--primary-foreground`        | `oklch(1 0 0)`             | `oklch(0.18 0.035 264)`    |
| `--secondary`                 | `oklch(0.945 0.012 258)`   | `oklch(0.28 0.028 264)`    |
| `--secondary-foreground`      | `oklch(0.25 0.035 262)`    | `oklch(0.95 0.008 258)`    |
| `--accent`                    | `oklch(0.94 0.022 258)`    | `oklch(0.3 0.035 264)`     |
| `--accent-foreground`         | `oklch(0.25 0.035 262)`    | `oklch(0.95 0.008 258)`    |
| `--destructive`               | `oklch(0.53 0.2 27)`       | `oklch(0.7 0.17 25)`       |
| `--destructive-foreground`    | `oklch(1 0 0)`             | `oklch(0.18 0.035 264)`    |
| `--success`                   | `oklch(0.5 0.12 152)`      | `oklch(0.74 0.14 152)`     |
| `--success-foreground`        | `oklch(1 0 0)`             | `oklch(0.18 0.035 264)`    |
| `--warning`                   | `oklch(0.8 0.15 80)`       | `oklch(0.82 0.14 82)`      |
| `--warning-foreground`        | `oklch(0.27 0.06 60)`      | `oklch(0.2 0.04 60)`       |
| `--info`                      | `oklch(0.5 0.12 235)`      | `oklch(0.74 0.11 235)`     |
| `--info-foreground`           | `oklch(1 0 0)`             | `oklch(0.18 0.035 264)`    |
| `--sidebar`                   | `oklch(0.255 0.065 264)`   | `oklch(0.2 0.05 264)`      |
| `--sidebar-foreground`        | `oklch(0.94 0.012 258)`    | `oklch(0.94 0.012 258)`    |
| `--sidebar-muted`             | `oklch(0.76 0.035 258)`    | `oklch(0.74 0.035 258)`    |
| `--sidebar-accent`            | `oklch(0.34 0.075 264)`    | `oklch(0.3 0.065 264)`     |
| `--sidebar-accent-foreground` | `oklch(1 0 0)`             | `oklch(1 0 0)`             |
| `--sidebar-primary`           | `oklch(0.76 0.13 245)`     | `oklch(0.76 0.13 245)`     |
| `--sidebar-border`            | `oklch(0.35 0.06 264)`     | `oklch(0.3 0.05 264)`      |
| `--sidebar-ring`              | `oklch(0.76 0.13 245)`     | `oklch(0.76 0.13 245)`     |
| `--banner`                    | `oklch(0.88 0.13 85)`      | `oklch(0.42 0.09 75)`      |
| `--banner-foreground`         | `oklch(0.25 0.06 60)`      | `oklch(0.97 0.03 90)`      |
| `--tone-neutral`              | `oklch(0.94 0.008 258)`    | `oklch(0.3 0.02 262)`      |
| `--tone-neutral-foreground`   | `oklch(0.38 0.025 260)`    | `oklch(0.88 0.015 258)`    |
| `--tone-info`                 | `oklch(0.94 0.035 240)`    | `oklch(0.3 0.06 245)`      |
| `--tone-info-foreground`      | `oklch(0.42 0.12 245)`     | `oklch(0.86 0.07 240)`     |
| `--tone-success`              | `oklch(0.94 0.05 150)`     | `oklch(0.3 0.06 152)`      |
| `--tone-success-foreground`   | `oklch(0.4 0.1 152)`       | `oklch(0.86 0.1 150)`      |
| `--tone-warning`              | `oklch(0.95 0.07 90)`      | `oklch(0.32 0.06 80)`      |
| `--tone-warning-foreground`   | `oklch(0.42 0.09 70)`      | `oklch(0.9 0.11 90)`       |
| `--tone-orange`               | `oklch(0.94 0.05 55)`      | `oklch(0.32 0.07 50)`      |
| `--tone-orange-foreground`    | `oklch(0.45 0.13 45)`      | `oklch(0.87 0.08 55)`      |
| `--tone-danger`               | `oklch(0.94 0.04 25)`      | `oklch(0.32 0.08 25)`      |
| `--tone-danger-foreground`    | `oklch(0.47 0.18 27)`      | `oklch(0.87 0.07 25)`      |
| `--tone-purple`               | `oklch(0.94 0.04 300)`     | `oklch(0.31 0.08 300)`     |
| `--tone-purple-foreground`    | `oklch(0.45 0.17 300)`     | `oklch(0.87 0.07 300)`     |
| `--tone-magenta`              | `oklch(0.94 0.04 345)`     | `oklch(0.31 0.08 345)`     |
| `--tone-magenta-foreground`   | `oklch(0.46 0.17 350)`     | `oklch(0.87 0.07 345)`     |
| `--chart-1`                   | `oklch(0.575 0.163 255.5)` | `oklch(0.622 0.161 255.1)` |
| `--chart-2`                   | `oklch(0.671 0.175 40.6)`  | `oklch(0.622 0.173 40.1)`  |
| `--chart-3`                   | `oklch(0.59 0.12 164.3)`   | `oklch(0.621 0.128 163.1)` |
| `--chart-4`                   | `oklch(0.641 0.134 77.4)`  | `oklch(0.67 0.143 73.2)`   |
| `--chart-5`                   | `oklch(0.632 0.164 357.7)` | `oklch(0.622 0.171 0.8)`   |
| `--chart-6`                   | `oklch(0.529 0.18 142.5)`  | `oklch(0.529 0.18 142.5)`  |
| `--chart-7`                   | `oklch(0.527 0.197 283.4)` | `oklch(0.67 0.145 286.8)`  |
| `--chart-8`                   | `oklch(0.623 0.191 24.9)`  | `oklch(0.669 0.159 22.3)`  |
| `--chart-grid`                | `oklch(0.905 0.012 258)`   | `oklch(0.32 0.026 264)`    |
