'use client';

import { PlusIcon } from 'lucide-react';
import { useId, type ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { cn } from '@/lib/utils';
import { fieldOf, type BuilderCatalog, type CatalogField } from './catalog';
import {
  getFact,
  outcomeOfTrigger,
  setFact,
  triggerOfOutcome,
  type FactPath,
  type SyntheticFacts,
} from './facts';
import { CheckboxList, ChipsInput, ChoiceSelect, IntegerInput } from './inputs';
import { RemoveButton } from './parts';
import { humanizeValue } from './summary';
import { NumberWithUnit } from './value-editor';

/**
 * Synthetic facts of a policy test (design B7; controlled). Every vocabulary comes from the
 * catalogue field with the same meaning (SPF values from `auth.spf`, DLP categories from
 * `dlp.categories`, …); a control whose catalogue field is missing is not shown. Only the keys
 * the user sets are written: everything else takes the server's documented defaults.
 */

type Props = {
  catalog: BuilderCatalog;
  value: SyntheticFacts;
  onChange: (value: SyntheticFacts) => void;
};

interface FactControl {
  catalog: BuilderCatalog;
  facts: SyntheticFacts;
  set: (path: FactPath, value: unknown) => void;
}

const optionsOf = (values: readonly string[] | null | undefined) =>
  (values ?? []).map((v) => ({ value: v, label: humanizeValue(v) }));

function Row({
  label,
  children,
  hint,
}: {
  label: (id: string) => ReactNode;
  children: (labelId: string) => ReactNode;
  hint?: string;
}) {
  const id = useId();
  return (
    <div className="grid min-w-0 content-start gap-1">
      {label(id)}
      {children(id)}
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

const textLabel = (text: string) => (id: string) => (
  <span id={id} className="text-xs text-muted-foreground">
    {text}
  </span>
);

/** A select over a catalogue field's vocabulary (hidden when the field is missing). */
function VocabularySelect({
  ctl,
  fieldName,
  path,
  label,
  map,
}: {
  ctl: FactControl;
  fieldName: string;
  path: FactPath;
  label?: string;
  /** Converts a catalogue value to the facts' value (and back for display). */
  map?: { toFact: (v: string) => string; fromFact: (v: string) => string };
}) {
  const field = fieldOf(ctl.catalog, fieldName);
  if (!field?.values) return null;
  const current = getFact(ctl.facts, path);
  return (
    <Row label={textLabel(label ?? field.label)}>
      {(labelId) => (
        <ChoiceSelect
          labelledBy={labelId}
          value={typeof current === 'string' ? (map ? map.fromFact(current) : current) : undefined}
          unsetLabel="Not set (default)"
          options={optionsOf(field.values)}
          onChange={(next) =>
            ctl.set(path, next === undefined ? undefined : map ? map.toFact(next) : next)
          }
        />
      )}
    </Row>
  );
}

function TextFact({
  ctl,
  path,
  label,
  placeholder,
  inputMode,
}: {
  ctl: FactControl;
  path: FactPath;
  label: string;
  placeholder?: string;
  inputMode?: 'email' | 'text';
}) {
  const current = getFact(ctl.facts, path);
  const id = useId();
  return (
    <div className="grid min-w-0 content-start gap-1">
      <Label htmlFor={id} className="text-xs text-muted-foreground">
        {label}
      </Label>
      <Input
        id={id}
        value={typeof current === 'string' ? current : ''}
        placeholder={placeholder}
        inputMode={inputMode}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) =>
          ctl.set(path, event.target.value.trim() === '' ? undefined : event.target.value.trim())
        }
        className="h-8"
      />
    </div>
  );
}

function BooleanFact({ ctl, path, label }: { ctl: FactControl; path: FactPath; label: string }) {
  const current = getFact(ctl.facts, path);
  return (
    <Row label={textLabel(label)}>
      {(labelId) => (
        <ChoiceSelect
          labelledBy={labelId}
          value={current === true ? 'yes' : current === false ? 'no' : undefined}
          unsetLabel="Not set (default)"
          options={[
            { value: 'yes', label: 'Yes' },
            { value: 'no', label: 'No' },
          ]}
          onChange={(next) => ctl.set(path, next === undefined ? undefined : next === 'yes')}
        />
      )}
    </Row>
  );
}

function NumberFact({
  ctl,
  fieldName,
  path,
  label,
}: {
  ctl: FactControl;
  fieldName: string;
  path: FactPath;
  label?: string;
}) {
  const field = fieldOf(ctl.catalog, fieldName);
  if (!field) return null;
  const current = getFact(ctl.facts, path);
  return (
    <Row label={textLabel(label ?? field.label)}>
      {(labelId) =>
        field.unit === 'bytes' ? (
          <NumberWithUnit
            field={field}
            value={current}
            labelledBy={labelId}
            onChange={(next) => ctl.set(path, next)}
          />
        ) : (
          <IntegerInput
            labelledBy={labelId}
            value={typeof current === 'number' ? current : undefined}
            required={false}
            min={field.min ?? undefined}
            max={field.max !== null && field.max < Number.MAX_SAFE_INTEGER ? field.max : undefined}
            onChange={(next) => ctl.set(path, next)}
          />
        )
      }
    </Row>
  );
}

function CodesFact({
  ctl,
  fieldName,
  path,
  label,
}: {
  ctl: FactControl;
  fieldName: string;
  path: FactPath;
  label?: string;
}) {
  const field = fieldOf(ctl.catalog, fieldName);
  if (!field) return null;
  const current = getFact(ctl.facts, path);
  const items = Array.isArray(current) ? current : [];
  const set = (next: unknown[]) => ctl.set(path, next.length > 0 ? next : undefined);
  return (
    <Row label={textLabel(label ?? field.label)}>
      {(labelId) =>
        field.values ? (
          <CheckboxList
            labelledBy={labelId}
            values={items}
            options={optionsOf(field.values)}
            onChange={set}
          />
        ) : (
          <ChipsInput
            labelledBy={labelId}
            items={items}
            onChange={set}
            noun="code"
            suggestions={field.suggestions}
            split
          />
        )
      }
    </Row>
  );
}

function Section({
  title,
  children,
  show = true,
}: {
  title: string;
  children: ReactNode;
  show?: boolean;
}) {
  const id = useId();
  if (!show) return null;
  return (
    <fieldset aria-labelledby={id} className="grid min-w-0 gap-3 rounded-md border p-3">
      <legend id={id} className="px-1 text-sm font-semibold">
        {title}
      </legend>
      <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2">{children}</div>
    </fieldset>
  );
}

const has = (catalog: BuilderCatalog, ...names: string[]) =>
  names.some((n) => fieldOf(catalog, n) !== null);

function ListOfObjects({
  ctl,
  path,
  noun,
  addLabel,
  newItem,
  render,
}: {
  ctl: FactControl;
  path: FactPath;
  noun: string;
  addLabel: string;
  newItem: Record<string, unknown>;
  render: (itemPath: FactPath, index: number) => ReactNode;
}) {
  const current = getFact(ctl.facts, path);
  const items: unknown[] = Array.isArray(current) ? current : [];
  return (
    <div className="grid min-w-0 gap-2 sm:col-span-2">
      {items.map((_, i) => (
        <div
          key={i}
          role="group"
          aria-label={`${noun} ${i + 1}`}
          className="grid min-w-0 gap-2 rounded-md border bg-muted/30 p-2"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold">{`${noun} ${i + 1}`}</span>
            <RemoveButton
              name={`${noun.toLowerCase()} ${i + 1}`}
              onClick={() => {
                const next = items.filter((__, j) => j !== i);
                ctl.set(path, next.length > 0 ? next : undefined);
              }}
            />
          </div>
          <div className="grid min-w-0 grid-cols-1 gap-2 sm:grid-cols-2">
            {render([...path, i], i)}
          </div>
        </div>
      ))}
      <Button
        variant="outline"
        size="sm"
        className="w-fit"
        onClick={() => ctl.set(path, [...items, newItem])}
      >
        <PlusIcon aria-hidden />
        {addLabel}
      </Button>
    </div>
  );
}

function HardBlocks({ ctl }: { ctl: FactControl }) {
  const field = fieldOf(ctl.catalog, 'risk.hard_blocks');
  const actions = fieldOf(ctl.catalog, 'risk.recommended_action')?.values ?? [];
  const labelId = useId();
  if (!field?.values || actions.length === 0) return null;
  const path: FactPath = ['risk', 'rev0', 'hardBlocks'];
  const current = getFact(ctl.facts, path);
  const blocks = Array.isArray(current)
    ? current.filter(
        (b): b is { id: string; action: string } =>
          typeof b === 'object' && b !== null && 'id' in b,
      )
    : [];
  const set = (next: Array<{ id: string; action: string }>) =>
    ctl.set(path, next.length > 0 ? next : undefined);
  const strongest = actions[actions.length - 1]!;
  return (
    <div role="group" aria-labelledby={labelId} className="grid min-w-0 gap-2 sm:col-span-2">
      <span id={labelId} className="text-xs text-muted-foreground">
        {field.label}
      </span>
      <ul className="grid min-w-0 gap-1.5">
        {field.values.map((id) => {
          const block = blocks.find((b) => b.id === id);
          const checkboxId = `${labelId}-${id}`;
          return (
            <li key={id} className="flex min-h-7 min-w-0 flex-wrap items-center gap-2">
              <Checkbox
                id={checkboxId}
                checked={block !== undefined}
                onCheckedChange={(checked) =>
                  set(
                    checked === true
                      ? [...blocks, { id, action: strongest }]
                      : blocks.filter((b) => b.id !== id),
                  )
                }
              />
              <Label htmlFor={checkboxId} className="min-w-40 font-mono text-xs font-normal">
                {id}
              </Label>
              {block ? (
                <ChoiceSelect
                  ariaLabel={`Action of ${id}`}
                  value={block.action}
                  options={optionsOf(actions)}
                  onChange={(action) =>
                    set(
                      blocks.map((b) => (b.id === id ? { ...b, action: action ?? strongest } : b)),
                    )
                  }
                  className="w-48"
                />
              ) : null}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/**
 * The "Account takeover" facts (step 8.4 D23). The section is driven by the catalogue group
 * `ACCOUNT_TAKEOVER_GROUP`: every field of that group gets a control whose facts key is derived
 * from the field name (`<prefix>.<snake_case>` → facts `<prefix>.<camelCase>`), its label,
 * vocabulary and bounds come from the catalogue, so no DSL field name lives in the portal
 * (ADR-0063). The block is all-or-nothing on the server (score and level required when present);
 * "Account known" is the facts' own flag (default true on the server).
 */
export const ACCOUNT_TAKEOVER_GROUP = 'account_takeover';
/** Facts keys the server requires once the block is present (synthetic facts schema). */
const ATO_REQUIRED_FACT_KEYS = ['riskScore', 'riskLevel'] as const;

const camelCase = (snake: string) =>
  snake.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());

/** `{ root, key }` of a catalogue field in the synthetic facts (`a.b_c` → `a`, `bC`). */
export function factKeyOfField(name: string): { root: string; key: string } | null {
  const dot = name.indexOf('.');
  if (dot <= 0 || dot === name.length - 1) return null;
  return { root: name.slice(0, dot), key: camelCase(name.slice(dot + 1)) };
}

/** The account takeover fields of the catalogue with their facts keys (catalogue order). */
export function accountTakeoverFactFields(
  catalog: BuilderCatalog,
): Array<{ field: CatalogField; root: string; key: string }> {
  return catalog.fields.flatMap((field) => {
    if (field.group !== ACCOUNT_TAKEOVER_GROUP) return [];
    const keyed = factKeyOfField(field.name);
    return keyed ? [{ field, ...keyed }] : [];
  });
}

/** A new facts block with the required keys at their first catalogue value (score: its minimum). */
export function initialAccountTakeoverFacts(catalog: BuilderCatalog): Record<string, unknown> {
  const block: Record<string, unknown> = {};
  for (const { field, key } of accountTakeoverFactFields(catalog)) {
    if (!(ATO_REQUIRED_FACT_KEYS as readonly string[]).includes(key)) continue;
    block[key] = field.values ? field.values[0] : (field.min ?? 0);
  }
  return block;
}

function AccountTakeoverFacts({ ctl }: { ctl: FactControl }) {
  const includeId = useId();
  const fields = accountTakeoverFactFields(ctl.catalog);
  if (fields.length === 0) return null;
  const root = fields[0]!.root;
  const block = getFact(ctl.facts, [root]);
  const present = isPlainObjectFact(block);
  const title =
    ctl.catalog.fieldGroups.find((g) => g.id === ACCOUNT_TAKEOVER_GROUP)?.label ??
    'Account takeover';
  return (
    <Section title={title}>
      <Row
        label={(id) => (
          <span id={id} className="text-xs text-muted-foreground">
            Sender account facts
          </span>
        )}
        hint="Outbound and internal mail only: the server drops these facts for inbound mail."
      >
        {(labelId) => (
          <ChoiceSelect
            id={includeId}
            labelledBy={labelId}
            value={present ? 'yes' : undefined}
            unsetLabel="None (fields are unknown)"
            options={[{ value: 'yes', label: 'Set account takeover facts' }]}
            onChange={(next) =>
              ctl.set([root], next === 'yes' ? initialAccountTakeoverFacts(ctl.catalog) : undefined)
            }
          />
        )}
      </Row>
      {present ? (
        <>
          {fields.map(({ field, key }) => {
            const required = (ATO_REQUIRED_FACT_KEYS as readonly string[]).includes(key);
            const path = [root, key];
            const current = getFact(ctl.facts, path);
            if (field.values) {
              return (
                <Row key={field.name} label={textLabel(field.label)}>
                  {(labelId) => (
                    <ChoiceSelect
                      labelledBy={labelId}
                      value={typeof current === 'string' ? current : undefined}
                      unsetLabel={required ? undefined : 'None (no active incident)'}
                      options={optionsOf(field.values)}
                      onChange={(next) => {
                        if (required && next === undefined) return;
                        ctl.set(path, next);
                      }}
                    />
                  )}
                </Row>
              );
            }
            return (
              <Row key={field.name} label={textLabel(field.label)}>
                {(labelId) => (
                  <IntegerInput
                    labelledBy={labelId}
                    value={typeof current === 'number' ? current : undefined}
                    required={required}
                    min={field.min ?? undefined}
                    max={field.max ?? undefined}
                    onChange={(next) => ctl.set(path, next)}
                  />
                )}
              </Row>
            );
          })}
          <BooleanFact ctl={ctl} path={[root, 'accountKnown']} label="Account known (monitored)" />
        </>
      ) : null}
    </Section>
  );
}

const isPlainObjectFact = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export function SyntheticFactsForm({ catalog, value, onChange }: Props) {
  const ctl: FactControl = {
    catalog,
    facts: value,
    set: (path, next) => onChange(setFact(value, path, next)),
  };
  const evaluationTimeId = useId();
  const resolveId = useId();
  const noRiskId = useId();
  const time = typeof value.evaluationTime === 'string' ? value.evaluationTime.slice(0, 16) : '';
  const recipients = (value.recipients ?? []).map((r) => r.address);
  const dlpAction = fieldOf(catalog, 'dlp.action');
  const becVerdict = fieldOf(catalog, 'bec.deterministic_verdict');
  const riskNull = value.risk === null;
  const field = (name: string): CatalogField | null => fieldOf(catalog, name);
  return (
    <div className="grid min-w-0 gap-3" data-builder="facts-form">
      <Section title="Message">
        <Row label={textLabel('Direction')}>
          {(labelId) => (
            <ChoiceSelect
              labelledBy={labelId}
              value={value.direction}
              unsetLabel="Not set (default)"
              options={optionsOf(catalog.messageDirections)}
              onChange={(next) => ctl.set(['direction'], next)}
            />
          )}
        </Row>
        <VocabularySelect
          ctl={ctl}
          fieldName="scan.outcome"
          path={['trigger']}
          map={{ toFact: triggerOfOutcome, fromFact: outcomeOfTrigger }}
        />
        <div className="grid min-w-0 content-start gap-1">
          <Label htmlFor={evaluationTimeId} className="text-xs text-muted-foreground">
            Evaluation time (UTC)
          </Label>
          <Input
            id={evaluationTimeId}
            type="datetime-local"
            step={60}
            value={time}
            onChange={(event) =>
              ctl.set(
                ['evaluationTime'],
                event.target.value ? `${event.target.value.slice(0, 16)}:00.000Z` : undefined,
              )
            }
            className="h-8"
          />
          <p className="text-xs text-muted-foreground">Not set: the time of the test.</p>
        </div>
        <NumberFact ctl={ctl} fieldName="message.size_bytes" path={['message', 'sizeBytes']} />
      </Section>

      <Section
        title="Sender"
        show={has(
          catalog,
          'sender.envelope.address',
          'sender.header_from.address',
          'sender.authenticated.address',
          'sender.trusted',
        )}
      >
        {field('sender.envelope.address') ? (
          <TextFact
            ctl={ctl}
            path={['sender', 'envelope']}
            label={field('sender.envelope.address')!.label}
            inputMode="email"
            placeholder="sender@example.com"
          />
        ) : null}
        {field('sender.header_from.address') ? (
          <TextFact
            ctl={ctl}
            path={['sender', 'headerFrom']}
            label={field('sender.header_from.address')!.label}
            inputMode="email"
          />
        ) : null}
        {field('sender.authenticated.address') ? (
          <BooleanFact ctl={ctl} path={['sender', 'authenticated']} label="Sender authenticated" />
        ) : null}
        {field('sender.trusted') ? (
          <BooleanFact
            ctl={ctl}
            path={['sender', 'trusted']}
            label={field('sender.trusted')!.label}
          />
        ) : null}
      </Section>

      <Section title="Recipients" show={has(catalog, 'recipient.address')}>
        <div className="sm:col-span-2">
          <Row label={textLabel(field('recipient.address')?.label ?? 'Recipient address')}>
            {(labelId) => (
              <ChipsInput
                labelledBy={labelId}
                items={recipients}
                noun="recipient"
                split
                onChange={(next) =>
                  ctl.set(
                    ['recipients'],
                    next.length > 0
                      ? next.map((address) => ({ address: String(address) }))
                      : undefined,
                  )
                }
              />
            )}
          </Row>
        </div>
        {field('recipient.department') || field('sender.department') ? (
          <div className="flex items-center gap-2 sm:col-span-2">
            <Checkbox
              id={resolveId}
              checked={value.resolveDirectory === true}
              onCheckedChange={(checked) =>
                ctl.set(['resolveDirectory'], checked === true ? true : undefined)
              }
            />
            <Label htmlFor={resolveId} className="font-normal">
              Resolve department and user memberships of these addresses from the directory
            </Label>
          </div>
        ) : null}
      </Section>

      <Section title="Connection" show={has(catalog, 'client.ip', 'client.hostname')}>
        {field('client.ip') ? (
          <TextFact
            ctl={ctl}
            path={['client', 'ip']}
            label={field('client.ip')!.label}
            placeholder="198.51.100.25"
          />
        ) : null}
        {field('client.hostname') ? (
          <TextFact
            ctl={ctl}
            path={['client', 'hostname']}
            label={field('client.hostname')!.label}
          />
        ) : null}
      </Section>

      <Section
        title="Authentication"
        show={has(catalog, 'auth.spf', 'auth.dkim', 'auth.dmarc', 'auth.arc', 'auth.dmarc_policy')}
      >
        <VocabularySelect ctl={ctl} fieldName="auth.spf" path={['auth', 'spf']} />
        <VocabularySelect ctl={ctl} fieldName="auth.dkim" path={['auth', 'dkim']} />
        <VocabularySelect ctl={ctl} fieldName="auth.dmarc" path={['auth', 'dmarc']} />
        <VocabularySelect ctl={ctl} fieldName="auth.arc" path={['auth', 'arc']} />
        <VocabularySelect ctl={ctl} fieldName="auth.dmarc_policy" path={['auth', 'dmarcPolicy']} />
      </Section>

      <Section
        title="Attachments"
        show={has(catalog, 'attachment.filename', 'attachment.type_family', 'attachment.verdict')}
      >
        <ListOfObjects
          ctl={ctl}
          path={['attachments']}
          noun="Attachment"
          addLabel="Add attachment"
          newItem={{}}
          render={(itemPath) => (
            <>
              {field('attachment.filename') ? (
                <TextFact
                  ctl={ctl}
                  path={[...itemPath, 'filename']}
                  label={field('attachment.filename')!.label}
                />
              ) : null}
              <VocabularySelect
                ctl={ctl}
                fieldName="attachment.type_family"
                path={[...itemPath, 'typeFamily']}
              />
              <VocabularySelect
                ctl={ctl}
                fieldName="attachment.verdict"
                path={[...itemPath, 'verdict']}
              />
              <NumberFact
                ctl={ctl}
                fieldName="attachment.size_bytes"
                path={[...itemPath, 'sizeBytes']}
              />
              {field('attachment.is_archive') ? (
                <BooleanFact
                  ctl={ctl}
                  path={[...itemPath, 'isArchive']}
                  label={field('attachment.is_archive')!.label}
                />
              ) : null}
              {field('attachment.encrypted') ? (
                <BooleanFact
                  ctl={ctl}
                  path={[...itemPath, 'encrypted']}
                  label={field('attachment.encrypted')!.label}
                />
              ) : null}
              <CodesFact
                ctl={ctl}
                fieldName="attachment.reason_codes"
                path={[...itemPath, 'reasonCodes']}
              />
            </>
          )}
        />
      </Section>

      <Section title="Links" show={has(catalog, 'url.host', 'url.verdict', 'urls.rewrite_status')}>
        <VocabularySelect ctl={ctl} fieldName="urls.rewrite_status" path={['urlRewriteStatus']} />
        <ListOfObjects
          ctl={ctl}
          path={['urls']}
          noun="Link"
          addLabel="Add link"
          newItem={{}}
          render={(itemPath) => (
            <>
              <TextFact
                ctl={ctl}
                path={[...itemPath, 'host']}
                label={`${field('url.host')?.label ?? 'Host'} (required)`}
              />
              <VocabularySelect ctl={ctl} fieldName="url.scheme" path={[...itemPath, 'scheme']} />
              <VocabularySelect ctl={ctl} fieldName="url.verdict" path={[...itemPath, 'verdict']} />
              <CodesFact
                ctl={ctl}
                fieldName="url.reason_codes"
                path={[...itemPath, 'reasonCodes']}
              />
            </>
          )}
        />
      </Section>

      <Section
        title="Risk (revision 0)"
        show={has(catalog, 'risk.score', 'risk.level', 'risk.verdict', 'risk.recommended_action')}
      >
        <div className="flex items-center gap-2 sm:col-span-2">
          <Checkbox
            id={noRiskId}
            checked={riskNull}
            onCheckedChange={(checked) => ctl.set(['risk'], checked === true ? null : undefined)}
          />
          <Label htmlFor={noRiskId} className="font-normal">
            No risk result (a missing risk row)
          </Label>
        </div>
        {riskNull ? null : (
          <>
            <NumberFact ctl={ctl} fieldName="risk.score" path={['risk', 'rev0', 'score']} />
            <VocabularySelect ctl={ctl} fieldName="risk.level" path={['risk', 'rev0', 'level']} />
            <VocabularySelect
              ctl={ctl}
              fieldName="risk.verdict"
              path={['risk', 'rev0', 'verdict']}
            />
            <VocabularySelect
              ctl={ctl}
              fieldName="risk.recommended_action"
              path={['risk', 'rev0', 'recommendedAction']}
            />
            <HardBlocks ctl={ctl} />
            <CodesFact
              ctl={ctl}
              fieldName="risk.reason_codes"
              path={['risk', 'rev0', 'reasonCodes']}
            />
          </>
        )}
      </Section>

      <Section title="Data loss prevention" show={dlpAction?.values != null}>
        <Row
          label={textLabel(dlpAction?.label ?? 'DLP action')}
          hint="Choose the action to add a DLP result."
        >
          {(labelId) => (
            <ChoiceSelect
              labelledBy={labelId}
              value={value.dlp?.action}
              unsetLabel="No DLP result"
              options={optionsOf(dlpAction?.values)}
              onChange={(next) =>
                onChange(
                  setFact(
                    value,
                    ['dlp'],
                    next === undefined ? undefined : { ...(value.dlp ?? {}), action: next },
                  ),
                )
              }
            />
          )}
        </Row>
        {value.dlp ? (
          <>
            <VocabularySelect ctl={ctl} fieldName="dlp.verdict" path={['dlp', 'verdict']} />
            <VocabularySelect
              ctl={ctl}
              fieldName="dlp.max_severity"
              path={['dlp', 'maxSeverity']}
            />
            <div className="sm:col-span-2">
              <CodesFact ctl={ctl} fieldName="dlp.categories" path={['dlp', 'categories']} />
            </div>
            <CodesFact ctl={ctl} fieldName="dlp.detector_codes" path={['dlp', 'detectorCodes']} />
          </>
        ) : null}
      </Section>

      <Section title="Business email compromise" show={becVerdict?.values != null}>
        <Row
          label={textLabel(becVerdict?.label ?? 'BEC verdict')}
          hint="Choose the deterministic verdict to add a BEC result."
        >
          {(labelId) => (
            <ChoiceSelect
              labelledBy={labelId}
              value={value.bec?.deterministicVerdict}
              unsetLabel="No BEC result"
              options={optionsOf(becVerdict?.values)}
              onChange={(next) =>
                onChange(
                  setFact(
                    value,
                    ['bec'],
                    next === undefined
                      ? undefined
                      : { ...(value.bec ?? {}), deterministicVerdict: next },
                  ),
                )
              }
            />
          )}
        </Row>
        {value.bec ? (
          <>
            <VocabularySelect ctl={ctl} fieldName="bec.verdict" path={['bec', 'verdict']} />
            {field('bec.ai_raised') ? (
              <BooleanFact
                ctl={ctl}
                path={['bec', 'aiRaised']}
                label={field('bec.ai_raised')!.label}
              />
            ) : null}
            <CodesFact ctl={ctl} fieldName="bec.rule_codes" path={['bec', 'ruleCodes']} />
          </>
        ) : null}
      </Section>

      <AccountTakeoverFacts ctl={ctl} />

      <Section title="Scan" show={has(catalog, 'scan.verdict', 'scan.reason_codes')}>
        <VocabularySelect ctl={ctl} fieldName="scan.verdict" path={['scan', 'verdict']} />
        <CodesFact ctl={ctl} fieldName="scan.reason_codes" path={['scan', 'reasonCodes']} />
      </Section>
      <p className={cn('text-xs text-muted-foreground')}>
        Facts you leave unset take the server&apos;s defaults. The server builds the evaluation
        input and answers <span className="font-mono">400 policy_test_facts_invalid</span> for facts
        it cannot use.
      </p>
    </div>
  );
}
