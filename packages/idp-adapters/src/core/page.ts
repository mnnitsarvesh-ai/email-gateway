/**
 * Collects the events of one ingest page (design note D3, D11): events of disabled streams are
 * dropped before they leave the page (`stream_disabled`), every event is checked against the strict
 * shim (`invalid` otherwise), and per-stream counts go to the metrics sink once per page.
 */
import type { ProviderEvent, ProviderStream } from '../port/ato-port';
import type { IdpMetricsSink } from './http';
import { isValidEvent } from './normalize';
import type { IdpBindingSettings } from './settings';

export type EventResult =
  'emitted' | 'dropped_operation' | 'stream_disabled' | 'invalid' | 'foreign_domain';

export class PageCollector {
  readonly events: ProviderEvent[] = [];
  private readonly ids = new Set<string>();
  private readonly counts = new Map<string, number>();

  constructor(
    private readonly provider: string,
    private readonly settings: IdpBindingSettings,
    private readonly metrics?: IdpMetricsSink,
  ) {}

  get size(): number {
    return this.events.length;
  }

  add(event: ProviderEvent): void {
    if (!this.settings.streams[event.stream].enabled) {
      this.count(event.stream, 'stream_disabled');
      return;
    }
    if (!isValidEvent(event)) {
      this.count(event.stream, 'invalid');
      return;
    }
    // Duplicates inside one page are collapsed (downstream dedupes across pages by eventId).
    if (this.ids.has(event.eventId)) return;
    this.ids.add(event.eventId);
    this.events.push(event);
    this.count(event.stream, 'emitted');
  }

  drop(stream: ProviderStream, result: Exclude<EventResult, 'emitted'>, n = 1): void {
    this.count(stream, result, n);
  }

  private count(stream: ProviderStream, result: EventResult, n = 1): void {
    const key = `${stream}|${result}`;
    this.counts.set(key, (this.counts.get(key) ?? 0) + n);
  }

  /** Counts by `stream|result` (tests) — flushed to the metrics sink by `flush`. */
  snapshot(): Record<string, number> {
    return Object.fromEntries(this.counts);
  }

  flush(): void {
    for (const [key, count] of this.counts) {
      const [stream, result] = key.split('|') as [string, string];
      this.metrics?.events?.({ provider: this.provider, stream, result }, count);
    }
    this.counts.clear();
  }
}
