import { createHash, type Hash } from 'node:crypto';
import type { EventEmitter } from 'node:events';
import type { Readable } from 'node:stream';
import { Splitter, type MessageChunk, type SplitterChunk } from '@zone-eu/mailsplit';
import { inspectGzip } from './archive/gzip';
import { inspectZip } from './archive/zip';
import { ClosingDelimiterScanner } from './boundary-tracker';
import {
  type AttachmentFlag,
  MAX_PART_PATH_CHARS,
  type MimeDefectCode,
  type MimeLimitName,
} from './constants';
import {
  Base64Decoder,
  CharsetConverter,
  type ChunkDecoder,
  iconvCharset,
  KNOWN_TRANSFER_ENCODINGS,
  normalizeCharset,
  QuotedPrintableDecoder,
  transferDecoder,
} from './decode';
import { InfrastructureFailure, isMailsplitLimitError, ParseStop, ParseTimeout } from './errors';
import { sanitizeFilename } from './filename';
import { checkHeaderBlock, extractTopLevelHeaders, type RawHeaderLine } from './headers';
import { assertMimeLimits, type MimeLimits } from './limits';
import { ARCHIVE_TYPES, SNIFF_BYTES, sniffContentType, sniffFlags } from './sniff';
import type {
  ArchiveInfo,
  ArchiveSummary,
  AttachmentResult,
  BodyResult,
  ExtractedHeader,
  MimeParseResult,
  ParseOptions,
  PartInfo,
  PartWriter,
  StoredPart,
  StructureNode,
} from './types';

/** mailsplit's node type, taken from its chunk union (the class and the interface agree). */
type Node = Exclude<SplitterChunk, MessageChunk>;

/** `decoded_ratio` is only judged once this many bytes of a leaf are decoded (design M5). */
const RATIO_CHECK_FROM_BYTES = 64 * 1024;
/** gzip ISIZE plus CRC32: the trailer kept from every attachment. */
const TAIL_BYTES = 8;

interface NodeState {
  node: Node;
  structure: StructureNode;
  depth: number;
  path: string;
  children: number;
  /** Inside an embedded message (its root included). */
  inMessage: boolean;
  /** A multipart with a boundary (its closing delimiter is tracked). */
  delimited: boolean;
}

interface LeafState {
  state: NodeState;
  kind: PartInfo['kind'];
  decoder: ChunkDecoder;
  converter: CharsetConverter | null;
  writer: PartWriter | null;
  notStored: boolean;
  hash: Hash;
  sizeBytes: number;
  encodedBytes: number;
  decodedBytes: number;
  head: Buffer[];
  headLength: number;
  tail: Buffer;
  charset: string | null;
  flags: Set<AttachmentFlag>;
  maxBytes: number;
  limitName: Extract<MimeLimitName, 'body_size' | 'attachment_size'>;
}

/**
 * Streams one message through mailsplit, decodes every leaf on the fly and hands bodies and
 * attachments to the sink (design M4). Bounded memory: mailsplit's line buffer, at most 4 KiB plus
 * 8 bytes per open leaf, the header blocks mailsplit bounds by maxHeadSize, and the sink.
 */
export async function parseMessage(
  input: Readable,
  options: ParseOptions,
): Promise<MimeParseResult> {
  assertMimeLimits(options.limits);
  return new MessageParse(input, options).run();
}

class MessageParse {
  private readonly limits: MimeLimits;
  private readonly signal: AbortSignal;
  private readonly started = performance.now();
  private readonly inputHash = createHash('sha256');
  private bytesRead = 0;
  private inputComplete = false;

  private readonly limitsExceeded = new Set<MimeLimitName>();
  private readonly defects = new Set<MimeDefectCode>();
  private parserError = false;
  private infrastructureError: InfrastructureFailure | null = null;
  private inputError: { error: unknown } | null = null;

  /** No further node is processed; the input is still read (and hashed) to its end. */
  private stopped = false;
  /** The input is no longer read either (message_size, parse_timeout). */
  private timedOut = false;
  /** Reading stops without recording anything (an infrastructure error is rethrown). */
  private abandoned = false;
  private feeding = true;
  private attachmentLeaves = 0;

  private readonly splitter: Splitter;
  private readonly states = new Map<Node, NodeState>();
  private readonly delimiters = new ClosingDelimiterScanner();
  private readonly structure: StructureNode[] = [];
  private leaf: LeafState | null = null;
  private maxDepth = 0;
  private headerCount = 0;
  private totalDecodedBytes = 0;
  private subject: string | null = null;
  private headers: ExtractedHeader[] = [];
  private textBody: BodyResult | null = null;
  private htmlBody: BodyResult | null = null;
  private readonly attachments: AttachmentResult[] = [];

  private readonly abortPromise: Promise<never>;
  private rejectAbort: (reason: unknown) => void = () => undefined;
  private readonly onAbort = (): void => this.timeout();
  private readonly ownTimeout = new AbortController();
  private readonly timer: NodeJS.Timeout;

  constructor(
    private readonly input: Readable,
    private readonly options: ParseOptions,
  ) {
    this.limits = options.limits;
    // The library's own wall clock (cleared when the parse ends) on top of the caller's signal.
    this.timer = setTimeout(() => this.ownTimeout.abort(), options.limits.parseTimeoutMs);
    this.timer.unref();
    this.signal = AbortSignal.any([options.signal, this.ownTimeout.signal]);
    this.abortPromise = new Promise<never>((_resolve, reject) => {
      this.rejectAbort = reject;
    });
    this.abortPromise.catch(() => undefined);
    this.splitter = new Splitter({
      maxHeadSize: this.limits.maxHeaderBlockBytes,
      maxChildNodes: this.limits.maxParts + 1,
      ignoreEmbedded: false,
      // Without it mailsplit parses an embedded message only when its disposition is `inline`.
      defaultInlineEmbedded: true,
    });
    // Errors reach the consumer through the iterator; this keeps late ones from going unhandled.
    this.splitterEvents().on('error', () => undefined);
  }

  async run(): Promise<MimeParseResult> {
    if (this.signal.aborted) {
      clearTimeout(this.timer);
      this.timeout();
      return this.result();
    }
    this.signal.addEventListener('abort', this.onAbort, { once: true });
    try {
      const pump = this.pump();
      await this.consume();
      this.feeding = false;
      if (this.infrastructureError) this.abandonInput();
      if (!this.splitter.destroyed) this.splitter.destroy();
      await pump;
      await this.abortOpenLeaf();
    } catch (error) {
      // Only an infrastructure error from aborting the open leaf gets here.
      if (!(error instanceof InfrastructureFailure)) throw error;
      this.infrastructureError ??= error;
    } finally {
      clearTimeout(this.timer);
      this.signal.removeEventListener('abort', this.onAbort);
    }
    if (this.inputError) throw this.inputError.error;
    if (this.infrastructureError) throw this.infrastructureError.error;
    return this.result();
  }

  // ---------------------------------------------------------------- input

  /** Reads, counts and hashes the input and feeds mailsplit with backpressure. */
  private async pump(): Promise<void> {
    let reachedEnd = false;
    try {
      for await (const raw of this.input as AsyncIterable<Buffer | Uint8Array | string>) {
        if (this.timedOut || this.abandoned) break;
        const chunk =
          typeof raw === 'string'
            ? Buffer.from(raw)
            : Buffer.isBuffer(raw)
              ? raw
              : Buffer.from(raw);
        if (this.bytesRead + chunk.length > this.limits.maxMessageBytes) {
          this.bytesRead += chunk.length;
          this.inputHash.update(chunk);
          this.recordStop('message_size');
          this.splitter.destroy();
          break;
        }
        this.bytesRead += chunk.length;
        this.inputHash.update(chunk);
        if (this.feeding && !this.splitter.destroyed && !this.splitter.write(chunk)) {
          await this.drained();
        }
      }
      reachedEnd = !this.timedOut && !this.abandoned && !this.limitsExceeded.has('message_size');
    } catch (error) {
      if (!this.timedOut && !this.abandoned) this.inputError = { error };
      this.feeding = false;
      this.splitter.destroy();
      return;
    }
    this.inputComplete = reachedEnd;
    if (this.feeding && !this.splitter.destroyed) this.splitter.end();
  }

  /** mailsplit's typings only declare 'data'; the other events are the Transform's own. */
  private splitterEvents(): EventEmitter {
    return this.splitter;
  }

  private drained(): Promise<void> {
    return new Promise((resolve) => {
      const stream = this.splitterEvents();
      const done = (): void => {
        stream.off('drain', done);
        stream.off('close', done);
        resolve();
      };
      stream.on('drain', done);
      stream.on('close', done);
    });
  }

  // ---------------------------------------------------------------- consumer

  private async consume(): Promise<void> {
    const iterator = (this.splitter as AsyncIterable<SplitterChunk>)[Symbol.asyncIterator]();
    try {
      for (;;) {
        let next: IteratorResult<SplitterChunk>;
        try {
          next = await iterator.next();
        } catch (error) {
          this.onSplitterError(error);
          return;
        }
        if (next.done || this.stopped) break;
        try {
          await this.handle(next.value);
        } catch (error) {
          this.onHandleError(error);
          return;
        }
        if (this.stopped) return;
      }
      if (this.stopped || this.inputError) return;
      try {
        await this.finishLeaf();
        this.endOfMessageChecks();
      } catch (error) {
        this.onHandleError(error);
      }
    } finally {
      this.feeding = false;
      await iterator.return?.();
    }
  }

  private onSplitterError(error: unknown): void {
    // Errors after a stop or an input failure come from the splitter being destroyed.
    if (this.stopped || this.inputError) return;
    if (isMailsplitLimitError(error)) {
      const counter = (this.splitter as unknown as { nodeCounter?: unknown }).nodeCounter;
      const tooManyNodes = typeof counter === 'number' && counter > this.limits.maxParts + 1;
      this.recordStop(tooManyNodes ? 'part_count' : 'header_block_size');
      return;
    }
    this.parserError = true;
    this.stopped = true;
  }

  private onHandleError(error: unknown): void {
    if (error instanceof InfrastructureFailure) {
      this.infrastructureError ??= error;
      this.stopped = true;
      return;
    }
    if (error instanceof ParseStop || error instanceof ParseTimeout || this.timedOut) {
      this.stopped = true;
      return;
    }
    // An exception of mailsplit, libmime, a decoder or iconv-lite that was not mapped to a
    // defect: parse_failed / parser_error, keeping what was extracted.
    this.parserError = true;
    this.stopped = true;
  }

  private async handle(item: SplitterChunk): Promise<void> {
    if (item.type === 'node') {
      await this.finishLeaf();
      await this.onNode(item);
      return;
    }
    if (this.leaf && this.leaf.state.node !== item.node) await this.finishLeaf();
    if (this.leaf && this.leaf.state.node === item.node) {
      // Leaf content ('body'), or the content of a multipart without a boundary ('data').
      await this.feedLeaf(this.leaf, item.value);
      return;
    }
    if (item.type === 'data') this.delimiters.push(item.value);
  }

  // ---------------------------------------------------------------- nodes

  private async onNode(node: Node): Promise<void> {
    const parent = node.parentNode ? this.states.get(node.parentNode) : undefined;
    if (node.parentNode && parent === undefined) throw new Error('node without a recorded parent');
    const index = this.structure.length;
    if (index + 1 > this.limits.maxParts) this.stopStructural('part_count');

    let path = '0';
    if (parent) {
      parent.children++;
      path =
        parent.node.messageNode === true ? `${parent.path}.0` : `${parent.path}.${parent.children}`;
    }
    const depth = parent ? parent.depth + 1 : 0;
    const inMessage = parent ? parent.inMessage || parent.node.messageNode === true : false;
    // An empty block (empty input, or a blank first line) comes back as one empty line.
    const lines: RawHeaderLine[] = (node.headers ? node.headers.getList() : []).filter(
      (line) => line.line !== '',
    );
    const check = checkHeaderBlock(lines, this.limits);
    for (const defect of check.defects) this.defects.add(defect);
    if (!parent) {
      this.headerCount = check.fieldCount;
      if (lines.length === 0 || check.firstLineInvalid) this.defects.add('no_headers');
      const extracted = extractTopLevelHeaders(lines, this.limits, this.defects);
      this.headers = extracted.headers;
      this.subject = extracted.subject;
    }

    const contentType = mimeToken(node.contentType, 127) ?? 'text/plain';
    const multipart = node.multipart ? (mimeToken(node.multipart, 64) ?? 'mixed') : null;
    const boundary = node.multipart ? node._boundary : false;
    const charset = normalizeCharset(node.charset);
    const encoding = mimeToken(node.encoding, 32);
    const disposition = mimeToken(node.disposition, 32);
    const structure: StructureNode = {
      index,
      path,
      parent: parent ? parent.structure.index : null,
      depth,
      contentType,
      kind: 'container',
    };
    if (multipart !== null) structure.multipart = multipart;
    if (charset !== null) structure.charset = charset;
    if (encoding !== null) structure.encoding = encoding;
    if (disposition !== null) structure.disposition = disposition;

    const state: NodeState = {
      node,
      structure,
      depth,
      path,
      children: 0,
      inMessage,
      delimited: Boolean(boundary),
    };
    if (boundary) this.delimiters.register(index, boundary);
    this.structure.push(structure);
    this.states.set(node, state);
    if (depth > this.maxDepth) this.maxDepth = depth;

    if (depth > this.limits.maxDepth || path.length > MAX_PART_PATH_CHARS) {
      this.truncateAndStop(structure, 'nesting_depth');
    }
    if (check.limit !== null) this.truncateAndStop(structure, check.limit);

    if (multipart !== null && boundary) return;
    if (node.messageNode === true) {
      structure.kind = 'message';
      return;
    }
    if (multipart !== null) this.defects.add('missing_boundary_parameter');

    const kind = this.classify(state, contentType, multipart !== null);
    structure.kind = kind;
    if (kind === 'attachment' && ++this.attachmentLeaves > this.limits.maxAttachments) {
      this.truncateAndStop(structure, 'attachment_count');
    }
    await this.openLeaf(state, kind, encoding ?? '', charset);
  }

  /** Body selection of design M8. */
  private classify(state: NodeState, contentType: string, multipart: boolean): PartInfo['kind'] {
    const { node } = state;
    const candidate =
      !state.inMessage && !multipart && node.disposition !== 'attachment' && !node.filename;
    if (candidate && contentType === 'text/plain' && !this.textTaken) {
      this.textTaken = true;
      return 'text';
    }
    if (candidate && contentType === 'text/html' && !this.htmlTaken) {
      this.htmlTaken = true;
      return 'html';
    }
    return 'attachment';
  }

  private textTaken = false;
  private htmlTaken = false;

  private truncateAndStop(structure: StructureNode, limit: MimeLimitName): never {
    structure.truncated = true;
    return this.stopStructural(limit);
  }

  /** Records a structural limit: no further node is processed (design M5 "Parse stops"). */
  private recordStop(limit: MimeLimitName): void {
    this.limitsExceeded.add(limit);
    this.stopped = true;
    this.feeding = false;
  }

  private stopStructural(limit: MimeLimitName): never {
    this.recordStop(limit);
    throw new ParseStop();
  }

  private abandonInput(): void {
    this.abandoned = true;
    this.input.destroy();
  }

  private timeout(): void {
    if (this.timedOut) return;
    this.timedOut = true;
    this.limitsExceeded.add('parse_timeout');
    this.stopped = true;
    this.feeding = false;
    this.splitter.destroy();
    this.input.destroy();
    this.rejectAbort(new ParseTimeout());
  }

  // ---------------------------------------------------------------- leaves

  private async openLeaf(
    state: NodeState,
    kind: PartInfo['kind'],
    encoding: string,
    charset: string | null,
  ): Promise<void> {
    if (!KNOWN_TRANSFER_ENCODINGS.has(encoding)) this.defects.add('unknown_transfer_encoding');
    let converter: CharsetConverter | null = null;
    if (kind !== 'attachment') {
      let name = iconvCharset(charset);
      if (name === null) {
        this.defects.add('unknown_charset');
        name = 'utf-8';
      }
      converter = new CharsetConverter(name);
    }
    const leaf: LeafState = {
      state,
      kind,
      decoder: transferDecoder(encoding),
      converter,
      writer: null,
      notStored: false,
      hash: createHash('sha256'),
      sizeBytes: 0,
      encodedBytes: 0,
      decodedBytes: 0,
      head: [],
      headLength: 0,
      tail: Buffer.alloc(0),
      charset,
      flags: new Set(),
      maxBytes: kind === 'attachment' ? this.limits.maxAttachmentBytes : this.limits.maxBodyBytes,
      limitName: kind === 'attachment' ? 'attachment_size' : 'body_size',
    };
    if (state.inMessage) leaf.flags.add('nested_message_part');
    this.leaf = leaf;
    const info: PartInfo = {
      partIndex: state.structure.index,
      partPath: state.path,
      depth: state.depth,
      kind,
    };
    leaf.writer = await this.infra(() => this.options.sink.open(info));
  }

  private async feedLeaf(leaf: LeafState, encoded: Buffer): Promise<void> {
    leaf.encodedBytes += encoded.length;
    await this.emitDecoded(leaf, leaf.decoder.write(encoded));
  }

  private async emitDecoded(leaf: LeafState, decoded: Buffer): Promise<void> {
    if (decoded.length === 0) return;
    leaf.decodedBytes += decoded.length;
    this.totalDecodedBytes += decoded.length;
    if (this.totalDecodedBytes > this.limits.maxTotalDecodedBytes) {
      this.truncateAndStop(leaf.state.structure, 'total_decoded_size');
    }
    if (
      leaf.decodedBytes >= RATIO_CHECK_FROM_BYTES &&
      leaf.decodedBytes / Math.max(leaf.encodedBytes, 1) > this.limits.maxDecodedRatio
    ) {
      this.truncateAndStop(leaf.state.structure, 'decoded_ratio');
    }
    await this.emitOutput(leaf, leaf.converter ? leaf.converter.write(decoded) : decoded);
  }

  private async emitOutput(leaf: LeafState, output: Buffer): Promise<void> {
    if (output.length === 0) return;
    if (!leaf.notStored && leaf.sizeBytes + output.length > leaf.maxBytes) {
      // Per-part limit: no object, the part is still hashed and measured; the parse goes on.
      leaf.notStored = true;
      leaf.flags.add('not_stored_size_limit');
      this.limitsExceeded.add(leaf.limitName);
      const writer = leaf.writer;
      leaf.writer = null;
      if (writer) await this.infra(() => writer.abort());
    }
    leaf.sizeBytes += output.length;
    leaf.hash.update(output);
    if (leaf.kind === 'attachment') keepHeadAndTail(leaf, output);
    const writer = leaf.writer;
    if (writer) await this.infra(() => writer.write(output));
  }

  private async finishLeaf(): Promise<void> {
    const leaf = this.leaf;
    if (!leaf) return;
    await this.emitDecoded(leaf, leaf.decoder.end());
    if (leaf.converter) await this.emitOutput(leaf, leaf.converter.end());
    if (leaf.decoder.invalid) {
      if (leaf.decoder instanceof Base64Decoder) this.defects.add('invalid_base64');
      if (leaf.decoder instanceof QuotedPrintableDecoder)
        this.defects.add('invalid_quoted_printable');
    }
    const { structure } = leaf.state;
    structure.encodedBytes = leaf.encodedBytes;
    structure.decodedBytes = leaf.decodedBytes;
    const writer = leaf.writer;
    leaf.writer = null;
    // From here on the leaf is complete; a failing finish leaves no in-flight writer to abort.
    this.leaf = null;
    const stored = writer ? await this.infra(() => writer.finish()) : null;
    const sha256 = leaf.hash.digest('hex');

    if (leaf.kind !== 'attachment') {
      const body: BodyResult = {
        key: stored ? stored.key : null,
        sha256,
        sizeBytes: leaf.sizeBytes,
        charset: leaf.charset,
        partIndex: structure.index,
        flags: [...leaf.flags],
      };
      if (leaf.kind === 'text') this.textBody = body;
      else this.htmlBody = body;
      return;
    }
    await this.recordAttachment(leaf, stored, sha256);
  }

  private async recordAttachment(
    leaf: LeafState,
    stored: StoredPart | null,
    sha256: string,
  ): Promise<void> {
    const { node, structure } = leaf.state;
    const head = Buffer.concat(leaf.head, leaf.headLength);
    const detected = sniffContentType(head);
    const declared = mimeToken(node.contentType, 255) ?? 'application/octet-stream';
    const name = sanitizeFilename(node.filename || undefined, this.limits.filenameMaxChars);
    const flags = new Set<AttachmentFlag>([
      ...name.flags,
      ...sniffFlags(declared, detected, name.filename),
      ...leaf.flags,
    ]);
    let archiveInfo: ArchiveSummary | null = null;
    const archiveType = ARCHIVE_TYPES.get(detected);
    if (archiveType !== undefined) {
      const info = await this.inspectArchive(archiveType, stored, head, leaf);
      for (const flag of info.flags) flags.add(flag);
      const { flags: _flags, ...summary } = info;
      archiveInfo = summary;
    }
    this.attachments.push({
      partIndex: structure.index,
      partPath: leaf.state.path,
      depth: leaf.state.depth,
      disposition: attachmentDisposition(node.disposition, Boolean(node.filename)),
      declaredContentType: declared,
      detectedContentType: detected,
      sizeBytes: leaf.sizeBytes,
      encodedSizeBytes: leaf.encodedBytes,
      sha256,
      key: stored ? stored.key : null,
      filename: name.filename,
      originalFilename: name.originalFilename,
      flags: [...flags],
      archiveInfo,
    });
  }

  private async inspectArchive(
    type: ArchiveSummary['type'],
    stored: StoredPart | null,
    head: Buffer,
    leaf: LeafState,
  ): Promise<ArchiveInfo> {
    if (type === 'gzip') return inspectGzip(head, leaf.tail, leaf.sizeBytes, this.limits);
    if (type === 'zip' && stored) {
      // readRange failures stay infrastructure errors; everything else inspectZip maps to flags.
      const part: StoredPart = {
        key: stored.key,
        readRange: (start, end, signal) =>
          stored.readRange(start, end, signal).catch((error: unknown) => {
            throw new InfrastructureFailure(error);
          }),
      };
      try {
        return await Promise.race([
          inspectZip(part, leaf.sizeBytes, this.limits, this.signal),
          this.abortPromise,
        ]);
      } catch (error) {
        if (this.timedOut) throw new ParseTimeout();
        throw error;
      }
    }
    return {
      type,
      inspected: false,
      entries: null,
      declaredUncompressedBytes: null,
      maxRatio: null,
      encryptedEntries: null,
      nestedArchives: null,
      flags: ['archive_not_inspected'],
    };
  }

  /** The in-flight part after a stop: no object, recorded in structure as truncated. */
  private async abortOpenLeaf(): Promise<void> {
    const leaf = this.leaf;
    if (!leaf) return;
    this.leaf = null;
    leaf.state.structure.truncated = true;
    const writer = leaf.writer;
    leaf.writer = null;
    if (!writer) return;
    if (this.infrastructureError || this.inputError) {
      // Best effort only: the original error is what the caller gets.
      await writer.abort().catch(() => undefined);
      return;
    }
    try {
      await writer.abort();
    } catch (error) {
      throw new InfrastructureFailure(error);
    }
  }

  /** Runs a sink or storage call; failures become infrastructure errors, the timeout wins. */
  private async infra<T>(call: () => Promise<T>): Promise<T> {
    let pending: Promise<T>;
    try {
      pending = call();
    } catch (error) {
      if (this.timedOut) throw new ParseTimeout();
      throw new InfrastructureFailure(error);
    }
    pending.catch(() => undefined);
    try {
      return await Promise.race([pending, this.abortPromise]);
    } catch (error) {
      if (this.timedOut || error instanceof ParseTimeout) throw new ParseTimeout();
      throw new InfrastructureFailure(error);
    }
  }

  // ---------------------------------------------------------------- end

  private endOfMessageChecks(): void {
    if (this.bytesRead === 0) {
      this.defects.add('empty_message');
      this.defects.add('no_headers');
    }
    this.delimiters.finish();
    for (const state of this.states.values()) {
      if (!state.delimited) continue;
      if (state.children === 0) this.defects.add('boundary_not_found');
      else if (!this.delimiters.isClosed(state.structure.index))
        this.defects.add('missing_closing_boundary');
    }
  }

  private result(): MimeParseResult {
    const limitsExceeded = [...this.limitsExceeded];
    const defects = [...this.defects];
    let status: MimeParseResult['status'] = 'parsed';
    if (this.parserError) status = 'parse_failed';
    else if (limitsExceeded.length > 0) status = 'parse_limit_exceeded';
    else if (defects.length > 0) status = 'parsed_with_defects';
    const result: MimeParseResult = {
      status,
      limitsExceeded,
      defects,
      stats: {
        bytesRead: this.bytesRead,
        sha256: this.inputHash.digest('hex'),
        inputComplete: this.inputComplete,
        partCount: this.structure.length,
        maxDepth: this.maxDepth,
        headerCount: this.headerCount,
        attachmentCount: this.attachments.length,
        decodedBytes: this.totalDecodedBytes,
        durationMs: Math.round(performance.now() - this.started),
      },
      subject: this.subject,
      headers: this.headers,
      textBody: this.textBody,
      htmlBody: this.htmlBody,
      attachments: this.attachments,
      structure: this.structure,
    };
    if (this.parserError) result.failureReason = 'parser_error';
    return result;
  }
}

function keepHeadAndTail(leaf: LeafState, output: Buffer): void {
  if (leaf.headLength < SNIFF_BYTES) {
    const piece = Buffer.from(output.subarray(0, SNIFF_BYTES - leaf.headLength));
    leaf.head.push(piece);
    leaf.headLength += piece.length;
  }
  leaf.tail =
    output.length >= TAIL_BYTES
      ? Buffer.from(output.subarray(output.length - TAIL_BYTES))
      : Buffer.concat([leaf.tail, output]).subarray(-TAIL_BYTES);
}

/** A MIME token as stored in structure and rows: lower case, token characters only, bounded. */
function mimeToken(value: string | false | null | undefined, max: number): string | null {
  if (!value) return null;
  const token = value
    .toLowerCase()
    .replace(/[^a-z0-9!#$&^_.+/-]/g, '')
    .slice(0, max);
  return token || null;
}

/** `attachment` or `inline` for the row: explicit dispositions win, a named part is an attachment. */
function attachmentDisposition(
  disposition: string | false,
  named: boolean,
): 'attachment' | 'inline' {
  if (disposition === 'attachment') return 'attachment';
  if (disposition === 'inline') return 'inline';
  return named ? 'attachment' : 'inline';
}
