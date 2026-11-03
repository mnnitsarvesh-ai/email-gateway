import { type FileHandle, open, stat } from 'node:fs/promises';

/** `<dev>:<ino>` of a file (the identity that survives a rename). */
export const fileIdentity = (s: { dev: number | bigint; ino: number | bigint }): string =>
  `${s.dev.toString()}:${s.ino.toString()}`;

export interface FollowerPosition {
  fileId: string;
  /** Byte offset just after the last complete line handed out. */
  offset: number;
}

export interface ReadChunk extends FollowerPosition {
  lines: string[];
  /** True when the file had more bytes than this chunk (read again without waiting). */
  more: boolean;
  /** True when this chunk switched to a new file after a rotation. */
  rotated: boolean;
}

const isMissing = (err: unknown): boolean => {
  const code = (err as { code?: unknown } | null)?.code;
  return code === 'ENOENT' || code === 'EACCES' || code === 'EPERM';
};

/**
 * Follows a log file that is rotated by rename (`postfix logrotate`, docs/deployment/
 * mail-routing.md "Rotation"): the descriptor stays open on the old inode; when the path's
 * device/inode changes, the old file is drained to EOF (and for `rotationGraceMs` more, in case
 * postlogd writes a last line before it reopens), then the follower switches to the new file
 * at offset 0. A missing or unreadable path (`ENOENT`/`EACCES` right after the rename) is "not
 * yet", never an error. A file that shrank below the read position (copytruncate) restarts at 0.
 * Only complete lines are handed out; a partial last line waits for its LF.
 */
export class LogFollower {
  private handle: FileHandle | null = null;
  private fileId: string | null = null;
  private readPos = 0;
  private partial: Buffer = Buffer.alloc(0);
  private rotationSeenAt: number | null = null;

  constructor(
    readonly path: string,
    private readonly options: { rotationGraceMs: number; clock?: () => number } = {
      rotationGraceMs: 2000,
    },
  ) {}

  get isOpen(): boolean {
    return this.handle !== null;
  }

  /**
   * True when everything written to the followed file has been handed out: no partial line is
   * buffered and no rotation is being drained (only meaningful right after a read that returned
   * no lines).
   */
  get caughtUp(): boolean {
    return this.handle !== null && this.partial.length === 0 && this.rotationSeenAt === null;
  }

  get position(): FollowerPosition | null {
    return this.fileId === null
      ? null
      : { fileId: this.fileId, offset: this.readPos - this.partial.length };
  }

  /**
   * Opens the path. With a cursor of the same file identity it resumes at the cursor offset;
   * otherwise (first start, or the cursor's file was rotated away while the reader was down) it
   * starts at 0. Returns false when the file does not exist (yet).
   */
  async open(cursor: FollowerPosition | null): Promise<{ opened: boolean; resumed: boolean }> {
    await this.close();
    let handle: FileHandle;
    try {
      handle = await open(this.path, 'r');
    } catch (err) {
      if (isMissing(err)) return { opened: false, resumed: false };
      throw err;
    }
    const info = await handle.stat();
    const id = fileIdentity(info);
    this.handle = handle;
    this.fileId = id;
    this.partial = Buffer.alloc(0);
    this.rotationSeenAt = null;
    const resumed = cursor !== null && cursor.fileId === id && cursor.offset <= info.size;
    this.readPos = resumed ? cursor.offset : 0;
    return { opened: true, resumed };
  }

  async close(): Promise<void> {
    const handle = this.handle;
    this.handle = null;
    this.fileId = null;
    this.partial = Buffer.alloc(0);
    if (handle) await handle.close().catch(() => undefined);
  }

  /** Reads up to `maxBytes` of complete lines from the current position. */
  async read(maxBytes: number): Promise<ReadChunk | null> {
    if (!this.handle || this.fileId === null) return null;
    const info = await this.handle.stat();
    if (info.size < this.readPos) {
      // Truncated in place: start over (signals are idempotent).
      this.readPos = 0;
      this.partial = Buffer.alloc(0);
    }
    const buffer = Buffer.allocUnsafe(maxBytes);
    const { bytesRead } = await this.handle.read(buffer, 0, maxBytes, this.readPos);
    if (bytesRead > 0) {
      this.readPos += bytesRead;
      const lines = this.split(buffer.subarray(0, bytesRead));
      return {
        lines,
        ...this.position!,
        more: this.readPos < info.size || bytesRead === maxBytes,
        rotated: false,
      };
    }
    // EOF on the open descriptor: has the path moved to a new file?
    const now = (this.options.clock ?? Date.now)();
    let pathId: string | null = null;
    try {
      pathId = fileIdentity(await stat(this.path));
    } catch (err) {
      if (!isMissing(err)) throw err;
    }
    if (pathId === null || pathId === this.fileId) {
      this.rotationSeenAt = null;
      return { lines: [], ...this.position!, more: false, rotated: false };
    }
    this.rotationSeenAt ??= now;
    if (now - this.rotationSeenAt < this.options.rotationGraceMs) {
      return { lines: [], ...this.position!, more: false, rotated: false };
    }
    // Drained: hand out a last unterminated line (Postfix always ends lines; defensive).
    const tail = this.partial.length > 0 ? [this.partial.toString('utf8')] : [];
    const opened = await this.open(null);
    if (!opened.opened)
      return {
        lines: tail,
        ...(this.position ?? { fileId: pathId, offset: 0 }),
        more: false,
        rotated: false,
      };
    return { lines: tail, ...this.position!, more: true, rotated: true };
  }

  private split(data: Buffer): string[] {
    const all = this.partial.length > 0 ? Buffer.concat([this.partial, data]) : data;
    const lines: string[] = [];
    let start = 0;
    for (;;) {
      const lf = all.indexOf(0x0a, start);
      if (lf === -1) break;
      lines.push(all.subarray(start, lf).toString('utf8'));
      start = lf + 1;
    }
    this.partial = Buffer.from(all.subarray(start));
    return lines;
  }
}
