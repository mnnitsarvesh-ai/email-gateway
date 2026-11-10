import { describe, expect, it } from 'vitest';
import {
  canonicalIp,
  imageName,
  parseSockaddr,
  parseSyscall,
  parseTrace,
  quotedStrings,
  TRACE_MAX_LINES,
} from './trace-parser';

// Lines in the exact shape `strace -f -q -tt -s 256 -o` (strace 6.19, musl) wrote in the runner
// (captured from a synthetic probe on this host; addresses are probe targets).
const TRACE = [
  '16    23:49:20.663985 execve("/usr/local/bin/node", ["/usr/local/bin/node", "/scratch/in/sample"], 0xffffc1c30e38 /* 1 var */) = 0',
  '16    23:49:20.664503 openat(AT_FDCWD, "/etc/ld-musl-aarch64.path", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
  '16    23:49:20.674048 --- SIGILL {si_signo=SIGILL, si_code=ILL_ILLOPC, si_addr=0xaaaae0d624e0} ---',
  '16    23:49:20.690613 clone(child_stack=0xffffb743b950, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID|0x400000, parent_tid=[17], tls=0xffffb743ba50, child_tidptr=0xffffb78a9e88) = 17',
  '16    23:49:20.753997 openat(AT_FDCWD, "/etc/x", O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE|O_CLOEXEC, 0666) = -1 EROFS (Read-only file system)',
  '16    23:49:20.754100 openat(AT_FDCWD, "dropped.txt", O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE|O_CLOEXEC, 0666) = 18',
  '16    23:49:20.774171 clone(child_stack=NULL, flags=SIGCHLD) = 23',
  '23    23:49:20.777484 execve("/bin/sh", ["/bin/sh", "-c", "echo hi from sh"], 0xffffb74bfc90 /* 1 var */) = 0',
  '23    23:49:20.780229 exit_group(0)     = ?',
  '23    23:49:20.780348 +++ exited with 0 +++',
  '16    23:49:20.804046 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 18',
  '16    23:49:20.804131 connect(18, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("169.254.169.254")}, 16) = -1 ENETUNREACH (Network unreachable)',
  '24    23:49:20.807262 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP <unfinished ...>',
  '16    23:49:20.807303 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP <unfinished ...>',
  '24    23:49:20.807310 <... socket resumed>) = 20',
  '16    23:49:20.807320 <... socket resumed>) = 19',
  '16    23:49:20.807380 connect(19, {sa_family=AF_INET, sin_port=htons(3307), sin_addr=inet_addr("172.31.253.53")}, 16 <unfinished ...>',
  '24    23:49:20.807418 sendto(20, "\\316\\376\\1\\0\\0\\1\\0\\0\\0\\0\\0\\0\\5mysql\\0\\0\\1\\0\\1", 23, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16) = 23',
  '16    23:49:20.807505 <... connect resumed>) = -1 EINPROGRESS (Operation in progress)',
  '16    23:49:20.808712 getsockopt(19, SOL_SOCKET, SO_ERROR, [ECONNREFUSED], [4]) = 0',
  '16    23:49:25.844497 exit_group(0)     = ?',
  '17    23:49:25.845464 +++ exited with 0 +++',
  '16    23:49:25.845466 +++ exited with 0 +++',
].join('\n');

const ctx = { timedOut: false, oomKilled: false };

describe('parseTrace', () => {
  it('extracts processes, connections, denied writes', () => {
    const summary = parseTrace(TRACE, ctx);
    expect(summary.processCount).toBe(2);
    expect(summary.processes).toEqual([
      expect.objectContaining({
        seq: 0,
        parentSeq: null,
        image: 'node',
        exitCode: 0,
        killedBy: null,
      }),
      expect.objectContaining({ seq: 1, parentSeq: 0, image: 'sh', exitCode: 0, killedBy: null }),
    ]);
    expect(summary.processes[1]!.argvSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(summary.images).toEqual(['node', 'sh']);
    expect(summary.shellSpawns).toBe(1);
    expect(summary.connections).toEqual([
      { ip: '169.254.169.254', port: 80, protocol: 'tcp', outcome: 'unreachable' },
      { ip: '172.31.253.53', port: 3307, protocol: 'tcp', outcome: 'refused' },
    ]);
    expect(summary.connectionAttempts).toBe(2);
    expect(summary.deniedWrites).toBe(1);
    expect(summary.persistenceAttempts).toBe(0);
    expect(summary.truncated).toBe(false);
  });

  it('IPv6, v4-mapped and successful connects; UDP sendto to a non-loopback address', () => {
    const summary = parseTrace(
      [
        '5 00:00:00.000001 execve("/bin/sh", ["sh"], 0x1 /* 1 var */) = 0',
        '5 00:00:00.000002 socket(AF_INET6, SOCK_STREAM, IPPROTO_IP) = 3',
        '5 00:00:00.000003 connect(3, {sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "fd00:ec2::254", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network unreachable)',
        '5 00:00:00.000004 connect(4, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:10.0.0.1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ETIMEDOUT (Connection timed out)',
        '5 00:00:00.000005 connect(6, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("172.31.253.53")}, 16) = 0',
        '5 00:00:00.000006 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 7',
        '5 00:00:00.000007 sendto(7, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (Network unreachable)',
        '5 00:00:00.000008 connect(8, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT (No such file or directory)',
        '5 00:00:00.000009 connect(9, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16) = 0',
      ].join('\n'),
      ctx,
    );
    expect(summary.connections).toEqual([
      { ip: 'fd00:ec2::254', port: 80, protocol: 'tcp', outcome: 'unreachable' },
      { ip: '10.0.0.1', port: 443, protocol: 'tcp', outcome: 'timeout' },
      { ip: '172.31.253.53', port: 80, protocol: 'tcp', outcome: 'connected' },
      { ip: '8.8.8.8', port: 53, protocol: 'udp', outcome: 'unreachable' },
    ]);
  });

  it('pending non-blocking connects without a SO_ERROR answer stay timeout; numeric SO_ERROR is understood', () => {
    const summary = parseTrace(
      [
        '5 00:00:00.000001 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.1.1.1")}, 16) = -1 EINPROGRESS (Operation now in progress)',
        '5 00:00:00.000002 connect(4, {sa_family=AF_INET, sin_port=htons(81), sin_addr=inet_addr("10.1.1.2")}, 16) = -1 EINPROGRESS (Operation now in progress)',
        '5 00:00:00.000003 getsockopt(4, SOL_SOCKET, SO_ERROR, [113], [4]) = 0',
      ].join('\n'),
      ctx,
    );
    expect(summary.connections.map((c) => c.outcome)).toEqual(['timeout', 'unreachable']);
  });

  it('privilege, persistence, environment checks and pids exhaustion', () => {
    const summary = parseTrace(
      [
        '5 00:00:00.000001 execve("/bin/sh", ["sh"], 0x1 /* 1 var */) = 0',
        '5 00:00:00.000002 clone(child_stack=NULL, flags=SIGCHLD) = 6',
        '6 00:00:00.000003 execve("/bin/mount", ["mount", "-t", "tmpfs"], 0x1 /* 1 var */) = 0',
        '6 00:00:00.000004 mount("none", "/scratch/m", "tmpfs", 0, NULL) = -1 EPERM (Operation not permitted)',
        '5 00:00:00.000005 setuid(0) = -1 EPERM (Operation not permitted)',
        '5 00:00:00.000006 execve("/usr/bin/sudo", ["sudo"], 0x1 /* 1 var */) = -1 ENOENT (No such file or directory)',
        '5 00:00:00.000007 openat(AT_FDCWD, "/etc/crontab", O_WRONLY|O_APPEND) = -1 EROFS (Read-only file system)',
        '5 00:00:00.000008 openat(AT_FDCWD, "/.dockerenv", O_RDONLY) = -1 ENOENT (No such file or directory)',
        '5 00:00:00.000009 newfstatat(AT_FDCWD, "/proc/1/cgroup", {st_mode=S_IFREG|0444, st_size=0, ...}, 0) = 0',
        '5 00:00:00.000010 clone(child_stack=NULL, flags=SIGCHLD) = -1 EAGAIN (Resource temporarily unavailable)',
        '5 00:00:00.000011 mkdir("/usr/local/eg", 0777) = -1 EROFS (Read-only file system)',
        '5 00:00:00.000012 mkdir("/scratch/work/x", 0777) = 0',
        '5 00:00:00.000013 openat(AT_FDCWD, "/scratch/../etc/passwd", O_WRONLY) = -1 EROFS (Read-only file system)',
      ].join('\n'),
      ctx,
    );
    expect(summary.privilegeAttempts).toBe(4); // mount exec, mount syscall, setuid, sudo exec
    expect(summary.persistenceAttempts).toBe(2); // crontab, ../etc/passwd
    expect(summary.environmentChecks).toBe(2);
    expect(summary.pidsLimitHits).toBe(1);
    expect(summary.deniedWrites).toBe(3); // crontab, /usr/local/eg, ../etc/passwd
  });

  it('kills are attributed to the timeout or the OOM killer', () => {
    const lines = [
      '5 00:00:00.000001 execve("/usr/local/bin/node", ["node"], 0x1 /* 1 var */) = 0',
      '5 00:00:01.000000 +++ killed by SIGKILL +++',
    ].join('\n');
    expect(parseTrace(lines, { timedOut: true, oomKilled: false }).processes[0]!.killedBy).toBe(
      'timeout',
    );
    expect(parseTrace(lines, { timedOut: false, oomKilled: true }).processes[0]!.killedBy).toBe(
      'memory',
    );
    expect(parseTrace(lines, ctx).processes[0]!.killedBy).toBeNull();
  });

  it('caps listed processes at 32 and connections at 50, counts all', () => {
    const lines = ['1 00:00:00.000001 execve("/bin/sh", ["sh"], 0x1 /* 1 var */) = 0'];
    for (let pid = 2; pid < 80; pid += 1)
      lines.push(`1 00:00:00.000002 clone(child_stack=NULL, flags=SIGCHLD) = ${pid}`);
    for (let i = 0; i < 70; i += 1) {
      lines.push(
        `1 00:00:00.000003 connect(3, {sa_family=AF_INET, sin_port=htons(${1000 + i}), sin_addr=inet_addr("10.0.0.9")}, 16) = -1 ECONNREFUSED (Connection refused)`,
      );
    }
    const summary = parseTrace(lines.join('\n'), ctx);
    expect(summary.processCount).toBe(79);
    expect(summary.processes).toHaveLength(32);
    expect(summary.connections).toHaveLength(50);
    expect(summary.connectionAttempts).toBe(70);
  });

  it('stops at the line cap', () => {
    const line =
      '1 00:00:00.000001 openat(AT_FDCWD, "/x", O_RDONLY) = -1 ENOENT (No such file or directory)\n';
    const summary = parseTrace(line.repeat(TRACE_MAX_LINES + 5), ctx);
    expect(summary.truncated).toBe(true);
    expect(summary.linesParsed).toBe(TRACE_MAX_LINES);
  });

  it('hostile lines never throw and never produce invalid images or IPs', () => {
    const hostile = [
      '1 00:00:00.000001 execve("/tmp/../$(reboot)\\n\\"evil name", ["x"], 0x1 /* 1 var */) = 0',
      '1 00:00:00.000002 connect(3, {sa_family=AF_INET, sin_port=htons(99999), sin_addr=inet_addr("999.1.1.1")}, 16) = 0',
      '1 00:00:00.000003 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("010.000.000.001")}, 16) = 0',
      'not a trace line at all',
      '1 00:00:00.000004 <... connect resumed>) = 0',
      `1 00:00:00.000005 openat(AT_FDCWD, "${'a'.repeat(20_000)}", O_RDONLY) = 3`,
    ].join('\n');
    const summary = parseTrace(hostile, ctx);
    for (const p of summary.processes) expect(p.image).toMatch(/^[A-Za-z0-9._+-]{1,64}$/);
    // Out-of-range ports and non-canonical / invalid addresses are dropped, never guessed.
    expect(summary.connections).toEqual([]);
  });
});

describe('helpers', () => {
  it('parseSyscall takes the last result marker', () => {
    expect(
      parseSyscall('openat(AT_FDCWD, "a) = 5", O_RDONLY) = -1 ENOENT (No such file or directory)'),
    ).toEqual({
      name: 'openat',
      args: 'AT_FDCWD, "a) = 5", O_RDONLY',
      result: '-1',
      errno: 'ENOENT',
    });
    expect(parseSyscall('exit_group(0)     = ?')?.result).toBe('?');
    expect(parseSyscall('garbage')).toBeNull();
  });

  it('quotedStrings, imageName, canonicalIp, parseSockaddr', () => {
    expect(quotedStrings('AT_FDCWD, "/a \\"b\\"", "/c"', 2)).toEqual(['/a "b"', '/c']);
    expect(imageName('/usr/bin/python3.12')).toBe('python3.12');
    expect(imageName('/bin/evil name;rm')).toBe('evil_name_rm');
    expect(imageName('')).toBe('unknown');
    expect(canonicalIp('FD00:EC2:0:0:0:0:0:254')).toBe('fd00:ec2::254');
    expect(canonicalIp('::ffff:7f00:1')).toBe('127.0.0.1');
    expect(canonicalIp('1.2.3')).toBeNull();
    expect(
      parseSockaddr('3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("1.2.3.4")}'),
    ).toBeNull();
  });
});
