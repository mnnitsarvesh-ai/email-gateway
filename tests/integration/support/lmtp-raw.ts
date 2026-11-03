import { composeExec } from './compose';
import { TOOLS } from './smtp-tools';

/**
 * Raw LMTP client run inside smtp-tools (Perl, which swaks already needs). It plays Postfix's
 * LMTP client against smtp-adapter at SMTP_ADAPTER_HOST from the Docker network, so the test
 * works the same whether the adapter runs on the host or as the `smtp-adapter` container (whose
 * LMTP ports are never published). The message travels base64-encoded on stdin; every other
 * value is an argv element (no shell).
 */
const SCRIPT = String.raw`
use strict; use warnings; use IO::Socket::INET; use MIME::Base64;
my ($host, $port, $lhlo, $from) = splice(@ARGV, 0, 4);
my (@xf, @rcpt);
for (@ARGV) { if (/^XF:(.*)$/s) { push @xf, $1 } elsif (/^RCPT:(.*)$/s) { push @rcpt, $1 } else { die "bad argument\n" } }
my $msg = do { local $/; decode_base64(<STDIN>) };
my $s = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Timeout => 30) or die "connect: $!\n";
binmode $s; $s->autoflush(1); $| = 1;
sub rd { my $tag = shift; while (defined(my $l = <$s>)) { $l =~ s/\r?\n$//; print "$tag $l\n"; return $l if $l =~ /^\d{3} /; } die "connection closed\n" }
sub cmd { my ($tag, $line) = @_; print $s "$line\r\n"; return rd($tag) }
rd('GREETING');
cmd('LHLO', "LHLO $lhlo");
cmd('XFORWARD', "XFORWARD $_") for @xf;
cmd('MAIL', "MAIL FROM:<$from>");
my ($ok, $i) = (0, 0);
for my $r (@rcpt) { my $rep = cmd("RCPT#$i", "RCPT TO:<$r>"); $ok++ if $rep =~ /^2/; $i++ }
if ($ok) {
  my $d = cmd('DATA', 'DATA');
  if ($d =~ /^354/) {
    $msg =~ s/\r?\n/\r\n/g; $msg .= "\r\n" unless $msg =~ /\r\n\z/; $msg =~ s/^\./../mg;
    print $s $msg, ".\r\n";
    rd("DATA-END#$_") for 0 .. $ok - 1;
  }
}
cmd('QUIT', 'QUIT');
`;

export interface RawLmtpRequest {
  host: string;
  port: number;
  lhlo: string;
  /** XFORWARD command arguments, one command each (e.g. `ADDR=203.0.113.9 HELO=x`). */
  xforward: readonly string[];
  from: string;
  to: readonly string[];
  message: Buffer;
}

/** Reply lines keyed by stage (`GREETING`, `LHLO`, `MAIL`, `RCPT#n`, `DATA`, `DATA-END#n`). */
export async function rawLmtp(request: RawLmtpRequest): Promise<Map<string, string>> {
  const args = [
    'perl',
    '-e',
    SCRIPT,
    request.host,
    String(request.port),
    request.lhlo,
    request.from,
    ...request.xforward.map((x) => `XF:${x}`),
    ...request.to.map((r) => `RCPT:${r}`),
  ];
  const result = await composeExec(TOOLS, args, {
    input: request.message.toString('base64'),
    timeoutMs: 120_000,
  });
  if (result.exitCode !== 0) throw new Error(`raw LMTP failed: ${result.stderr}${result.stdout}`);
  const replies = new Map<string, string>();
  for (const line of result.stdout.split('\n')) {
    const match = /^(\S+) (\d{3} .*)$/.exec(line);
    if (match) replies.set(match[1]!, match[2]!);
  }
  return replies;
}
